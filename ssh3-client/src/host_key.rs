//! The verification of the certificate of a server against the known_hosts
//! file.
//!
//! The verification happens during the TLS handshake: the certificate the
//! server presents is compared with the certificates pinned for the host,
//! and the `StrictHostKeyChecking` policy decides what happens when they do
//! not match.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{Error as RustlsError, RootCertStore};
use ssh3_quinn::Ssh3ConfigError;

use crate::known_hosts::{HostCertificateStatus, KnownHosts, certificate_fingerprint};
use crate::strict_host_key::{
    HostKeyContext, HostKeyOutcome, Ssh3StrictHostKeyChecking, decide_host_key,
};

/// The ALPN protocol the SSH3 client speaks.
const H3_ALPN: &[u8] = b"h3";

/// The trust of the client that is based on the known_hosts file.
///
/// The certificates pinned for the host are the trust anchors of the
/// connection, and the `StrictHostKeyChecking` policy decides what happens
/// when the server presents another certificate.
#[derive(Clone, Debug)]
pub struct Ssh3KnownHostsTrust {
    /// The policy that decides what to do with a host that is not pinned yet
    /// or that presents another certificate.
    pub policy: Ssh3StrictHostKeyChecking,
    /// The path of the known_hosts file.
    pub path: PathBuf,
    /// The certificate authorities the chain of the server may be verified
    /// against, on top of the built-in roots.
    pub authorities: Vec<CertificateDer<'static>>,
}

/// The reason why the user could not be asked about an unknown certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ssh3HostKeyPromptError {
    /// The session has no terminal to ask the question on.
    NotInteractive,
}

impl fmt::Display for Ssh3HostKeyPromptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInteractive => {
                write!(f, "the session is not interactive")
            }
        }
    }
}

impl std::error::Error for Ssh3HostKeyPromptError {}

/// The state the host key verification shares with the client.
///
/// The verification runs inside the TLS handshake, so the outcome of the
/// decision is handed over to the client through this state.
#[derive(Debug)]
pub(crate) struct HostKeyState {
    inner: Mutex<HostKeyStateInner>,
}

#[derive(Debug)]
struct HostKeyStateInner {
    host: String,
    path: PathBuf,
    known_hosts: KnownHosts,
    refusal: Option<String>,
    to_pin: Option<CertificateDer<'static>>,
}

impl HostKeyState {
    /// Builds the state of a verification.
    pub(crate) fn new(host: String, path: PathBuf, known_hosts: KnownHosts) -> Self {
        Self {
            inner: Mutex::new(HostKeyStateInner {
                host,
                path,
                known_hosts,
                refusal: None,
                to_pin: None,
            }),
        }
    }

    /// The state of the verification, even when the lock is poisoned.
    fn lock(&self) -> MutexGuard<'_, HostKeyStateInner> {
        self.inner.lock().unwrap_or_else(|err| err.into_inner())
    }

    /// The message of the refusal of the certificate, when there was one.
    pub(crate) fn refusal(&self) -> Option<String> {
        self.lock().refusal.clone()
    }

    /// The certificate the handshake accepted and that must be pinned.
    pub(crate) fn take_to_pin(&self) -> Option<CertificateDer<'static>> {
        self.lock().to_pin.take()
    }

    /// Records the certificate the handshake accepted.
    fn set_to_pin(&self, certificate: CertificateDer<'static>) {
        self.lock().to_pin = Some(certificate);
    }

    /// Records the refusal of the certificate.
    fn set_refusal(&self, message: String) {
        self.lock().refusal = Some(message);
    }

    /// The canonical host key of the target.
    pub(crate) fn host(&self) -> String {
        self.lock().host.clone()
    }

    /// The path of the known_hosts file.
    pub(crate) fn path(&self) -> PathBuf {
        self.lock().path.clone()
    }

    /// Classifies a presented certificate against the pins of the host.
    fn check_certificate(&self, certificate: &CertificateDer<'_>) -> HostCertificateStatus {
        let inner = self.lock();
        inner
            .known_hosts
            .check_certificate(&inner.host, certificate)
    }

    /// The fingerprints of the certificates pinned for the host.
    fn fingerprints(&self) -> Vec<String> {
        let inner = self.lock();
        inner.known_hosts.fingerprints(&inner.host)
    }
}

/// The certificate verifier that pins the certificate of the server.
///
/// The verifier delegates the verification of the chain of the certificate to
/// the standard verifier of the certificate authorities, and applies the
/// `StrictHostKeyChecking` policy to the result.
pub(crate) struct KnownHostsVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    policy: Ssh3StrictHostKeyChecking,
    state: Arc<HostKeyState>,
    interactive: bool,
}

impl fmt::Debug for KnownHostsVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KnownHostsVerifier")
            .field("policy", &self.policy)
            .finish()
    }
}

impl ServerCertVerifier for KnownHostsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let fingerprint = certificate_fingerprint(end_entity);
        let status = self.state.check_certificate(end_entity);
        crate::diag_debug!(
            "ssh3 known_hosts: the presented fingerprint of {} is {}, the pin status is {status:?}, the pinned fingerprints are {:?}",
            self.state.host(),
            fingerprint,
            self.state.fingerprints()
        );

        if status == HostCertificateStatus::Matches {
            // The presented certificate is the pinned one: it is the trust
            // anchor of the connection.
            return Ok(ServerCertVerified::assertion());
        }

        let chain_trusted = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .is_ok();
        let pinned = self.state.fingerprints();
        let host = self.state.host();
        let path = self.state.path();

        let decision = decide_host_key(
            self.policy,
            &HostKeyContext {
                host: &host,
                path: &path,
                status,
                presented_fingerprint: &fingerprint,
                pinned_fingerprints: &pinned,
                chain_trusted,
                self_signed: is_self_signed(end_entity),
                interactive: self.interactive,
            },
        );

        match decision.outcome {
            HostKeyOutcome::Accept => {
                if decision.pin {
                    self.state.set_to_pin(end_entity.clone().into_owned());
                }
                Ok(ServerCertVerified::assertion())
            }
            HostKeyOutcome::Warn => {
                if let Some(message) = decision.message.as_deref() {
                    eprintln!("ssh3: {message}");
                }
                if decision.pin {
                    self.state.set_to_pin(end_entity.clone().into_owned());
                }
                Ok(ServerCertVerified::assertion())
            }
            HostKeyOutcome::Ask => match prompt_host_key_confirmation(&fingerprint, &path) {
                Ok(true) => {
                    self.state.set_to_pin(end_entity.clone().into_owned());
                    Ok(ServerCertVerified::assertion())
                }
                Ok(false) => {
                    let message = format!(
                        "the certificate of {host} was not confirmed, the connection is aborted"
                    );
                    self.state.set_refusal(message.clone());
                    Err(RustlsError::General(message))
                }
                Err(Ssh3HostKeyPromptError::NotInteractive) => {
                    let message = format!(
                        "the certificate of {host} is not pinned in {} and the session is not interactive, refusing to connect",
                        path.display()
                    );
                    self.state.set_refusal(message.clone());
                    Err(RustlsError::General(message))
                }
            },
            HostKeyOutcome::Reject => {
                let message = decision
                    .message
                    .unwrap_or_else(|| format!("the certificate presented by {host} was refused"));
                self.state.set_refusal(message.clone());
                Err(RustlsError::General(message))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Builds the trust anchors of the known_hosts verification.
///
/// The built-in roots of the webpki certificate authorities are used, plus
/// the authorities the caller provides.
pub(crate) fn known_hosts_roots(
    authorities: &[CertificateDer<'static>],
) -> Result<RootCertStore, crate::Ssh3ClientError> {
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for authority in authorities {
        if let Err(err) = roots.add(authority.clone()) {
            return Err(crate::Ssh3ClientError::QuinnConfig(
                Ssh3ConfigError::Rustls(err),
            ));
        }
    }
    Ok(roots)
}

/// Builds the QUIC client configuration of the known_hosts verification.
///
/// The certificate the server presents is verified by the verifier of the
/// known_hosts, which pins the certificate of the host and applies the
/// `StrictHostKeyChecking` policy to it.
pub(crate) fn known_hosts_client_config(
    trust: &Ssh3KnownHostsTrust,
    state: Arc<HostKeyState>,
) -> Result<quinn::ClientConfig, crate::Ssh3ClientError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let roots = known_hosts_roots(&trust.authorities)?;
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|err| crate::Ssh3ClientError::QuinnConfig(Ssh3ConfigError::Verifier(err)))?;

    let verifier = KnownHostsVerifier {
        inner,
        policy: trust.policy,
        state,
        interactive: console_available(),
    };

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| crate::Ssh3ClientError::QuinnConfig(Ssh3ConfigError::Rustls(err)))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![H3_ALPN.to_vec()];

    let quic_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).map_err(|err| {
            crate::Ssh3ClientError::QuinnConfig(Ssh3ConfigError::NoInitialCipherSuite(err))
        })?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
}

/// Tells whether a certificate is self-signed.
///
/// A self-signed certificate is the only one the client can pin: a
/// certificate signed by an authority the client does not know is not a
/// trust-on-first-use candidate.
fn is_self_signed(certificate: &CertificateDer<'_>) -> bool {
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(certificate.as_ref()) else {
        return false;
    };
    parsed.verify_signature(None).is_ok()
}

/// Tells whether the user can be asked about an unknown certificate.
///
/// The question is asked on the console of the user: a session that runs
/// without a console cannot ask it.
fn console_available() -> bool {
    #[cfg(unix)]
    {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Asks the user to confirm a certificate that is not pinned yet.
///
/// The question is asked on the console of the user, not on the standard
/// input of the session, and a session without a console refuses the
/// certificate instead of trusting it silently.
#[cfg(unix)]
fn prompt_host_key_confirmation(
    fingerprint: &str,
    path: &Path,
) -> Result<bool, Ssh3HostKeyPromptError> {
    use std::io::{BufRead, BufReader, Write};

    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Ssh3HostKeyPromptError::NotInteractive)?;
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .map_err(|_| Ssh3HostKeyPromptError::NotInteractive)?;
    let mut reader = BufReader::new(reader);

    let _ = writeln!(
        writer,
        "Received an unknown self-signed certificate from the server."
    );
    let _ = writeln!(writer, "We recommend not using self-signed certificates.");
    let _ = writeln!(
        writer,
        "This session is vulnerable to a machine-in-the-middle attack."
    );
    let _ = writeln!(writer, "Certificate fingerprint: {fingerprint}");
    let _ = writeln!(
        writer,
        "Do you want to add this certificate to {} (yes/no)? ",
        path.display()
    );
    let _ = writer.flush();

    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|_| Ssh3HostKeyPromptError::NotInteractive)?;
        if read == 0 {
            return Err(Ssh3HostKeyPromptError::NotInteractive);
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "yes" => return Ok(true),
            "no" => return Ok(false),
            _ => {
                let _ = writeln!(writer, "Invalid answer, answer \"yes\" or \"no\"");
                let _ = writer.flush();
            }
        }
    }
}

/// Asks the user to confirm a certificate that is not pinned yet.
///
/// The Windows client has no console to ask the question on: the
/// certificate is refused, exactly like the Go implementation does.
#[cfg(not(unix))]
fn prompt_host_key_confirmation(
    _fingerprint: &str,
    _path: &Path,
) -> Result<bool, Ssh3HostKeyPromptError> {
    Err(Ssh3HostKeyPromptError::NotInteractive)
}

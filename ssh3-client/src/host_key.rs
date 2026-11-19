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

/// The pin request the handshake accepted: the certificate to record in the
/// known_hosts file, and whether it replaces the old pins of the host (the
/// rotation of a legitimate certificate) instead of appending (a first
/// contact).
#[derive(Clone, Debug)]
pub(crate) struct PinRequest {
    /// The certificate the handshake accepted.
    pub certificate: CertificateDer<'static>,
    /// Whether the certificate replaces the old pins of the host.
    pub replaces: bool,
}

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
    to_pin: Option<PinRequest>,
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
    pub(crate) fn take_to_pin(&self) -> Option<PinRequest> {
        self.lock().to_pin.take()
    }

    /// Records the certificate the handshake accepted.
    ///
    /// The `replaces` flag marks a legitimate rotation: the certificate
    /// replaces the old pins of the host instead of appending to them
    /// (CERT-VERIFICATION-CANON.md 2.4).
    fn set_to_pin(&self, certificate: CertificateDer<'static>, replaces: bool) {
        self.lock().to_pin = Some(PinRequest {
            certificate,
            replaces,
        });
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
                    self.state
                        .set_to_pin(end_entity.clone().into_owned(), decision.replace);
                }
                Ok(ServerCertVerified::assertion())
            }
            HostKeyOutcome::Warn => {
                if let Some(message) = decision.message.as_deref() {
                    eprintln!("ssh3: {message}");
                }
                if decision.pin {
                    self.state
                        .set_to_pin(end_entity.clone().into_owned(), decision.replace);
                }
                Ok(ServerCertVerified::assertion())
            }
            HostKeyOutcome::Ask => match prompt_host_key_confirmation(&fingerprint, &path) {
                Ok(true) => {
                    self.state
                        .set_to_pin(end_entity.clone().into_owned(), decision.replace);
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
    key_log: Option<Arc<dyn rustls::KeyLog>>,
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
    if let Some(key_log) = key_log {
        client_crypto.key_log = key_log;
    }
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

#[cfg(test)]
mod tests {
    use super::{HostKeyState, KnownHostsVerifier};
    use crate::known_hosts::{KnownHosts, append_known_host, replace_known_host};
    use crate::strict_host_key::Ssh3StrictHostKeyChecking;
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::sync::Arc;

    /// A certificate authority and two leaves signed by it, all three in
    /// the DER form. The two leaves carry the same SANs but ride different
    /// keys: the pinned certificate and the rotated one of the tests.
    fn certificate_authority_and_leaves(
        san: &str,
    ) -> (
        CertificateDer<'static>,
        CertificateDer<'static>,
        CertificateDer<'static>,
    ) {
        let issuer_key = rcgen::KeyPair::generate().expect("a key pair can be generated");
        let mut issuer_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("the parameters are valid");
        issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let issuer_certificate = issuer_params
            .self_signed(&issuer_key)
            .expect("the certificate authority can be signed");
        let issuer = rcgen::Issuer::new(issuer_params, &issuer_key);

        let leaf_der = || {
            let leaf_key = rcgen::KeyPair::generate().expect("a key pair can be generated");
            let leaf_params = rcgen::CertificateParams::new(vec![san.to_string()])
                .expect("the parameters are valid");
            let leaf = leaf_params
                .signed_by(&leaf_key, &issuer)
                .expect("the leaf can be signed by the authority");
            CertificateDer::from(leaf.der().to_vec())
        };
        let pinned = leaf_der();
        let rotated = leaf_der();

        (
            CertificateDer::from(issuer_certificate.der().to_vec()),
            pinned,
            rotated,
        )
    }

    /// The verifier of a trust whose roots hold exactly the given
    /// authorities: the production construction of the inner verifier.
    fn verifier_with_authorities(
        authorities: &[CertificateDer<'static>],
        policy: Ssh3StrictHostKeyChecking,
        state: Arc<HostKeyState>,
    ) -> KnownHostsVerifier {
        let roots = crate::host_key::known_hosts_roots(authorities)
            .expect("the trust anchors can be built");
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .expect("the inner verifier can be built");
        KnownHostsVerifier {
            inner,
            policy,
            state,
            interactive: false,
        }
    }

    /// The renewal of a CA signed certificate is a legitimate rotation: the
    /// pinned certificate is the old leaf, the server presents a new leaf
    /// signed by the very same authority, and the chain verifies against it
    /// (CERT-VERIFICATION-CANON.md 2.4). The rotated certificate replaces
    /// the old pins instead of refusing the session.
    #[tokio::test]
    async fn a_ca_valid_rotation_repins_instead_of_refusing() {
        let (authority, pinned_leaf, rotated_leaf) = certificate_authority_and_leaves("localhost");

        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("known_hosts");
        let host = "127.0.0.1:4433/ssh3-term";
        append_known_host(&path, host, &pinned_leaf).unwrap();

        let (known_hosts, _) = KnownHosts::load(&path).unwrap();
        let state = Arc::new(HostKeyState::new(
            host.to_string(),
            path.clone(),
            known_hosts,
        ));
        let verifier =
            verifier_with_authorities(&[authority], Ssh3StrictHostKeyChecking::Yes, state.clone());

        let verdict = verifier.verify_server_cert(
            &rotated_leaf,
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(
            verdict.is_ok(),
            "the rotation of a CA valid certificate is legitimate: {verdict:?}"
        );

        let pin = state
            .take_to_pin()
            .expect("the rotated certificate is pinned");
        assert_eq!(pin.certificate.as_ref(), rotated_leaf.as_ref());
        assert!(
            pin.replaces,
            "the rotation replaces the old pins instead of appending"
        );

        replace_known_host(&path, host, &pin.certificate).unwrap();
        let (known_hosts, _) = KnownHosts::load(&path).unwrap();
        assert_eq!(
            known_hosts.check_certificate(host, &rotated_leaf),
            crate::known_hosts::HostCertificateStatus::Matches
        );
        assert_eq!(
            known_hosts.check_certificate(host, &pinned_leaf),
            crate::known_hosts::HostCertificateStatus::Changed,
            "the old pin is gone"
        );
    }

    /// The first contact of a host whose certificate is signed by a known
    /// authority rides the CA anchor: the host is accepted, and only the
    /// `accept-new` policy records the pin.
    #[tokio::test]
    async fn a_first_contact_of_a_ca_valid_host_is_accepted_without_a_pin() {
        let (authority, leaf, _second_leaf) = certificate_authority_and_leaves("localhost");

        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("known_hosts");
        let host = "127.0.0.1:4433/ssh3-term";
        let (known_hosts, _) = KnownHosts::load(&path).unwrap();
        let state = Arc::new(HostKeyState::new(
            host.to_string(),
            path.clone(),
            known_hosts,
        ));
        let verifier =
            verifier_with_authorities(&[authority], Ssh3StrictHostKeyChecking::Yes, state.clone());

        let verdict = verifier.verify_server_cert(
            &leaf,
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(
            verdict.is_ok(),
            "a CA valid first contact is accepted under the yes policy: {verdict:?}"
        );
        assert!(
            state.take_to_pin().is_none(),
            "the yes policy never pins a first contact"
        );
    }

    /// A host pinned under one certificate that presents a self-signed
    /// certificate is refused: the rotation of a self-signed certificate has
    /// no proof (CERT-VERIFICATION-CANON.md 2.4: the SSHFP re-pin rides an
    /// out-of-band unpinned first contact, not a Changed leaf).
    #[tokio::test]
    async fn a_self_signed_rotation_stays_a_refusal() {
        let (_authority, pinned_leaf, _second_leaf) = certificate_authority_and_leaves("localhost");
        let rotated_key = rcgen::KeyPair::generate().expect("a key pair can be generated");
        let rotated_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("the parameters are valid");
        let rotated = rotated_params
            .self_signed(&rotated_key)
            .expect("the rotated certificate can be signed");
        let rotated = CertificateDer::from(rotated.der().to_vec());

        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("known_hosts");
        let host = "127.0.0.1:4433/ssh3-term";
        append_known_host(&path, host, &pinned_leaf).unwrap();

        let (known_hosts, _) = KnownHosts::load(&path).unwrap();
        let state = Arc::new(HostKeyState::new(
            host.to_string(),
            path.clone(),
            known_hosts,
        ));
        let verifier =
            verifier_with_authorities(&[], Ssh3StrictHostKeyChecking::Yes, state.clone());

        let verdict = verifier.verify_server_cert(
            &rotated,
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(
            verdict.is_err(),
            "a self-signed rotation is refused: {verdict:?}"
        );
        assert!(state.take_to_pin().is_none());
    }

    /// The pinned certificate rides the chain check untouched: a pinned
    /// leaf is its own trust anchor, so the session continues without a new
    /// pin (the byte-exact semantics of the pins).
    #[tokio::test]
    async fn the_pinned_certificate_is_its_own_trust_anchor() {
        let (_authority, leaf, _second_leaf) = certificate_authority_and_leaves("localhost");

        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("known_hosts");
        let host = "127.0.0.1:4433/ssh3-term";
        append_known_host(&path, host, &leaf).unwrap();

        let (known_hosts, _) = KnownHosts::load(&path).unwrap();
        let state = Arc::new(HostKeyState::new(
            host.to_string(),
            path.clone(),
            known_hosts,
        ));
        // No authority at all: the pin is the only anchor of the session.
        let verifier =
            verifier_with_authorities(&[], Ssh3StrictHostKeyChecking::Yes, state.clone());

        let verdict = verifier.verify_server_cert(
            &leaf,
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(
            verdict.is_ok(),
            "the pinned certificate is the trust anchor: {verdict:?}"
        );
        assert!(state.take_to_pin().is_none(), "no new pin is recorded");
    }

    /// The state hands the pinned certificate over exactly once: the
    /// `take` clears the request, a rotation keeps its `replaces` flag.
    #[test]
    fn the_pin_request_is_taken_exactly_once() {
        let (_, leaf, _second_leaf) = certificate_authority_and_leaves("localhost");
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("known_hosts");
        let (known_hosts, _) = KnownHosts::load(&path).unwrap();
        let state = HostKeyState::new("127.0.0.1:4433/ssh3-term".to_string(), path, known_hosts);

        state.set_to_pin(leaf, true);
        let pin = state.take_to_pin().expect("the request rides once");
        assert!(pin.replaces);
        assert!(state.take_to_pin().is_none(), "the second take is empty");
    }

    /// A poisoned lock of the shared state never wedges the client: the
    /// recovery reads through the poisoned guard, like the production
    /// callers do.
    #[test]
    fn a_poisoned_lock_releases_the_state() {
        let (_, leaf, _second_leaf) = certificate_authority_and_leaves("localhost");
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("known_hosts");
        let (known_hosts, _) = KnownHosts::load(&path).unwrap();
        let state = Arc::new(HostKeyState::new(
            "127.0.0.1:4433/ssh3-term".to_string(),
            path,
            known_hosts,
        ));

        let breaker = state.clone();
        let _ = std::thread::spawn(move || {
            let _guard = breaker.inner.lock();
            panic!("the lock is poisoned on purpose");
        })
        .join();

        state.set_to_pin(leaf, false);
        let pin = state.take_to_pin().expect("the poisoned lock recovers");
        assert!(!pin.replaces);
    }
}

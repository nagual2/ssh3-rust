use std::fmt;
use std::sync::Arc;

use quinn::{
    ClientConfig, ServerConfig,
    crypto::rustls::{NoInitialCipherSuite, QuicClientConfig, QuicServerConfig},
};
use rustls::{
    RootCertStore,
    client::VerifierBuilderError,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};

#[derive(Debug)]
pub enum Ssh3ConfigError {
    Rcgen(rcgen::Error),
    Rustls(rustls::Error),
    Verifier(VerifierBuilderError),
    NoInitialCipherSuite(NoInitialCipherSuite),
}

impl fmt::Display for Ssh3ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rcgen(err) => write!(f, "{err}"),
            Self::Rustls(err) => write!(f, "{err}"),
            Self::Verifier(err) => write!(f, "{err}"),
            Self::NoInitialCipherSuite(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Ssh3ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rcgen(err) => Some(err),
            Self::Rustls(err) => Some(err),
            Self::Verifier(err) => Some(err),
            Self::NoInitialCipherSuite(err) => Some(err),
        }
    }
}

impl From<rcgen::Error> for Ssh3ConfigError {
    fn from(value: rcgen::Error) -> Self {
        Self::Rcgen(value)
    }
}

impl From<rustls::Error> for Ssh3ConfigError {
    fn from(value: rustls::Error) -> Self {
        Self::Rustls(value)
    }
}

impl From<VerifierBuilderError> for Ssh3ConfigError {
    fn from(value: VerifierBuilderError) -> Self {
        Self::Verifier(value)
    }
}

impl From<NoInitialCipherSuite> for Ssh3ConfigError {
    fn from(value: NoInitialCipherSuite) -> Self {
        Self::NoInitialCipherSuite(value)
    }
}

const H3_ALPN: &[u8] = b"h3";

fn tls_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

pub fn server_config_with_single_cert(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, Ssh3ConfigError> {
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(tls_provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    server_crypto.alpn_protocols = vec![H3_ALPN.to_vec()];
    Ok(ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto)?,
    )))
}

pub fn client_config_with_roots(roots: RootCertStore) -> Result<ClientConfig, Ssh3ConfigError> {
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(tls_provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![H3_ALPN.to_vec()];
    Ok(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        client_crypto,
    )?)))
}

pub fn client_config_for_certificate(
    server_certificate: CertificateDer<'static>,
) -> Result<ClientConfig, Ssh3ConfigError> {
    let mut roots = RootCertStore::empty();
    roots.add(server_certificate)?;
    client_config_with_roots(roots)
}

pub fn client_config_with_webpki_roots() -> Result<ClientConfig, Ssh3ConfigError> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    client_config_with_roots(roots)
}

pub fn client_config_insecure() -> Result<ClientConfig, Ssh3ConfigError> {
    let mut client_config = rustls::ClientConfig::builder_with_provider(tls_provider())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    client_config.alpn_protocols = vec![H3_ALPN.to_vec()];
    Ok(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        client_config,
    )?)))
}

pub fn self_signed_server_config(
    subject_alt_names: Vec<String>,
) -> Result<(ServerConfig, CertificateDer<'static>), Ssh3ConfigError> {
    // `generate_simple_self_signed` turns every name into a DNS SAN, which
    // leaves a certificate that rustls refuses for an IP address. Split the
    // names instead: the addresses become IP SANs, the rest stay DNS names.
    let mut dns_names = Vec::new();
    let mut ip_sans = Vec::new();
    for name in &subject_alt_names {
        match name.parse::<std::net::IpAddr>() {
            Ok(address) => ip_sans.push(rcgen::SanType::IpAddress(address)),
            Err(_) => dns_names.push(name.clone()),
        }
    }
    let mut params = rcgen::CertificateParams::new(dns_names)?;
    params.subject_alt_names.extend(ip_sans);
    let signing_key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&signing_key)?;
    let certificate = cert.der().clone();
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let server_config = server_config_with_single_cert(vec![certificate.clone()], private_key)?;
    Ok((server_config, certificate))
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        ))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

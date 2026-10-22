//! The known_hosts file of the SSH3 client.
//!
//! The file pins the X.509 certificate of a server, exactly like the Go
//! implementation does. A line is made of the canonical host key of the
//! target, the key type of the pin and the base64 of the DER of the
//! certificate:
//!
//! ```text
//! example.org:443/ssh3-term x509-certificate MIIDqTCCAnugAwIBAgIU...
//! ```
//!
//! The canonical host key is the part of the URL the client connects to: the
//! host, the port and the path, without the scheme and without the user.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use http::Uri;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};

/// The name of the directory that holds the state of the client.
pub const SSH3_DIRECTORY_NAME: &str = ".ssh3";

/// The name of the known_hosts file inside the state directory.
pub const KNOWN_HOSTS_FILE_NAME: &str = "known_hosts";

/// The key type of a pinned certificate.
const CERTIFICATE_KEY_TYPE: &str = "x509-certificate";

/// The port of a target URL that does not carry one.
const DEFAULT_PORT: u16 = 443;

/// The errors of the known_hosts handling.
#[derive(Debug)]
pub enum Ssh3KnownHostsError {
    /// The file could not be read or written.
    Io(io::Error),
    /// The host key of a pin is empty.
    InvalidHost(String),
}

impl fmt::Display for Ssh3KnownHostsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::InvalidHost(host) => write!(f, "invalid known host key: {host:?}"),
        }
    }
}

impl std::error::Error for Ssh3KnownHostsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::InvalidHost(_) => None,
        }
    }
}

impl From<io::Error> for Ssh3KnownHostsError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// How the certificate presented by a server relates to the pinned ones.
///
/// The variants mirror the ones of the Go implementation: the comparison is
/// made on the raw DER of the certificates, so a match means the very same
/// certificate and not only the same key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostCertificateStatus {
    /// No certificate is pinned for the host.
    Unknown,
    /// The presented certificate is exactly the pinned one.
    Matches,
    /// The host is pinned, but the presented certificate is another one: the
    /// server key changed, which can be a machine-in-the-middle attack.
    Changed,
}

/// The certificates pinned for the hosts of a known_hosts file.
#[derive(Clone, Debug, Default)]
pub struct KnownHosts {
    entries: HashMap<String, Vec<CertificateDer<'static>>>,
}

impl KnownHosts {
    /// Builds an empty set of pins.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses the content of a known_hosts file.
    ///
    /// A line that does not hold the three expected fields, or whose payload
    /// is not a base64 encoded certificate, is skipped: the numbers of the
    /// skipped lines are returned so that the caller can report them.
    pub fn parse(content: &str) -> (Self, Vec<usize>) {
        let mut entries: HashMap<String, Vec<CertificateDer<'static>>> = HashMap::new();
        let mut invalid_lines = Vec::new();

        for (index, line) in content.lines().enumerate() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() != 3 || fields[1] != CERTIFICATE_KEY_TYPE {
                invalid_lines.push(index);
                continue;
            }
            let Ok(der) = BASE64_STANDARD.decode(fields[2]) else {
                invalid_lines.push(index);
                continue;
            };
            if !is_certificate(&der) {
                invalid_lines.push(index);
                continue;
            }
            entries
                .entry(fields[0].to_string())
                .or_default()
                .push(CertificateDer::from(der));
        }

        (Self { entries }, invalid_lines)
    }

    /// Loads the pins of a known_hosts file.
    ///
    /// A file that does not exist yet simply holds no pin.
    pub fn load(path: &Path) -> Result<(Self, Vec<usize>), Ssh3KnownHostsError> {
        match fs::read_to_string(path) {
            Ok(content) => Ok(Self::parse(&content)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok((Self::new(), Vec::new())),
            Err(err) => Err(Ssh3KnownHostsError::Io(err)),
        }
    }

    /// Tells whether a certificate is pinned for the host.
    pub fn knows(&self, host: &str) -> bool {
        self.entries.contains_key(host)
    }

    /// The certificates pinned for the host.
    pub fn certificates(&self, host: &str) -> &[CertificateDer<'static>] {
        self.entries
            .get(host)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Classifies a presented certificate against the pins of the host.
    pub fn check_certificate(
        &self,
        host: &str,
        certificate: &CertificateDer<'_>,
    ) -> HostCertificateStatus {
        let Some(pinned) = self.entries.get(host) else {
            return HostCertificateStatus::Unknown;
        };
        if pinned.is_empty() {
            return HostCertificateStatus::Unknown;
        }
        if pinned
            .iter()
            .any(|candidate| candidate.as_ref() == certificate.as_ref())
        {
            return HostCertificateStatus::Matches;
        }
        HostCertificateStatus::Changed
    }

    /// The `SHA256:` fingerprints of the certificates pinned for the host.
    pub fn fingerprints(&self, host: &str) -> Vec<String> {
        self.certificates(host)
            .iter()
            .map(certificate_fingerprint)
            .collect()
    }
}

/// The `SHA256:` fingerprint of a certificate.
///
/// The format is the one the Go implementation uses in its messages: the
/// base64 of the SHA-256 digest of the DER of the certificate.
pub fn certificate_fingerprint(certificate: &CertificateDer<'_>) -> String {
    format!("SHA256:{}", certificate_digest_base64(certificate))
}

/// The base64 of the SHA-256 digest of the DER of a certificate.
///
/// The digest is the one the `SHA256:` fingerprint is made of.
pub fn certificate_digest_base64(certificate: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(certificate.as_ref());
    BASE64_STANDARD.encode(&digest[..])
}

/// Appends the certificate of a host to a known_hosts file.
///
/// The file is created when it does not exist yet, and the pin is appended
/// to it, exactly like the Go implementation does.
pub fn append_known_host(
    path: &Path,
    host: &str,
    certificate: &CertificateDer<'_>,
) -> Result<(), Ssh3KnownHostsError> {
    if host.trim().is_empty() {
        return Err(Ssh3KnownHostsError::InvalidHost(host.to_string()));
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        create_state_directory(parent)?;
    }

    let encoded = BASE64_STANDARD.encode(certificate.as_ref());
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{host} {CERTIFICATE_KEY_TYPE} {encoded}")?;
    Ok(())
}

/// The canonical host key of a target URL.
///
/// The key is the part of the URL the client connects to: the host, the port
/// and the path. It is the key the known_hosts file pins the certificates
/// under.
pub fn canonical_host_key(uri: &Uri) -> Option<String> {
    let host = uri.host()?;
    let port = uri.port_u16().unwrap_or(DEFAULT_PORT);
    Some(format!("{host}:{port}{}", uri.path()))
}

/// The default location of the known_hosts file.
///
/// The file lives in the state directory of the client: `~/.ssh3/known_hosts`
/// on unix and `%USERPROFILE%\.ssh3\known_hosts` on Windows.
pub fn default_known_hosts_path() -> Option<PathBuf> {
    home_directory().map(|home| home.join(SSH3_DIRECTORY_NAME).join(KNOWN_HOSTS_FILE_NAME))
}

/// The home directory of the user.
pub fn home_directory() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }
}

/// Tells whether a payload is a DER encoded X.509 certificate.
fn is_certificate(der: &[u8]) -> bool {
    x509_parser::parse_x509_certificate(der).is_ok()
}

/// Creates the state directory of the client when it does not exist yet.
///
/// The directory is private to the user: it holds the pinned certificates.
fn create_state_directory(path: &Path) -> Result<(), Ssh3KnownHostsError> {
    if path.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        HostCertificateStatus, KnownHosts, append_known_host, canonical_host_key,
        certificate_fingerprint, default_known_hosts_path,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use http::Uri;
    use rustls::pki_types::CertificateDer;

    /// Builds a self-signed certificate for the tests.
    fn self_signed_certificate(common_name: &str) -> CertificateDer<'static> {
        let params = rcgen::CertificateParams::new(vec![common_name.to_string()])
            .expect("the parameters of the certificate are valid");
        let key = rcgen::KeyPair::generate().expect("a key pair can be generated");
        let certificate = params
            .self_signed(&key)
            .expect("the certificate can be signed");
        CertificateDer::from(certificate.der().to_vec())
    }

    #[test]
    fn the_default_path_is_the_known_hosts_file_of_the_state_directory() {
        let path = default_known_hosts_path().expect("the home directory is known");
        assert!(path.ends_with(".ssh3/known_hosts") || path.ends_with(".ssh3\\known_hosts"));
    }

    #[test]
    fn the_canonical_host_key_is_the_host_the_port_and_the_path() {
        let uri = Uri::try_from("https://example.org:8443/ssh3-term").unwrap();
        assert_eq!(
            canonical_host_key(&uri).as_deref(),
            Some("example.org:8443/ssh3-term")
        );

        let uri = Uri::try_from("https://example.org/ssh3-term").unwrap();
        assert_eq!(
            canonical_host_key(&uri).as_deref(),
            Some("example.org:443/ssh3-term")
        );

        let uri = Uri::try_from("https://example.org").unwrap();
        assert_eq!(
            canonical_host_key(&uri).as_deref(),
            Some("example.org:443/")
        );
    }

    #[test]
    fn a_pinned_certificate_is_written_and_read_back() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("known_hosts");
        let certificate = self_signed_certificate("servera.ssh3");

        append_known_host(&path, "example.org:443/ssh3-term", &certificate).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let line = content.trim_end();
        assert!(line.starts_with("example.org:443/ssh3-term x509-certificate "));
        assert_eq!(
            line.split_whitespace().nth(2).unwrap(),
            BASE64_STANDARD.encode(certificate.as_ref())
        );

        let (known_hosts, invalid_lines) = KnownHosts::load(&path).unwrap();
        assert!(invalid_lines.is_empty());
        assert!(known_hosts.knows("example.org:443/ssh3-term"));
        assert_eq!(
            known_hosts.check_certificate("example.org:443/ssh3-term", &certificate),
            HostCertificateStatus::Matches
        );
        assert_eq!(
            known_hosts.fingerprints("example.org:443/ssh3-term"),
            vec![certificate_fingerprint(&certificate)]
        );
    }

    #[test]
    fn a_known_host_that_presents_another_certificate_is_detected() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("known_hosts");
        let pinned = self_signed_certificate("servera.ssh3");
        let other = self_signed_certificate("serverb.ssh3");

        append_known_host(&path, "example.org:443/", &pinned).unwrap();
        let (known_hosts, _) = KnownHosts::load(&path).unwrap();

        assert_eq!(
            known_hosts.check_certificate("example.org:443/", &pinned),
            HostCertificateStatus::Matches
        );
        assert_eq!(
            known_hosts.check_certificate("example.org:443/", &other),
            HostCertificateStatus::Changed
        );
        assert_eq!(
            known_hosts.check_certificate("unknown.example.org:443/", &pinned),
            HostCertificateStatus::Unknown
        );
    }

    #[test]
    fn the_invalid_lines_are_skipped() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("known_hosts");
        std::fs::write(
            &path,
            "not enough fields\nhost wrong-algo abc\nhost x509-certificate not-base64!!\n",
        )
        .unwrap();

        let (known_hosts, invalid_lines) = KnownHosts::load(&path).unwrap();
        assert_eq!(invalid_lines, vec![0, 1, 2]);
        assert!(!known_hosts.knows("host"));
    }

    #[test]
    fn a_missing_known_hosts_file_holds_no_pin() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("known_hosts");

        let (known_hosts, invalid_lines) = KnownHosts::load(&path).unwrap();
        assert!(invalid_lines.is_empty());
        assert!(!known_hosts.knows("example.org:443/"));
    }

    #[test]
    fn the_fingerprint_is_the_base64_of_the_sha256_of_the_der() {
        let certificate = self_signed_certificate("servera.ssh3");
        let fingerprint = certificate_fingerprint(&certificate);
        assert!(fingerprint.starts_with("SHA256:"));
        let digest = BASE64_STANDARD
            .decode(fingerprint.trim_start_matches("SHA256:"))
            .unwrap();
        assert_eq!(digest.len(), 32);
    }
}

//! SSHFP (RFC 4255) verification of the host identity.
//!
//! ssh3 pins X.509 certificates in its known_hosts file instead of raw SSH
//! public keys, so the "host key" verified here is the DER certificate
//! itself: the digests are taken over the certificate bytes, exactly the
//! bytes the known_hosts check compares.
//!
//! The DNS exchange is implemented on top of the standard library only: the
//! wire format is built and parsed here, so no third-party resolver is
//! needed. Parsing ([`parse_response`]) is deliberately kept apart from the
//! network call ([`lookup_sshfp`]) so that it can be exercised on raw
//! fixtures.
//!
//! Only a mismatch is ever fatal: a host without records, an unreachable
//! resolver or a timeout means the DNS signal is simply absent, and reading
//! that as an attack would make every host without SSHFP records unusable.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use tokio::net::UdpSocket;

/// SSHFP algorithm numbers (RFC 4255 section 5, extended by RFC 7479 for
/// Ed25519). They designate the signature algorithm of the host key the
/// fingerprint belongs to.
pub const ALGORITHM_RESERVED: u8 = 0;
pub const ALGORITHM_RSA: u8 = 1;
pub const ALGORITHM_DSA: u8 = 2;
pub const ALGORITHM_ECDSA: u8 = 3;
pub const ALGORITHM_ED25519: u8 = 4;

/// SSHFP digest numbers (RFC 4255 section 5).
pub const DIGEST_RESERVED: u8 = 0;
pub const DIGEST_SHA1: u8 = 1;
pub const DIGEST_SHA256: u8 = 2;

/// DNS constants needed to carry a type 44 (SSHFP) question and its answer.
const DNS_TYPE_SSHFP: u16 = 44;
const DNS_CLASS_IN: u16 = 1;
const DNS_HEADER_SIZE: usize = 12;

/// Asks the resolver to recurse on our behalf.
const DNS_FLAG_RECURSION_DESIRED: u16 = 1 << 8;
/// The TC bit: the answer was cut by the UDP datagram size.
const DNS_FLAG_TRUNCATED: u16 = 1 << 9;

const DNS_RCODE_SUCCESS: u8 = 0;
const DNS_RCODE_NXDOMAIN: u8 = 3;

/// Bounds the number of compression pointers followed while decoding a
/// name, so that a hostile answer cannot make us loop.
const DNS_MAX_NAME_POINTERS: usize = 16;
/// The maximum length of a domain name in wire format.
const DNS_MAX_NAME_LENGTH: usize = 255;

/// Bounds the DNS exchange. SSHFP is meant to be a cheap extra signal,
/// never a new source of connection latency - the same bound the reference
/// implementation uses.
pub const DEFAULT_SSHFP_TIMEOUT: Duration = Duration::from_secs(2);

/// The errors of the SSHFP machinery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SshfpError {
    /// The host publishes no SSHFP record at all (NXDOMAIN or NODATA). This
    /// is a soft signal, not an error.
    NoRecords,
    /// No DNS server could be determined for the lookup.
    NoDnsServers,
    /// The DNS message could not be decoded.
    Malformed(&'static str),
    /// The answer does not belong to our query.
    ResponseMismatch,
    /// The answer was cut by the UDP datagram size; a TCP retry would be
    /// required to read it.
    Truncated,
    /// No SSHFP query name could be derived from a host key.
    Name(String),
    /// The network exchange failed.
    Io(String),
}

impl std::fmt::Display for SshfpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRecords => write!(f, "no SSHFP record published for this host"),
            Self::NoDnsServers => write!(f, "no DNS server available for the SSHFP lookup"),
            Self::Malformed(reason) => write!(f, "malformed DNS message: {reason}"),
            Self::ResponseMismatch => write!(f, "DNS response does not match the query"),
            Self::Truncated => write!(f, "truncated DNS response"),
            Self::Name(reason) => write!(f, "could not derive an SSHFP query name: {reason}"),
            Self::Io(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for SshfpError {}

/// One SSHFP resource record: the algorithm of the host key, the digest
/// algorithm used to fingerprint it, and the fingerprint itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshfpRecord {
    pub algorithm: u8,
    pub digest_type: u8,
    pub fingerprint: Vec<u8>,
}

impl SshfpRecord {
    /// Reports whether the record is self-consistent: the digest type must
    /// be known and the fingerprint must have the digest length it implies.
    pub fn valid(&self) -> bool {
        match self.digest_type {
            DIGEST_SHA1 => self.fingerprint.len() == 20,
            DIGEST_SHA256 => self.fingerprint.len() == 32,
            _ => false,
        }
    }

    /// The RFC name of the host key algorithm.
    pub fn algorithm_name(&self) -> String {
        match self.algorithm {
            ALGORITHM_RSA => "RSA".to_string(),
            ALGORITHM_DSA => "DSA".to_string(),
            ALGORITHM_ECDSA => "ECDSA".to_string(),
            ALGORITHM_ED25519 => "ED25519".to_string(),
            other => format!("ALG{other}"),
        }
    }

    /// The RFC name of the digest algorithm.
    pub fn digest_name(&self) -> String {
        match self.digest_type {
            DIGEST_SHA1 => "SHA-1".to_string(),
            DIGEST_SHA256 => "SHA-256".to_string(),
            other => format!("DIGEST{other}"),
        }
    }

    /// Reports whether the record certifies the given host key: the
    /// algorithm must be the one of the key, the digest type must be one we
    /// can compute, and the bytes must be equal (in constant time).
    pub fn matches(&self, algorithm: u8, host_key: &[u8]) -> bool {
        if self.algorithm != algorithm || !self.valid() {
            return false;
        }
        match digest(self.digest_type, host_key) {
            Some(want) => constant_time_eq(&want, &self.fingerprint),
            None => false,
        }
    }
}

impl std::fmt::Display for SshfpRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} ({} {})",
            self.algorithm,
            self.digest_type,
            hex(&self.fingerprint),
            self.algorithm_name(),
            self.digest_name()
        )
    }
}

/// Computes the fingerprint of a host key with the requested digest
/// algorithm, or `None` when the digest type is unknown.
pub fn digest(digest_type: u8, host_key: &[u8]) -> Option<Vec<u8>> {
    match digest_type {
        DIGEST_SHA1 => {
            let mut hasher = Sha1::new();
            hasher.update(host_key);
            Some(hasher.finalize().to_vec())
        }
        DIGEST_SHA256 => {
            let mut hasher = Sha256::new();
            hasher.update(host_key);
            Some(hasher.finalize().to_vec())
        }
        _ => None,
    }
}

/// Compares two byte slices in constant time.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The verdict of an SSHFP verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshfpStatus {
    /// The check did not run (no certificate, disabled, or an algorithm the
    /// request does not cover).
    NotChecked,
    /// A published record certifies the presented host key.
    Verified,
    /// The host publishes no SSHFP record at all.
    NoRecords,
    /// The lookup itself failed: unreachable resolver, timeout, malformed
    /// answer.
    LookupFailed,
    /// Records are published but none matches the presented host key.
    Mismatch,
}

impl std::fmt::Display for SshfpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::NotChecked => "not-checked",
            Self::Verified => "verified",
            Self::NoRecords => "no-records",
            Self::LookupFailed => "lookup-failed",
            Self::Mismatch => "mismatch",
        };
        write!(f, "{name}")
    }
}

/// The verdict of an SSHFP verification together with the evidence behind
/// it.
#[derive(Clone, Debug)]
pub struct SshfpResult {
    /// The DNS name the records were requested for.
    pub query_name: String,
    /// The verdict.
    pub status: SshfpStatus,
    /// The records that were published, empty when none were obtained.
    pub records: Vec<SshfpRecord>,
    /// The record that certified the host key, `None` otherwise.
    pub matched: Option<SshfpRecord>,
    /// The reason of a lookup failure, `None` otherwise.
    pub error: Option<String>,
}

/// The `VerifyHostKeyDNS` policy: when the check runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VerifyHostKeyDnsMode {
    /// The check never runs (the default).
    #[default]
    No,
    /// A mismatch is fatal, unless `StrictHostKeyChecking=no` explicitly
    /// allows it.
    Ask,
    /// The same as `Ask`: there is no interactive prompt on the mismatch
    /// path, the connection is refused.
    Yes,
}

/// The parsed `VerifyHostKeyDNS` value: when the SSHFP check runs (the
/// mode) and which host key algorithms it covers (the numbers, empty
/// meaning "every algorithm").
///
/// The algorithm list accepts both host key algorithm names (`rsa`,
/// `ecdsa`, `ed25519`, ...) and digest names (`sha1`, `sha256`): the numbers
/// of the two families do not collide on the wire, so one list filters both
/// dimensions the way the reference implementation filters them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyHostKeyDns {
    pub mode: VerifyHostKeyDnsMode,
    pub algorithms: Vec<u8>,
}

impl VerifyHostKeyDns {
    /// Parses an OpenSSH `VerifyHostKeyDNS` value: `yes`, `no`, `ask` (with
    /// the `on`/`off`/`true`/`false` aliases), optionally followed by
    /// `:algorithm[,algorithm...]`.
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut setting = Self::default();
        let mut base = value.trim();
        if let Some(separator) = base.find(':') {
            let algorithms = &base[separator + 1..];
            base = base[..separator].trim();
            if algorithms.is_empty() {
                return Err(format!(
                    "invalid VerifyHostKeyDNS value {value:?} (no algorithm after \":\")"
                ));
            }
            for raw in algorithms.split(',') {
                let name = raw.trim().to_ascii_lowercase();
                if name.is_empty() {
                    return Err(format!(
                        "invalid VerifyHostKeyDNS value {value:?} (empty algorithm name)"
                    ));
                }
                match algorithm_number(&name) {
                    Some(number) => setting.algorithms.push(number),
                    None => {
                        return Err(format!(
                            "invalid VerifyHostKeyDNS value {value:?} (unknown algorithm {name:?})"
                        ));
                    }
                }
            }
        }
        setting.mode = match base.to_ascii_lowercase().as_str() {
            "" | "no" | "false" | "off" => VerifyHostKeyDnsMode::No,
            "ask" => VerifyHostKeyDnsMode::Ask,
            "yes" | "true" | "on" => VerifyHostKeyDnsMode::Yes,
            other => return Err(format!("invalid VerifyHostKeyDNS value {other:?}")),
        };
        Ok(setting)
    }

    /// Reports whether an SSHFP lookup has to be performed for a host key
    /// of the given algorithm. `None` (no host key algorithm known) means
    /// "no reason to skip", and a disabled verification never restricts
    /// anything.
    pub fn allows_algorithm(&self, algorithm: Option<u8>) -> bool {
        if self.mode == VerifyHostKeyDnsMode::No {
            return true;
        }
        let Some(algorithm) = algorithm else {
            return true;
        };
        self.algorithms.is_empty() || self.algorithms.contains(&algorithm)
    }

    /// Reports whether the verdict rejects the host: only a mismatch is
    /// ever fatal, and only when the check runs.
    pub fn rejects(&self, status: SshfpStatus) -> bool {
        self.mode != VerifyHostKeyDnsMode::No && status == SshfpStatus::Mismatch
    }
}

/// Maps an algorithm or digest name to its SSHFP number.
fn algorithm_number(name: &str) -> Option<u8> {
    match name {
        "rsa" | "ssh-rsa" => Some(ALGORITHM_RSA),
        "dsa" | "ssh-dss" | "ssh-dsa" => Some(ALGORITHM_DSA),
        "ecdsa" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            Some(ALGORITHM_ECDSA)
        }
        "ed25519" => Some(ALGORITHM_ED25519),
        "sha1" => Some(DIGEST_SHA1),
        "sha256" => Some(DIGEST_SHA256),
        _ => None,
    }
}

/// Derives the DNS name under which the SSHFP records of a host key are
/// published. It accepts the canonical ssh3 host key (`host:port/path`) as
/// well as a bare hostname, and maps IP literals to the corresponding
/// in-addr.arpa / ip6.arpa name (RFC 4255 section 3).
pub fn query_name(host_key: &str) -> Result<String, SshfpError> {
    let mut name = host_key.trim();
    if name.is_empty() {
        return Err(SshfpError::Name("empty host key".to_string()));
    }
    // Drop the URL path and any query/fragment.
    if let Some(index) = name.find(['/', '?', '#']) {
        name = &name[..index];
    }
    if let Some(rest) = name.strip_prefix('[') {
        // A bracketed IPv6 literal.
        let Some(end) = rest.find(']') else {
            return Err(SshfpError::Name(format!(
                "unbalanced brackets in {host_key:?}"
            )));
        };
        name = &rest[..end];
    } else if let Some((host, _port)) = rsplit_host_port(name) {
        name = host;
    }
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return Err(SshfpError::Name(format!("no host in {host_key:?}")));
    }
    if let Ok(v4) = name.parse::<Ipv4Addr>() {
        return Ok(reverse_v4_name(v4));
    }
    if let Ok(v6) = name.parse::<Ipv6Addr>() {
        return Ok(reverse_v6_name(&v6));
    }
    Ok(name.to_ascii_lowercase())
}

/// Splits `host:port` when the port parses; IPv6 literals must be
/// bracketed, so the last colon of a bare host is not a separator.
fn rsplit_host_port(value: &str) -> Option<(&str, &str)> {
    let (host, port) = value.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    // A host that still contains a colon is a bare IPv6 literal, not a
    // separated pair (the "too many colons" refusal of the reference).
    if host.contains(':') {
        return None;
    }
    Some((host, port))
}

/// Builds the reverse-mapping name of an IPv4 address.
fn reverse_v4_name(ip: Ipv4Addr) -> String {
    let octets = ip.octets();
    format!(
        "{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]
    )
}

/// Builds the reverse-mapping name of an IPv6 address.
fn reverse_v6_name(ip: &Ipv6Addr) -> String {
    let octets = ip.octets();
    let mut name = String::with_capacity(71);
    for octet in octets.iter().rev() {
        name.push(hex_digit(octet & 0x0f));
        name.push('.');
        name.push(hex_digit(octet >> 4));
        name.push('.');
    }
    name.push_str("ip6.arpa");
    name
}

fn hex_digit(nibble: u8) -> char {
    char::from_digit(u32::from(nibble), 16).unwrap_or('0')
}

/// Encodes a standard recursive DNS query for the SSHFP records (type 44,
/// class IN) of `name`.
pub fn build_query(id: u16, name: &str) -> Result<Vec<u8>, SshfpError> {
    let encoded = encode_dns_name(name)?;
    let mut message = Vec::with_capacity(DNS_HEADER_SIZE + encoded.len() + 4);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&DNS_FLAG_RECURSION_DESIRED.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    message.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    message.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    message.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    message.extend_from_slice(&encoded);
    message.extend_from_slice(&DNS_TYPE_SSHFP.to_be_bytes());
    message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(message)
}

/// Converts a dotted name into the length-prefixed label sequence
/// terminated by a zero octet.
fn encode_dns_name(name: &str) -> Result<Vec<u8>, SshfpError> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return Err(SshfpError::Name("empty name".to_string()));
    }
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() {
            return Err(SshfpError::Malformed("empty label"));
        }
        if label.len() > 63 {
            return Err(SshfpError::Malformed("label longer than 63 octets"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    if out.len() > DNS_MAX_NAME_LENGTH {
        return Err(SshfpError::Malformed("name longer than 255 octets"));
    }
    Ok(out)
}

/// Decodes a DNS answer and returns the SSHFP records it carries (type 44,
/// class IN), along with the rcode of the message.
///
/// An empty record list with rcode NXDOMAIN or NOERROR means the host
/// simply publishes no SSHFP record; the caller must treat that as a soft
/// signal rather than a verification failure.
pub fn parse_response(message: &[u8]) -> Result<(Vec<SshfpRecord>, u8), SshfpError> {
    if message.len() < DNS_HEADER_SIZE {
        return Err(SshfpError::Malformed("message shorter than a header"));
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let rcode = (flags & 0x0f) as u8;
    let questions = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let answers = usize::from(u16::from_be_bytes([message[6], message[7]]));

    let mut offset = DNS_HEADER_SIZE;
    for _ in 0..questions {
        let next = parse_dns_name(message, offset)?.1 + 4; // QTYPE + QCLASS
        if next > message.len() {
            return Err(SshfpError::Malformed(
                "question section runs past the message",
            ));
        }
        offset = next;
    }

    let mut records = Vec::new();
    for _ in 0..answers {
        let next = parse_dns_name(message, offset)?.1;
        if next + 10 > message.len() {
            return Err(SshfpError::Malformed("answer header runs past the message"));
        }
        let rr_type = u16::from_be_bytes([message[next], message[next + 1]]);
        let rr_class = u16::from_be_bytes([message[next + 2], message[next + 3]]);
        let rd_length = usize::from(u16::from_be_bytes([message[next + 8], message[next + 9]]));
        let rdata_start = next + 10;
        if rdata_start + rd_length > message.len() {
            return Err(SshfpError::Malformed("record data runs past the message"));
        }
        let rdata = &message[rdata_start..rdata_start + rd_length];
        if rr_type == DNS_TYPE_SSHFP && rr_class == DNS_CLASS_IN && rd_length >= 2 {
            records.push(SshfpRecord {
                algorithm: rdata[0],
                digest_type: rdata[1],
                fingerprint: rdata[2..].to_vec(),
            });
        }
        offset = rdata_start + rd_length;
    }
    Ok((records, rcode))
}

/// Decodes a (possibly compressed) name starting at `offset`. It returns
/// the dotted name and the offset just after the encoded name in the
/// enclosing message.
fn parse_dns_name(message: &[u8], mut offset: usize) -> Result<(String, usize), SshfpError> {
    let mut labels: Vec<&str> = Vec::new();
    let mut next: Option<usize> = None;
    let mut jumps = 0;
    loop {
        if offset >= message.len() {
            return Err(SshfpError::Malformed("name runs past the message"));
        }
        let length = message[offset] as usize;
        match length & 0xc0 {
            0x00 => {
                if length == 0 {
                    let next = next.unwrap_or(offset + 1);
                    return Ok((labels.join("."), next));
                }
                let start = offset + 1;
                if start + length > message.len() {
                    return Err(SshfpError::Malformed("label runs past the message"));
                }
                let label = std::str::from_utf8(&message[start..start + length])
                    .map_err(|_| SshfpError::Malformed("label is not UTF-8"))?;
                labels.push(label);
                offset = start + length;
            }
            0xc0 => {
                if offset + 1 >= message.len() {
                    return Err(SshfpError::Malformed("truncated compression pointer"));
                }
                if next.is_none() {
                    next = Some(offset + 2);
                }
                jumps += 1;
                if jumps > DNS_MAX_NAME_POINTERS {
                    return Err(SshfpError::Malformed("too many compression pointers"));
                }
                offset = ((message[offset] & 0x3f) as usize) << 8 | message[offset + 1] as usize;
            }
            _ => {
                return Err(SshfpError::Malformed("reserved label type"));
            }
        }
    }
}

/// Returns the resolvers declared in the system configuration, or an empty
/// list when they cannot be determined (typically on Windows, which keeps
/// that configuration in the registry rather than in a file).
pub fn system_dns_servers() -> Vec<String> {
    let content = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(content) => content,
        Err(_) => return Vec::new(),
    };
    parse_resolv_conf(&content)
}

/// Parses the `nameserver` lines of an /etc/resolv.conf file.
fn parse_resolv_conf(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            line.strip_prefix("nameserver")
                .map(|rest| rest.trim().to_string())
                .filter(|server| !server.is_empty())
        })
        .collect()
}

/// Queries DNS servers directly over UDP for the SSHFP records of `name`.
///
/// The servers are tried in order; an authoritative "no record" answer is a
/// final verdict, a network failure falls through to the next server.
pub async fn lookup_sshfp(
    servers: &[SocketAddr],
    name: &str,
    timeout: Duration,
) -> Result<Vec<SshfpRecord>, SshfpError> {
    if servers.is_empty() {
        return Err(SshfpError::NoDnsServers);
    }
    let id = rand::random::<u16>();
    let query = build_query(id, name)?;

    let mut last_error = SshfpError::NoDnsServers;
    for server in servers {
        match query_once(*server, &query, id, name, timeout).await {
            Ok(records) => return Ok(records),
            Err(SshfpError::NoRecords) => return Err(SshfpError::NoRecords),
            Err(err) => last_error = err,
        }
    }
    Err(last_error)
}

/// Runs a single query/response exchange against one server.
async fn query_once(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    name: &str,
    timeout: Duration,
) -> Result<Vec<SshfpRecord>, SshfpError> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().expect("static address")
    } else {
        "[::]:0".parse().expect("static address")
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|err| SshfpError::Io(format!("could not bind the DNS socket: {err}")))?;
    socket
        .connect(server)
        .await
        .map_err(|err| SshfpError::Io(format!("could not reach the DNS server {server}: {err}")))?;
    socket.send(query).await.map_err(|err| {
        SshfpError::Io(format!("could not send the DNS query to {server}: {err}"))
    })?;
    let mut buffer = [0u8; 1500];
    let received = tokio::time::timeout(timeout, socket.recv(&mut buffer))
        .await
        .map_err(|_| SshfpError::Io(format!("no answer from {server}")))?
        .map_err(|err| SshfpError::Io(format!("no answer from {server}: {err}")))?;

    let response = &buffer[..received];
    if response.len() < 2 || u16::from_be_bytes([response[0], response[1]]) != id {
        return Err(SshfpError::ResponseMismatch);
    }
    if response.len() >= 4
        && u16::from_be_bytes([response[2], response[3]]) & DNS_FLAG_TRUNCATED != 0
    {
        return Err(SshfpError::Truncated);
    }
    let (records, rcode) = parse_response(response)?;
    match rcode {
        DNS_RCODE_SUCCESS => {}
        DNS_RCODE_NXDOMAIN => return Err(SshfpError::NoRecords),
        other => {
            return Err(SshfpError::Io(format!(
                "the DNS server {server} answered with rcode {other} for {name}"
            )));
        }
    }
    if records.is_empty() {
        return Err(SshfpError::NoRecords);
    }
    Ok(records)
}

/// The verification entry point: fetches the SSHFP records of a host key
/// and looks for one matching the presented certificate.
///
/// It never returns [`SshfpStatus::Mismatch`] for a missing answer: a
/// timeout, an unreachable resolver, a truncated datagram or a host without
/// any record all yield [`SshfpStatus::NoRecords`] or
/// [`SshfpStatus::LookupFailed`], so that an absent DNS signal can never be
/// read as a MITM.
pub async fn check_sshfp(
    host_key: &str,
    certificate_der: &[u8],
    algorithm: Option<u8>,
    servers: &[SocketAddr],
) -> SshfpResult {
    let name = match query_name(host_key) {
        Ok(name) => name,
        Err(err) => {
            return SshfpResult {
                query_name: String::new(),
                status: SshfpStatus::LookupFailed,
                records: Vec::new(),
                matched: None,
                error: Some(err.to_string()),
            };
        }
    };
    let lookup = lookup_sshfp(servers, &name, DEFAULT_SSHFP_TIMEOUT).await;
    let mut result = SshfpResult {
        query_name: name,
        status: SshfpStatus::NotChecked,
        records: Vec::new(),
        matched: None,
        error: None,
    };
    match lookup {
        Err(SshfpError::NoRecords) => {
            result.status = SshfpStatus::NoRecords;
            return result;
        }
        Err(err) => {
            result.status = SshfpStatus::LookupFailed;
            result.error = Some(err.to_string());
            return result;
        }
        Ok(records) => result.records = records,
    }
    for record in &result.records {
        let Some(algorithm) = algorithm else {
            break;
        };
        if record.matches(algorithm, certificate_der) {
            result.status = SshfpStatus::Verified;
            result.matched = Some(record.clone());
            return result;
        }
    }
    result.status = if algorithm.is_some() {
        SshfpStatus::Mismatch
    } else {
        // A key algorithm without an SSHFP number can never match: the
        // records say nothing about it.
        SshfpStatus::NoRecords
    };
    result
}

/// Maps the public key of a DER certificate to the SSHFP algorithm number
/// it must be published with. `None` when the key algorithm has no SSHFP
/// number, in which case no SSHFP record can ever match this host key.
pub fn host_key_algorithm(certificate_der: &[u8]) -> Option<u8> {
    let certificate = x509_parser::parse_x509_certificate(certificate_der).ok()?.1;
    let algorithm = certificate
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_string()
        .to_ascii_lowercase();
    match algorithm.as_str() {
        "1.2.840.113549.1.1.1" => Some(ALGORITHM_RSA), // rsaEncryption
        "1.2.840.10045.2.1" => Some(ALGORITHM_ECDSA),  // id-ecPublicKey
        "1.3.101.112" => Some(ALGORITHM_ED25519),      // Ed25519
        _ => None,
    }
}

/// Renders bytes as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        ALGORITHM_ED25519, DIGEST_SHA1, DIGEST_SHA256, SshfpError, SshfpStatus, VerifyHostKeyDns,
        VerifyHostKeyDnsMode, build_query, check_sshfp, constant_time_eq, digest,
        host_key_algorithm, lookup_sshfp, parse_resolv_conf, parse_response, query_name,
        system_dns_servers,
    };
    use std::net::SocketAddr;
    use std::time::Duration;

    /// The query the reference implementation builds for id 0x1234 and
    /// example.org, dumped with its own `BuildSSHFPQuery`.
    const GO_QUERY_HEX: &str = "123401000001000000000000076578616d706c65036f726700002c0001";

    /// The answer of the reference test fixture: two SSHFP records of an
    /// Ed25519 key (SHA-1 and SHA-256), the answer names compressed as
    /// pointers to the question name.
    const GO_RESPONSE_HEX: &str = "123481000001000200000000076578616d706c65036f726700002c0001c00c002c00010000012c00160401c96d719008cedc59b546ea4771a1ccfd55544eacc00c002c00010000012c00220402a27acdca282772bc90a54cdfa5a252c60959fb12cd019f39b38c8e08e5d71bf0";

    /// The host key of the fixture: its SHA-1 and SHA-256 digests are the
    /// records of [`GO_RESPONSE_HEX`].
    const HOST_KEY: &[u8] = b"the host key under test";

    fn decode_hex(value: &str) -> Vec<u8> {
        (0..value.len() / 2)
            .map(|index| {
                u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                    .expect("the fixture is valid hex")
            })
            .collect()
    }

    /// The query is byte-for-byte the one of the reference implementation
    /// (`TestBuildSSHFPQuery` of the reference).
    #[test]
    fn the_query_matches_the_reference_bytes() {
        let query = build_query(0x1234, "example.org").unwrap();
        assert_eq!(query, decode_hex(GO_QUERY_HEX));
    }

    /// The answer of the reference fixture parses into its two records,
    /// compression pointers included (`TestParseSSHFPResponse` of the
    /// reference).
    #[test]
    fn the_response_of_the_reference_parses() {
        let (records, rcode) = parse_response(&decode_hex(GO_RESPONSE_HEX)).unwrap();
        assert_eq!(rcode, 0);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].algorithm, ALGORITHM_ED25519);
        assert_eq!(records[0].digest_type, DIGEST_SHA1);
        assert_eq!(
            records[0].fingerprint,
            digest(DIGEST_SHA1, HOST_KEY).unwrap()
        );
        assert_eq!(records[1].digest_type, DIGEST_SHA256);
        assert_eq!(
            records[1].fingerprint,
            digest(DIGEST_SHA256, HOST_KEY).unwrap()
        );
        for record in &records {
            assert!(record.valid());
            assert!(record.matches(ALGORITHM_ED25519, HOST_KEY));
            assert!(!record.matches(super::ALGORITHM_RSA, HOST_KEY));
        }
    }

    /// A message shorter than a header, a name past the end, a truncated
    /// pointer and a reserved label type are all refused
    /// (`TestParseSSHFPResponseMalformed` of the reference).
    #[test]
    fn a_malformed_response_is_refused() {
        assert!(matches!(
            parse_response(&[0u8; 4]),
            Err(SshfpError::Malformed(_))
        ));
        // a compression pointer that points past the message
        let mut truncated = decode_hex(GO_RESPONSE_HEX);
        truncated.truncate(20);
        assert!(parse_response(&truncated).is_err());
        // a reserved label type (0x40)
        let mut reserved = decode_hex(GO_QUERY_HEX);
        reserved[12] = 0x40;
        assert!(matches!(
            parse_response(&reserved),
            Err(SshfpError::Malformed(_))
        ));
    }

    /// The query names follow RFC 4255 section 3: the URL path and the port
    /// go away, IP literals map to their reverse zone
    /// (`TestSSHFPQueryName` of the reference).
    #[test]
    fn the_query_names_follow_the_reference() {
        assert_eq!(query_name("example.org").unwrap(), "example.org");
        assert_eq!(query_name("example.org.").unwrap(), "example.org");
        assert_eq!(
            query_name("example.org:443/ssh3-term").unwrap(),
            "example.org"
        );
        assert_eq!(query_name("EXAMPLE.ORG").unwrap(), "example.org");
        assert_eq!(query_name("192.0.2.10").unwrap(), "10.2.0.192.in-addr.arpa");
        assert_eq!(
            query_name("2001:db8::1").unwrap(),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        assert_eq!(
            query_name("[2001:db8::1]:443").unwrap(),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        assert!(query_name("").is_err());
        assert!(query_name("/path").is_err());
    }

    /// The `VerifyHostKeyDNS` values parse the way the reference parses
    /// them: the modes with their aliases and the algorithm suffix.
    #[test]
    fn the_verification_settings_parse() {
        use VerifyHostKeyDnsMode::{Ask, No, Yes};
        assert_eq!(VerifyHostKeyDns::parse("no").unwrap().mode, No);
        assert_eq!(VerifyHostKeyDns::parse("").unwrap().mode, No);
        assert_eq!(VerifyHostKeyDns::parse("off").unwrap().mode, No);
        assert_eq!(VerifyHostKeyDns::parse("ask").unwrap().mode, Ask);
        assert_eq!(VerifyHostKeyDns::parse("YES").unwrap().mode, Yes);
        assert_eq!(VerifyHostKeyDns::parse(" on ").unwrap().mode, Yes);

        let setting = VerifyHostKeyDns::parse("yes:rsa,ecdsa").unwrap();
        assert_eq!(setting.mode, Yes);
        assert_eq!(
            setting.algorithms,
            vec![super::ALGORITHM_RSA, super::ALGORITHM_ECDSA]
        );
        assert!(setting.allows_algorithm(Some(super::ALGORITHM_RSA)));
        assert!(!setting.allows_algorithm(Some(ALGORITHM_ED25519)));
        assert!(setting.allows_algorithm(None));

        let setting = VerifyHostKeyDns::parse("ask:sha256").unwrap();
        assert_eq!(setting.mode, Ask);
        assert_eq!(setting.algorithms, vec![DIGEST_SHA256]);

        assert!(VerifyHostKeyDns::parse("yes:").is_err());
        assert!(VerifyHostKeyDns::parse("yes:nosuch").is_err());
        assert!(VerifyHostKeyDns::parse("maybe").is_err());
    }

    /// Only a mismatch rejects the host, and only when the check runs.
    #[test]
    fn only_a_mismatch_rejects() {
        let setting = VerifyHostKeyDns::parse("yes").unwrap();
        assert!(setting.rejects(SshfpStatus::Mismatch));
        assert!(!setting.rejects(SshfpStatus::NoRecords));
        assert!(!setting.rejects(SshfpStatus::LookupFailed));
        assert!(!setting.rejects(SshfpStatus::Verified));
        let setting = VerifyHostKeyDns::parse("no").unwrap();
        assert!(!setting.rejects(SshfpStatus::Mismatch));
    }

    /// The comparison runs in constant time over the bytes it compares, and
    /// lengths must match up front.
    #[test]
    fn the_comparison_is_constant_time() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    /// The digests have the length their type implies.
    #[test]
    fn the_digests_have_the_right_length() {
        assert_eq!(digest(DIGEST_SHA1, HOST_KEY).unwrap().len(), 20);
        assert_eq!(digest(DIGEST_SHA256, HOST_KEY).unwrap().len(), 32);
        assert_eq!(digest(super::DIGEST_RESERVED, HOST_KEY), None);
    }

    /// The `nameserver` lines of an /etc/resolv.conf parse, comments
    /// included.
    #[test]
    fn the_resolv_conf_parses() {
        let servers = parse_resolv_conf(
            "# comment\nnameserver 192.0.2.53\nnameserver 2001:db8::53\noptions edns0\n",
        );
        assert_eq!(
            servers,
            vec!["192.0.2.53".to_string(), "2001:db8::53".to_string()]
        );
        // The system file of the test host simply parses.
        let _ = system_dns_servers();
    }

    /// Spawns a fake DNS server that answers every query with the given
    /// wire response, echoing the query id.
    async fn fake_dns_server(response: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            loop {
                let Ok((received, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                if received < 2 {
                    continue;
                }
                let mut answer = response.clone();
                // The id of the answer is the id of the query.
                answer[0] = buffer[0];
                answer[1] = buffer[1];
                let _ = socket.send_to(&answer, peer).await;
            }
        });
        (address, task)
    }

    /// A record that matches the host key verifies it through a live
    /// exchange against a fake resolver.
    #[tokio::test]
    async fn a_matching_record_verifies_the_host_key() {
        let (server, task) = fake_dns_server(decode_hex(GO_RESPONSE_HEX)).await;
        let result = check_sshfp("example.org", HOST_KEY, Some(ALGORITHM_ED25519), &[server]).await;
        assert_eq!(result.status, SshfpStatus::Verified, "{result:?}");
        assert!(result.matched.is_some());
        task.abort();
    }

    /// A host key the records do not certify yields the mismatch verdict.
    #[tokio::test]
    async fn a_foreign_host_key_mismatches() {
        let (server, task) = fake_dns_server(decode_hex(GO_RESPONSE_HEX)).await;
        let result = check_sshfp(
            "example.org",
            b"a different host key",
            Some(ALGORITHM_ED25519),
            &[server],
        )
        .await;
        assert_eq!(result.status, SshfpStatus::Mismatch, "{result:?}");
        task.abort();
    }

    /// A server that answers NXDOMAIN yields the soft no-records signal.
    #[tokio::test]
    async fn an_nxdomain_answer_yields_no_records() {
        // The fixture answer with the rcode set to NXDOMAIN and no answers.
        let mut nxdomain = decode_hex(GO_RESPONSE_HEX);
        nxdomain[3] = (nxdomain[3] & 0xf0) | 3; // rcode
        nxdomain[7] = 0; // ANCOUNT
        nxdomain.truncate(12 + 21); // header + question
        let (server, task) = fake_dns_server(nxdomain).await;
        let result = check_sshfp("example.org", HOST_KEY, Some(ALGORITHM_ED25519), &[server]).await;
        assert_eq!(result.status, SshfpStatus::NoRecords, "{result:?}");
        task.abort();
    }

    /// A server that never answers yields the lookup-failed verdict, never a
    /// mismatch: an absent DNS signal must not be read as a MITM.
    #[tokio::test]
    async fn a_silent_server_fails_the_lookup_softly() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        // The socket is bound but nobody reads it: the exchange times out.
        let result =
            check_sshfp("example.org", HOST_KEY, Some(ALGORITHM_ED25519), &[address]).await;
        assert_eq!(result.status, SshfpStatus::LookupFailed, "{result:?}");
        assert!(result.error.is_some());
        assert!(
            !VerifyHostKeyDns::parse("yes")
                .unwrap()
                .rejects(result.status)
        );
    }

    /// The lookup itself maps the errors of the exchange.
    #[tokio::test]
    async fn the_lookup_maps_its_errors() {
        assert_eq!(
            lookup_sshfp(&[], "example.org", Duration::from_millis(50)).await,
            Err(SshfpError::NoDnsServers)
        );
        // An unreachable server falls through to the IO error.
        let unreachable: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let error = lookup_sshfp(&[unreachable], "example.org", Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(matches!(error, SshfpError::Io(_)), "{error:?}");
    }

    /// The certificate fixture maps to its SSHFP number: rcgen picks an
    /// ECDSA or Ed25519 key, both have a number, so whatever it picked must
    /// map. Garbage is not a certificate.
    #[test]
    fn the_host_key_algorithm_of_a_certificate() {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let der = certificate.cert.der().as_ref().to_vec();
        let algorithm = host_key_algorithm(&der).expect("rcgen keys always have an SSHFP number");
        assert!(matches!(
            algorithm,
            super::ALGORITHM_ECDSA | ALGORITHM_ED25519
        ));
        assert_eq!(host_key_algorithm(b"not a certificate"), None);
    }
}

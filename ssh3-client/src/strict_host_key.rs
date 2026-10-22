//! The `StrictHostKeyChecking` policy of the client.
//!
//! The policy decides what the client does with the certificate a server
//! presents: it mirrors the values of the OpenSSH keyword of the same name,
//! on top of the known_hosts mechanism of the SSH3 client.

use std::fmt;
use std::path::Path;

use crate::known_hosts::HostCertificateStatus;

/// The policy that decides how the client handles the certificate of a host.
///
/// The values are the ones of the `StrictHostKeyChecking` keyword of
/// ssh_config.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Ssh3StrictHostKeyChecking {
    /// The default: an unknown host is confirmed by the user; a session
    /// without a terminal refuses it instead of trusting it silently.
    #[default]
    Ask,
    /// Only a host whose certificate is pinned in the known_hosts file is
    /// accepted.
    Yes,
    /// An unknown host is pinned on first use; a host whose certificate
    /// changed is refused.
    AcceptNew,
    /// The certificate is never enforced: a mismatch only produces a
    /// warning. This is the explicitly allowed insecure behaviour.
    No,
}

impl Ssh3StrictHostKeyChecking {
    /// Parses the value of the `StrictHostKeyChecking` option.
    ///
    /// The comparison is case insensitive and the boolean aliases `true` and
    /// `on`, `false` and `off` are accepted for `yes` and `no`, like
    /// OpenSSH does.
    pub fn parse(value: &str) -> Result<Self, Ssh3StrictHostKeyCheckingError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "ask" => Ok(Self::Ask),
            "yes" | "true" | "on" => Ok(Self::Yes),
            "no" | "false" | "off" => Ok(Self::No),
            "accept-new" => Ok(Self::AcceptNew),
            _ => Err(Ssh3StrictHostKeyCheckingError {
                value: value.to_string(),
            }),
        }
    }
}

/// The error of an invalid `StrictHostKeyChecking` value.
#[derive(Clone, Debug)]
pub struct Ssh3StrictHostKeyCheckingError {
    /// The rejected value.
    pub value: String,
}

impl fmt::Display for Ssh3StrictHostKeyCheckingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid StrictHostKeyChecking value: {:?} (expected yes, accept-new, no or ask)",
            self.value
        )
    }
}

impl std::error::Error for Ssh3StrictHostKeyCheckingError {}

/// Resolves the policy from its sources.
///
/// The precedence follows OpenSSH: the command line flag wins over the `-o`
/// option, which wins over the `~/.ssh/config` keyword. A source that does
/// not set the keyword leaves the policy to the next one, and the default
/// policy is `ask`.
pub fn resolve_strict_host_key_checking(
    cli_flag: Option<&str>,
    option: Option<&str>,
    config: Option<&str>,
) -> Result<Ssh3StrictHostKeyChecking, Ssh3StrictHostKeyCheckingError> {
    if let Some(value) = non_empty(cli_flag) {
        return Ssh3StrictHostKeyChecking::parse(value);
    }
    if let Some(value) = non_empty(option) {
        return Ssh3StrictHostKeyChecking::parse(value);
    }
    if let Some(value) = non_empty(config) {
        return Ssh3StrictHostKeyChecking::parse(value);
    }
    Ok(Ssh3StrictHostKeyChecking::Ask)
}

/// Tells whether a source sets the policy.
///
/// An empty value is a source that does not set it.
fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// What the client does with the certificate a server presents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKeyOutcome {
    /// The certificate is trusted: the session continues.
    Accept,
    /// The certificate is trusted, but the user must confirm it first.
    Ask,
    /// The certificate is accepted although it does not match the pin: the
    /// client warns about it.
    Warn,
    /// The certificate is refused: the session does not start.
    Reject,
}

/// The decision the client takes about a presented certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKeyDecision {
    /// What happens to the session.
    pub outcome: HostKeyOutcome,
    /// Whether the certificate must be pinned in the known_hosts file.
    pub pin: bool,
    /// The message that explains the decision.
    pub message: Option<String>,
}

impl HostKeyDecision {
    /// A decision that lets the session continue.
    fn accept(pin: bool) -> Self {
        Self {
            outcome: HostKeyOutcome::Accept,
            pin,
            message: None,
        }
    }

    /// A decision that lets the session continue, with a warning.
    fn warn(message: impl Into<String>, pin: bool) -> Self {
        Self {
            outcome: HostKeyOutcome::Warn,
            pin,
            message: Some(message.into()),
        }
    }

    /// A decision that refuses the certificate.
    fn reject(message: impl Into<String>) -> Self {
        Self {
            outcome: HostKeyOutcome::Reject,
            pin: false,
            message: Some(message.into()),
        }
    }

    /// A decision that waits for the confirmation of the user.
    fn ask() -> Self {
        Self {
            outcome: HostKeyOutcome::Ask,
            pin: false,
            message: None,
        }
    }
}

/// The facts the decision about a presented certificate is taken from.
pub struct HostKeyContext<'a> {
    /// The canonical host key of the target.
    pub host: &'a str,
    /// The path of the known_hosts file.
    pub path: &'a Path,
    /// How the certificate relates to the pins of the host.
    pub status: HostCertificateStatus,
    /// The `SHA256:` fingerprint of the presented certificate.
    pub presented_fingerprint: &'a str,
    /// The `SHA256:` fingerprints of the pinned certificates.
    pub pinned_fingerprints: &'a [String],
    /// Whether the chain of the certificate is trusted by a certificate
    /// authority.
    pub chain_trusted: bool,
    /// Whether the presented certificate is self-signed.
    pub self_signed: bool,
    /// Whether the user can be asked about an unknown certificate.
    pub interactive: bool,
}

/// Decides what the client does with the certificate a server presents.
///
/// The decision follows the policy of the `StrictHostKeyChecking` keyword:
/// `yes` refuses a certificate that is not the pinned one, `accept-new` pins
/// an unknown host on first use, `no` only warns about a mismatch and `ask`
/// hands the decision over to the user.
pub fn decide_host_key(
    policy: Ssh3StrictHostKeyChecking,
    context: &HostKeyContext<'_>,
) -> HostKeyDecision {
    match context.status {
        HostCertificateStatus::Matches => HostKeyDecision::accept(false),
        HostCertificateStatus::Changed => decide_changed_certificate(policy, context),
        HostCertificateStatus::Unknown => decide_unknown_certificate(policy, context),
    }
}

/// The decision about a host whose certificate is not the pinned one.
fn decide_changed_certificate(
    policy: Ssh3StrictHostKeyChecking,
    context: &HostKeyContext<'_>,
) -> HostKeyDecision {
    let path = context.path.display();
    let pinned = context.pinned_fingerprints.join(", ");

    if policy == Ssh3StrictHostKeyChecking::No {
        return HostKeyDecision::warn(
            format!(
                "StrictHostKeyChecking=no: the certificate of {} differs from the one pinned in {} (pinned: {}, received: {}), connecting anyway (insecure)",
                context.host, path, pinned, context.presented_fingerprint
            ),
            false,
        );
    }

    HostKeyDecision::reject(format!(
        "the certificate presented by {} does not match the one pinned in {}. Pinned: {}. Received: {}. \
         If you did not change the server certificate, it could be a machine-in-the-middle attack. \
         If this change is legitimate, remove the host from {} or run again with -o StrictHostKeyChecking=no.",
        context.host, path, pinned, context.presented_fingerprint, path
    ))
}

/// The decision about a host that is not pinned yet.
fn decide_unknown_certificate(
    policy: Ssh3StrictHostKeyChecking,
    context: &HostKeyContext<'_>,
) -> HostKeyDecision {
    let path = context.path.display();

    if context.chain_trusted {
        // The certificate is signed by a known authority: the host is simply
        // not pinned yet. The `accept-new` policy records it, the other
        // policies let the session continue.
        return match policy {
            Ssh3StrictHostKeyChecking::AcceptNew => HostKeyDecision::accept(true),
            _ => HostKeyDecision::accept(false),
        };
    }

    // The certificate cannot be verified against any authority: only a
    // self-signed certificate can be pinned.
    if !context.self_signed {
        return HostKeyDecision::reject(format!(
            "the peer provided an unknown, insecure certificate for {}, that is not self-signed",
            context.host
        ));
    }

    match policy {
        Ssh3StrictHostKeyChecking::Yes => HostKeyDecision::reject(format!(
            "StrictHostKeyChecking=yes: the certificate of {} could not be verified and the host is not pinned in {}, refusing to connect.",
            context.host, path
        )),
        Ssh3StrictHostKeyChecking::No => HostKeyDecision::warn(
            format!(
                "StrictHostKeyChecking=no: the certificate of {} could not be verified and the host is not pinned in {}, connecting anyway (insecure)",
                context.host, path
            ),
            true,
        ),
        Ssh3StrictHostKeyChecking::AcceptNew => HostKeyDecision::accept(true),
        Ssh3StrictHostKeyChecking::Ask => {
            if context.interactive {
                HostKeyDecision::ask()
            } else {
                // A session without a console refuses the certificate
                // instead of trusting it silently.
                HostKeyDecision::reject(format!(
                    "the certificate of {} is not pinned in {} and the session is not interactive, refusing to connect",
                    context.host,
                    context.path.display()
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HostKeyContext, HostKeyOutcome, Ssh3StrictHostKeyChecking, decide_host_key,
        resolve_strict_host_key_checking,
    };
    use crate::known_hosts::HostCertificateStatus;
    use std::path::Path;

    fn context<'a>(
        status: HostCertificateStatus,
        pinned: &'a [String],
        presented: &'a str,
        chain_trusted: bool,
        self_signed: bool,
    ) -> HostKeyContext<'a> {
        HostKeyContext {
            host: "example.org:443/ssh3-term",
            path: Path::new("/tmp/known_hosts"),
            status,
            presented_fingerprint: presented,
            pinned_fingerprints: pinned,
            chain_trusted,
            self_signed,
            interactive: true,
        }
    }

    #[test]
    fn the_policy_values_are_parsed_like_openssh() {
        assert_eq!(
            Ssh3StrictHostKeyChecking::parse("ask").unwrap(),
            Ssh3StrictHostKeyChecking::Ask
        );
        assert_eq!(
            Ssh3StrictHostKeyChecking::parse("YES").unwrap(),
            Ssh3StrictHostKeyChecking::Yes
        );
        assert_eq!(
            Ssh3StrictHostKeyChecking::parse(" true ").unwrap(),
            Ssh3StrictHostKeyChecking::Yes
        );
        assert_eq!(
            Ssh3StrictHostKeyChecking::parse("off").unwrap(),
            Ssh3StrictHostKeyChecking::No
        );
        assert_eq!(
            Ssh3StrictHostKeyChecking::parse("accept-new").unwrap(),
            Ssh3StrictHostKeyChecking::AcceptNew
        );
        assert!(Ssh3StrictHostKeyChecking::parse("maybe").is_err());
    }

    #[test]
    fn the_sources_are_resolved_in_the_openssh_order() {
        assert_eq!(
            resolve_strict_host_key_checking(Some("yes"), Some("no"), Some("accept-new")).unwrap(),
            Ssh3StrictHostKeyChecking::Yes
        );
        assert_eq!(
            resolve_strict_host_key_checking(None, Some("no"), Some("accept-new")).unwrap(),
            Ssh3StrictHostKeyChecking::No
        );
        assert_eq!(
            resolve_strict_host_key_checking(None, None, Some("accept-new")).unwrap(),
            Ssh3StrictHostKeyChecking::AcceptNew
        );
        assert_eq!(
            resolve_strict_host_key_checking(None, None, None).unwrap(),
            Ssh3StrictHostKeyChecking::Ask
        );
    }

    #[test]
    fn the_pinned_certificate_is_always_accepted() {
        for policy in [
            Ssh3StrictHostKeyChecking::Ask,
            Ssh3StrictHostKeyChecking::Yes,
            Ssh3StrictHostKeyChecking::AcceptNew,
            Ssh3StrictHostKeyChecking::No,
        ] {
            let decision = decide_host_key(
                policy,
                &context(
                    HostCertificateStatus::Matches,
                    &["SHA256:pinned".to_string()],
                    "SHA256:pinned",
                    false,
                    true,
                ),
            );
            assert_eq!(decision.outcome, HostKeyOutcome::Accept);
            assert!(!decision.pin);
        }
    }

    #[test]
    fn the_yes_policy_refuses_a_changed_certificate_and_shows_both_fingerprints() {
        let pinned = vec!["SHA256:pinned".to_string()];
        let decision = decide_host_key(
            Ssh3StrictHostKeyChecking::Yes,
            &context(
                HostCertificateStatus::Changed,
                &pinned,
                "SHA256:presented",
                false,
                true,
            ),
        );

        assert_eq!(decision.outcome, HostKeyOutcome::Reject);
        let message = decision.message.unwrap();
        assert!(message.contains("SHA256:pinned"));
        assert!(message.contains("SHA256:presented"));
    }

    #[test]
    fn the_accept_new_policy_pins_an_unknown_host() {
        let decision = decide_host_key(
            Ssh3StrictHostKeyChecking::AcceptNew,
            &context(
                HostCertificateStatus::Unknown,
                &[],
                "SHA256:presented",
                false,
                true,
            ),
        );

        assert_eq!(decision.outcome, HostKeyOutcome::Accept);
        assert!(decision.pin);
    }

    #[test]
    fn the_no_policy_only_warns_about_a_changed_certificate() {
        let pinned = vec!["SHA256:pinned".to_string()];
        let decision = decide_host_key(
            Ssh3StrictHostKeyChecking::No,
            &context(
                HostCertificateStatus::Changed,
                &pinned,
                "SHA256:presented",
                false,
                true,
            ),
        );

        assert_eq!(decision.outcome, HostKeyOutcome::Warn);
        assert!(!decision.pin);
        let message = decision.message.unwrap();
        assert!(message.contains("SHA256:pinned"));
        assert!(message.contains("SHA256:presented"));
    }

    #[test]
    fn the_ask_policy_hands_the_decision_over_to_the_user() {
        let decision = decide_host_key(
            Ssh3StrictHostKeyChecking::Ask,
            &context(
                HostCertificateStatus::Unknown,
                &[],
                "SHA256:presented",
                false,
                true,
            ),
        );

        assert_eq!(decision.outcome, HostKeyOutcome::Ask);
    }

    #[test]
    fn the_ask_policy_refuses_a_session_without_a_console() {
        let mut context = context(
            HostCertificateStatus::Unknown,
            &[],
            "SHA256:presented",
            false,
            true,
        );
        context.interactive = false;

        let decision = decide_host_key(Ssh3StrictHostKeyChecking::Ask, &context);

        assert_eq!(decision.outcome, HostKeyOutcome::Reject);
        assert!(!decision.pin);
    }

    #[test]
    fn an_unknown_certificate_that_is_not_self_signed_is_refused() {
        let decision = decide_host_key(
            Ssh3StrictHostKeyChecking::AcceptNew,
            &context(
                HostCertificateStatus::Unknown,
                &[],
                "SHA256:presented",
                false,
                false,
            ),
        );

        assert_eq!(decision.outcome, HostKeyOutcome::Reject);
        assert!(!decision.pin);
    }

    /// Builds a self-signed certificate for the tests.
    fn self_signed_certificate(common_name: &str) -> rustls::pki_types::CertificateDer<'static> {
        let params = rcgen::CertificateParams::new(vec![common_name.to_string()])
            .expect("the parameters of the certificate are valid");
        let key = rcgen::KeyPair::generate().expect("a key pair can be generated");
        let certificate = params
            .self_signed(&key)
            .expect("the certificate can be signed");
        rustls::pki_types::CertificateDer::from(certificate.der().to_vec())
    }

    #[test]
    fn the_accept_new_policy_pins_the_host_on_the_first_contact() {
        use crate::known_hosts::{KnownHosts, append_known_host, certificate_fingerprint};

        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("known_hosts");
        let certificate = self_signed_certificate("servera.ssh3");
        let fingerprint = certificate_fingerprint(&certificate);
        let host = "example.org:443/ssh3-term";

        // The first contact: the host is not pinned yet, so the certificate
        // is pinned and the session continues.
        let (known_hosts, _) = KnownHosts::load(&path).unwrap();
        assert_eq!(
            known_hosts.check_certificate(host, &certificate),
            HostCertificateStatus::Unknown
        );
        let pinned_fingerprints = known_hosts.fingerprints(host);
        let decision = decide_host_key(
            Ssh3StrictHostKeyChecking::AcceptNew,
            &context(
                HostCertificateStatus::Unknown,
                &pinned_fingerprints,
                &fingerprint,
                false,
                true,
            ),
        );
        assert_eq!(decision.outcome, HostKeyOutcome::Accept);
        assert!(decision.pin);
        append_known_host(&path, host, &certificate).unwrap();

        // The second contact: the pinned certificate is the one the server
        // presents, so the session continues without a new pin.
        let (known_hosts, _) = KnownHosts::load(&path).unwrap();
        assert_eq!(
            known_hosts.check_certificate(host, &certificate),
            HostCertificateStatus::Matches
        );
        let pinned_fingerprints = known_hosts.fingerprints(host);
        let decision = decide_host_key(
            Ssh3StrictHostKeyChecking::AcceptNew,
            &context(
                HostCertificateStatus::Matches,
                &pinned_fingerprints,
                &fingerprint,
                false,
                true,
            ),
        );
        assert_eq!(decision.outcome, HostKeyOutcome::Accept);
        assert!(!decision.pin);
    }

    #[test]
    fn the_yes_policy_refuses_a_host_that_presents_another_certificate() {
        use crate::known_hosts::{KnownHosts, append_known_host, certificate_fingerprint};

        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("known_hosts");
        let pinned = self_signed_certificate("servera.ssh3");
        let presented = self_signed_certificate("serverb.ssh3");
        let pinned_fingerprint = certificate_fingerprint(&pinned);
        let presented_fingerprint = certificate_fingerprint(&presented);
        let host = "example.org:443/ssh3-term";

        append_known_host(&path, host, &pinned).unwrap();
        let (known_hosts, _) = KnownHosts::load(&path).unwrap();
        let pinned_fingerprints = known_hosts.fingerprints(host);

        let decision = decide_host_key(
            Ssh3StrictHostKeyChecking::Yes,
            &context(
                known_hosts.check_certificate(host, &presented),
                &pinned_fingerprints,
                &presented_fingerprint,
                false,
                true,
            ),
        );

        assert_eq!(decision.outcome, HostKeyOutcome::Reject);
        let message = decision.message.unwrap();
        assert!(message.contains(&pinned_fingerprint));
        assert!(message.contains(&presented_fingerprint));
    }

    #[test]
    fn the_no_policy_continues_the_session_of_a_host_that_presents_another_certificate() {
        use crate::known_hosts::{KnownHosts, append_known_host, certificate_fingerprint};

        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("known_hosts");
        let pinned = self_signed_certificate("servera.ssh3");
        let presented = self_signed_certificate("serverb.ssh3");
        let pinned_fingerprint = certificate_fingerprint(&pinned);
        let presented_fingerprint = certificate_fingerprint(&presented);
        let host = "example.org:443/ssh3-term";

        append_known_host(&path, host, &pinned).unwrap();
        let (known_hosts, _) = KnownHosts::load(&path).unwrap();
        let pinned_fingerprints = known_hosts.fingerprints(host);

        let decision = decide_host_key(
            Ssh3StrictHostKeyChecking::No,
            &context(
                known_hosts.check_certificate(host, &presented),
                &pinned_fingerprints,
                &presented_fingerprint,
                false,
                true,
            ),
        );

        assert_eq!(decision.outcome, HostKeyOutcome::Warn);
        let message = decision.message.unwrap();
        assert!(message.contains(&pinned_fingerprint));
        assert!(message.contains(&presented_fingerprint));
    }
}

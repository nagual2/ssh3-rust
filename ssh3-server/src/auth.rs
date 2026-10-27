//! Server-side authentication and authorization of SSH3 requests.
//!
//! An SSH3 client authenticates with the HTTP `Authorization` header of the
//! CONNECT request:
//!
//! * `Authorization: Bearer <token>` — an SSH3 bearer token (public key) or
//!   an OIDC identity token, matched against the configured authorized
//!   identities;
//! * `Authorization: Basic <base64(user:password)>` — password login, checked
//!   either by a custom [`Ssh3PasswordVerifier`](crate::Ssh3PasswordVerifier) or by
//!   the platform default (`crypt(3)` against the shadow database on Linux).
//!
//! When the server is configured without any authentication requirement
//! (`require_authentication`, `enable_password_login` and
//! `authorized_identity_paths` are all empty/disabled), every request is
//! accepted.
//!
//! The authentication phase is guarded against denial of service by
//! [`Ssh3AuthGuard`]: the number of conversations that wait for their
//! authentication is capped (the `MaxStartups` analog) and repeated failed
//! password attempts lock an account out for a while.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use http::Request;
use ssh3_auth::{
    Ssh3AuthError, Ssh3AuthorizedIdentity, conversation_id_base64,
    load_authorized_identities_from_paths, verify_bearer_token, verify_oidc_identity_token,
};

use crate::config::Ssh3ServerConfig;
use crate::session::SessionUser;

/// Credentials extracted from the `Authorization` header of a CONNECT request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RequestAuthorization {
    /// No (or unparsable) `Authorization` header was present.
    None,
    /// HTTP basic authentication with a decoded username and password.
    Basic { username: String, password: String },
    /// HTTP bearer authentication carrying a raw token.
    Bearer(String),
}

/// The verdict of the authorization of a CONNECT request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthOutcome {
    /// The request may proceed.
    Authorized,
    /// The credentials were missing or wrong (`401 Unauthorized`).
    Unauthorized,
    /// The account is locked out after too many failed attempts
    /// (`429 Too Many Requests`).
    TooManyRequests,
}

/// The bookkeeping of the failed password attempts of one account.
#[derive(Clone, Copy, Debug)]
struct PasswordFailureRecord {
    /// Consecutive failed attempts that were booked.
    failures: u32,
    /// Instant the lockout expires; `None` while the account is not locked.
    locked_until: Option<Instant>,
}

/// The DoS guards of the authentication phase.
///
/// The guard holds the two counters of the `MaxStartups` analog: the number
/// of conversations that sit unauthenticated and the failed password attempts
/// per account. It is shared by all connections of a server, so a client that
/// opens many conversations or guesses many passwords exhausts its own budget
/// only.
#[derive(Debug, Default)]
pub struct Ssh3AuthGuard {
    unauthenticated: AtomicUsize,
    password_failures: Mutex<HashMap<String, PasswordFailureRecord>>,
}

impl Ssh3AuthGuard {
    /// Creates an empty guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits one more conversation into the unauthenticated phase.
    ///
    /// Returns `false` when the cap is reached; the caller has to refuse the
    /// conversation then.
    pub fn try_acquire_unauthenticated(&self, max: usize) -> bool {
        let mut current = self.unauthenticated.load(Ordering::SeqCst);
        loop {
            if current >= max {
                return false;
            }
            match self.unauthenticated.compare_exchange_weak(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Gives one unauthenticated slot back.
    pub fn release_unauthenticated(&self) {
        let mut current = self.unauthenticated.load(Ordering::SeqCst);
        loop {
            if current == 0 {
                return;
            }
            match self.unauthenticated.compare_exchange_weak(
                current,
                current - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    /// Reports whether the account is currently locked out of the password
    /// backend.
    ///
    /// An expired lockout clears the record lazily.
    pub fn password_locked(&self, user: &str) -> bool {
        let mut failures = self
            .password_failures
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(record) = failures.get(user) else {
            return false;
        };

        if let Some(locked_until) = record.locked_until
            && Instant::now() < locked_until
        {
            return true;
        }

        if record.locked_until.is_some() {
            failures.remove(user);
        }

        false
    }

    /// Books one failed password attempt.
    ///
    /// Hitting the failure limit locks the account out for the given
    /// duration. An account that is already locked out is not extended by
    /// attempts that never reached the password backend.
    pub fn password_failure(&self, user: &str, max_failures: u32, lockout: Duration) {
        let mut failures = self
            .password_failures
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let now = Instant::now();
        let record = failures
            .entry(user.to_string())
            .or_insert(PasswordFailureRecord {
                failures: 0,
                locked_until: None,
            });

        if record
            .locked_until
            .is_some_and(|locked_until| now < locked_until)
        {
            return;
        }

        record.failures = record.failures.saturating_add(1);
        if record.failures >= max_failures {
            record.locked_until = Some(now + lockout);
        }
    }

    /// Clears the failure bookkeeping of the account.
    pub fn password_success(&self, user: &str) {
        let mut failures = self
            .password_failures
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        failures.remove(user);
    }
}

/// One slot of the unauthenticated phase, held for the phase's lifetime.
///
/// The audit of 2026-10-27 (risk 3.5.2) asks the slot to survive a cancelled
/// phase: the guard gives the slot back when it is dropped, so the pre-auth
/// timeout of the runtime cannot leak a slot it aborts mid-verification.
pub(crate) struct UnauthenticatedSlot {
    guard: Arc<Ssh3AuthGuard>,
}

impl UnauthenticatedSlot {
    /// Admits one conversation into the unauthenticated phase.
    ///
    /// Returns `None` when the cap of the phase is reached; the caller
    /// refuses the conversation then.
    pub(crate) fn try_acquire(config: &Ssh3ServerConfig) -> Option<Self> {
        config
            .auth_guard
            .try_acquire_unauthenticated(config.max_unauthenticated_conversations)
            .then(|| Self {
                guard: config.auth_guard.clone(),
            })
    }
}

impl Drop for UnauthenticatedSlot {
    fn drop(&mut self) {
        self.guard.release_unauthenticated();
    }
}

/// Reports whether password authentication must be refused for the account.
///
/// The root account authenticates by key only — the `PermitRootLogin
/// prohibit-password` analog of the sshd canon.
pub(crate) fn password_login_refused(username: &str) -> bool {
    username == "root"
}

/// Extracts the value of a query parameter from a request URI.
///
/// Returns `None` when the parameter is absent or has an empty value.
fn extract_query_param(uri: &http::Uri, name: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|entry| {
        let mut parts = entry.splitn(2, '=');
        let key = parts.next()?;
        let value = parts.next().unwrap_or_default();
        (key == name && !value.is_empty()).then(|| value.to_string())
    })
}

/// Returns the user name requested by the client.
///
/// The `ssh3-user` header wins, the `user` query parameter is the fallback and
/// `config.default_user` closes the list. An empty value is treated as "not
/// requested".
pub(crate) fn requested_username(
    request: &Request<()>,
    config: &Ssh3ServerConfig,
) -> Option<String> {
    request
        .headers()
        .get(ssh3_h3::SSH3_USER_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| extract_query_param(request.uri(), "user"))
        .or_else(|| config.default_user.clone())
}

/// Parses the `Authorization` header into a [`RequestAuthorization`].
///
/// Malformed headers (bad base64, non-UTF-8 payload, missing colon) are
/// reported as [`RequestAuthorization::None`] rather than as an error, so the
/// caller can answer with a plain `401 Unauthorized`.
pub(crate) fn parse_request_authorization(request: &Request<()>) -> RequestAuthorization {
    fn strip_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
        let prefix_len = scheme.len();
        (value.len() > prefix_len
            && value[..prefix_len].eq_ignore_ascii_case(scheme)
            && value.as_bytes().get(prefix_len) == Some(&b' '))
        .then(|| value[prefix_len + 1..].trim())
    }

    let Some(value) = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return RequestAuthorization::None;
    };

    if let Some(encoded) = strip_scheme(value, "Basic") {
        let Some(decoded) = BASE64_STANDARD.decode(encoded).ok() else {
            return RequestAuthorization::None;
        };
        let Some(decoded) = String::from_utf8(decoded).ok() else {
            return RequestAuthorization::None;
        };
        let Some((username, password)) = decoded.split_once(':') else {
            return RequestAuthorization::None;
        };
        return RequestAuthorization::Basic {
            username: username.to_string(),
            password: password.to_string(),
        };
    }

    if let Some(token) = strip_scheme(value, "Bearer") {
        if !token.is_empty() {
            return RequestAuthorization::Bearer(token.to_string());
        }
    }

    RequestAuthorization::None
}

/// Default locations of the authorized identity file of a user.
fn default_authorized_identity_paths(session_user: &SessionUser) -> Vec<PathBuf> {
    vec![
        session_user
            .home_dir
            .join(".ssh3")
            .join("authorized_identities"),
        session_user.home_dir.join(".ssh").join("authorized_keys"),
    ]
}

/// Authorized identity files used for the given session user.
///
/// Falls back to the per-user defaults when the server does not configure any
/// path explicitly.
fn configured_authorized_identity_paths(
    config: &Ssh3ServerConfig,
    session_user: &SessionUser,
) -> Vec<PathBuf> {
    if config.authorized_identity_paths.is_empty() {
        default_authorized_identity_paths(session_user)
    } else {
        config.authorized_identity_paths.clone()
    }
}

/// Returns `true` when the configuration requires credentials from clients.
fn should_authenticate(config: &Ssh3ServerConfig) -> bool {
    config.require_authentication
        || config.enable_password_login
        || !config.authorized_identity_paths.is_empty()
}

#[cfg(target_os = "linux")]
#[link(name = "crypt")]
unsafe extern "C" {
    fn crypt(
        key: *const nix::libc::c_char,
        salt: *const nix::libc::c_char,
    ) -> *mut nix::libc::c_char;
}

#[cfg(target_os = "linux")]
fn crypt_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// Returns `true` when the platform provides a built-in password check.
#[cfg(target_os = "linux")]
fn platform_password_auth_available() -> bool {
    true
}

/// Returns `true` when the platform provides a built-in password check.
#[cfg(not(target_os = "linux"))]
fn platform_password_auth_available() -> bool {
    false
}

/// Returns `true` when password authentication can be performed at all.
pub(crate) fn password_auth_available(config: &Ssh3ServerConfig) -> bool {
    config.password_verifier.is_some() || platform_password_auth_available()
}

/// Verifies a password against the shadow database of the given user.
///
/// The stored hash is used as the salt for `crypt(3)`, exactly as the
/// classic Unix tools do. Accounts whose hash is locked (`!` or `*` prefix)
/// never authenticate.
#[cfg(target_os = "linux")]
fn default_password_verifier(username: &str, password: &str) -> io::Result<bool> {
    let username = std::ffi::CString::new(username)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "username contains NUL byte"))?;
    let password = std::ffi::CString::new(password)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "password contains NUL byte"))?;

    let mut buffer_len = 1024usize;
    loop {
        let mut shadow_entry = std::mem::MaybeUninit::<nix::libc::spwd>::uninit();
        let mut buffer = vec![0u8; buffer_len];
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            nix::libc::getspnam_r(
                username.as_ptr(),
                shadow_entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };

        if status == 0 {
            if result.is_null() {
                return Ok(false);
            }

            let shadow_entry = unsafe { shadow_entry.assume_init() };
            if shadow_entry.sp_pwdp.is_null() {
                return Ok(false);
            }

            let stored_hash = unsafe { std::ffi::CStr::from_ptr(shadow_entry.sp_pwdp) };
            let stored_bytes = stored_hash.to_bytes();
            if stored_bytes.is_empty() || matches!(stored_bytes[0], b'!' | b'*') {
                return Ok(false);
            }

            let computed_hash = {
                // F-21: a panic while holding this process-wide lock must not
                // poison it — that would turn one panicking thread into a
                // process-wide password-auth outage. Recover the guard even
                // from a poisoned lock: the critical section holds no
                // invariant to repair (crypt(3) works on a static buffer).
                let _guard = crypt_lock()
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let computed = unsafe { crypt(password.as_ptr(), shadow_entry.sp_pwdp) };
                if computed.is_null() {
                    return Err(io::Error::last_os_error());
                }
                unsafe { std::ffi::CStr::from_ptr(computed).to_owned() }
            };

            // the hash comparison runs in constant time (the audit of
            // 2026-10-27, I8): the computed hash of a well-formed stored
            // entry has the same length as the entry itself, but a malformed
            // or unsupported entry may differ, so the length is folded into
            // the comparison as well
            return Ok(constant_time_eq(
                computed_hash.as_c_str().to_bytes(),
                stored_bytes,
            ));
        }

        if status == nix::libc::ERANGE && buffer_len < 1 << 20 {
            buffer_len *= 2;
            continue;
        }

        return Err(io::Error::from_raw_os_error(status));
    }
}

/// Platform stub: password authentication is not available here.
#[cfg(not(target_os = "linux"))]
fn default_password_verifier(_username: &str, _password: &str) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "password authentication is not supported on this platform",
    ))
}

/// Compares two byte slices without leaking their contents through timing.
///
/// The audit of 2026-10-27 (the F-16 remainder, I8) asks the password check
/// not to leak where the stored and the computed `crypt(3)` hashes diverge:
/// the plain `==` gives up on the first differing byte, so a locally timing
/// attacker can probe the hash byte by byte. The comparison walks the longer
/// of the slices and folds every byte of both inputs — and the difference of
/// the lengths — into one accumulator, so the runtime of the check depends on
/// the inputs only through their lengths, and a length mismatch is folded in
/// rather than returned early.
#[cfg(target_os = "linux")]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u64;
    for index in 0..a.len().max(b.len()) {
        let left = a.get(index).copied().unwrap_or(0);
        let right = b.get(index).copied().unwrap_or(0);
        diff |= u64::from(left ^ right);
    }
    diff == 0
}

/// Verifies a password with the configured verifier or with the platform default.
fn verify_password(config: &Ssh3ServerConfig, username: &str, password: &str) -> io::Result<bool> {
    if let Some(verifier) = config.password_verifier.as_ref() {
        return verifier(username, password);
    }
    default_password_verifier(username, password)
}

/// Authorizes a request against the credentials it carries.
///
/// Returns [`AuthOutcome::Authorized`] when the request may proceed. A wrong
/// or missing credential yields [`AuthOutcome::Unauthorized`], a locked-out
/// account [`AuthOutcome::TooManyRequests`]; an `Err` is reserved for
/// infrastructure failures (an unreadable identity file, a failing OIDC
/// provider).
pub(crate) async fn authorize_request(
    authorization: &RequestAuthorization,
    session_user: &SessionUser,
    conversation_id: &[u8; 32],
    config: &Ssh3ServerConfig,
) -> Result<AuthOutcome, Ssh3AuthError> {
    if !should_authenticate(config) {
        return Ok(AuthOutcome::Authorized);
    }

    match authorization {
        RequestAuthorization::Basic { username, password } => {
            if !config.enable_password_login || username != &session_user.username {
                return Ok(AuthOutcome::Unauthorized);
            }

            // the sshd PermitRootLogin prohibit-password analog: the root
            // account never authenticates by password, whatever its shadow
            // entry says
            if password_login_refused(username) {
                eprintln!(
                    "ssh3-rust-server password auth for {username} refused: the root account authenticates by key only"
                );
                return Ok(AuthOutcome::Unauthorized);
            }

            if config.auth_guard.password_locked(username) {
                eprintln!(
                    "ssh3-rust-server password auth for {username} refused: the account is locked out"
                );
                return Ok(AuthOutcome::TooManyRequests);
            }

            let verified = match verify_password(config, username, password) {
                Ok(verified) => verified,
                Err(err) => {
                    // a failing password backend is booked as a failed
                    // attempt as well, so a broken backend cannot be used to
                    // brute-force the account
                    eprintln!("ssh3-rust-server password auth for {username} failed: {err}");
                    false
                }
            };
            if !verified {
                config.auth_guard.password_failure(
                    username,
                    config.max_password_failures,
                    config.password_lockout,
                );
                return Ok(AuthOutcome::Unauthorized);
            }

            config.auth_guard.password_success(username);
            Ok(AuthOutcome::Authorized)
        }
        RequestAuthorization::Bearer(token) => {
            let identities = load_authorized_identities_from_paths(
                &configured_authorized_identity_paths(config, session_user),
            )?;
            if identities.is_empty() {
                return Ok(AuthOutcome::Unauthorized);
            }

            for identity in &identities {
                match identity {
                    Ssh3AuthorizedIdentity::PublicKey(public_key) => {
                        if verify_bearer_token(
                            public_key,
                            token,
                            &session_user.username,
                            conversation_id,
                        )
                        .is_ok()
                        {
                            return Ok(AuthOutcome::Authorized);
                        }
                    }
                    Ssh3AuthorizedIdentity::Oidc(oidc_identity) => {
                        let expected_nonce = conversation_id_base64(conversation_id);
                        if verify_oidc_identity_token(
                            oidc_identity,
                            token,
                            Some(expected_nonce.as_str()),
                        )
                        .await
                        .is_ok()
                        {
                            return Ok(AuthOutcome::Authorized);
                        }
                    }
                }
            }

            Ok(AuthOutcome::Unauthorized)
        }
        RequestAuthorization::None => Ok(AuthOutcome::Unauthorized),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod constant_time_eq_tests {
    use super::constant_time_eq;

    #[test]
    fn equal_slices_compare_equal() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(constant_time_eq(b"", b""));
        // a realistic crypt(3) shape: the computed hash equals the stored one
        let stored = b"$6$salt$hashedpasswordvalue";
        assert!(constant_time_eq(stored, stored));
    }

    #[test]
    fn differing_slices_do_not_compare_equal() {
        // the difference may sit in any byte, first or last
        assert!(!constant_time_eq(b"abc", b"xbc"));
        assert!(!constant_time_eq(b"abc", b"abx"));
        assert!(!constant_time_eq(b"$6$a$b", b"$6$a$c"));
    }

    #[test]
    fn slices_of_different_length_do_not_compare_equal() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
        assert!(!constant_time_eq(b"", b"a"));
    }
}

//! The OpenSSH-style escape sequences of an interactive session.
//!
//! An escape character at the start of a line introduces the sequences
//!
//! - `~.` disconnects the client (a clean client-side teardown),
//! - `~^Z` suspends the client locally (unix only; elsewhere the sequence
//!   travels to the remote side literally),
//! - `~~` stands for one literal escape character.
//!
//! Any other sequence travels to the remote side literally. The filter is a
//! pure state machine over the stdin chunks, so a sequence split across two
//! reads still fires. The filter only arms for interactive pty sessions: the
//! traffic of an exec session stays byte-exact.

/// The action an escape sequence triggered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ssh3EscapeAction {
    /// No sequence fired.
    None,
    /// The `~.` sequence: the client tears the session down.
    Disconnect,
    /// The `~^Z` sequence: the client suspends itself locally.
    Suspend,
}

/// The filter of the escape sequences of the interactive stdin pump.
#[derive(Clone, Debug)]
pub struct Ssh3EscapeFilter {
    escape_char: u8,
    suspend_supported: bool,
    line_start: bool,
    pending: bool,
}

impl Ssh3EscapeFilter {
    /// Builds a filter for the escape character `escape_char`.
    ///
    /// A zero escape character disables the filter: every byte travels to the
    /// remote side literally.
    ///
    /// `suspend_supported` tells whether the local console can suspend the
    /// process. Where it cannot, the `~^Z` sequence travels literally.
    pub fn new(escape_char: u8, suspend_supported: bool) -> Self {
        Self {
            escape_char,
            suspend_supported,
            line_start: true,
            pending: false,
        }
    }

    /// Filters one stdin chunk.
    ///
    /// Returns the bytes to forward and the action that fired. After a
    /// disconnect the caller must stop pumping; after a suspend the pump
    /// continues.
    pub fn feed(&mut self, chunk: &[u8]) -> (Vec<u8>, Ssh3EscapeAction) {
        if self.escape_char == 0 {
            return (chunk.to_vec(), Ssh3EscapeAction::None);
        }

        let mut out = Vec::with_capacity(chunk.len());
        for &byte in chunk {
            if self.pending {
                self.pending = false;
                match byte {
                    b'.' => return (out, Ssh3EscapeAction::Disconnect),
                    0x1a if self.suspend_supported => {
                        return (out, Ssh3EscapeAction::Suspend);
                    }
                    byte if byte == self.escape_char => {
                        // ~~ collapses into one literal escape character; the
                        // emitted one does not arm the filter again.
                        out.push(self.escape_char);
                    }
                    byte => {
                        // an unknown sequence travels literally: the escape
                        // character on top of the action byte.
                        out.push(self.escape_char);
                        out.push(byte);
                        self.line_start = byte == b'\n' || byte == b'\r';
                    }
                }
                continue;
            }

            if byte == self.escape_char && self.line_start {
                self.pending = true;
                continue;
            }

            out.push(byte);
            self.line_start = byte == b'\n' || byte == b'\r';
        }

        (out, Ssh3EscapeAction::None)
    }
}

/// The error of an escape character the OpenSSH syntax does not accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssh3EscapeCharError {
    value: String,
}

impl std::fmt::Display for Ssh3EscapeCharError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid EscapeChar {:?}: want one ASCII printable character, a ^X control form or none",
            self.value
        )
    }
}

impl std::error::Error for Ssh3EscapeCharError {}

/// Parses the value of the `EscapeChar` option.
///
/// The value is a single ASCII printable character, a control form (`^A`..`^Z`,
/// `^[`, `^]`, `^?`) or "none" (zero, the escape sequences are disabled). The
/// OpenSSH default is `~`.
pub fn parse_escape_char(value: &str) -> Result<u8, Ssh3EscapeCharError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return Ok(0);
    }

    let bytes = trimmed.as_bytes();
    if bytes.len() == 2 && bytes[0] == b'^' {
        let upper = bytes[1].to_ascii_uppercase();
        let control = match upper {
            b'A'..=b'Z' => upper - b'A' + 1,
            b'[' => 27,
            b']' => 29,
            b'?' => 127,
            _ => 0,
        };
        if control != 0 {
            return Ok(control);
        }
        return Err(Ssh3EscapeCharError {
            value: value.to_string(),
        });
    }

    if bytes.len() == 1 && (0x21..=0x7e).contains(&bytes[0]) {
        return Ok(bytes[0]);
    }

    Err(Ssh3EscapeCharError {
        value: value.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::{Ssh3EscapeAction, Ssh3EscapeFilter, parse_escape_char};

    #[test]
    fn forwards_the_plain_bytes() {
        let mut filter = Ssh3EscapeFilter::new(b'~', true);
        let (out, action) = filter.feed(b"hello\n");
        assert_eq!(out, b"hello\n");
        assert_eq!(action, Ssh3EscapeAction::None);
    }

    #[test]
    fn disconnects_on_the_dot_sequence() {
        let mut filter = Ssh3EscapeFilter::new(b'~', true);
        let (out, action) = filter.feed(b"text\n~.");
        assert_eq!(out, b"text\n");
        assert_eq!(action, Ssh3EscapeAction::Disconnect);
    }

    #[test]
    fn suspends_on_the_control_z_sequence() {
        let mut filter = Ssh3EscapeFilter::new(b'~', true);
        let (out, action) = filter.feed(&[b'~', 0x1a]);
        assert!(out.is_empty());
        assert_eq!(action, Ssh3EscapeAction::Suspend);
    }

    #[test]
    fn forwards_the_suspend_sequence_where_it_is_unsupported() {
        let mut filter = Ssh3EscapeFilter::new(b'~', false);
        let (out, action) = filter.feed(&[b'~', 0x1a]);
        assert_eq!(out, vec![b'~', 0x1a]);
        assert_eq!(action, Ssh3EscapeAction::None);
    }

    #[test]
    fn collapses_a_doubled_escape_character() {
        let mut filter = Ssh3EscapeFilter::new(b'~', true);
        let (out, action) = filter.feed(b"~~");
        assert_eq!(out, b"~");
        assert_eq!(action, Ssh3EscapeAction::None);
    }

    #[test]
    fn forwards_an_unknown_sequence_literally() {
        let mut filter = Ssh3EscapeFilter::new(b'~', true);
        let (out, action) = filter.feed(b"~x");
        assert_eq!(out, b"~x");
        assert_eq!(action, Ssh3EscapeAction::None);
    }

    #[test]
    fn only_arms_at_the_start_of_a_line() {
        let mut filter = Ssh3EscapeFilter::new(b'~', true);
        let (out, action) = filter.feed(b"a~.");
        assert_eq!(out, b"a~.");
        assert_eq!(action, Ssh3EscapeAction::None);
    }

    #[test]
    fn fires_a_sequence_split_across_two_chunks() {
        let mut filter = Ssh3EscapeFilter::new(b'~', true);
        let (out, action) = filter.feed(b"~");
        assert!(out.is_empty());
        assert_eq!(action, Ssh3EscapeAction::None);
        let (out, action) = filter.feed(b".");
        assert!(out.is_empty());
        assert_eq!(action, Ssh3EscapeAction::Disconnect);
    }

    #[test]
    fn parses_the_escape_char_values() {
        assert_eq!(parse_escape_char("~").unwrap(), b'~');
        assert_eq!(parse_escape_char("none").unwrap(), 0);
        assert_eq!(parse_escape_char("NONE").unwrap(), 0);
        assert_eq!(parse_escape_char("^A").unwrap(), 1);
        assert_eq!(parse_escape_char("^?").unwrap(), 127);
        assert!(parse_escape_char("^[").is_ok());
        assert!(parse_escape_char("ab").is_err());
        assert_eq!(parse_escape_char(" ").unwrap(), 0);
    }
}

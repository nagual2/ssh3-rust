//! The NSS keylog writer of the `-keylog` option.
//!
//! Every negotiated secret rides one line of the NSS format
//! (`LABEL hex_client_random hex_secret`), the file is appended, so a
//! packet analyzer (Wireshark: Preferences → Protocols → TLS → the same
//! file) decrypts the capture of the session.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// The keylog writer over the file named by `--keylog`.
#[derive(Debug)]
pub struct FileKeyLog {
    path: PathBuf,
    file: Mutex<Option<std::fs::File>>,
}

impl FileKeyLog {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            file: Mutex::new(None),
        }
    }

    fn write_line(&self, line: &str) {
        let mut guard = self.file.lock().unwrap();
        if guard.is_none() {
            match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                Ok(file) => *guard = Some(file),
                Err(err) => {
                    crate::diag_info!("ssh3: could not open the keylog file: {err}");
                    return;
                }
            }
        }
        if let Some(file) = guard.as_mut() {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

impl rustls::KeyLog for FileKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let line = format!("{} {} {}\n", label, hex(client_random), hex(secret));
        self.write_line(&line);
    }

    fn will_log(&self, _label: &str) -> bool {
        true
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::KeyLog;
    use std::fs;

    #[test]
    fn the_keylog_lines_ride_the_nss_format() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("keys.log");
        let keylog = FileKeyLog::new(path.clone());
        keylog.log("CLIENT_HANDSHAKE_TRAFFIC_SECRET", &[0xAA; 32], &[0xBB; 32]);
        keylog.log("SERVER_HANDSHAKE_TRAFFIC_SECRET", &[0xCC; 32], &[0xDD; 32]);
        let content = fs::read_to_string(&path).unwrap();
        assert!(content
            .starts_with("CLIENT_HANDSHAKE_TRAFFIC_SECRET AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"));
        assert!(content.contains("SERVER_HANDSHAKE_TRAFFIC_SECRET"));
        assert!(content.ends_with('\n'));
    }
}

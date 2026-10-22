//! A minimal reader of the ssh_config file of the user.
//!
//! Only the keywords the client needs are read: the file is parsed into the
//! blocks of its `Host` patterns, and a keyword is looked up with the
//! patterns of OpenSSH (`*` and `?` wildcards, `!` for an exclusion).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The name of the directory that holds the configuration of the user.
const SSH_DIRECTORY_NAME: &str = ".ssh";

/// The name of the configuration file of the user.
const SSH_CONFIG_FILE_NAME: &str = "config";

/// The blocks of an ssh_config file.
#[derive(Clone, Debug, Default)]
pub struct SshConfig {
    blocks: Vec<SshConfigBlock>,
}

/// A block of an ssh_config file: the host patterns it applies to and the
/// keywords it sets.
#[derive(Clone, Debug, Default)]
struct SshConfigBlock {
    patterns: Vec<String>,
    entries: Vec<(String, String)>,
}

impl SshConfigBlock {
    /// Tells whether the block applies to a host.
    ///
    /// A block matches when one of its patterns matches the host and none of
    /// its excluded patterns does.
    fn matches(&self, host: &str) -> bool {
        let mut included = false;
        for pattern in &self.patterns {
            if let Some(pattern) = pattern.strip_prefix('!') {
                if matches_pattern(pattern, host) {
                    return false;
                }
            } else if matches_pattern(pattern, host) {
                included = true;
            }
        }
        included
    }
}

impl SshConfig {
    /// Parses the content of an ssh_config file.
    pub fn parse(content: &str) -> Self {
        let mut blocks: Vec<SshConfigBlock> = Vec::new();
        let mut current: Option<SshConfigBlock> = None;
        let mut in_match_block = false;

        for raw_line in content.lines() {
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = match line.split_once(char::is_whitespace) {
                Some((key, value)) => (key.trim(), value.trim()),
                None => (line, ""),
            };

            if key.eq_ignore_ascii_case("Host") {
                if let Some(block) = current.take() {
                    blocks.push(block);
                }
                current = Some(SshConfigBlock {
                    patterns: value.split_whitespace().map(str::to_string).collect(),
                    entries: Vec::new(),
                });
                in_match_block = false;
                continue;
            }
            if key.eq_ignore_ascii_case("Match") {
                // The conditional blocks are not read: their keywords do not
                // apply to the client.
                current = None;
                in_match_block = true;
                continue;
            }
            if in_match_block {
                continue;
            }
            if let Some(block) = current.as_mut() {
                block.entries.push((key.to_string(), value.to_string()));
            }
        }
        if let Some(block) = current {
            blocks.push(block);
        }

        Self { blocks }
    }

    /// The value of a keyword for a host.
    ///
    /// The first block that matches the host and sets the keyword wins, like
    /// OpenSSH does.
    pub fn get(&self, host: &str, keyword: &str) -> Option<&str> {
        for block in &self.blocks {
            if !block.matches(host) {
                continue;
            }
            let entry = block
                .entries
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(keyword));
            if let Some((_, value)) = entry {
                return Some(value.as_str());
            }
        }
        None
    }
}

/// Loads the ssh_config file of the user.
///
/// A file that does not exist leaves the configuration empty.
pub fn load_ssh_config(path: &Path) -> Result<SshConfig, io::Error> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(SshConfig::parse(&content)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(SshConfig::default()),
        Err(err) => Err(err),
    }
}

/// The default location of the ssh_config file of the user.
pub fn default_ssh_config_path() -> Option<PathBuf> {
    crate::known_hosts::home_directory()
        .map(|home| home.join(SSH_DIRECTORY_NAME).join(SSH_CONFIG_FILE_NAME))
}

/// Removes the comment of a line.
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(index) => &line[..index],
        None => line,
    }
}

/// Matches a host against the pattern of an ssh_config block.
///
/// The pattern supports the `*` wildcard, which matches any sequence of
/// characters, and the `?` wildcard, which matches exactly one character.
fn matches_pattern(pattern: &str, host: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let host: Vec<char> = host.chars().collect();

    let (mut pattern_index, mut host_index) = (0usize, 0usize);
    let (mut star_index, mut star_host_index) = (None, 0usize);

    while host_index < host.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == '?' || pattern[pattern_index] == host[host_index])
        {
            pattern_index += 1;
            host_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star_index = Some(pattern_index);
            star_host_index = host_index;
            pattern_index += 1;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_host_index += 1;
            host_index = star_host_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::{SshConfig, load_ssh_config};

    #[test]
    fn the_keyword_of_a_matching_block_is_read() {
        let config = SshConfig::parse(
            "Host example.org\n  StrictHostKeyChecking yes\n\nHost other.org\n  StrictHostKeyChecking no\n",
        );

        assert_eq!(
            config.get("example.org", "StrictHostKeyChecking"),
            Some("yes")
        );
        assert_eq!(config.get("other.org", "StrictHostKeyChecking"), Some("no"));
        assert_eq!(config.get("unknown.org", "StrictHostKeyChecking"), None);
    }

    #[test]
    fn the_wildcards_of_the_patterns_are_honored() {
        let config = SshConfig::parse("Host *.example.org\n  StrictHostKeyChecking accept-new\n");

        assert_eq!(
            config.get("server.example.org", "StrictHostKeyChecking"),
            Some("accept-new")
        );
        assert_eq!(config.get("example.org", "StrictHostKeyChecking"), None);
    }

    #[test]
    fn the_first_block_that_sets_the_keyword_wins() {
        let config = SshConfig::parse(
            "Host example.org\n  StrictHostKeyChecking yes\n\nHost *\n  StrictHostKeyChecking no\n",
        );

        assert_eq!(
            config.get("example.org", "StrictHostKeyChecking"),
            Some("yes")
        );
        assert_eq!(config.get("other.org", "StrictHostKeyChecking"), Some("no"));
    }

    #[test]
    fn the_comments_and_the_empty_lines_are_ignored() {
        let config = SshConfig::parse(
            "# a comment\n\nHost example.org\n  # another comment\n  StrictHostKeyChecking yes\n",
        );

        assert_eq!(
            config.get("example.org", "StrictHostKeyChecking"),
            Some("yes")
        );
    }

    #[test]
    fn a_missing_configuration_file_leaves_the_configuration_empty() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("config");

        let config = load_ssh_config(&path).unwrap();
        assert_eq!(config.get("example.org", "StrictHostKeyChecking"), None);
    }
}

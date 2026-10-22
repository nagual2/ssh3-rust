//! A reader of the ssh_config file of the user.
//!
//! The file is parsed into the blocks of its `Host` and `Match` patterns:
//! a keyword is looked up with the patterns of OpenSSH (`*` and `?`
//! wildcards, `!` for an exclusion) and with the criteria of the `Match`
//! directive (`all`, `final`, `host`, `originalhost`, `user`, `localuser`
//! and `exec`).
//!
//! The `Include` directive pulls the content of other files into the
//! configuration, at the place of the directive, exactly like OpenSSH does:
//! the included content continues the block that surrounds the directive.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

/// The name of the directory that holds the configuration of the user.
const SSH_DIRECTORY_NAME: &str = ".ssh";

/// The name of the configuration file of the user.
const SSH_CONFIG_FILE_NAME: &str = "config";

/// The maximum depth of the `Include` recursion.
///
/// OpenSSH refuses to parse more than five nested levels; the Go
/// implementation uses a larger bound and stops expanding at the limit
/// instead of failing, so that a pathological configuration can never block
/// a connection.
const MAX_INCLUDE_DEPTH: usize = 16;

/// The blocks of an ssh_config file.
#[derive(Clone, Debug, Default)]
pub struct SshConfig {
    sections: Vec<SshConfigSection>,
}

/// A block of an ssh_config file.
#[derive(Clone, Debug)]
struct SshConfigSection {
    kind: SshConfigSectionKind,
    /// The host patterns of a `Host` block.
    patterns: Vec<String>,
    /// The criteria of a `Match` block.
    criteria: Vec<MatchCriterion>,
    /// The keywords of the block, in the order of the file.
    entries: Vec<(String, String)>,
}

/// The kind of a block of an ssh_config file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SshConfigSectionKind {
    /// The directives written before the first `Host` or `Match` line: they
    /// apply to every host.
    Top,
    /// A `Host` block: it applies to the hosts its patterns match.
    Host,
    /// A `Match` block: it applies to the hosts its criteria select.
    Match,
}

/// A criterion of a `Match` block.
///
/// The criteria are the ones of ssh_config(5) that the Go implementation
/// supports: `all`, `final`, `host`, `originalhost`, `user`, `localuser` and
/// `exec`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct MatchCriterion {
    /// The attribute the criterion compares.
    attribute: MatchAttribute,
    /// Whether the attribute is negated with a `!` prefix.
    negated: bool,
}

/// The attribute a `Match` criterion compares.
#[derive(Clone, Debug, PartialEq, Eq)]
enum MatchAttribute {
    /// The block applies to every host.
    All,
    /// The block applies to every host of the last parsing pass.
    Final,
    /// The block applies to the hosts matching the patterns, compared with
    /// the effective host of the connection.
    Host(Vec<String>),
    /// The block applies to the hosts matching the patterns, compared with
    /// the name the user typed on the command line.
    OriginalHost(Vec<String>),
    /// The block applies to the hosts matching the patterns, compared with
    /// the user of the connection.
    User(Vec<String>),
    /// The block applies to the hosts matching the patterns, compared with
    /// the local user of the process.
    LocalUser(Vec<String>),
    /// The block applies when the command exits with the status zero.
    Exec(String),
}

/// The context of a lookup: the host the user typed, the effective host and
/// the effective user of the connection.
struct LookupContext<'a> {
    original_host: &'a str,
    effective_host: String,
    effective_user: String,
    local_user: String,
    /// Whether a `HostName` keyword was already seen: the first one wins.
    host_seen: bool,
    /// Whether a `User` keyword was already seen: the first one wins.
    user_seen: bool,
}

impl SshConfigSection {
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

    /// Tells whether the criteria of a `Match` block hold for a host.
    ///
    /// The criteria are evaluated in order and the first one that fails
    /// decides the block, so the `exec` criterion of a block whose other
    /// criteria already failed never runs its command.
    fn criteria_hold(&self, context: &LookupContext<'_>) -> bool {
        for criterion in &self.criteria {
            let holds = match &criterion.attribute {
                MatchAttribute::All => true,
                // The configuration is parsed in a single pass and the
                // hostnames are never canonicalized, so that pass is the
                // final one.
                MatchAttribute::Final => true,
                MatchAttribute::Host(patterns) => patterns_match(patterns, &context.effective_host),
                MatchAttribute::OriginalHost(patterns) => {
                    patterns_match(patterns, context.original_host)
                }
                MatchAttribute::User(patterns) => patterns_match(patterns, &context.effective_user),
                MatchAttribute::LocalUser(patterns) => {
                    patterns_match(patterns, &context.local_user)
                }
                MatchAttribute::Exec(command) => exec_succeeds(command),
            };
            // A negated criterion holds when the comparison fails.
            if holds == criterion.negated {
                return false;
            }
        }
        true
    }
}

impl SshConfig {
    /// Parses the content of an ssh_config file.
    ///
    /// The `Include` directives are not expanded: the parsing of a file that
    /// includes other ones needs the path of the file, which
    /// [`load_ssh_config`] has.
    pub fn parse(content: &str) -> Self {
        Self::parse_with_base(content, None)
    }

    /// Parses the content of an ssh_config file, expanding the `Include`
    /// directives.
    ///
    /// The base directory is the directory the relative include patterns are
    /// resolved against; the home directory of the user is the fallback, like
    /// in OpenSSH.
    pub fn parse_with_base(content: &str, base: Option<&Path>) -> Self {
        let lines = expand_includes(content, base, 0, &mut Vec::new());
        let mut sections: Vec<SshConfigSection> = Vec::new();
        let mut current: Option<SshConfigSection> = None;

        for line in lines {
            let line = strip_comment(&line).trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = match line.split_once(char::is_whitespace) {
                Some((key, value)) => (key.trim(), value.trim()),
                None => (line, ""),
            };

            if key.eq_ignore_ascii_case("Host") {
                if let Some(section) = current.take() {
                    sections.push(section);
                }
                current = Some(SshConfigSection {
                    kind: SshConfigSectionKind::Host,
                    patterns: split_patterns(value),
                    criteria: Vec::new(),
                    entries: Vec::new(),
                });
                continue;
            }
            if key.eq_ignore_ascii_case("Match") {
                // The conditional blocks are read: their criteria decide
                // whether their keywords apply to the host.
                if let Some(section) = current.take() {
                    sections.push(section);
                }
                current = Some(SshConfigSection {
                    kind: SshConfigSectionKind::Match,
                    patterns: Vec::new(),
                    criteria: parse_match_criteria(value),
                    entries: Vec::new(),
                });
                continue;
            }
            let section = current.get_or_insert_with(|| SshConfigSection {
                kind: SshConfigSectionKind::Top,
                patterns: Vec::new(),
                criteria: Vec::new(),
                entries: Vec::new(),
            });
            section.entries.push((key.to_string(), value.to_string()));
        }
        if let Some(section) = current {
            sections.push(section);
        }

        Self { sections }
    }

    /// The value of a keyword for a host.
    ///
    /// The first block that matches the host and sets the keyword wins,
    /// like OpenSSH does. The `Match` blocks are evaluated with the local
    /// user of the process.
    pub fn get(&self, host: &str, keyword: &str) -> Option<&str> {
        self.get_for_user(host, "", keyword)
    }

    /// The value of a keyword for a host and a user.
    ///
    /// The user is the one of the connection; the `user` criterion of a
    /// `Match` block is compared with it, and the `localuser` criterion with
    /// the local user of the process.
    pub fn get_for_user(&self, host: &str, user: &str, keyword: &str) -> Option<&str> {
        self.values_for_user(host, user, keyword).into_iter().next()
    }

    /// The values of a keyword for a host and a user.
    ///
    /// The keywords that may appear several times in a configuration, like
    /// `LocalForward`, are read with this method.
    pub fn values_for_user(&self, host: &str, user: &str, keyword: &str) -> Vec<&str> {
        let local_user = local_user_name();
        let user_known = !user.is_empty();
        let mut context = LookupContext {
            original_host: host,
            effective_host: host.to_string(),
            effective_user: if user_known {
                user.to_string()
            } else {
                local_user.clone()
            },
            local_user,
            host_seen: false,
            user_seen: user_known,
        };
        let mut values = Vec::new();
        for section in &self.sections {
            let applies = match section.kind {
                SshConfigSectionKind::Top => true,
                SshConfigSectionKind::Host => section.matches(context.original_host),
                SshConfigSectionKind::Match => section.criteria_hold(&context),
            };
            if !applies {
                continue;
            }
            for (key, value) in &section.entries {
                if key.eq_ignore_ascii_case(keyword) {
                    values.push(value.as_str());
                }
            }
            // The `HostName` and `User` keywords of a block that applies
            // change the host and the user the later `Match` blocks are
            // compared with, like OpenSSH does. The first value wins.
            if !context.host_seen
                && let Some(value) = first_value(section, "HostName")
            {
                context.effective_host = value.to_string();
                context.host_seen = true;
            }
            if !context.user_seen
                && let Some(value) = first_value(section, "User")
            {
                context.effective_user = value.to_string();
                context.user_seen = true;
            }
        }
        values
    }
}

/// The first value of a keyword in a block.
fn first_value<'a>(section: &'a SshConfigSection, keyword: &str) -> Option<&'a str> {
    section
        .entries
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(keyword))
        .map(|(_, value)| value.as_str())
}

/// Loads the ssh_config file of the user.
///
/// A file that does not exist leaves the configuration empty.
pub fn load_ssh_config(path: &Path) -> Result<SshConfig, io::Error> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(SshConfig::parse_with_base(
            &content,
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty()),
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(SshConfig::default()),
        Err(err) => Err(err),
    }
}

/// The default location of the ssh_config file of the user.
pub fn default_ssh_config_path() -> Option<PathBuf> {
    crate::known_hosts::home_directory()
        .map(|home| home.join(SSH_DIRECTORY_NAME).join(SSH_CONFIG_FILE_NAME))
}

/// The name of the local user of the process.
///
/// The `localuser` criterion of a `Match` block is compared with it.
fn local_user_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default()
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

/// Tells whether a value matches a list of patterns.
///
/// A negated pattern (`!` prefix) rejects the value; a positive pattern
/// accepts it. The list matches when one of its positive patterns matches
/// the value and none of its negated ones does.
fn patterns_match(patterns: &[String], value: &str) -> bool {
    let mut included = false;
    for pattern in patterns {
        if let Some(pattern) = pattern.strip_prefix('!') {
            if matches_pattern(pattern, value) {
                return false;
            }
        } else if matches_pattern(pattern, value) {
            included = true;
        }
    }
    included
}

/// Splits the patterns of a `Host` line.
fn split_patterns(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_string).collect()
}

/// Splits the pattern list of a `Match` criterion.
///
/// The list is a comma-separated one, like in ssh_config(5).
fn split_pattern_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parses the criteria of a `Match` line.
///
/// The syntax is the one of ssh_config(5): the criteria are separated by
/// spaces, a criterion may be negated with a `!` prefix and a criterion that
/// takes a value accepts the `attribute=value` form.
fn parse_match_criteria(value: &str) -> Vec<MatchCriterion> {
    let Some(args) = split_match_args(value) else {
        return Vec::new();
    };
    let mut criteria = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        let token = args[index].clone();
        index += 1;
        let (negated, token) = match token.strip_prefix('!') {
            Some(rest) => (true, rest.to_string()),
            None => (false, token),
        };
        let (attribute, inline_value) = match token.split_once('=') {
            Some((attribute, value)) => (attribute.to_string(), Some(value.to_string())),
            None => (token, None),
        };
        let attribute = attribute.to_ascii_lowercase();
        let parsed = match attribute.as_str() {
            "all" | "final" => {
                if inline_value.is_some() {
                    return Vec::new();
                }
                if attribute == "all" {
                    MatchAttribute::All
                } else {
                    MatchAttribute::Final
                }
            }
            "host" | "originalhost" | "user" | "localuser" => {
                let value = match inline_value {
                    Some(value) => value,
                    None => match args.get(index) {
                        Some(value) => {
                            index += 1;
                            value.clone()
                        }
                        None => return Vec::new(),
                    },
                };
                let patterns = split_pattern_list(&value);
                match attribute.as_str() {
                    "host" => MatchAttribute::Host(patterns),
                    "originalhost" => MatchAttribute::OriginalHost(patterns),
                    "user" => MatchAttribute::User(patterns),
                    _ => MatchAttribute::LocalUser(patterns),
                }
            }
            "exec" => {
                let value = match inline_value {
                    Some(value) => value,
                    None => match args.get(index) {
                        Some(value) => {
                            index += 1;
                            value.clone()
                        }
                        None => return Vec::new(),
                    },
                };
                MatchAttribute::Exec(value)
            }
            _ => return Vec::new(),
        };
        criteria.push(MatchCriterion {
            attribute: parsed,
            negated,
        });
    }
    criteria
}

/// Splits the arguments of a `Match` line.
///
/// The arguments are separated by spaces; a double quote groups several
/// words into a single argument, which the `exec` criterion needs.
fn split_match_args(value: &str) -> Option<Vec<String>> {
    let mut args = Vec::new();
    let mut token = String::new();
    let mut in_token = false;
    let mut in_quotes = false;
    for character in value.chars() {
        match character {
            _ if in_quotes => {
                if character == '"' {
                    in_quotes = false;
                } else {
                    token.push(character);
                }
            }
            '"' => {
                in_quotes = true;
                in_token = true;
            }
            ' ' | '\t' => {
                if in_token {
                    args.push(std::mem::take(&mut token));
                    in_token = false;
                }
            }
            _ => {
                token.push(character);
                in_token = true;
            }
        }
    }
    if in_quotes {
        return None;
    }
    if in_token {
        args.push(token);
    }
    Some(args)
}

/// Runs the command of an `exec` criterion and tells whether it exits with
/// the status zero.
///
/// The command runs with the shell of the user, like OpenSSH does.
fn exec_succeeds(command: &str) -> bool {
    let mut process = std::process::Command::new(if cfg!(windows) { "cmd" } else { "sh" });
    if cfg!(windows) {
        process.arg("/c");
    } else {
        process.arg("-c");
    }
    process
        .arg(command)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    match process.status() {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

/// Expands the `Include` directives of a configuration.
///
/// The content of an included file takes the place of the directive, so the
/// included lines continue the block that surrounds the directive.
fn expand_includes(
    content: &str,
    base: Option<&Path>,
    depth: usize,
    stack: &mut Vec<PathBuf>,
) -> Vec<String> {
    let mut lines = Vec::new();
    for line in content.lines() {
        let (key, value) = match line.split_once(char::is_whitespace) {
            Some((key, value)) => (key.trim(), value.trim()),
            None => (line.trim(), ""),
        };
        if !key.eq_ignore_ascii_case("Include") {
            lines.push(line.to_string());
            continue;
        }
        if depth >= MAX_INCLUDE_DEPTH {
            // The recursion limit is reached: the directive is dropped
            // instead of failing the whole configuration.
            continue;
        }
        for target in value.split_whitespace() {
            let mut seen = Vec::new();
            for path in resolve_include_target(target, base) {
                let canonical = fs::canonicalize(&path).unwrap_or(path.clone());
                if seen.contains(&canonical) || stack.contains(&canonical) {
                    // A file already pulled in by this directive, or a cyclic
                    // include: the expansion stops, it does not fail.
                    continue;
                }
                let Ok(included) = fs::read_to_string(&path) else {
                    // An unreadable include does not invalidate the rest of
                    // the configuration.
                    continue;
                };
                let included_base = path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty());
                seen.push(canonical.clone());
                stack.push(canonical);
                lines.extend(expand_includes(&included, included_base, depth + 1, stack));
                stack.pop();
            }
        }
    }
    lines
}

/// Resolves the target of an `Include` directive into the files it names.
///
/// The target may be a glob pattern; a relative pattern is resolved against
/// the directory of the including file first and against the `~/.ssh`
/// directory afterwards, like OpenSSH does.
fn resolve_include_target(target: &str, base: Option<&Path>) -> Vec<PathBuf> {
    let expanded = match target.strip_prefix('~') {
        Some(rest) => match crate::known_hosts::home_directory() {
            Some(home) => home.join(rest.trim_start_matches(['/', '\\'])),
            None => PathBuf::from(target),
        },
        None => PathBuf::from(target),
    };
    if expanded.is_absolute() {
        return glob_paths(&expanded);
    }
    let mut candidates = Vec::new();
    if let Some(base) = base {
        candidates.push(base.join(&expanded));
    }
    if let Some(home) = crate::known_hosts::home_directory() {
        candidates.push(home.join(SSH_DIRECTORY_NAME).join(&expanded));
    }
    for candidate in candidates {
        let matches = glob_paths(&candidate);
        if !matches.is_empty() {
            return matches;
        }
    }
    Vec::new()
}

/// Expands a path that may hold the `*` and `?` wildcards into the files it
/// names.
///
/// The wildcards of a path component are matched against the names of the
/// directory, like the glob of OpenSSH does.
fn glob_paths(pattern: &Path) -> Vec<PathBuf> {
    let mut current: Vec<PathBuf> = Vec::new();
    for component in pattern.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {
                current.push(PathBuf::from(component.as_os_str()));
            }
            Component::CurDir => {}
            Component::ParentDir => {
                for path in &mut current {
                    path.push("..");
                }
            }
            Component::Normal(name) => {
                let name = name.to_string_lossy().to_string();
                let mut next = Vec::new();
                for directory in &current {
                    if has_magic(&name) {
                        if let Ok(entries) = fs::read_dir(directory) {
                            for entry in entries.flatten() {
                                let entry_name = entry.file_name().to_string_lossy().to_string();
                                if matches_pattern(&name, &entry_name) {
                                    next.push(entry.path());
                                }
                            }
                        }
                    } else {
                        next.push(directory.join(&name));
                    }
                }
                current = next;
            }
        }
    }
    let mut matches: Vec<PathBuf> = current.into_iter().filter(|path| path.is_file()).collect();
    matches.sort();
    matches
}

/// Tells whether a path component holds a wildcard.
fn has_magic(name: &str) -> bool {
    name.contains('*') || name.contains('?')
}

#[cfg(test)]
mod tests {
    use super::{SshConfig, load_ssh_config};
    use std::fs;

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
    fn the_directives_before_the_first_block_apply_to_every_host() {
        let config = SshConfig::parse("StrictHostKeyChecking yes\n\nHost example.org\n");

        assert_eq!(
            config.get("example.org", "StrictHostKeyChecking"),
            Some("yes")
        );
        assert_eq!(
            config.get("other.org", "StrictHostKeyChecking"),
            Some("yes")
        );
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

    #[test]
    fn an_included_file_is_read_at_the_place_of_the_directive() {
        let directory = tempfile::TempDir::new().unwrap();
        let included = directory.path().join("included");
        fs::write(
            &included,
            "Host example.org\n  StrictHostKeyChecking accept-new\n",
        )
        .unwrap();
        let path = directory.path().join("config");
        fs::write(&path, format!("Include {}\n", included.to_string_lossy())).unwrap();

        let config = load_ssh_config(&path).unwrap();
        assert_eq!(
            config.get("example.org", "StrictHostKeyChecking"),
            Some("accept-new")
        );
    }

    #[test]
    fn the_includes_of_an_included_file_are_expanded() {
        let directory = tempfile::TempDir::new().unwrap();
        let inner = directory.path().join("inner");
        fs::write(&inner, "  StrictHostKeyChecking yes\n").unwrap();
        let outer = directory.path().join("outer");
        fs::write(
            &outer,
            format!("Host example.org\nInclude {}\n", inner.to_string_lossy()),
        )
        .unwrap();
        let path = directory.path().join("config");
        fs::write(&path, format!("Include {}\n", outer.to_string_lossy())).unwrap();

        let config = load_ssh_config(&path).unwrap();
        assert_eq!(
            config.get("example.org", "StrictHostKeyChecking"),
            Some("yes")
        );
    }

    #[test]
    fn an_included_file_may_be_named_by_a_glob() {
        let directory = tempfile::TempDir::new().unwrap();
        let included = directory.path().join("conf.d").join("example");
        fs::create_dir_all(included.parent().unwrap()).unwrap();
        fs::write(
            &included,
            "Host example.org\n  StrictHostKeyChecking accept-new\n",
        )
        .unwrap();
        let path = directory.path().join("config");
        fs::write(
            &path,
            format!(
                "Include {}\n",
                directory.path().join("conf.d/*").to_string_lossy()
            ),
        )
        .unwrap();

        let config = load_ssh_config(&path).unwrap();
        assert_eq!(
            config.get("example.org", "StrictHostKeyChecking"),
            Some("accept-new")
        );
    }

    #[test]
    fn a_cyclic_include_is_stopped() {
        let directory = tempfile::TempDir::new().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        fs::write(
            &first,
            format!(
                "Host example.org\n  StrictHostKeyChecking yes\nInclude {}\n",
                second.to_string_lossy()
            ),
        )
        .unwrap();
        fs::write(
            &second,
            format!(
                "  StrictHostKeyChecking no\nInclude {}\n",
                first.to_string_lossy()
            ),
        )
        .unwrap();
        let path = directory.path().join("config");
        fs::write(&path, format!("Include {}\n", first.to_string_lossy())).unwrap();

        let config = load_ssh_config(&path).unwrap();
        assert_eq!(
            config.get("example.org", "StrictHostKeyChecking"),
            Some("yes")
        );
    }

    #[test]
    fn a_match_block_applies_to_the_matching_hosts() {
        let config = SshConfig::parse(
            "Match host example.org\n  StrictHostKeyChecking yes\n\nHost other.org\n  StrictHostKeyChecking no\n",
        );

        assert_eq!(
            config.get("example.org", "StrictHostKeyChecking"),
            Some("yes")
        );
        assert_eq!(config.get("other.org", "StrictHostKeyChecking"), Some("no"));
    }

    #[test]
    fn a_match_block_with_the_all_criterion_applies_to_every_host() {
        let config = SshConfig::parse("Match all\n  StrictHostKeyChecking yes\n");

        assert_eq!(
            config.get("example.org", "StrictHostKeyChecking"),
            Some("yes")
        );
        assert_eq!(
            config.get("other.org", "StrictHostKeyChecking"),
            Some("yes")
        );
    }

    #[test]
    fn a_match_block_with_the_final_criterion_applies_to_every_host() {
        let config = SshConfig::parse("Match final\n  StrictHostKeyChecking yes\n");

        assert_eq!(
            config.get("example.org", "StrictHostKeyChecking"),
            Some("yes")
        );
    }

    #[test]
    fn a_negated_match_criterion_rejects_the_host() {
        let config = SshConfig::parse("Match !host example.org\n  StrictHostKeyChecking yes\n");

        assert_eq!(config.get("example.org", "StrictHostKeyChecking"), None);
        assert_eq!(
            config.get("other.org", "StrictHostKeyChecking"),
            Some("yes")
        );
    }

    #[test]
    fn a_match_criterion_compares_the_user_of_the_connection() {
        let config = SshConfig::parse("Match user alice\n  StrictHostKeyChecking yes\n");

        assert_eq!(
            config.get_for_user("example.org", "alice", "StrictHostKeyChecking"),
            Some("yes")
        );
        assert_eq!(
            config.get_for_user("example.org", "bob", "StrictHostKeyChecking"),
            None
        );
    }

    #[test]
    fn a_match_criterion_with_a_glob_matches_the_hosts() {
        let config = SshConfig::parse("Match host *.example.org\n  StrictHostKeyChecking yes\n");

        assert_eq!(
            config.get("server.example.org", "StrictHostKeyChecking"),
            Some("yes")
        );
        assert_eq!(config.get("example.org", "StrictHostKeyChecking"), None);
    }

    #[test]
    fn a_match_criterion_may_use_the_attribute_value_form() {
        let config = SshConfig::parse("Match host=example.org\n  StrictHostKeyChecking yes\n");

        assert_eq!(
            config.get("example.org", "StrictHostKeyChecking"),
            Some("yes")
        );
        assert_eq!(config.get("other.org", "StrictHostKeyChecking"), None);
    }

    #[test]
    fn a_match_criterion_may_negate_a_pattern_of_its_list() {
        let config = SshConfig::parse(
            "Match host *.example.org,!secret.example.org\n  StrictHostKeyChecking yes\n",
        );

        assert_eq!(
            config.get("server.example.org", "StrictHostKeyChecking"),
            Some("yes")
        );
        assert_eq!(
            config.get("secret.example.org", "StrictHostKeyChecking"),
            None
        );
    }

    #[test]
    fn a_match_criterion_may_run_a_command() {
        let command = if cfg!(windows) { "exit 0" } else { "true" };
        let config = SshConfig::parse(&format!(
            "Match exec \"{command}\"\n  StrictHostKeyChecking yes\n"
        ));

        assert_eq!(
            config.get("example.org", "StrictHostKeyChecking"),
            Some("yes")
        );
    }

    #[test]
    fn the_values_of_a_repeated_keyword_are_all_read() {
        let config = SshConfig::parse(
            "Host example.org\n  LocalForward 8080:example.org:80\n  LocalForward 8081:example.org:81\n",
        );

        assert_eq!(
            config.values_for_user("example.org", "", "LocalForward"),
            vec!["8080:example.org:80", "8081:example.org:81"]
        );
    }
}

# SSH3 CLI keys - three-way matrix (Go vs C vs Rust)

Reference matrix for UD1. Sources:
- Go: `project/ssh3/cmd/ssh3.go` (client flags) + `project/ssh3/cmd/cli_flags.go`
- C: `project/ssh3-c/app/ssh3_client.c` (`getopt` short string + pre-scan long forms)
- Rust: `project/ssh3-rust/ssh3-client/src/main.rs` (clap `Cli`)

Legend for the platform columns: `yes` = implemented, `-` = not implemented / N/A.

| short | long | arg | default | Go | C | Rust | status |
|---|---|---|---|---|---|---|---|
| `-4` | `--ipv4-only` (Rust) | flag | false | yes | yes (`-4`) | yes | all three |
| `-6` | `--ipv6-only` (Rust) | flag | false | yes | yes (`-6`) | yes | all three |
| `-A` | `--forward-agent` | flag | false | yes | yes | yes | all three |
| `-C` | - | string (codec/none) | "" | yes | yes | - | missing in Rust |
| `-D` | - | spec (repeatable) | none | yes | yes | yes | all three |
| `-F` | `--ssh-config` (Rust) / `-F` (Go,C) | path | "" | yes | yes | yes | all three (long name differs) |
| `-J` | `--jump` / `--proxy-jump` | destination | "" | yes | yes | yes | all three |
| `-L` | - | spec | none | yes | yes | yes | all three |
| `-M` | - | flag | false | yes | yes | yes (unix) | all three |
| `-N` | - | flag | false | yes | yes | yes | all three |
| `-O` | - | op | "" | yes | yes | yes (unix) | all three |
| `-P` | - | int (port) | 443 | yes | - | - | Go only |
| `-R` | - | spec | none | yes | yes | yes | all three |
| `-S` | - | path | "" | yes | yes | yes (unix) | all three |
| `-T` | - | flag | false | yes | yes | yes | all three |
| `-U` | `--url-path` (Rust) | path/string | "/ssh3-term" | yes | yes | yes | all three (semantics differ in C) |
| `-V` | `--version` | flag | false | yes | yes | yes | all three |
| - | `--agent` | flag | false | - | - | yes | Rust only |
| - | `--agent-key` / `-pubkey-for-agent` | path | none | yes (`-pubkey-for-agent`) | yes (`--agent-key`) | yes (`--agent-key`) | all three (name differs) |
| - | `--agent-socket` | path | none | - | - | yes | Rust only |
| - | `-bearer-token` / `-bearer-token-file` | string/path | none | - | - | yes | Rust only |
| - | `--ca-cert` | path | none | - | - | yes | Rust only |
| - | `--checksum` | flag | false | yes | - | yes | Go + Rust |
| - | `--conn-rx-mb` | int | 16 | yes | - | - | Go only |
| - | `--continue` / `--resume` | flag | false | yes (`--continue`) | - | yes (`--continue`) | Go + Rust |
| - | `--control-master` | value | "no" | yes | - | yes (unix) | Go + Rust |
| - | `--control-path` | path | "" | yes | - | yes (unix) | Go + Rust (C via `-S`) |
| - | `--control-persist` | value | "no" | yes | - | yes (unix) | Go + Rust |
| - | `--dynamic-forward` (internal? no) | - | - | - | - | - | (see `-D`) |
| `-e` | - | char | none | - | yes | - | C only |
| `-f` | - | flag | false | yes | yes | yes | all three |
| - | `--forward-agent` | flag | false | yes | - (see `-A`) | yes | all three (short `-A`) |
| - | `--forward-tcp` / `--forward-udp` | string (`localport/remoteip@remoteport`) | "" | yes | - | yes (deprecated alias of `-L` / `-L udp://`) | Go + Rust (C never carried the aliases) |
| - | `--handshake-idle-timeout` | duration | none | - | - | yes | Rust only |
| - | `--identity` / `-i` / `--privkey` | path | "" | yes (`-i` / `-privkey`) | yes (`-i` / `-privkey`) | yes (`-i` / `--privkey`) | all three |
| - | `--insecure` / `-insecure` | flag | false | yes | yes | yes | all three |
| `-i` | `--identity` | path | "" | yes | yes | yes | all three |
| `-J` | `--jump` / `--proxy-jump` | destination | "" | yes | yes | yes | all three |
| - | `--known-hosts` | path | none | - | - | yes | Rust only |
| - | `--keylog` | path | "" | yes | - | yes | Go + Rust |
| `-l` | - | login name (C) / `--log-level` hint | none | - | yes | - | C only (Go `--log-level`? no) |
| - | `--local-forward` | spec | none | - (see `-L`) | - (see `-L`) | - (`-L` only) | all three (short `-L`) |
| - | `--max-idle-timeout` | duration | none | - | - | yes | Rust only |
| `-M` | - | flag | false | yes | yes | yes (unix) | all three |
| `-n` | - | flag | false | - | yes | - | C only (no stdin) |
| `  ` | `--no-pkce` | flag | false | yes | - | yes | Go + Rust |
| `-N` | - | flag | false | yes | yes | yes | all three |
| `-o` | - | KEY=VALUE | none | yes | yes | yes | all three |
| - | `--oidc-client-id` / `--oidc-client-secret` / `--oidc-client-secret-file` | - | none | - (cid via use-oidc) | - | yes | Rust only |
| - | `--oidc-config` | path | "" | yes (`--oidc-config`) | - | yes | Go + Rust |
| - | `--oidc-issuer` (C) / `--use-oidc` (Go/Rust) | issuer | "" | yes (`--use-oidc`) | yes (`--oidc-issuer`) | yes (`--use-oidc`) | all three (name differs) |
| - | `--oidc-token` / `--oidc-audience` | - | none | - | yes (C) | - | C only (Go/Rust use -o / --use-oidc) |
| - | `--option` | KEY=VALUE | none | - (see `-o`) | - (see `-o`) | - (`-o` only) | all three (short `-o`) |
| `-p` | - | int (port) | 0 | yes | yes | yes | all three |
| - | `--packet-size` | int | 1200 | yes | - | yes | Go + Rust (client; the server rides `-initial-packet-size` in Go) |
| - | `--password` / `--password-file` | string/path | "" | yes (`--password`) | yes (`--password`) | yes | all three |
| - | `--port` | u16 | none | - (see `-p`) | - (see `-p`) | yes (`-p`) | all three |
| - | `--privkey` | path | "" | yes | yes (alias) | yes (alias) | all three |
| - | `--proxy-jump` | destination | "" | yes | - | yes | Go + Rust |
| `-q` | - | flag | false | yes | yes | yes | all three |
| `-r` | `--recursive` | flag | false | yes | yes | yes | all three |
| `-s` | `--subsystem` | name | "" | yes | yes | yes | all three |
| - | `--stream-rx-mb` | int | 8 | yes | - | - | Go only |
| - | `--strict-host-key-checking` | value | "" | yes | yes (`-strict-host-key-checking`) | yes | all three |
| `-t` | - | flag | false | yes | yes | yes | all three |
| - | `--transfer` | flag | false | yes | - (--sftp replaces) | yes | Go + Rust (Rust exposes `--sftp` as its alias) |
| - | `--sftp` | flag (scp canon; the `put|get:local:remote` spec form stays UD4) | false | yes | yes | yes (`--transfer` alias) | all three (Rust rides `--transfer`; spec forms — UD4) |
| - | `--url` | URL | required | - (positional) | - (positional) | yes | Rust only |
| - | `--url-path` | path | `/ssh3-term` | - (see `-U`) | - (see `-U`) | yes (`-U`) | all three |
| - | `--use-password` | flag | false | yes | - | - | Go only |
| - | `--use-oidc` | issuer | "" | yes | - (see `--oidc-issuer`) | yes | Go + Rust (+ C alias) |
| `-v` | - | flag/count | false | yes | yes | yes | all three |
| `-x` / `-X` / `-Y` | - | flag/ignored | false | - | yes (deprecated/ignored) | - | C only |

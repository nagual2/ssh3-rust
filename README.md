# SSH3 over HTTP/3 — Rust implementation

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Status: active](https://img.shields.io/badge/status-active-brightgreen.svg)](FROZEN.md)

**English** | [Русский](README.ru.md) | [Deutsch](README.de.md)

SSH3 maps RFC 4254-style remote session semantics onto QUIC, TLS 1.3 and HTTP/3
Extended CONNECT. The protocol keeps the familiar SSH workflow — shell
sessions, exec, PTY allocation, window resize, signal forwarding, direct
TCP/UDP port forwarding, SSH agent forwarding — and carries it over an
HTTP-native transport with QUIC-native datagrams.

This repository contains **only the Rust implementation**. It is an
independent reference implementation of the SSH3 protocol.

> [!NOTE]
> SSH3 is still experimental, and the protocol name may still change. The
> protocol remains SSH-style session and channel semantics carried over QUIC
> and HTTP/3 Extended CONNECT.

> [!WARNING]
> **This workspace was frozen (dormant) from 2026-10-13 to 2026-10-22; the
> owner lifted the freeze on 2026-10-22** with the goal of reaching parity
> with the Go implementation ([nagual2/ssh3-go](https://github.com/nagual2/ssh3-go)).
> The Go implementation remains the only shipped product: this repository is
> in no release artifact yet, and a fresh audit pass is still required before
> the first one. See [`FROZEN.md`](FROZEN.md) and [`ROADMAP.md`](ROADMAP.md).

## Positioning

> Independent reference implementation of the SSH3 protocol in Rust.
> Wire-compatible with [francoismichel/ssh3](https://github.com/francoismichel/ssh3)
> and with [nagual2/ssh3-go](https://github.com/nagual2/ssh3-go), but **not a
> fork of them and not a replacement for them**.

This repository is the **second stack** and the **protocol reference** of the
SSH3 family of implementations. Its purpose is to keep a second, independent
reading of the wire format alive, to serve as the base for the C port
([nagual2/ssh3-c](https://github.com/nagual2/ssh3-c)), and to give the protocol
a reviewable, auditable implementation that is not tied to the Go product
surface.

## Requirements

| Requirement | Notes |
| --- | --- |
| Rust 1.85 or newer | The crates use edition 2024; the minimum supported version is 1.85. |
| Network access to crates.io | Required for the first build only; `Cargo.lock` is committed. |
| Go toolchain (1.21+) | **Only** for the cross-implementation interop tests. Not needed to build, run or test the Rust code alone. |
| Unix-like host | The interop scenarios are compiled only on Unix (`#[cfg(unix)]`); the rest of the workspace builds on Windows too. |

## Build and run

```bash
git clone https://github.com/nagual2/ssh3-rust.git
cd ssh3-rust
cargo build --workspace
```

The workspace produces two binaries:

| Binary | Package | Purpose |
| --- | --- | --- |
| `ssh3-rust-client` | `ssh3-client` | SSH3 client: shell, exec, PTY, auth, forwarding. |
| `ssh3-rust-server` | `ssh3-server` | SSH3 server: sessions, PTY, auth, forwarding. |

The package names stay `ssh3-client` / `ssh3-server` — they describe the
protocol, not the product; the binaries carry the product name so that they
never collide with the Go implementation in `PATH`.

Run the help of both binaries straight from the workspace:

```bash
cargo run -p ssh3-client -- --help
cargo run -p ssh3-server -- --help
```

For secret material prefer the file-backed flags (`--password-file`,
`--bearer-token-file`, `--oidc-client-secret-file`) over passing secrets on
the command line: values in `argv` leak through shell history, process
listings and CI logs.

## Quick start

The Rust server starts with a self-signed certificate, so the examples below
use `--insecure` (pin the certificate with `--ca-cert` instead whenever the
peer is not on the same host).

Start a local server:

```bash
cargo run -p ssh3-server -- \
  --bind 127.0.0.1:4433 \
  --user "$USER" \
  --require-auth \
  --authorized-identity ~/.ssh/authorized_keys
```

Connect with a private key and open a shell:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term
```

Run a remote command instead of requesting a shell:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term \
  -- "printf 'hello from ssh3\n'"
```

The server currently accepts any URL path — there is no secret path support
yet (see the limitations below).

### Host key verification

The client can pin the certificate of a server in a `known_hosts` file, the
way the Go implementation does:

```bash
cargo run -p ssh3-client -- \
  -o StrictHostKeyChecking=accept-new \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term
```

The pins live in `~/.ssh3/known_hosts` (`%USERPROFILE%\.ssh3\known_hosts` on
Windows), one line per certificate:

```text
127.0.0.1:4433/ssh3-term x509-certificate MIIDqTCCAnugAwIBAgIU...
```

The `StrictHostKeyChecking` policy takes the values of OpenSSH: `ask` (the
default: the user confirms an unknown host on the console, and a session
without a console refuses it), `yes` (only a pinned certificate is accepted),
`accept-new` (an unknown host is pinned on first use) and `no` (a mismatch
only warns and the session continues). The policy comes from the
`--strict-host-key-checking` flag, from the `-o StrictHostKeyChecking=` option
or from the keyword of the same name of the `~/.ssh/config` file, in that
order of precedence. The check only runs when one of the sources sets the
policy.

### Client configuration

The client reads the ssh_config file of the user (`~/.ssh/config` by default,
`%USERPROFILE%\.ssh\config` on Windows). The `-F` flag names another file;
a file that cannot be read is ignored with a warning on the standard error,
like the Go implementation does.

The `-o` option accepts the keywords of ssh(1): `RequestTTY`, `Term`,
`EscapeChar`, `StrictHostKeyChecking`, `LocalForward`, `RemoteForward`,
`DynamicForward`, `ProxyJump` and `ServerAliveInterval`. The `LocalForward`,
`RemoteForward` and `DynamicForward` values use the syntax of the `-L`, `-R`
and `-D` flags. Every setting is resolved with the precedence of OpenSSH: the
command line wins over the `-o` option, which wins over the keyword of the
ssh_config file, which wins over the default.

The ssh_config file understands the `Include` directive (recursive, with glob
patterns, a guard against cycles and a depth limit of 16) and the `Match`
blocks, with the `all`, `final`, `host`, `originalhost`, `user`, `localuser`
and `exec` criteria and the `!` negation of a criterion or of a pattern of a
list.

The `-N` flag opens no session at all: the connection is held open for the
forwards, and the client waits until it is interrupted.

```bash
# the connection is held open for the forwards, without a session
cargo run -p ssh3-client -- -N -L 8080:example.org:80 ...
```

The `-V` flag prints the version string of the client, in the format of the
Go implementation:

```text
SSH 3.0 ssh3-rust 0.1.0 experimental_spec_version=alpha-00
```

### Port forwarding

The client forwards ports in the three directions of the ssh(1) canon:

```bash
# -L: a local listener whose connections the server dials on the client behalf
cargo run -p ssh3-client -- -L 8080:example.org:80 ...

# -R: the server binds a port and bridges every connection to a local target
cargo run -p ssh3-client -- -R 8080:127.0.0.1:3000 ...

# -D: a local SOCKS5 proxy whose connections the server dials
cargo run -p ssh3-client -- -D 1080 ...
```

The `-L` specification is `[bind_address:]port:host:hostport` (with the
`udp://` prefix for the datagram forward), the `-R` one is
`[bind_address:]bind_port[/udp]:target_host:target_port` and the `-D` one is
`[bind_address:]port`. A bind address of `*` listens on every interface; a
forward without one stays on the loopback.

The target of a reverse forward is resolved on the client, the way OpenSSH
resolves it, and the client only bridges the forwarded channels whose target
it asked for: a server that asks the client to reach another endpoint is
refused.

## Workspace crates

| Crate | Description |
| --- | --- |
| `ssh3-proto` | Wire format: message types, SSH strings and varints, encoding and decoding of the SSH3 framing. |
| `ssh3-core` | Conversation and channel runtime: channel lifecycle, data and extended-data streams, datagram queues. |
| `ssh3-quinn` | QUIC transport bindings on top of `quinn`, TLS configuration and self-signed certificate generation. |
| `ssh3-h3` | HTTP/3 bootstrap and Extended CONNECT handling (`:protocol=ssh3`), including the datagram dispatch path. |
| `ssh3-auth` | Authentication helpers: public key (ed25519, P-256, RSA), password verifier support and OIDC token verification. |
| `ssh3-client` | Client runtime and CLI binary: session setup, PTY, resize, signals, agent and port forwarding. |
| `ssh3-server` | Server runtime and CLI binary: authentication, session handling, PTY, forwarding. |

`vendor/h3` is a deliberate `[patch.crates-io]` shim over the crates.io crate
`h3` 0.0.8. It adds the `:protocol` pseudo-header support that Extended
CONNECT requires and that upstream `h3` does not provide. Do not swap it for
the upstream crate — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Tests

```bash
cargo test --workspace          # the whole suite: 89 tests
cargo test -p ssh3-client       # adds the cross-implementation matrix
```

`cargo check --workspace --locked` is expected to pass without touching the
network once the dependencies are cached.

### Cross-implementation (interop) matrix

22 scenarios drive **real Go binaries** built from the
[nagual2/ssh3-go](https://github.com/nagual2/ssh3-go) repository against the
Rust implementation, in both directions:

| Scenario | Rust → Go | Go → Rust |
| --- | --- | --- |
| exec (remote command) | yes | yes |
| Public-key auth (ed25519, P-256, RSA, extra-algorithm negotiation) | yes | yes |
| Password auth | yes | yes |
| OIDC auth (token and interactive login) | yes | yes |
| PTY shell | yes | yes |
| Window resize (SIGWINCH) | — | yes |
| Signal forwarding | — | yes |
| Direct TCP forwarding | yes | yes |
| Direct UDP (datagram) forwarding | yes | yes |
| SSH agent auth and agent forwarding | yes | yes |

> [!WARNING]
> The interop tests need a **checkout of the Go repository** and a **Go
> toolchain**. Point the `SSH3_GO_REPO` environment variable at that checkout;
> the harness builds the Go peers from it and runs the scenarios against them.
> Without it (or without a Go toolchain) every interop scenario is **skipped**
> with a `skipping:` line in the test log instead of failing. Pin the checkout
> to a release tag of the Go implementation: the interop matrix is verified
> against a specific Go release, not against `main` (see `M0.C.2` in
> [`ROADMAP.md`](ROADMAP.md)). The CI runs the matrix against the release
> `v0.1.37`, which carries `quic-go` v0.63.0. The `h3` 0.0.8 shim speaks the
> final HTTP/3 (RFC 9114) and interoperates with that release; the
> scenarios are compiled only on Unix-like hosts.

## Compatibility with the Go implementation

The Rust implementation speaks the same wire protocol as the Go
implementation: the same message numbering, the same framing, the same
authentication flows and the same forwarding headers. The interop matrix
above is the regression guard for that statement — a change in one
implementation that breaks the other fails the Rust test suite.

The Go implementation is ahead on product surface. It is the shipped product,
and the Rust workspace does not attempt to replicate it:

| Capability | Go implementation | Rust workspace |
| --- | --- | --- |
| Session shell and exec | yes | yes |
| PTY, resize, signal forwarding | yes | yes |
| Public key, password, OIDC, agent auth | yes | yes |
| Direct TCP/UDP forwarding | yes | yes (runtime and CLI) |
| Reverse forwarding (`-R`) | yes | yes (runtime and CLI) |
| Dynamic SOCKS forwarding (`-D`) | yes | yes (runtime and CLI) |
| Proxy jump | yes | no |
| Control master / connection multiplexing | yes | no |
| File transfer (`-transfer`) | yes | no |
| Secret URL path | yes | no |
| Public certificate automation (Let's Encrypt) | yes | no (self-signed only) |
| Release packaging (`.deb`, systemd unit, goreleaser) | yes | no |

## Known limitations and audit findings

The workspace was frozen with the following open items. They are listed here
so that nobody mistakes this code for production-hardened.

| Finding | Severity | Location | Description |
| --- | --- | --- | --- |
| F-16 | Low (pre-auth) | `ssh3-server/src/lib.rs:344-393` | Password authentication compares the computed hash with the short-circuiting `==` operator instead of a constant-time comparison, and there is no lockout for repeated failures. |
| F-19 (Rust client residual) | Medium | `ssh3-client/src/lib.rs:1406-1411` | A malformed datagram still terminates datagram reception in the Rust client. The Go side of F-19 was fixed in the Go repository; the Rust residual was not. |
| F-20 | Medium | `ssh3-core/src/conversation.rs:292` | No channel budget: `dangling_datagram_queues` is an unbounded `HashMap` keyed by a peer-supplied identifier. |
| SSH string length limit | High | `ssh3-proto/src/wire.rs:167` | `read_ssh_bytes` allocates a buffer whose size comes from the peer-supplied varint length. The Go implementation caps the length (`util.MaxSSHStringLen = 1<<24`); the Rust one does not. |
| `max_packet_size` is not clamped | High | `ssh3-quinn/src/channel.rs:364`, `ssh3-core/src/channel.rs:447` | The peer-advertised value is taken as-is: it is neither clamped to a local maximum nor floored to a sane minimum. |
| No `permit-open` / `permit-listen` | High | `ssh3-server/src/lib.rs:1718` | The server forwards to any address the peer asks for; there is no forwarding policy to restrict it. |
| Outdated QUIC dependency | Medium | `Cargo.lock` (`quinn-proto` 0.11.14) | RUSTSEC-2026-0185 (remote memory exhaustion) and a DATAGRAM limit bypass. Fixed in `quinn-proto` 0.11.19+. The DATAGRAM path is core to SSH3, so the advisory applies to the protocol itself. |
| Minimal server | — | `ssh3-server` | Self-signed certificates only, no public certificate automation, no secret URL path. |

The workspace is built by `.github/workflows/ci.yml`: `cargo fmt --check`, clippy
with `-D warnings`, the test suite and the interop matrix against the pinned Go
release `v0.1.37`. The toolchain is pinned in `rust-toolchain.toml`, the
formatter and the linter are configured in `rustfmt.toml` and `clippy.toml`.

The wire parser also has a second, asynchronous copy in
`ssh3-core/src/channel.rs:439-615`; the round-trip tests exercise
`ssh3_proto::Ssh3Message::parse`, which is not on the production path.

## Wire specification

The protocol spoken here is the experimental IETF draft
`draft-michel-remote-terminal-http3-00` (pre-standard). The concrete
encoding used by the implementations — message layout, string encoding,
forwarding headers — is specified in the C port repository:
[SSH3 wire protocol, rev nagual2/1](https://github.com/nagual2/ssh3-c/blob/main/docs/SPEC-wire.md).

## Project documents

| Document | Purpose |
| --- | --- |
| [`ROADMAP.md`](ROADMAP.md) | Development plan: rebranding, security backlog, infrastructure restoration, unfreezing conditions. |
| [`FROZEN.md`](FROZEN.md) | The freeze decision of 2026-10-13 and what it means for audits and releases. |
| [`CHANGELOG.md`](CHANGELOG.md) | History of the Rust line only. |
| [`NOTICE`](NOTICE) | Attribution and provenance of the imported code. |
| [`SECURITY.md`](SECURITY.md) | Threat model, known limitations and how to report a vulnerability. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Build, test and contribution rules. |

## License and attribution

Licensed under the Apache License, Version 2.0
(<https://www.apache.org/licenses/LICENSE-2.0>).

The Rust code was **imported** on 2026-04-02 from
[MatiasHiltunen/ssh3](https://github.com/MatiasHiltunen/ssh3) — a fork of
[francoismichel/ssh3](https://github.com/francoismichel/ssh3) — and was
extended afterwards by the `nagual2` maintainers. It is not a rewrite from
scratch. See [`NOTICE`](NOTICE) for the full attribution.

## Go implementation

The shipped Go implementation lives in a separate repository:
[nagual2/ssh3-go](https://github.com/nagual2/ssh3-go) — a fork of
[francoismichel/ssh3](https://github.com/francoismichel/ssh3).

# Security Policy

## Scope

This document describes the security model of the **Rust implementation** of
SSH3 in this repository. It does not cover the Go implementation, which lives
in a separate repository ([nagual2/ssh3-go](https://github.com/nagual2/ssh3-go))
and is the only shipped product.

> [!WARNING]
> The workspace is **frozen (dormant) since 2026-10-13** (see
> [`FROZEN.md`](FROZEN.md)). It is built by CI (build, tests, clippy, advisory
> scan), but not shipped in any release, and the findings listed below are
> frozen together with the code. The
> protocol itself is experimental and pre-standard. Do not deploy this code in
> production.

## Threat model

The threat model is deliberately narrow and explicit:

- **The peer is untrusted.** A remote peer may connect, send arbitrary bytes
  and open conversations before authentication has succeeded. Everything that
  is parsed before the authentication handshake completes must be treated as
  hostile input.
- **Authentication protects the session, not the parser.** Any data the peer
  sends — including a partial or malformed frame — reaches the wire parser
  before the peer's identity is known. Allocation, parsing and channel
  bookkeeping therefore have to be safe against hostile input, not only
  against buggy input.
- **The server is a network daemon.** It binds a QUIC/UDP socket, serves
  HTTP/3 Extended CONNECT requests and spawns processes for authenticated
  sessions. A local, unprivileged attacker on the same host is out of scope;
  a remote attacker and a malicious peer are in scope.
- **Availability matters.** The QUIC datagram path is core to SSH3 (UDP
  forwarding), so resource limits and per-peer budgets are part of the
  security model, not an optimisation detail.

### Attack surfaces

| Surface | Description |
| --- | --- |
| Wire parser | Message decoding in `ssh3-proto`, framing and string decoding in `ssh3-core/src/channel.rs`. |
| Channel and conversation bookkeeping | Channel identifiers, packet-size negotiation, datagram queues in `ssh3-core/src/conversation.rs`. |
| Authentication | Public key, password and OIDC verification in `ssh3-auth` and `ssh3-server`. |
| Port and agent forwarding | The server dials addresses requested by the peer; the client exposes local listeners. |
| Datagram path | QUIC datagram receive loops in `ssh3-client` and `ssh3-server`. |
| TLS material | Self-signed certificate generation and trust decisions in `ssh3-quinn` and `ssh3-client`. |

## Known limitations

These are open, known issues. They are listed here with their location so that
an operator can assess the risk; the fix plan is tracked in
[`ROADMAP.md`](ROADMAP.md) (section M2).

| Finding | Severity | Location | Description |
| --- | --- | --- | --- |
| F-16 | Low (pre-auth) | `ssh3-server/src/lib.rs:344-393` | Password authentication compares the computed hash with `==` instead of a constant-time comparison, and does not lock out repeated failures. |
| F-19 (Rust client residual) | Medium | `ssh3-client/src/lib.rs:1406-1411` | A malformed datagram terminates datagram reception in the Rust client. |
| F-20 | Medium | `ssh3-core/src/conversation.rs:292` | No channel budget: `dangling_datagram_queues` is an unbounded `HashMap` keyed by a peer-supplied identifier. |
| SSH string length limit | High | `ssh3-proto/src/wire.rs:167` | `read_ssh_bytes` allocates memory according to the peer-supplied length; no cap is applied (the Go implementation caps it at `util.MaxSSHStringLen = 1<<24`). |
| `max_packet_size` is not clamped | High | `ssh3-quinn/src/channel.rs:364`, `ssh3-core/src/channel.rs:447` | The peer-advertised value is neither clamped nor floored. |
| No `permit-open` / `permit-listen` | High | `ssh3-server/src/lib.rs:1718` | The server forwards to any address the peer requests. |
| Outdated QUIC dependency | Medium | `Cargo.lock` (`quinn-proto` 0.11.14) | RUSTSEC-2026-0185 (remote memory exhaustion) and a DATAGRAM limit bypass; fixed in `quinn-proto` 0.11.19+. |
| No authentication DoS guard | Medium | `ssh3-server` | No cap on unauthenticated conversations and no failed-attempt counter. |
| Secret URL path not enforced | Medium | `ssh3-h3` | The server accepts any URL path; the path is therefore not a secret. |
| Minimal server | Low | `ssh3-server` | Self-signed certificates only; no public certificate automation and no certificate pinning workflow. |

## Reporting a vulnerability

- Open a **security issue in this repository** (GitHub → *Security* →
  *Report a vulnerability*). Describe the surface, the reproduction steps and
  the observed impact.
- Please do not open a public issue for an exploitable defect before a fix is
  available.
- Fixes follow the workflow in [`CONTRIBUTING.md`](CONTRIBUTING.md): a
  regression test first, then the fix, then the changelog entry.

Because this workspace is frozen, a report does not imply a fix in this
repository: the report is triaged against the plan in
[`ROADMAP.md`](ROADMAP.md), and the corresponding fix may land in the Go
implementation or in a future, unfrozen Rust release.

## Disclaimer

SSH3 is an experimental, pre-standard protocol
(`draft-michel-remote-terminal-http3-00`). This implementation is a reference
implementation for protocol work, not a hardened product. It is provided
"as is", without warranty of any kind, as required by the Apache License 2.0.

# Security Policy

## Scope

This document describes the security model of the **Rust implementation** of
SSH3 in this repository. It does not cover the Go implementation, which lives
in a separate repository ([nagual2/ssh3-go](https://github.com/nagual2/ssh3-go))
and is the only shipped product.

> [!WARNING]
> The workspace was **frozen (dormant) from 2026-10-13 until 2026-10-22**
> (see [`FROZEN.md`](FROZEN.md)). The freeze was lifted on 2026-10-22, but
> the code is still **not shipped**: the Go implementation
> ([nagual2/ssh3-go](https://github.com/nagual2/ssh3-go)) remains the only
> released product. The workspace is built by CI (build, tests, clippy,
> cross-build, advisory scan, dependency policy, shim verification), and the
> findings listed below are tracked in
> [`ROADMAP.md`](ROADMAP.md). The protocol itself is experimental and
> pre-standard. Do not deploy this code in production.

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
| Outdated QUIC dependency | Medium | `Cargo.lock` (`quinn-proto` 0.11.19) | **Fixed on 2026-10-22**: RUSTSEC-2026-0185 and the related `quinn-proto` advisories (RUSTSEC-2026-0338, RUSTSEC-2026-0339, RUSTSEC-2026-0340, RUSTSEC-2026-0342) are cleared by `quinn-proto` 0.11.19 and `quinn` 0.11.12. See "Known advisories and accepted risks". |
| No authentication DoS guard | Medium | `ssh3-server` | No cap on unauthenticated conversations and no failed-attempt counter. |
| Secret URL path not enforced | Medium | `ssh3-h3` | The server accepts any URL path; the path is therefore not a secret. |
| Minimal server | Low | `ssh3-server` | Self-signed certificates only; no public certificate automation and no certificate pinning workflow. |

## Known advisories and accepted risks

The dependency audit of 2026-10 (stage M3 of [`ROADMAP.md`](ROADMAP.md))
reviewed the whole dependency graph with `cargo audit` and the RustSec
advisory database, and cleared the findings that had an upstream fix. The
remaining entries are the accepted risks; they are the same entries that the
blocking `cargo deny` gate of the CI workflow allows in
[`deny.toml`](deny.toml), with the same justification.

| Advisory | Crate | Status | Risk decision |
| --- | --- | --- | --- |
| RUSTSEC-2026-0185 | `quinn-proto` 0.11.14 | **Fixed** (0.11.19) | Remote memory exhaustion through unbounded out-of-order stream reassembly. Relevant to SSH3: the QUIC stack is the transport of every SSH3 session. |
| RUSTSEC-2026-0338 | `quinn-proto` 0.11.14 | **Fixed** (0.11.19) | A remote peer can panic `quinn-proto` with zero-length STREAM frames during unordered reads. |
| RUSTSEC-2026-0339 | `quinn-proto` 0.11.14 | **Fixed** (0.11.19) | Unbounded growth of the pending connection ID retirements. |
| RUSTSEC-2026-0340 | `quinn-proto` 0.11.14 | **Fixed** (0.11.19) | A peer can panic `quinn-proto` when `ACK_FREQUENCY` transmission is enabled. |
| RUSTSEC-2026-0342 | `quinn-proto` 0.11.14 | **Fixed** (0.11.19) | Zero-length DATAGRAM frames bypass the receive buffer limit. This is the core DATAGRAM path of SSH3 (UDP forwarding), the advisory was treated as release blocking. |
| RUSTSEC-2026-0346 | `rustls` 0.23.45 | **Fixed** (0.23.46) | The `Debug` implementations of the client session values expose TLS secrets. |
| RUSTSEC-2026-0347 | `rustls` 0.23.45 | **Fixed** (0.23.46) | Buffered application data is sent to the outer server after an ECH rejection. |
| RUSTSEC-2026-0348 | `rustls` 0.23.45 | **Fixed** (0.23.46) | Brotli certificate decompression can allocate up to 1 GiB before the authentication completes (pre-authentication). |
| RUSTSEC-2026-0349 | `rustls` 0.23.45 | **Fixed** (0.23.46) | An unauthenticated ServerHello can downgrade later connections to a classical key exchange. |
| RUSTSEC-2026-0381 | `webpki-roots` 1.0.6 | **Fixed** (1.0.10) | The bundled root certificates include distrusted emSign intermediates. |
| RUSTSEC-2026-0382 | `rustls-webpki` 0.103.15 | **Fixed** (0.103.16) | The certificate verification may accept distrusted intermediates. |
| RUSTSEC-2026-0383 | `webpki-root-certs` 1.0.6 | **Fixed** (1.0.10) | Same emSign intermediate issue in the transitive root store. |
| RUSTSEC-2026-0097 | `rand` 0.8.5 and 0.9.2 | **Fixed** (0.8.8 and 0.10.3) | `rand` is unsound when a custom logger uses `rand::rng()`; the unsound code needs the `log` feature together with a reentrancy in the logger. |
| RUSTSEC-2025-0134 | `rustls-pemfile` 2.2.0 | **Accepted** | The crate is unmaintained (the repository was archived in August 2025), not vulnerable. `ssh3-client` uses it for a single call (`rustls_pemfile::certs`). The migration to `rustls-pki-types` (>= 1.9, already in the graph) is prepared but needs a source change in `ssh3-client/src/lib.rs`, which was out of scope for the dependency update. |
| RUSTSEC-2026-0387 | `crypto-bigint` 0.5.5 | **Accepted** | Timing variability in the crate (fixed in 0.6, which `ecdsa` 0.16 does not reach yet). The workspace never decrypts RSA ciphertexts and the SSH3 threat model has no ECDSA-decryption primitive to attack; the crate is transient through `ecdsa`/`ssh-key`. Also recorded as accepted in `deny.toml` (the live audit of 2026-10-27 found the SECURITY.md list missing it). |
| RUSTSEC-2023-0071 (CVE-2023-49092) | `rsa` 0.9.10 | **Accepted** | The Marvin attack: a timing side channel on the RSA decryption primitive. There is **no fixed release** - the advisory covers every published version of the crate, so no `cargo update` can clear it. The crate is required for the RSA path of the SSH3 bearer-token authentication in `ssh3-auth` and is pulled in by `ssh-key` (feature `rsa`). The workspace only *signs* and *verifies* RSA keys and never decrypts an RSA ciphertext with a private key, so the vulnerable primitive is not reachable from the SSH3 threat model (an untrusted peer). The removal condition is to drop the `rsa` feature of `ssh-key` and replace the RSA bearer-token path, or to wait for a fixed upstream release. |
| (yanked) | `spin` 0.9.8 | **Fixed** (0.9.9) | The release was yanked upstream; the lock file now uses the re-released version. |

Two further facts belong to this list:

- The Rust part of the project was **frozen from 2026-10-13 until 2026-10-22**.
  The audit of 2026-10 was carried out during the frozen period and closed
  part of the findings; the remaining ones are listed in
  [`ROADMAP.md`](ROADMAP.md).
- The `h3` crate is overridden by a local shim (`vendor/h3`) that is not
  covered by the crates.io advisory database, because it is not the crates.io
  release. The shim is verified against the pristine upstream release by
  `scripts/verify-h3-shim.sh`, which the CI workflow runs as a blocking job.
  See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the rebasing procedure when
  `h3` is updated.

The dependency policy itself is enforced by `cargo deny` (`deny.toml`):
advisories, duplicate and forbidden crates, licenses and dependency sources
are checked, and only the two accepted risks above are allowed.

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

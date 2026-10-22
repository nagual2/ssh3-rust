# Contributing

Thanks for taking the time to contribute. This document describes how to work
in the **Rust** workspace of this repository.

> [!NOTE]
> The workspace was **frozen (dormant) from 2026-10-13 until 2026-10-22**;
> the freeze was lifted on 2026-10-22 (see [`FROZEN.md`](FROZEN.md)). Before
> starting work, check [`ROADMAP.md`](ROADMAP.md): the plan defines which
> items are open, which are deferred and what the unfreezing conditions are.

## Ground rules

1. **Tests first.** Every bug fix comes with a regression test that fails
   before the fix and passes after it. Every feature comes with tests that
   describe the expected behaviour, including the edge cases.
2. **One concern per commit.** Keep commits small, atomic and reviewable.
3. **Conventional Commits.** Commit subjects follow
   `type(scope): subject`, for example:
   - `feat(client): add --forward-agent flag`
   - `fix(core): clamp peer max_packet_size`
   - `docs(readme): describe the interop matrix`
   - `test(proto): cover oversized SSH string length`
   - `chore(deps): update quinn-proto to 0.11.19`
   Types in use: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`,
   `ci`, `chore`, `revert`.
4. **No new dependency without justification.** Registry sources only — no git
   dependencies. Explain why the existing dependencies are not sufficient in
   the commit message or the pull request. `Cargo.lock` must stay committed and
   in sync (`cargo check --workspace --locked`).
5. **Wire compatibility is a contract.** The Rust implementation must stay
   wire-compatible with the Go implementation. Never change the on-the-wire
   format, the message numbering or the authentication flows without an
   explicit decision recorded in [`ROADMAP.md`](ROADMAP.md) and in the Go
   repository.
6. **No telemetry, no network calls** outside the SSH3 protocol semantics.
7. **Secrets belong in files.** Prefer `--password-file`,
   `--bearer-token-file` and `--oidc-client-secret-file` over passing secrets
   in `argv`.

## Build

```bash
cargo build --workspace
cargo check --workspace --locked
```

Rust 1.85 or newer is required (the crates use edition 2024).

## Tests

```bash
cargo test --workspace          # the whole suite
cargo test -p ssh3-client       # adds the cross-implementation matrix
```

The suite contains 91 tests. The cross-implementation (interop) scenarios build
**real Go binaries** from the [nagual2/ssh3-go](https://github.com/nagual2/ssh3-go)
repository and need:

- a **Go toolchain** (1.26+ for the current releases of the Go repository),
- a **checkout of the Go repository** — the `SSH3_GO_REPO` environment variable
  points at that checkout, and the harness builds the Go peers from it. Pin the
  checkout to a **release tag** of the Go implementation: the matrix is verified
  against a concrete Go release (`v0.1.37` in the CI), not against `main`
  (see `M0.C.2` in [`ROADMAP.md`](ROADMAP.md)),
- a Unix-like host (the scenarios are `#[cfg(unix)]`).

The `vendor/h3` shim speaks the final HTTP/3 (RFC 9114) and interoperates
with the current `quic-go` line (v0.49.0 and later, v0.63.0 in the CI
reference). The HTTP/3 datagram setting must stay disabled on the Rust side:
the SSH3 datagrams travel over the QUIC datagram API, and a peer that
announces the HTTP/3 datagram support opens a second reader on the same
connection-wide datagram queue and steals them.

When the checkout or the toolchain is missing, every interop scenario is
**skipped** — each one prints a `skipping:` line to the test log — and the rest
of the suite still runs. A scenario never passes without having exercised the
wire: it either ran against the Go peers or it reported the skip.

When a change touches the wire format, the authentication flow, the channel
lifecycle, PTY handling or forwarding, the interop matrix is the mandatory
regression gate: run it in both directions (Rust → Go and Go → Rust).

## Do not touch

- **`vendor/h3`** — this is a deliberate `[patch.crates-io]` shim over the
  crates.io crate `h3` 0.0.8 that adds the `:protocol` pseudo-header support
  required by Extended CONNECT. Upstream `h3` does not provide it. Replacing
  the directory with the upstream crate breaks the SSH3 handshake. Any change
  here must be a minimal, clearly documented patch on top of the upstream
  version, and it must keep `vendor/h3/LICENSE` intact.
- **The wire format** — see ground rule 5.
- **`ROADMAP.md` and `FROZEN.md`** — they record owner decisions. Propose
  changes, do not rewrite them unilaterally.

## The `h3` shim

The workspace overrides the crates.io crate `h3` with a local path dependency:

```toml
[patch.crates-io]
h3 = { path = "vendor/h3" }
```

**Why the shim exists.** SSH3 uses HTTP/3 Extended CONNECT (RFC 8441) and
carries the value `ssh3` in the `:protocol` pseudo-header. Upstream `h3`
0.0.8 models that pseudo-header as a closed enumeration with exactly two
values, `webtransport` and `connect-udp`, so the SSH3 protocol token cannot
be expressed. The shim makes the token an open `Cow<'static, str>` value and
adjusts the one call site that relied on the type being `Copy`.

**Why the shim is checked.** A vendored directory that nobody can diff
against its upstream is a supply-chain blind spot: it could be edited, and
nothing would notice. The shim is therefore kept reproducible:

| Artefact | Purpose |
|---|---|
| `patches/h3-0.0.8.patch` | The two edits, as a unified diff against the pristine crates.io release. |
| `scripts/verify-h3-shim.sh` | Downloads the pristine `h3` 0.0.8 crate, checks its SHA-256, applies the patch and compares the result with `vendor/h3`. |
| CI job `shim` | Runs the script. A drift between `vendor/h3` and the patch fails the build. |

Run it locally before pushing:

```bash
./scripts/verify-h3-shim.sh
```

The script accepts `H3_CRATE=/path/to/h3-0.0.8.crate` when the download is not
wanted, and it falls back to the cargo registry cache on its own.

**Rebasing the shim onto a new `h3` release.** When `h3` is updated:

1. Download the new crate and unpack it into a scratch directory.
2. Apply `patches/h3-0.0.8.patch` to it. A clean apply means the upstream
   code did not move; a rejected hunk means the shim has to be **rebased**:
   port the three edits by hand to the new upstream sources.
3. Replace `vendor/h3` with the patched tree (keep `vendor/h3/LICENSE` and
   `vendor/h3/Cargo.toml.orig` intact).
4. Regenerate the patch against the new release and store it as
   `patches/h3-<version>.patch`; update `H3_VERSION` and `H3_SHA256` in
   `scripts/verify-h3-shim.sh`.
5. Update the `h3` version requirement in the workspace `Cargo.toml` files,
   the `[patch.crates-io]` entry in the root `Cargo.toml` and the
   `ignore` rule for `h3` in `.github/dependabot.yml`.
6. Re-run `./scripts/verify-h3-shim.sh` and the `interop` job: a new `h3`
   release may change the HTTP/3 wire behaviour, and the interop matrix
   against the Go implementation is the gate for that.

The gate also checks that the `h3` requirement of `ssh3-h3/Cargo.toml` and the
`h3` version resolved in `Cargo.lock` still match the recorded base, so a
dependency bump cannot silently move the base of the shim.

A new `h3` release only helps if it can carry an arbitrary `:protocol` value:
upstream `h3` still knows a closed set of protocols (`webtransport`,
`connect-udp`, `connect-ip`, `websocket`), so the shim stays as long as the
SSH3 `:protocol` value is `ssh3`. The published `h3-quinn` releases pin the
`h3` version they are built against, so the two crates move together.

## Continuous integration

The pipeline lives in `.github/workflows/ci.yml` and has seven jobs:

| Job | What it does |
|---|---|
| `build` | `cargo build --workspace --locked`, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| `test` | `cargo test --workspace --locked` without the Go checkout: the interop scenarios skip instead of failing |
| `cross-build` | `cargo check --workspace --locked` on `windows-latest` and `macos-latest`. **Known gap:** the workspace does not compile on Windows yet (`AgentForwardingSlot::socket_path()` is `#[cfg(unix)]` but is called unconditionally in `ssh3-server/src/session.rs`), so the job is `continue-on-error` for now. |
| `interop` | checks out the Go reference repository at the pinned tag `v0.1.37`, installs the Go toolchain and runs the matrix with `SSH3_GO_REPO` |
| `audit` | `cargo audit`; tolerant of a network outage (`continue-on-error`) |
| `deny` | **blocking** dependency policy gate: `cargo deny check` with the configuration in `deny.toml` (advisories, bans, licenses, sources) |
| `shim` | **blocking** check that `vendor/h3` still matches the pristine crates.io release plus `patches/h3-0.0.8.patch` |

The toolchain is pinned in `rust-toolchain.toml`, the formatter in `rustfmt.toml`
and the linter in `clippy.toml`.

The following rules apply:

- **A new dependency requires a CI update in the same change.** The CI job
  must build the workspace with `--locked`, run the test suite and — for
  dependency changes — run the interop job with the Go repository checkout.
- **A change to the wire format requires the interop job**, not only the unit
  tests.
- **Dependency updates must include the advisory scan** (`cargo-audit`) and
  the `deny` job. The accepted risks (the `rsa` Marvin advisory and the
  unmaintained `rustls-pemfile`) are listed with their justification in
  `deny.toml` and in [`SECURITY.md`](SECURITY.md); they must not be
  reintroduced silently and must not grow without a new decision.
- **Only crates.io is allowed as a source.** `deny.toml` denies unknown
  registries and git dependencies.
- **The interop job stays on a release tag of the Go repository** (`v0.1.37`).
  The Go side has moved `quic-go` from v0.40.1 to v0.63.0, and the `h3` 0.0.8
  shim of this workspace speaks the final HTTP/3 (RFC 9114), which is the
  dialect of the current `quic-go` line. The checkout must not float to
  `main`: the matrix is verified against a concrete release, and a moving
  reference turns a regression of this workspace into a moving target.

## Style

- Rust: `cargo fmt --all` and `cargo clippy --workspace --all-targets` must be
  clean. The formatter and the linter are configured in `rustfmt.toml` and
  `clippy.toml`; both are checked by the `build` job of the CI.
- Comments and documentation are written in **English**.
- Public API changes are documented with doc comments (`///`, `//!`); the
  `ssh3-proto` and `ssh3-core` crates still lack them, and filling that gap
  is tracked in the roadmap.

## License

Contributions are accepted under the Apache License 2.0, the license of this
repository. See [`NOTICE`](NOTICE) for the provenance of the imported code.

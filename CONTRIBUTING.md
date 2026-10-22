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

## Releasing

The releases of this repository are cut from the tags of `main`. The Rust line
is the second stack of the SSH3 family — the shipped product is the Go
implementation of [`nagual2/ssh3-go`](https://github.com/nagual2/ssh3-go) — so
every release of this repository is published as a **pre-release** until the
parity audit of [`ROADMAP.md`](ROADMAP.md) is closed. The promotion of a
pre-release to a full release is a manual act (see *Promoting a release*).

### 1. Prepare

| № | Step | What to do |
|---|---|---|
| 1 | Green `main` | The seven jobs of `.github/workflows/ci.yml` (`build`, `test`, `cross-build`, `interop`, `audit`, `deny`, `shim`) have to be green on the commit that is tagged. The `deny` job is the blocking dependency gate. |
| 2 | Version of the crates | The version of the tag has to match the version of `ssh3-client/Cargo.toml` and `ssh3-server/Cargo.toml`. The pipeline refuses a tag whose version differs from the version of the crates, so the versions are bumped in the preparation commit. |
| 3 | Changelog | The entries of the `Unreleased` section of [`CHANGELOG.md`](CHANGELOG.md) move under the version of the release. |
| 4 | Version of the workspace | The `[profile.release]` of the workspace (`Cargo.toml`) is the reproducible one; do not change it in a release commit. |

### 2. Tag

```bash
git tag -a v0.2.0 -m "ssh3-rust 0.2.0"
git push origin v0.2.0
```

The tag has to be an annotated tag of the form `vX.Y.Z` that points to a
commit of `main`; the pipeline rejects any other spelling and any tag that
does not exist in the repository. Deleting the tag and pushing it again is
the way to restart a release that failed before the publication.

### 3. What the pipeline does

`.github/workflows/release.yml` runs on the tag and publishes a pre-release
with the following jobs:

| Job | What it does | Output |
|---|---|---|
| `prepare` | Resolves the version and the commit time of the tag (`SOURCE_DATE_EPOCH`), checks the version against the crates | The version and the epoch for the other jobs |
| `build` | Builds the client and the server for the five targets of the matrix (linux x86_64 and aarch64, windows x86_64, macOS x86_64 and aarch64), checks the architecture of the binaries, runs `--version` and `--help` on the binaries of the native legs, generates the SBOM and builds the reproducible archive | One archive, one SBOM and one checksum file per target |
| `deb` | Builds the Debian package of the server from the published linux binaries (the unit of `packaging/ssh3-rust-server.service`, the environment file, the binary, the license and the README) | `ssh3-rust-server_<version>-1_<arch>.deb` for amd64 and arm64 |
| `verify` | Verifies the checksums, runs the published linux binaries, inspects the content of the Debian packages and the SBOMs | Nothing is published if a check fails |
| `attest` | Publishes the build provenance of the artifacts (Sigstore, keyless, GitHub OIDC) | The attestation of the release |
| `release` | Computes `checksums.txt` over every published file and publishes the release with `softprops/action-gh-release` | The GitHub release (a pre-release) |

The linux aarch64 artifacts are cross compiled on the x86_64 runner, the
macOS x86_64 artifacts are cross compiled on the arm64 runner.

### 4. What to expect from the CI

| № | Expectation | Reaction |
|---|---|---|
| 1 | The `build` job takes the longest (the fat LTO of the release profile) | Nothing, it is normal |
| 2 | The `prepare` job fails when the version of the tag does not match the version of the crates | Bump the versions of the crates, delete the tag, tag again |
| 3 | A cross leg fails when the toolchain of the target is not installed on the runner | The `build` job installs the cross toolchain; check the log of the leg before touching the pipeline |
| 4 | The release is published as a pre-release | This is the intended state of the Rust line |
| 5 | The first release of a new target combination is a rehearsal | Check the artifacts locally before announcing the release |

### 5. Signing and verification

The artifacts are not signed with a GPG key: the provenance is attested with
the keyless Sigstore flow of GitHub, so there is no key material in the
repository and no secret to rotate. The verification of a downloaded file is:

```bash
gh attestation verify ssh3-rust_0.2.0_linux_x86_64.tar.gz --repo nagual2/ssh3-rust
sha256sum --check checksums.txt
```

### 6. Rollback

| № | Situation | What to do |
|---|---|---|
| 1 | The pipeline failed before the publication | Fix the cause, delete the tag (`git push --delete origin v0.2.0`), tag again |
| 2 | The release is published, but a file is wrong | Delete the release and the tag, tag a new patch version (`v0.2.1`): a published release is not replaced, the tag stays in the history |
| 3 | The release is published and must not be visible | Mark the release as a draft in the GitHub UI (it disappears from the release page, the tag stays) |
| 4 | The Debian package is broken | Delete the `.deb` from the release, publish a new patch version; the packages that were already installed are updated with `apt install ./ssh3-rust-server_<version>-1_<arch>.deb` |

### Promoting a release

When the audit of the roadmap is closed, a pre-release is promoted in the
GitHub UI: *Edit release* → uncheck *Set as a pre-release* and drop the
"second stack" paragraph from the description. The pipeline itself always
publishes pre-releases.

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

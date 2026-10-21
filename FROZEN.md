# FROZEN — do not extend, do not fix the frozen findings

The Rust workspace was declared **frozen (dormant)** by the repository owner
on 2026-10-13. That decision still stands: as of 2026-10-21

- no bug report or audit finding in this directory is scheduled for a fix:
  the pass-5/pass-6 Rust findings (F-16, F-20, and the pass-6 F-19 client
  residual) are frozen together with the code;
- no new functionality is added — `ROADMAP.md` stages the work that would
  only start after an explicit unfreeze;
- audits: **skip this directory entirely**, do not spend budget on it.

## Update 2026-10-21 — the workspace became a standalone project

The Rust implementation was extracted from `nagual2/ssh3-go` into its own
repository (`nagual2/ssh3-rust`) with its history intact, and a CI pipeline
was added. The CI gates the tree — build, format, clippy, unit tests, and a
cross-implementation job against a pinned Go tag — but it does **not** turn
the code into an active product:

- nothing here is shipped in any release artifact; the Go implementation
  remains the only released product;
- the frozen findings stay frozen: CI must not be used to close them as
  part of unrelated work;
- the interop job pins the Go reference repository at tag `v0.1.12`, because
  the Go `main` branch has moved to quic-go v0.63.0, which the pinned
  `h3` 0.0.8 shim does not support (HTTP/3 `0x104`).

To unfreeze, the owner must say so explicitly: update this file and the
README banner, then re-run a fresh audit pass over the workspace first
(`ROADMAP.md`, stage M7.1).

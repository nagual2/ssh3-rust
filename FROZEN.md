# STATUS — the freeze was lifted on 2026-10-22

The Rust workspace was declared **frozen (dormant)** by the repository owner
on 2026-10-13, and it was extracted from `nagual2/ssh3-go` into this
repository on 2026-10-21. On **2026-10-22 the owner lifted the freeze**: the
goal is to bring this implementation to parity with the Go implementation
([nagual2/ssh3-go](https://github.com/nagual2/ssh3-go)), which remains the
shipped product today.

What the freeze had held back, and what is in scope again:

- the audit findings F-16 (the password hash compare short-circuits), F-19
  (the Rust client residual: a malformed datagram still ends the datagram
  reception) and F-20 (no channel budget, unbounded dangling datagram
  queues) are scheduled for a fix;
- the defects the first CI run exposed are scheduled for a fix: the missing
  limit on the SSH string length, the unclamped peer `max_packet_size`, the
  missing `permit-open` on the server, the missing timeouts, the agent
  socket removed together with the session;
- new functionality is allowed again, with the Go implementation as the
  behavioural reference.

What the freeze did not lift:

- **no release artifact yet.** The Go implementation stays the only shipped
  product until a fresh audit pass over this workspace is done and the
  release profile is in place (`ROADMAP.md`, stage M7.1);
- the protocol itself stays experimental.

The report of the audit the freeze required, and the plan that follows from
it, live in [`ROADMAP.md`](ROADMAP.md).

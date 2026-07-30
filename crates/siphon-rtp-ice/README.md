# siphon-rtp-ice

Pure-Rust ICE (RFC 8445) agent core for [siphon-rtp](https://github.com/siphon-project/siphon-rtp):
the candidate model, the RFC 8445 §5.1.2 priority and §5.1.1.3 foundation rules, and the RFC 8839
SDP grammar for `a=candidate` / `a=ice-options` / `a=end-of-candidates`.

Zero C, no `unsafe`, and **no I/O**: this crate never opens a socket, never spawns a task, and never
reads a clock. That is deliberate — it makes the RFC's behaviour testable against the specification
without a runtime or a network, and it keeps the engine free to execute the resulting actions on
whichever datapath backend it is running.

Today it ships the candidate layer. Candidate gathering, checklists, connectivity checks, nomination,
and consent freshness land on top of it as the full agent replaces the current ICE-lite posture; see
`docs/security-and-nat.md` §4 layer 4 in the parent repository.

## Scope note

UDP only. TCP candidates (RFC 6544) are out of scope — peers on TCP-only networks are served through
the engine's built-in TURN server instead.

## Licence

MIT.

# siphon-rtp-ice

Pure-Rust ICE (RFC 8445) agent core for [siphon-rtp](https://github.com/siphon-project/siphon-rtp):
the candidate model, the RFC 8445 §5.1.2 priority and §5.1.1.3 foundation rules, and the RFC 8839
SDP grammar for `a=candidate` / `a=ice-options` / `a=end-of-candidates`.

Zero C, no `unsafe`, and **no I/O**: this crate never opens a socket, never spawns a task, and never
reads a clock. That is deliberate — it makes the RFC's behaviour testable against the specification
without a runtime or a network, and it keeps the engine free to execute the resulting actions on
whichever datapath backend it is running.

It ships the full RFC 8445 agent: candidate gathering (`Gatherer` — host and server-reflexive
candidates), checklists and candidate pairs (`Checklist`), and connectivity checks with
peer-reflexive discovery, role-conflict resolution, and regular nomination (`IceAgent`).
Trickle-ICE (RFC 8838) is supported — a candidate learned after the offer/answer is paired and
checked as a triggered check. The engine wires the agent behind `--ice-full`; consent freshness
(RFC 7675) and ICE-restart detection (RFC 8445 §9) live in the engine on top of this crate. See
`docs/security-and-nat.md` §4 layer 4 in the parent repository.

## Scope note

UDP only. TCP candidates (RFC 6544) are out of scope — peers on TCP-only networks are served through
the engine's built-in TURN server instead.

## Licence

MIT.

# siphon-rtp examples

Runnable, end-to-end examples of the common ways to drive siphon-rtp. Each directory is
self-contained with its own README.

| Example | What it shows |
|---|---|
| [`proxy-media-anchor/`](proxy-media-anchor/) | A SIP proxy (Kamailio) anchoring media through siphon-rtp over the rtpengine **NG** protocol. Point the `rtpengine` module at `--ng` and the routing script is unchanged. |
| [`b2bua-transcode/`](b2bua-transcode/) | A B2BUA setting up a **VoLTE (AMR-WB) ↔ PSTN (G.711)** transcoding call over the native **JSON-over-TCP** control protocol. A ~90-line, dependency-free driver. |
| [`voice-ai/`](voice-ai/) | A **voice-AI** WebSocket media server for the RTP↔WebSocket bridge. Set `ws_uri` on an offer and the engine streams decoded PCM to your agent and encodes replies back to the caller. |

Prose walkthroughs of these live in the docs at
[rtp.siphon-sip.org](https://rtp.siphon-sip.org/): the [Cookbook](https://rtp.siphon-sip.org/cookbook/)
for the per-feature control exchanges, and [Migrating from rtpengine](https://rtp.siphon-sip.org/migrating-from-rtpengine/)
for the Kamailio/OpenSIPS cutover.

## The two control planes these use

- **Native JSON-over-TCP** (`--control`, default `127.0.0.1:8080`): length-prefixed JSON,
  request/response by `id`, async events. The richer surface (WebSocket bridge, conferencing, auth).
  Used by `b2bua-transcode` and `voice-ai`.
- **rtpengine NG/bencode** (`--ng`, off unless given): the rtpengine wire protocol, so existing
  Kamailio / OpenSIPS deployments switch with no signalling change. Used by `proxy-media-anchor`.

Both drive the same engine; you can mix them.

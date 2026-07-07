# Examples

Runnable, end-to-end examples of the common ways to drive siphon-rtp live in
[`examples/`](https://github.com/siphon-project/siphon-rtp/tree/main/examples) in the repo. Each is
self-contained with its own README. The Cookbook explains the per-feature control exchanges; these
are the "clone it and run it" versions.

## Proxy media anchor (Kamailio + NG)

A SIP proxy anchoring every call's media through siphon-rtp, so endpoints never see each other's
media address. Because siphon-rtp speaks the rtpengine NG protocol, it is a stock Kamailio
`rtpengine` setup with the socket pointed at `--ng`:

```
loadmodule "rtpengine.so"
modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:22222")
```

`rtpengine_manage()` becomes NG `offer` / `answer` / `delete`; the routing script is otherwise
unchanged. Full config + run notes:
[`examples/proxy-media-anchor/`](https://github.com/siphon-project/siphon-rtp/tree/main/examples/proxy-media-anchor).
See also [Migrating from rtpengine](../migrating-from-rtpengine.md).

## B2BUA transcode (VoLTE ↔ PSTN)

A back-to-back user agent bridging a VoLTE UE (AMR-WB) and a PSTN gateway (G.711 A-law), transcoded
per direction. A ~90-line, dependency-free Python driver speaks the native JSON control protocol:
`offer` A's SDP with `codec-transcode-PCMA`, `answer` B's PCMA, and the engine anchors + transcodes.
Needs a daemon built `--features amr`. Code + walkthrough:
[`examples/b2bua-transcode/`](https://github.com/siphon-project/siphon-rtp/tree/main/examples/b2bua-transcode).
See also [Transcoding](../cookbook/transcoding.md).

## Voice-AI (RTP ↔ WebSocket)

A voice-AI media server for the WebSocket bridge. Set `ws_uri` on a native-JSON offer and the engine
dials your server, streams decoded L16 PCM uplink, and encodes replies back to the caller. The
example server echoes the caller (proving the path) with a clearly marked hook where a real
STT → LLM → TTS agent goes:
[`examples/voice-ai/`](https://github.com/siphon-project/siphon-rtp/tree/main/examples/voice-ai).
See also [Voice-AI: the RTP↔WebSocket bridge](../cookbook/voice-ai.md).

## Which control plane

- **Native JSON-over-TCP** (`--control`) drives the b2bua-transcode and voice-ai examples: the richer
  surface (WebSocket bridge, conferencing, auth). See [Native JSON-over-TCP](../control/json.md).
- **rtpengine NG/bencode** (`--ng`) drives the proxy example: the drop-in for existing
  Kamailio / OpenSIPS deployments. See [rtpengine NG / bencode](../control/ng.md).

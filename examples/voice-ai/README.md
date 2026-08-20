# Voice-AI: RTP ↔ WebSocket bridge

`server.py` is a minimal WebSocket media server for siphon-rtp's voice-AI bridge. When a native-JSON
`offer` carries `ws_uri` in its profile, the engine dials the server, decodes the caller's RTP to
linear PCM and streams it uplink, and encodes PCM sent back down into RTP toward the caller. Your
agent never touches RTP, jitter buffers, or codecs.

## Run

```sh
pip install websockets
python3 server.py                     # ws://127.0.0.1:9001/stream
```

Then offer a call with `ws_uri` pointing at it. With a running daemon
(`siphon-rtp --control 127.0.0.1:8080`) and a SIP endpoint sending RTP, the control side is:

```json
{
  "id": 1, "command": "offer",
  "call_id": "call-7@198.51.100.2", "from_tag": "caller",
  "sdp": "v=0\r\n...\r\nm=audio 30000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
  "profile": { "ws_uri": "ws://127.0.0.1:9001/stream" }
}
```

This example **echoes** the caller back (you hear yourself with ~2 frames of delay), which proves the
full RTP → decode → WebSocket → encode → RTP path. The `Session.handle_audio` hook is where a real
agent runs speech-to-text, an LLM, and text-to-speech, sending the synthesized PCM back as binary
frames.

## The wire (what `server.py` implements)

- **Text frames**: a `{"type": ..., "data": ...}` JSON envelope (camelCase). The first is `start`,
  announcing `streamId` and the audio `media` format (`L16`, `sampleRate`, `ptime`, little-endian).
  `sampleRate` is the **negotiated wire rate and is authoritative** in both directions — read it from
  `start` (as `server.py` does) rather than assuming the codec's rate. It defaults to the leg's codec
  rate, but the `ws_sample_rate` profile flag sets it independently, so an 8 kHz G.711 call can be
  streamed at 16 kHz and the engine resamples both ways.
- **Binary frames**: one raw little-endian L16 mono PCM frame per ptime —
  `sampleRate / 1000 * ptime * 2` bytes, so 320 at 8 kHz / 20 ms and 640 at 16 kHz / 20 ms.
  Send binary frames back to play audio; no announcement needed.
- **Barge-in**: send `clear` to flush queued playout; the engine replies with a `mark` named
  `cleared`.
- **Close**: send `stop` (or close the socket); deleting the call also tears the bridge down.

`wss://` now ships (ring/rustls, webpki-roots); prefer it when the server isn't on a trusted
segment. The local `ws://` example URIs above stay as-is. Full protocol reference:
[docs/cookbook/voice-ai.md](../../docs/cookbook/voice-ai.md).

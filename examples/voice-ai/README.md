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
- **Binary frames**: one raw little-endian L16 mono PCM frame per ptime (320 bytes at 8 kHz / 20 ms).
  Send binary frames back to play audio; no announcement needed.
- **Barge-in**: send `clear` to flush queued playout; the engine replies with a `mark` named
  `cleared`.
- **Close**: send `stop` (or close the socket); deleting the call also tears the bridge down.

`ws://` only in v1 (`wss://` is a follow-up), so run the server on a trusted segment. Full protocol
reference: [docs/cookbook/voice-ai.md](../../docs/cookbook/voice-ai.md).

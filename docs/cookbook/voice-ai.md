# Voice-AI: the RTP↔WebSocket bridge

siphon-rtp can attach a call leg's audio to an external WebSocket media server, the pattern
voice-AI stacks use (mod_audio_stream / mod_audio_fork style). Set `ws_uri` in the profile of a
native-JSON `offer` and the engine dials that URI as a WebSocket client, decodes the caller's
RTP to linear PCM, streams it uplink, and encodes PCM coming back down into RTP toward the
caller. Your agent server never touches RTP, jitter buffers, or codecs; it reads and writes raw
PCM frames on a WebSocket.

Two things to be clear about up front:

- This is a native siphon-rtp extension. The `ws_uri` field exists only on the JSON-over-TCP
  control channel; the rtpengine NG/bencode front-end never sets it.
- Both `ws://` and `wss://` are dialled. `wss://` runs the TLS handshake on the pure-Rust
  ring/rustls stack (no OpenSSL, no C), validating the server against the built-in webpki-roots
  Mozilla CA bundle. Prefer `wss://` when the WS server is off the trusted segment.

Adapters for OpenAI Realtime, gRPC media streaming, and a direct WebRTC leg are planned, not
shipped. What ships today is the raw-PCM WebSocket wire described below.

## The offer

```json
{
  "id": 1,
  "command": "offer",
  "call_id": "call-7@198.51.100.2",
  "from_tag": "caller",
  "sdp": "v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=-\r\nc=IN IP4 198.51.100.10\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
  "profile": { "ws_uri": "ws://127.0.0.1:9001/stream" }
}
```

The reply is a normal offer reply (the rewritten SDP advertising the engine's media address).
Behind it the engine has already dialed the WebSocket; if the dial, the redirect install, or the
codec setup fails, the half-built call is torn down and the offer errors.

The bridged leg is leg A, the offerer, using A's negotiated primary codec. The WS server becomes
A's far side, so the normal A↔B relay/transcode path is deliberately not wired on this call: B's
ports may still be allocated by offer/answer, but B's media is not bridged. `ws_uri` arriving
first on the `answer` also works (the bridge is then stood up against A's stored codec and
address).

The ingress is gated like every other leg: only packets from A's signalled source (or its
`received_from` public IP, when the proxy supplies one) reach the bridge. See
[Security & NAT](../security-and-nat.md).

## The WebSocket wire

Text frames carry a small `{"type": ..., "data": ...}` JSON control envelope (camelCase fields);
binary frames carry raw audio. Audio stays off the JSON path entirely: no base64, one binary
frame per ptime.

The first frame the server receives is `start`, announcing the leg and the audio format:

```json
{
  "type": "start",
  "data": {
    "streamId": "ws-call-7@198.51.100.2",
    "callId": "call-7@198.51.100.2",
    "direction": "duplex",
    "media": {
      "encoding": "L16", "sampleRate": 8000, "channels": 1,
      "bitDepth": 16, "endianness": "little", "ptime": 20
    }
  }
}
```

`sampleRate` is the codec's native PCM rate: 8000 for a G.711 leg, 16000 for a G.722 leg (G.722
audio is 16 kHz even though its RTP clock is 8 kHz, RFC 3551 §4.5.2). `ptime` follows the
negotiated packet time, default 20 ms.

After `start`:

- **Uplink (call → server).** Every ptime tick, one binary frame of little-endian L16 mono PCM.
  At 8 kHz / 20 ms that is 320 bytes per frame. The engine has already jitter-buffered, decoded,
  and (on loss) concealed, so frames arrive on a steady clock.
- **Downlink (server → call).** Send binary frames of the same format. The engine queues them
  (bounded, 8 frames, drop-oldest: late audio is worthless) and renders one frame per tick,
  encoding to A's codec and packetizing with the engine's own SSRC and sequence numbers. Just
  start sending PCM; no announcement message is required.
- **Barge-in.** Send `clear` to flush anything still queued for playout; it takes effect within
  one tick and the engine replies with a `mark` named `cleared` so you can resynchronize turn
  boundaries:

  ```json
  { "type": "clear", "data": { "streamId": "ws-call-7@198.51.100.2", "reason": "barge_in" } }
  ```

- **Close.** Send `stop` (or just close the socket) and the bridge ends; deleting the call from
  the control channel tears the bridge and the WS connection down too.

One byte-order gotcha worth repeating: the WS wire is little-endian L16, while RTP L16
(RFC 3551) is big-endian. The engine byte-swaps at the RTP boundary; your server should treat
the WS side as plain host-order 16-bit samples and never see the difference.

The envelope also defines `play_start` / `play_stop` / `mark` / `dtmf` / `event` message types
for compatibility with the mod_audio_stream family. In v1 the engine honours `clear` and `stop`,
and rejects an inline (base64) `play_start` with an `error` message; downlink audio needs no
`play_start` at all, binary frames are enough.

## Turn-taking, barge-in, and echo control

Three optional profile flags move the turn-taking work into the engine so your inference server
does not have to run its own VAD or fight the phone's echo of the AI. All are native-JSON-only and
inert without `ws_uri`.

- **`ws_vad`** runs a local energy-VAD on the uplink and emits two text control frames on the
  caller's speech edges: `speech_started` when the caller starts talking and `speech_stopped` (the
  turn endpoint) after the trailing hangover. The server gets clean turn boundaries with no VAD of
  its own, which cuts turn latency.
- **`ws_barge_in`** adds engine-side barge-in: the moment the caller starts speaking, the bridge
  flushes the queued downlink playout in the same tick (no server round-trip) and sends
  `speech_started`. It implies `ws_vad`. This is the counterpart to the server-initiated `clear`
  above: `clear` is the server flushing on its own decision, `ws_barge_in` is the engine flushing
  the instant the caller talks over the AI.
- **`ws_vad_threshold`** (mean-square energy, higher is less sensitive, default ≈ 1_000_000) and
  **`ws_vad_hangover_ms`** (how long speech is held after energy drops before `speech_stopped`
  fires, default ≈ 200 ms) tune the local VAD. Both only matter with `ws_vad` / `ws_barge_in`.

- **`echo_cancellation`** cancels the phone's echo of the AI on the uplink toward the server: the
  bridge runs `siphon-rtp-dsp`'s echo canceller on the caller's uplink using the AI downlink (what
  the engine last sent toward the caller) as the far-end reference, at the codec's native 8 or
  16 kHz. This stops the AI hearing itself looped back through the caller's handset, which otherwise
  triggers false barge-ins and derails the model. A codec at another rate passes through
  uncancelled.

```json
{
  "id": 1,
  "command": "offer",
  "call_id": "call-7@198.51.100.2",
  "from_tag": "caller",
  "sdp": "...",
  "profile": {
    "ws_uri": "ws://127.0.0.1:9001/stream",
    "ws_vad": true,
    "ws_barge_in": true,
    "ws_vad_hangover_ms": 300,
    "echo_cancellation": true
  }
}
```

## A minimal server

An echo agent in Python (`pip install websockets`), enough to prove the path end to end:

```python
import asyncio, json, websockets

async def handle(ws):
    async for message in ws:
        if isinstance(message, bytes):
            await ws.send(message)          # echo PCM back into the call
        else:
            control = json.loads(message)
            if control["type"] == "start":
                print("stream", control["data"]["streamId"], control["data"]["media"])

async def main():
    async with websockets.serve(handle, "127.0.0.1", 9001):
        await asyncio.Future()

asyncio.run(main())
```

Offer with `ws_uri: "ws://127.0.0.1:9001/stream"`, send RTP at the engine's answered port, and
you hear yourself back with roughly one jitter-buffer frame plus one playout frame of delay.

## Limits on a WS-bridged call

The on-the-wire bytes of a WS call are not the clear two-party media, so several runtime verbs
are rejected on it: `block_media` / `silence_media`, `start_recording` (pcap), SIPREC
`subscribe_request`, and `block_dtmf`. HA `checkpoint` works but `restore` of a WS call is
rejected (the WS connection cannot be rebuilt from a snapshot yet). Latency is tuned for
voice-AI: a shallow jitter buffer (target one frame) and the bounded playout queue keep
mouth-to-ear delay low at the cost of a little more concealment under jitter.

## How to verify

- `tracing` logs the dial at offer time; a failed dial fails the offer with the reason.
- On the server, assert the first frame is `start` and that uplink binary frames are exactly
  `sampleRate / 1000 * ptime * 2` bytes.
- Send a known tone as downlink PCM and capture A's inbound RTP: the payload decodes to your
  tone, stamped with the engine's SSRC.
- `query` on the call still reports packet counters; `delete` ends both the call and the WS
  connection.

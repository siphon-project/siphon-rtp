# Voice-AI: the RTP↔WebSocket bridge

siphon-rtp can attach a call leg's audio to an external WebSocket media server, the pattern
voice-AI stacks use (mod_audio_stream / mod_audio_fork style). Set `ws_uri` in the profile of a
native-JSON `offer` and the engine dials that URI as a WebSocket client, decodes the caller's
RTP to linear PCM, streams it uplink, and encodes PCM coming back down into RTP toward the
caller. Your agent server never touches RTP, jitter buffers, or codecs; it reads and writes raw
PCM frames on a WebSocket.

There are **two** modes, and they are separate fields on purpose:

| Mode | Field | What it does |
|---|---|---|
| **Takeover** | `ws_uri` | The WS server *is* leg A's far side. Duplex. A↔B is not wired. Use it when the AI answers the call. |
| **Tee** | `ws_tee` / `attach_ws_tee` | A send-only stream riding a call that keeps relaying normally. Use it to listen to a live two-party call. |

A call may hold both — they attach at different points. Takeover is the rest of this page;
the tee has [its own section](#teeing-a-live-call-to-a-websocket) further down.

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

`sampleRate` is **the negotiated wire rate, and it is authoritative** — the rate of every binary
frame in *both* directions, for the whole life of the stream. Frame it against this number, not
against whatever codec you believe the call is using.

By default it is the codec's native PCM rate: 8000 for a G.711 leg, 16000 for a G.722 leg (G.722
audio is 16 kHz even though its RTP clock is 8 kHz, RFC 3551 §4.5.2). Set the `ws_sample_rate`
profile flag to choose it instead — see [Choosing the wire sample rate](#choosing-the-wire-sample-rate).
`ptime` follows the negotiated packet time, default 20 ms.

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

### Choosing the wire sample rate

The wire rate is **independent of the leg's codec rate**. `ws_sample_rate` on the takeover profile
picks it, and the engine resamples in both directions: leg → wire on the uplink, wire → leg on the
downlink before re-encoding. So an 8 kHz G.711 call can speak 16 kHz L16 to a model that wants
wideband input, and a server that renders 24 kHz TTS into that same call has it played back at the
right speed and pitch instead of the wrong one.

```json
{
  "command": "offer",
  "call_id": "call-7@198.51.100.2",
  "from_tag": "a1b2",
  "sdp": "v=0\r\n...",
  "profile": {
    "ws_uri": "ws://127.0.0.1:9001/stream",
    "ws_sample_rate": 16000
  }
}
```

- Valid rates are multiples of 1000 from 8000 to 48000. Anything else — 0, 44100, 96000 — is
  **rejected** on the offer/answer with a message naming the reason. The engine never silently
  clamps: a rate you did not ask for would drift against your clock with nothing to point at.
- Omit the flag for today's behaviour: the leg's own codec rate, and no conversion anywhere. Asking
  for the rate you already have is also free — no resampler is built.
- Uplink noise suppression (`noise_suppression`) and echo cancellation (`echo_cancellation`) run in
  the **wire** domain, because that is what the far side hears and it is the only placement that
  keeps the echo canceller's near-end and far-end reference in one rate. The suppressor exists only
  at 8 and 16 kHz, so another wire rate leaves it off (logged at `warn`) — the *feature* degrades,
  the negotiated rate does not change.
- The turn-taking VAD is unaffected: `ws_vad_threshold` is a **mean-square** (per-sample) energy, so
  it means the same thing at any rate, and `ws_vad_hangover_ms` is a duration in ptime frames.
- Conversion is not free: expect a few microseconds per 20 ms frame per engaged direction, paid only
  when the rates actually differ.

The envelope also defines `play_start` / `play_stop` / `mark` / `dtmf` / `event` message types
for compatibility with the mod_audio_stream family. In v1 the engine honours `clear` and `stop`,
and rejects an inline (base64) `play_start` with an `error` message; downlink audio needs no
`play_start` at all, binary frames are enough.

## Turn-taking, barge-in, and echo control

A handful of optional profile flags move the turn-taking work into the engine so your inference
server does not have to run its own VAD or fight the phone's echo of the AI. All are
native-JSON-only and inert without `ws_uri`.

- **`ws_vad`** runs a local VAD on the uplink and emits two text control frames on the caller's
  speech edges: `speech_started` when the caller starts talking and `speech_stopped` (the turn
  endpoint) when they stop. The server gets clean turn boundaries with no VAD of its own, which
  cuts turn latency.
- **`ws_barge_in`** adds engine-side barge-in: the moment the caller starts speaking, the bridge
  flushes the queued downlink playout in the same tick (no server round-trip) and sends
  `speech_started`. It implies `ws_vad`. This is the counterpart to the server-initiated `clear`
  above: `clear` is the server flushing on its own decision, `ws_barge_in` is the engine flushing
  the instant the caller talks over the AI.
- **`ws_vad_engine`** picks *which* detector runs — see the next section.
- **`ws_vad_min_speech_ms`** requires the uplink to read as speech **continuously** for that long
  before the speech-start edge fires. See [Not barging in on a cough](#not-barging-in-on-a-cough).
- **`ws_vad_threshold`** (mean-square energy, higher is less sensitive, default ≈ 1_000_000) and
  **`ws_vad_hangover_ms`** (how long speech is held after energy drops before `speech_stopped`
  fires, default ≈ 200 ms) tune the **energy** detector specifically.

### Choosing a detector

|  | `energy` (default) | `neural` |
|---|---|---|
| answers | "is something loud here" | "is what is here speech" |
| cost | ~30 ns per 20 ms frame | ~37 µs per 32 ms window, i.e. ~23 µs per 20 ms frame amortised (~0.1 % of one core per call) |
| turn-detect floor | one media frame | 32 ms + up to one media frame |
| tuning | `ws_vad_threshold`, `ws_vad_hangover_ms` | none needed |
| fires on hum / breathing / fan noise | yes | no |

`energy` is a threshold on frame energy. It is exact, free, and correct for what it claims, but as
a *turn* detector it interrupts on things that are not a turn: 50 Hz mains hum, a breath into a
close-talking handset and a cooling fan all clear an absolute energy threshold. Keep it where a
false turn start is harmless — mute detection, cheap talk-spurt marking, a call where nobody barges
in.

`neural` runs the Silero v5 network, hand-written in pure Rust and embedded in the binary (309 633
parameters, ~1.2 MB; **no** inference runtime, no shared library, no extra deployment artifact —
`siphon-rtp` stays one static binary). On synthetic hum and breathing at **four times** the default
energy threshold — signals the energy gate fires on throughout — it peaks at probability 0.07 and
0.35 respectively, well under the 0.5 speech threshold. Pick it for turn taking and barge-in with a
conversational agent.

Selecting a detector the engine cannot build for the leg **fails the offer** with a reason; it is
never silently downgraded to the energy gate, because a controller that asked for `neural` asked
for it precisely to stop barge-in firing on noise.

#### Framing and the latency floor

The network consumes exactly 512 samples at 16 kHz — **32 ms** — with 64 samples of context carried
from the previous window and its recurrent state carried across windows. That is the framing it was
trained on, so the engine does not re-window it to the 20 ms media tick: it accumulates frames and
fires the network on each completed window. A decision therefore describes audio that ended 32 ms
ago, plus up to one media frame of accumulation remainder — **32–52 ms at a 20 ms ptime** — before
`ws_vad_min_speech_ms` adds anything on top.

A leg that is not already at 16 kHz (every G.711 call) is resampled into the detector by the
engine's own polyphase resampler. Nothing is refused for its rate.

#### What it will not do: echo

A speech classifier cannot reject acoustic echo, because echo of speech *is* speech. Measured
against the reference on far-end speech through a room response, the network still calls it speech
down to about −36 dB of echo-return loss, and only goes quiet at −42 dB:

| echo-return loss | 0 dB | −12 dB | −24 dB | −30 dB | −36 dB | −42 dB |
|---|---|---|---|---|---|---|
| windows called speech (of 64) | 59 | 56 | 54 | 50 | 36 | 0 |

So on a loudspeaker or handsfree endpoint, **`echo_cancellation` is not optional under barge-in** —
it is what puts the residual below the detector, and neither detector can substitute for it.

### Not barging in on a cough

Both detectors have a *trailing* hold, so speech is not chopped up at its end. Neither has a
*leading* one by default: the speech-start edge fires on the very first frame that reads as speech,
which is what lets a cough, a door, a keyboard or one burst of echo interrupt the prompt.

**`ws_vad_min_speech_ms`** is that missing leading requirement — the uplink must read as speech for
that many milliseconds *continuously* before `speech_started` (and barge-in) fires; anything shorter
is discarded and the counter restarts. It is rounded up to whole ptime frames and it adds directly
to turn-start latency, so 60–120 ms is the useful range: long enough to swallow a transient, short
enough that a caller talking over the AI still feels heard. It works with either detector, and
pairing it with `neural` is the combination that makes barge-in feel right.

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
    "ws_vad_engine": "neural",
    "ws_vad_min_speech_ms": 100,
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
`subscribe_request`, `block_dtmf`, and `attach_ws_tee`. HA `checkpoint` works but `restore` of a
WS call is rejected (the WS connection cannot be rebuilt from a snapshot yet). Latency is tuned
for voice-AI: a shallow jitter buffer (target one frame) and the bounded playout queue keep
mouth-to-ear delay low at the cost of a little more concealment under jitter.

**A takeover call cannot be bridged to a second party in place.** A WS call's leg B ports are
allocated by offer/answer, which makes it look like a later `answer` might hand the caller to a
real party — it does not. `answer` short-circuits on a WS call and returns the rewritten SDP
without installing any A↔B path, so the caller's media keeps going to the WS server and leg B
receives nothing. Moving a WS-bridged caller onto a live second leg (keeping A's ports and SSRC
continuous so no re-INVITE is needed) is a distinct transition that is **not implemented**. Today
the way to hand the call away is a SIP-level transfer (REFER), which takes the call off this
engine's WS bridge entirely.

## Teeing a live call to a WebSocket

Takeover replaces leg A's far side. A **tee** does the opposite: the call relays (or transcodes)
exactly as it would have, and a *copy* of the decoded audio is streamed to a WebSocket server.
That is what you want for live transcription, supervisor monitoring, or real-time analytics on a
normal two-party call — the parties keep talking to each other, and the AI listens.

The tee attaches where SIPREC forking already attaches: the post-decode fan-out. One decode of
each stream feeds the peer, the recorder, any SIPREC subscription **and** the WebSocket. There is
no second jitter buffer and no second concealment decision, so the WS consumer hears exactly what
the call carried.

Attach it on a live call:

```json
{
  "id": 7,
  "command": "attach_ws_tee",
  "call_id": "call-7@198.51.100.2",
  "from_tag": "caller",
  "ws_uri": "ws://127.0.0.1:9002/tee",
  "direction": "both",
  "channels": 2
}
```

or declaratively at answer time with `"profile": { "ws_tee": "ws://127.0.0.1:9002/tee" }`, which
saves a round-trip. `detach_ws_tee` (same `call_id` / `from_tag`) stops it; it is idempotent, and
`delete` tears any tee down with the call.

- **`direction`** — `both` (default), `caller`, or `callee`. `caller` is the offerer's audio.
- **`channels`** — with `direction: both`, `2` interleaves the two legs as stereo L16 (channel 0
  caller, channel 1 callee) and `1` mixes them to mono with saturation. A single-leg tee is always
  mono. Stereo on one connection beats one socket per leg: you get speaker separation for free.

The wire is the same envelope as takeover, except `start` announces `"direction": "send"` and
carries the track labels (`inbound` / `outbound`). Audio flows one way only — a v1 tee never
injects into the call. The wire sample rate follows the *caller* leg's decoded PCM rate, and a
callee on a different codec is resampled into it, so a stereo frame is always one rate.

Two behaviours worth knowing before you build on it:

- **A silent leg produces no frames.** The tee is driven by decoded ingress packets, not a clock,
  so a muted or gapped leg simply emits nothing (unlike takeover, whose ticker emits silence). A
  stereo tee needs a frame from *both* legs before it can interleave one, so a one-sided
  conversation streams only as fast as the quieter side.
- **A slow consumer loses frames, never the call.** The queue between the media path and the
  socket is bounded and drops on overflow. The `siphon_rtp_ws_tee_frames_dropped_total` metric and
  the `frames_dropped` field on the `ws_tee_ended` event tell you when that happened; the call's
  own RTP is never delayed by a byte.

The controller sees two events: `ws_tee_started` (with the negotiated `channels` / `sampleRate`
and the `stream_id` matching the `start` frame) and `ws_tee_ended` with a `reason`
(`detached`, `server_closed`, `server_stopped`, `call_ended`, `transport_error`) plus the lifetime
frame counters — so a stream that dies is visible, not silent.

Attaching a tee to a plain in-kernel relay promotes it to the userspace media pipeline for the
tee's lifetime and demotes it again on detach. A tee cannot be attached to a takeover
(`ws_uri`) call — that call has no relay path to copy — or to an SRTP-bridge call, whose
`Redirect` path carries ciphertext without decoding. Like `ws_uri`, the tee is native-JSON only;
the NG/bencode front-end does not carry it.

## How to verify

- `tracing` logs the dial at offer time; a failed dial fails the offer with the reason.
- On the server, assert the first frame is `start` and that uplink binary frames are exactly
  `sampleRate / 1000 * ptime * 2` bytes, where `sampleRate` is the **negotiated wire rate** the
  `start` frame announced.
- **Wire rate.** As with takeover, the tee's rate is independent of the codec: pass `sample_rate` on
  `attach_ws_tee` (or `ws_tee_sample_rate` in the profile) and every tapped leg is resampled into it
  before framing, so a stereo tee over legs on two different codecs still produces one coherent
  stream. Same 8000–48000 band, same multiple-of-1000 rule, same rejection-rather-than-clamp
  posture. Omitted, the tee follows the tapped leg's own codec rate exactly as before. A tee is
  send-only, so only the uplink direction converts.
- Send a known tone as downlink PCM and capture A's inbound RTP: the payload decodes to your
  tone, stamped with the engine's SSRC.
- `query` on the call still reports packet counters; `delete` ends both the call and the WS
  connection.

# Recording & forking (SIPREC)

Three independent ways to get a call's media out of the engine:

1. **Runtime pcap recording**: `start_recording` / `stop_recording` with
   `format: "pcap"` (the default) writes the raw wire packets of a live call to
   a `.pcap` file on the engine host. Any codec, byte-for-byte, toggleable
   mid-call. This is rtpengine's `start recording` shape, and it is an *audit*
   artefact — nobody listens to a pcap.
2. **Runtime decoded recording**: the same verb with `format: "wav"` writes
   **decoded audio**, streamed to disk as it arrives, and completes with a
   `recording_finished` event naming the finished file. A *product* artefact:
   a voicemail message to be emailed, transcribed and played back. See
   [Recording a voicemail message](#recording-a-voicemail-message).
   `format: "ogg_opus"` records the same audio compressed, about an eighth of
   the size; see [Compressed recordings: Ogg Opus](#compressed-recordings-ogg-opus).
3. **SIPREC-style media forking**: `subscribe_request` / `subscribe_answer` /
   `unsubscribe` tees a leg's RTP in real time to a Session Recording Server
   (the media half of SIPREC, RFC 7866). The recorder is another RTP endpoint,
   not a file.

Both work on plain relays and on transcoding calls. Neither works on a plain
SRTP bridge or a WebSocket-bridged call (details below, the engine refuses
rather than recording ciphertext).

There is also a third, smaller thing: the `record_call` flag on the answer,
which records one decoded WAV per party from the answer on. Covered at the end.

## Runtime pcap recording

Start recording an established call. Native JSON:

```json
{"id": 10, "command": "start_recording",
 "call_id": "a84b4c76e66710@198.51.100.10", "from_tag": "as7d900e",
 "recording_dir": "/var/spool/siphon-rtp/recordings"}
```

NG (Kamailio's `rtpengine_start_recording()` sends `call-id` only; the
directory rides the `recording-dir` key):

```
command:       start recording
call-id:       a84b4c76e66710@198.51.100.10
recording-dir: /var/spool/siphon-rtp/recordings
```

Stop with `stop_recording` (NG `stop recording`), or let call teardown finalize
the file. `recording_dir` is mandatory on start; without it you get
`no recording directory (set recording-dir)`.

What you get: `{recording_dir}/{call_id}.pcap`, a classic libpcap file
(Ethernet linktype). Every accepted media datagram from both legs is appended
verbatim (RTP, plus RTCP where it is muxed on the RTP port per RFC 5761;
non-muxed RTCP relays on its own path and is not captured), wrapped in
synthetic Ethernet + IPv4/IPv6 + UDP headers built from the real observed
5-tuple (peer source, engine endpoint destination), so the standard dissector
chain applies and the two legs are distinguishable by address and SSRC
(RFC 3550 §5.1). The payload is never decoded or re-encoded, which is exactly
why it works for codecs the engine cannot transcode: an AMR-WB relay records
fine.

Mechanics worth knowing:

- A plain passthrough relay is promoted into the userspace pipeline for the
  duration of the recording (there is no tap on the fast path), re-enforcing
  the same source gate and symmetric latch, and demoted back when the last
  hold (recording, SIPREC subscription, DTMF block) is released.
- Capture is best-effort by design: a bounded queue (1024 packets, several
  seconds of telephony media) sits between the media path and the disk writer,
  and a stalled disk drops capture packets rather than backpressuring audio.
- A bad path fails at `start_recording` time, before anything is promoted.
- Packet timestamps are the datapath receive clock, a relative timeline. Fine
  for RTP timing analysis; do not expect wall-clock capture times.
- Only the packets the security layer *accepted* are recorded. Gated-out
  spoofed traffic never appears in the capture.

Rejected with an explicit error on: a plain SRTP bridge, a secure transcoding
call, and a WebSocket-bridged call (`recording a secure (SRTP) or
WebSocket-bridged call is not supported yet`). The wire bytes there are
ciphertext (or diverted to a WS server), not the media; decrypt-then-record is
a follow-up. DTLS-bridged calls are equally unrecordable today.

### Verify

```bash
tcpdump -r /var/spool/siphon-rtp/recordings/a84b4c76e66710@198.51.100.10.pcap -c 6
capinfos /var/spool/siphon-rtp/recordings/*.pcap
```

Open it in Wireshark, `Telephony > RTP > RTP Streams`: you should see one
stream per direction with sane sequence/timestamp progressions, and for G.711
the RTP player plays the audio directly. The engine logs
`pcap recording finalized` with the path when the file is closed.

## SIPREC media forking (subscribe)

The fork model (RFC 7866): your SIP layer holds the recording session (the SRC
dialog and RFC 7865 metadata toward the SRS); the engine supplies the media
streams. The split matters, siphon-rtp does not speak SIP. SIPhon (or
Kamailio) creates the SIPREC INVITE and drives these three verbs.

**The engine offers, the SRS answers.** `subscribe_request` takes no SDP; the
engine builds the offer itself. Sending SDP in the request (the SRS offering
to the engine) is explicitly rejected: `SDP-offer-from-subscriber is not
supported (the engine offers; send sdp: null)`.

Step 1, request the fork. Native JSON:

```json
{"id": 20, "command": "subscribe_request",
 "call_id": "a84b4c76e66710@198.51.100.10",
 "from_tags": ["as7d900e"]}
```

NG: `command: subscribe request` with `from-tag` (or a `from-tags` list). The
reply carries the engine's SDP offer and a `to_tag` naming the subscription:

```json
{"id": 20, "result": "ok",
 "sdp": "v=0\r\no=- 0 0 IN IP4 203.0.113.10\r\ns=siphon-rtp-siprec\r\nc=IN IP4 203.0.113.10\r\nt=0 0\r\nm=audio 40010 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendonly\r\n",
 "to_tag": "sub-4f2c9a1e"}
```

The offer advertises the tapped leg's *negotiated* codec (RFC 4566 §6) and
`a=sendonly` (RFC 3264 §5.1): the subscriber endpoint transmits only. The
engine installs no inbound flow on it, so the fork adds no RTPBleed surface.

Step 2, complete it with the SRS's answer. No media flows before this:

```json
{"id": 21, "command": "subscribe_answer",
 "call_id": "a84b4c76e66710@198.51.100.10",
 "from_tag": "as7d900e", "to_tag": "sub-4f2c9a1e",
 "sdp": "v=0\r\no=- 3 3 IN IP4 198.51.100.77\r\ns=-\r\nc=IN IP4 198.51.100.77\r\nt=0 0\r\nm=audio 12000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=recvonly\r\n"}
```

From that point every accepted ingress packet on each tapped leg is copied
byte-for-byte out the subscriber endpoint toward the SRS (RFC 7866 §6): RTP
and RFC 4733 telephone-events, plus RTCP where it is muxed on the RTP port, in
the leg's own codec, no re-encode. The tee is upstream of hold/mute/transcode
on the A-B path, so the SRS keeps recording a leg you have blocked toward its
peer.

Step 3, tear it down (also automatic on call teardown):

```json
{"id": 22, "command": "unsubscribe",
 "call_id": "a84b4c76e66710@198.51.100.10",
 "from_tag": "as7d900e", "to_tag": "sub-4f2c9a1e"}
```

Notes and limits, honestly:

- **Which legs**: `from_tags` picks the tapped legs; the call's to-tag means
  leg B, anything else (or an empty list) means leg A. Naming both legs taps
  both into the one subscription; the SRS receives the streams interleaved on
  the single endpoint, separable by SSRC. A mixed single-stream fork is a
  later feature. One codec is advertised in the offer (the first tapped
  leg's), so tap legs of different codecs with two subscriptions instead.
- **Any relayable codec works** because nothing is decoded: taps on an AMR-WB
  passthrough relay fork AMR-WB. Like recording, a plain relay is promoted to
  userspace while at least one subscription lives, then demoted.
- **Multiple concurrent subscriptions** per call are fine (each gets its own
  `to_tag` and endpoint).
- **Rejected on**: a plain SRTP bridge and a WebSocket-bridged call (`SIPREC
  on a secure (SRTP) or WebSocket-bridged call is not supported yet`). On a
  secure *transcoding* call the media actor already holds decrypted media, so
  a subscription there is accepted and the SRS receives clear RTP; the fork
  leg itself is plain `RTP/AVP` either way, so place the SRS accordingly.
- The subscriber endpoint binds the call's address family, so a v6 call is
  offered to the SRS as `c=IN IP6` (RFC 4566 §5.7).

### Verify

Watch the fork arrive at the SRS address from step 2:

```bash
tcpdump -n -i any udp port 12000 -c 10
```

You should see RTP from the engine's subscriber port (40010 above) toward the
SRS, with the tapped leg's payload type, and packet timing matching the live
call. Compare SSRCs against a capture of the call legs to confirm which leg is
which. `query` on the call keeps counting the primary legs; the fork does not
alter A-B media.

## The `record_call` answer flag (one WAV per party)

Setting `"record_call": true` (NG `record call: yes`) with `record_path` (NG
`recording-dir`) on the **answer** forces the call through the transcoding
pipeline and records each party's *decoded* audio as mono WAV at the codec's
native rate: `{record_path}/{call_id}-a.wav` (the offerer) and `-b.wav` (the
answerer). This is the shape a SIPREC recording server or a per-party
transcription wants.

Each party is an ordinary decoded recording, streamed to disk as the call runs
(bounded memory, nothing lost if the engine is stopped hard), written as
`{name}.partial` and renamed into place when the call ends. Each then ends
with its own `recording_finished`, with the predictable `recording_id`
`{call_id}-a` / `{call_id}-b`:

```json
{"event":"recording_finished","call_id":"call-7","from_tag":"tag-a","to_tag":"tag-b","recording_id":"call-7-a","path":"/var/spool/rec/call-7-a.wav","duration_ms":61240,"reason":"call_ended"}
{"event":"recording_finished","call_id":"call-7","from_tag":"tag-a","to_tag":"tag-b","recording_id":"call-7-b","duration_ms":0,"reason":"no_audio"}
```

Exactly one event per party, so a consumer never has to guess with a timeout:
`no_audio` means that party sent nothing and no file will appear. The streams
carry across a re-offer and its answer (hold, resume, a codec change), so a
call keeps one file per party however often it is renegotiated, and the
answer to the re-offer does not need to repeat the flag. `stop_recording`
with the id ends one party early. Because it decodes, it needs codecs the
engine can decode and encode (unlike the pcap and SIPREC paths), and it costs
a transcode session.

## See also

- [Secure media with SRTP](secure-srtp.md), including the exact table of which
  verbs are refused on secure calls and why.
- [Observability](../observability.md) for RTCP statistics, call-quality events,
  and HEP export, often the better tool when what you really want is quality
  metrics rather than payload.
- [Security & NAT](../security-and-nat.md) on why the fork endpoint is
  send-only and what "accepted ingress" means.


## Recording a voicemail message

A voicemail box answers the caller locally, plays a greeting and a beep, and
*then* records — which is the point of the runtime form: recording starts at a
moment you pick, not at answer.

```json
{
  "id": 40,
  "command": "start_recording",
  "call_id": "7f9a2b1c@198.51.100.20",
  "from_tag": "a7c31f",
  "format": "wav",
  "direction": "ingress",
  "max_duration_ms": 120000,
  "silence_ms": 4000,
  "path": "/var/spool/voicemail/7f9a2b1c.wav"
}
```

```json
{"id": 40, "result": "ok", "recording_id": "rec-1"}
```

`direction: "ingress"` is what the caller *sent* — the message. `max_duration_ms`
is the time limit the greeting announced, and `silence_ms` ends the message when
the caller stops talking; both are evaluated in the engine, where the decoded
audio already is, so neither costs the media path anything.

The message ends by whichever comes first, and the event says which:

```json
{
  "event": "recording_finished",
  "call_id": "7f9a2b1c@198.51.100.20",
  "from_tag": "a7c31f",
  "recording_id": "rec-1",
  "path": "/var/spool/voicemail/7f9a2b1c.wav",
  "duration_ms": 8740,
  "reason": "silence"
}
```

**Only attach the file when this event arrives.** It is emitted after the WAV
header has been finalized and the file flushed, so acting on it is the one way
to be sure you are not reading a half-written file. `reason` is `silence`,
`max_duration`, `stopped` (you sent `stop_recording`), `call_ended` (the caller
hung up — the *normal* way a message ends, and the file is complete and playable),
or `error`.

To end it yourself, name the recording so anything else on the call keeps running:

```json
{"id": 41, "command": "stop_recording", "call_id": "7f9a2b1c@198.51.100.20", "from_tag": "a7c31f", "recording_id": "rec-1"}
```

### What a decoded recording captures

| | |
|---|---|
| `direction` | `ingress` (default) = what the parties sent. `egress` = what the engine sent them (its prompts and announcements) — the only way to capture the engine's own audio on a single-leg call, where there is no second party whose ingress it would be. `both` = both: what the caller said and what the caller heard, which on a two-party call is the other party plus any prompt played to the caller. |
| `channels` | `mono` (default) sums the sources sample for sample; `stereo` puts the caller left and the other side right. A single source is mono whatever is asked (`egress` alone, or a single-leg call). |
| silence | A party that sends nothing (a hold, a phone that suppresses silence, a prompt that has ended) is recorded as silence. The other party is never held back by more than 160 ms and nothing it says is dropped to wait. |
| rate | The caller leg's decoded PCM rate — **not** its RTP clock, which for G.722 is half of it (RFC 3551 §4.5.2) and would replay the file at the wrong pitch. A second leg at another rate is resampled into it. |
| where | `path` names the file exactly; otherwise `recording_dir` plus a generated `{call_id}-{recording_id}.wav` (`.opus` for `ogg_opus`). A path that cannot be opened fails the verb immediately, with the call untouched. |

Unlike the pcap form, a decoded recording works on a **secure** call. On a
transcoded one it taps the audio after decryption and decode, so there is nothing
ciphered about it.

A secure *crypto bridge* (two legs on a shared codec, where the engine only
re-keys and never decodes) records too. The bridge holds each party's plaintext
between its two transforms, after the source gate and the SRTP authentication, and
the recording decodes a copy of that in a task of its own. The bridge keeps
relaying untouched: nothing is re-keyed, the call is not moved onto the media
path, and a recording and a WebSocket tee can sit on the same leg and be stopped
independently. Two things differ from a call on the media path:

- A bridge originates no audio, so what reaches one party is exactly what the
  other sent. `egress` is therefore the callee's stream, and `both` is each party
  once.
- Each packet is decoded as it arrives. There is no jitter buffer and no loss
  concealment in front of the file, so a lost packet is a gap rather than a
  concealed frame.

### Recording a call a voice bot has taken over

A call the engine answered and handed to a bot (`ws_uri` on `answer_local`, or
`attach_ws_bridge` on an engine-answered call) records with the same
`start_recording`. Nothing on the relay carries that audio, so the recording
taps the bridge session, which decodes the caller and renders the bot in one
place:

- **Caller (left):** the uplink as decoded, before the noise suppression, echo
  cancellation and turn-taking the bot is given. The file holds what the
  caller said, not the bot's input.
- **Bot (right):** the downlink as rendered toward the caller, resampled from
  the WS wire rate into the caller leg's. A frame flushed by a barge-in was
  never played, so it is not recorded.

```json
{"cmd":"start_recording","call_id":"call-7","from_tag":"tag-a","format":"ogg_opus","direction":"both","channels":"stereo"}
```

A bot that displaced one party of a **relayed** two-party call refuses it
(`recording-needs-an-anchored-takeover`): handing that leg back restores an
in-kernel relay, which has no decoded audio to carry the recording on.

### Compressed recordings: Ogg Opus

A WAV is the right file for a voicemail box on the same node, and the wrong one for
a call recording that has to leave it. Its size is fixed by the format: 16 kB/s per
channel at 8 kHz, 32 kB/s at 16 kHz.

| one hour | mono | stereo | stereo, base64 |
|---|--:|--:|--:|
| `wav`, 8 kHz | 57.6 MB | 115 MB | 154 MB |
| `wav`, 16 kHz | 115 MB | 230 MB | 307 MB |
| `ogg_opus`, default bitrate | ~7.5 MB | ~14.7 MB | ~19.6 MB |

A collector behind a proxy that caps request bodies at 100 MB cannot take a stereo
8 kHz WAV much past half an hour. Ask for `ogg_opus` instead:

```json
{
  "id": 42,
  "command": "start_recording",
  "call_id": "7f9a2b1c@198.51.100.20",
  "from_tag": "a7c31f",
  "format": "ogg_opus",
  "channels": "stereo",
  "recording_dir": "/var/spool/siphon-rtp/recordings"
}
```

Everything else is the `wav` recording: the same taps, `direction`, `channels`,
`max_duration_ms`, `silence_ms` and `path`, the same `recording_id`, and the same
`recording_finished` once the file is closed. The limits are measured on the
decoded audio before it is encoded, so `duration_ms` means the same thing in both
formats, and the file decodes to exactly that much audio.

The file is Ogg Opus (RFC 7845), mapping family 0, so anything that plays `.opus`
plays it: `opusdec`, ffmpeg, browsers, and the transcription services that take
Ogg Opus. Encoder settings are fixed, apart from the bitrate:

| | |
|---|---|
| `bitrate_bps` | Optional. Default 16 000 per channel (16 kbit/s mono, 32 kbit/s stereo), transparent for narrowband speech and comfortable for wideband. Accepted range 6 000 to 510 000 (RFC 6716 §2.1.1), exported as `RECORDING_OPUS_BITRATE_BPS_MIN` / `_MAX` from `siphon-rtp-proto`. Outside it, or given with `wav` or `pcap`, the verb fails rather than clamping or ignoring it. |
| rate | The recording's rate, chosen exactly as for `wav`, and declared as the file's input rate. Opus takes 8, 12, 16, 24 and 48 kHz. Anything else (an `L16/11025` leg, say) fails the verb rather than being resampled behind your back. |
| frames | 20 ms, VBR, voice-tuned. |
| FEC, DTX | **Off.** In-band FEC spends bits protecting against packet loss a file never has. DTX packets decode as gaps, and would tie the file's timing to the encoder's speech decision instead of to the audio recorded. |
| metadata | The vendor string only. No Call-ID or tag goes into a file that may travel; you have them from the event. |

**Stereo at the default bitrate is not fully separated.** Opus codes stereo jointly,
and at 16 kbit/s per channel the difference between the channels gets few bits, so
each party is audible in the other's channel at roughly 30 dB down (measured on test
tones through G.711; the reference libopus encoder does the same or worse). Fine for
listening and for most transcription. If you separate speakers by channel and need
the other party gone, raise `bitrate_bps`: about 40 dB at 64 000, over 80 dB at
128 000.

**An interrupted writer still leaves a playable file.** Pages of about one second
each are written and flushed as they complete, and each decodes on its own. If the
engine dies mid-recording, the file plays up to the last whole second; it only lacks
the end-of-stream flag. As with WAV, act on `recording_finished` and you never see
that case.

**Before you send it, check the engine has it.** `node_info` lists
`record_ogg_opus` in `features`. An engine from before the format cannot parse
`"ogg_opus"`, and refuses the whole control frame: no recording is started (it does
not fall back to `pcap`), but it closes the control connection instead of answering
with an error.

Cost is an Opus encode per 20 ms, in the recording's own task, off the media path.
See [Capacity](../capacity.md#recording-to-ogg-opus) for the numbers.

### Why not the `record_call` offer flag

`record_call` writes decoded WAV too, but it starts at the answer rather than
at a point in the call you choose, it records one file per party rather than
the caller alone, and it needs two legs (it never reaches an `answer_local`
call at all). A voicemail needs the runtime form.

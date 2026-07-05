# Recording & forking (SIPREC)

Two independent ways to get a call's media out of the engine:

1. **Runtime pcap recording**: `start_recording` / `stop_recording` writes the
   raw wire packets of a live call to a `.pcap` file on the engine host. Any
   codec, byte-for-byte, toggleable mid-call. This is rtpengine's
   `start recording` shape.
2. **SIPREC-style media forking**: `subscribe_request` / `subscribe_answer` /
   `unsubscribe` tees a leg's RTP in real time to a Session Recording Server
   (the media half of SIPREC, RFC 7866). The recorder is another RTP endpoint,
   not a file.

Both work on plain relays and on transcoding calls. Neither works on a plain
SRTP bridge or a WebSocket-bridged call (details below, the engine refuses
rather than recording ciphertext).

There is also a third, smaller thing: the `record_call` flag on offer/answer,
which writes decoded WAV audio. Covered at the end.

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

## The `record_call` offer flag (decoded WAV)

For completeness: setting `"record_call": true` (NG `record call: yes`) with
`record_path` (NG `recording-dir`) on the **answer** forces the call through
the transcoding pipeline and writes each direction's *decoded* audio as mono
WAV at the codec's native rate, `{record_path}/{call_id}-a.wav` and `-b.wav`,
when the call ends. Because it decodes, it needs codecs the engine can decode
and encode (unlike the pcap and SIPREC paths), and it costs a transcode
session. Prefer `start_recording` unless you specifically want ready-to-play
decoded audio.

## See also

- [Secure media with SRTP](secure-srtp.md), including the exact table of which
  verbs are refused on secure calls and why.
- [Observability](../observability.md) for RTCP statistics, call-quality events,
  and HEP export, often the better tool when what you really want is quality
  metrics rather than payload.
- [Security & NAT](../security-and-nat.md) on why the fork endpoint is
  send-only and what "accepted ingress" means.

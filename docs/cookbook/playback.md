# Announcements, ringback and hold music

Everything a call has to *say*: an announcement over the top of a leg, a call-progress tone
mixed underneath it, a music bed that ducks when the announcement starts. One verb,
`play_media`, in two modes.

- [Supersede or overlay](#supersede-or-overlay)
- [Playing an announcement](#playing-an-announcement)
- [Ringback while a leg rings](#ringback-while-a-leg-rings)
- [Hold music, ducked under a prompt](#hold-music-ducked-under-a-prompt)
- [Where the audio comes from](#where-the-audio-comes-from)
- [Tone presets and cadences](#tone-presets-and-cadences)
- [Fetching a prompt over HTTP](#fetching-a-prompt-over-http)
- [What to verify](#what-to-verify)

---

## Supersede or overlay

`play_media` accepts immediately with a `play_id` and reports the end asynchronously as a
`play_finished` event carrying that same id. What differs is where the audio goes:

| Mode | Field | What the party hears |
|---|---|---|
| **Supersede** (default) | — | The playback *replaces* the leg's egress. One at a time: starting another reports the first as `superseded`. |
| **Overlay** | `"overlay": true` | The playback is *mixed under* whatever the egress already carries. Up to four at once, each with its own `play_id`. |

The rule of thumb: an announcement the party must hear clearly supersedes; anything that
should sit *behind* something else — ringback, hold music, a background bed — overlays.

An overlay supersedes nothing, including other overlays, so a bed and a prompt coexist
without either one having to know about the other.

Both modes need a **media-processing** call. An offer-only single-leg call, or a plain
in-kernel relay, is promoted into one by `play_media` itself; there is nothing to configure.

## Playing an announcement

The classic: answer locally, say something, then act on the completion.

```json
{
  "id": 10,
  "command": "play_media",
  "call_id": "7f9a2b1c@198.51.100.20",
  "from_tag": "a7c31f",
  "source": {"source": "file", "path": "/var/lib/siphon-rtp/prompts/welcome.wav"}
}
```

```json
{"id": 10, "result": "ok", "play_id": 7, "duration_ms": 3400}
```

```json
{
  "event": "play_finished",
  "call_id": "7f9a2b1c@198.51.100.20",
  "from_tag": "a7c31f",
  "play_id": 7,
  "reason": "completed",
  "played_ms": 3400
}
```

Only `completed` means it played out in full. `stopped`, `superseded` and `error` all
resolve an await as *not* completed, so a script never runs its next step on a prompt that
never finished.

## Ringback while a leg rings

The case the overlay mode exists for. Party A is connected and B has not answered, so there
is no audio flowing toward A at all — a playback that only mixed into a live stream would be
inaudible. An overlay carries the egress itself when nothing else is producing it.

```json
{
  "id": 20,
  "command": "play_media",
  "call_id": "7f9a2b1c@198.51.100.20",
  "from_tag": "a7c31f",
  "source": {"source": "tone", "tone": "ringback_eu"},
  "overlay": true
}
```

```json
{"id": 20, "result": "ok", "play_id": 41}
```

No `duration_ms` in the accept: a call-progress preset repeats forever, so there is no
finite length to report. Stop it when B answers:

```json
{"id": 21, "command": "stop_media", "call_id": "7f9a2b1c@198.51.100.20", "from_tag": "a7c31f", "play_id": 41}
```

Or cap it up front, if you would rather the engine ended it than remembered to:

```json
{
  "id": 20,
  "command": "play_media",
  "call_id": "7f9a2b1c@198.51.100.20",
  "from_tag": "a7c31f",
  "source": {"source": "tone", "tone": "ringback_eu"},
  "overlay": true,
  "duration_ms": 60000
}
```

`duration_ms` is a hard playout cap on either mode. When it expires the playback reports
`completed`, the same as draining naturally.

Once B answers and audio starts flowing, an overlay that is still running rides that live
stream instead — one overlay frame per emitted egress frame, so it neither doubles the
packet rate nor plays fast. There is no handover to manage.

## Hold music, ducked under a prompt

Two playbacks on one leg, at two levels, ended independently.

Start the bed quietly:

```json
{
  "id": 30,
  "command": "play_media",
  "call_id": "7f9a2b1c@198.51.100.20",
  "from_tag": "a7c31f",
  "source": {"source": "file", "path": "/var/lib/siphon-rtp/prompts/hold.wav"},
  "overlay": true,
  "repeat_times": 0,
  "gain_decibels": -12
}
```

```json
{"id": 30, "result": "ok", "play_id": 50, "duration_ms": 45000}
```

Duck it and talk over it:

```json
{"id": 31, "command": "set_play_gain", "call_id": "7f9a2b1c@198.51.100.20", "from_tag": "a7c31f", "play_id": 50, "gain_decibels": -24}
```

```json
{
  "id": 32,
  "command": "play_media",
  "call_id": "7f9a2b1c@198.51.100.20",
  "from_tag": "a7c31f",
  "source": {"source": "file", "path": "/var/lib/siphon-rtp/prompts/still-holding.wav"}
}
```

The announcement is a *superseding* play, so it takes over the egress — and the bed, being
an overlay, keeps mixing underneath it. When the announcement reports `completed`, lift the
bed back:

```json
{"id": 33, "command": "set_play_gain", "call_id": "7f9a2b1c@198.51.100.20", "from_tag": "a7c31f", "play_id": 50, "gain_decibels": -12}
```

`gain_decibels` is whole decibels, −60 … +12, clamped. It applies at start on either mode
and `set_play_gain` changes it in flight. The mix saturates, so a boosted playback over loud
audio clips rather than wrapping — but at sane levels a −12 dB bed under speech has ample
headroom.

**Four overlay slots per direction.** A fifth start is an error naming the cap, and the four
already running are untouched:

```json
{"id": 34, "result": "error", "reason": "play_media: overlay: no free overlay slot (limit 4)"}
```

That is a deliberate choice over silently displacing one: a controller that loses a playback
it believes is running has no way to notice.

## Where the audio comes from

| Source | Use it for |
|---|---|
| `{"source": "file", "path": "…"}` | Prompts provisioned on the engine host. |
| `{"source": "blob", "data": […]}` | Small, dynamic prompts the controller already holds. |
| `{"source": "tone", "tone": "…"}` | Call-progress audio with no files to ship. |
| `{"source": "http", "url": "…"}` | Prompts held centrally, fetched by the engine. |

Recorded audio is 16-bit linear PCM WAV at any rate and channel count; it is downmixed to
mono and resampled onto the leg's codec rate. A tone is synthesised **at** the leg's rate,
so it never resamples.

`repeat_times` (`0`/`1` = once) and `start_pos_ms` apply to recorded audio; a tone's
repetition is part of its cadence.

## Tone presets and cadences

Fourteen presets, each with the standard its frequencies and cadence come from — the full
table is in [the JSON control reference](../control/json.md#tones). In short:

- `ringback_eu` / `busy_eu` / `congestion_eu` / `dial_eu` / `call_waiting_eu` — the 425 Hz
  European set (ETSI ETR 187; 425 Hz per ITU-T E.180/Q.35).
- `ringback_na` / `busy_na` / `congestion_na` / `dial_na` / `call_waiting_na` — North
  American (Telcordia GR-506-CORE; ITU-T E.180 Supplement 2).
- `ringback_uk` / `busy_uk` / `congestion_uk` / `dial_uk` — United Kingdom (ITU-T E.180
  Supplement 2).

For anything the table does not cover, write the cadence out:

```json
{"source": "tone", "tone": "425/1000,0/4000*inf"}
```

`frequency[+frequency]/duration_ms`, comma-separated segments, `*count` or `*inf` for the
repeat. `0` alone is silence. So `440+480/2000,0/4000*3` is a dual-frequency burst three
times, and `425/1000*inf` is a continuous 425 Hz tone. A malformed spec is a control error
naming the offending segment — it never starts a playback.

## Fetching a prompt over HTTP

Keep prompts in one place and let the engine pull them:

```json
{
  "id": 40,
  "command": "play_media",
  "call_id": "7f9a2b1c@198.51.100.20",
  "from_tag": "a7c31f",
  "source": {"source": "http", "url": "https://prompts.internal.example/welcome.wav"}
}
```

```json
{"id": 40, "result": "ok", "play_id": 60}
```

The accept carries **no `duration_ms`** — the length is not known until the body arrives.
The fetch runs on its own task: it never touches the media path, and a slow server does not
stall the control connection. Every failure (timeout, bad status, oversized body, non-WAV
bytes) resolves the playback as an error, and the leg keeps relaying:

```json
{
  "event": "play_finished",
  "call_id": "7f9a2b1c@198.51.100.20",
  "from_tag": "a7c31f",
  "play_id": 60,
  "reason": "error",
  "played_ms": 0
}
```

A `stop_media` in the window between the accept and the body cancels the fetch, so a
playback you stopped never starts a second later.

Defaults: 2 s connect, 5 s to first byte, 15 s overall, 8 MiB body, 3 redirects — all
tunable with `--media-fetch-*` or the TOML equivalents.

!!! warning "The engine fetches from its own network position"
    Only `http` and `https` are accepted, and every redirect hop is re-validated against
    that rule, so an open redirect cannot walk the fetch onto `file:` or off the allow-list.
    But with no `--media-fetch-allow-host` the engine will fetch **any host it can route
    to** — an SSRF surface bounded only by that scheme rule. Set the allow-list, put the
    engine behind an egress policy, or leave the URL source unused if the control plane is
    not fully trusted. See [the security note](../control/json.md#playback-from-a-url).

## What to verify

- **The party hears it.** A pcap on the leg's engine port shows one RTP stream at the
  negotiated ptime with continuous sequence numbers — an overlay never adds a second stream
  or a second SSRC, whether it is riding live audio or carrying the egress alone.
- **Each playback reports itself.** Four overlays ending give four `play_finished` events,
  one per `play_id`. If you are awaiting a specific prompt, match on the id from its accept.
- **Nothing is left running.** `stop_media` with no `play_id` ends everything on the call —
  the superseding prompt, any DTMF burst and every overlay — and each reports `stopped`.
  Call teardown does the same with reason `error`, so no controller is left awaiting a
  completion that will never come.
- **A blocked leg stays silent.** `block_media` drops the direction's egress entirely; an
  overlay is not a way around it.

## See also

- [Native JSON control protocol](../control/json.md#media-control) — the full field
  reference, the preset table with citations, and the cadence grammar.
- [Voice-AI streaming](voice-ai.md) — when the audio should come from a WebSocket server
  rather than a file.
- [Conferencing](conferencing.md) — playback into a room rather than a leg.

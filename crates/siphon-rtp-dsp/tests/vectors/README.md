# Neural VAD conformance vectors

Reference data for `tests/neural_vad_conformance.rs`. Each case is a pair:

* `<name>.pcm` — raw signed 16-bit little-endian mono PCM at 16 kHz, a whole number of
  512-sample windows, no header.
* `<name>.f32` — one little-endian `f32` per window: the speech probability the **reference**
  implementation produced for that window, with the LSTM state carried across the file.

The reference is `onnxruntime` running the published Silero VAD v5 ONNX (`snakers4/silero-vad`
tag `v5.1.2`). It ran once, out of tree; it is not a build or test dependency. `reference/silero-vad/`
holds the scripts, the hashes, and how to regenerate all of this.

Unlike the codec reference vectors under `reference/`, these are **committed and must ship** — they
are the acceptance criteria for a detector that is compiled into the binary, and they are
redistributable (MIT). Attribution is in `THIRD-PARTY-NOTICES.md`.

| case | windows | what it is | reference verdict |
|---|---|---|---|
| `neural_vad_speech` | 937 | 30 s of the upstream test recording — the decision-agreement corpus | 738 windows speech |
| `neural_vad_hum` | 64 | 50 Hz mains hum + 2nd/3rd harmonics at 4× the engine's default energy threshold | no speech (max p 0.066) |
| `neural_vad_breath` | 64 | low-passed noise in slow bursts, same energy budget | no speech (max p 0.347) |
| `neural_vad_echo_residual` | 64 | far-end speech through a room response, then ~42 dB echo-return loss | no speech (max p 0.246) |
| `neural_vad_echo_coupled` | 64 | the same echo path at the near-end talker's level | 59 windows speech — echo of speech *is* speech; the canceller has to remove it, the detector cannot |
| `neural_vad_onset` | 130 | 1.6 s of a quiet room, then speech from window 50 | first speech window is exactly 50 |

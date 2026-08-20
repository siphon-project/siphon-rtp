"""Generate the committed conformance vectors for the pure-Rust neural VAD port.

The oracle is `onnxruntime` running the published Silero VAD v5 ONNX.  It runs ONCE, here,
out of tree; the siphon-rtp build never sees onnxruntime, onnx, numpy or Python.  What ships
is the raw i16 PCM of each case plus the reference speech probability per 512-sample window.
"""

import hashlib
import os
import wave

import numpy as np
import onnxruntime as ort

WINDOW = 512
CONTEXT = 64
RATE = 16000
OUT_DIR = "vectors"

session = ort.InferenceSession("silero_vad_v5.1.2.onnx", providers=["CPUExecutionProvider"])


def reference_probabilities(pcm):
    """Speech probability per full 512-sample window, LSTM state carried, context prepended."""
    state = np.zeros((2, 1, 128), dtype=np.float32)
    context = np.zeros(CONTEXT, dtype=np.float32)
    out = []
    for start in range(0, len(pcm) - WINDOW + 1, WINDOW):
        chunk = pcm[start : start + WINDOW].astype(np.float32) / 32768.0
        model_input = np.concatenate([context, chunk])[None, :].astype(np.float32)
        probability, state = session.run(
            None, {"input": model_input, "state": state, "sr": np.array(RATE, dtype=np.int64)}
        )
        out.append(float(probability[0, 0]))
        context = chunk[-CONTEXT:].copy()
    return np.asarray(out, dtype=np.float32)


def write_case(name, pcm):
    pcm = np.asarray(pcm, dtype=np.int16)
    assert len(pcm) % WINDOW == 0, (name, len(pcm))
    probabilities = reference_probabilities(pcm)
    pcm_path = os.path.join(OUT_DIR, f"{name}.pcm")
    probability_path = os.path.join(OUT_DIR, f"{name}.f32")
    pcm.astype("<i2").tofile(pcm_path)
    probabilities.astype("<f4").tofile(probability_path)
    energy = (pcm.astype(np.float64) ** 2).mean()
    speech_windows = int((probabilities >= 0.5).sum())
    print(
        f"{name:22s} samples={len(pcm):7d} windows={len(probabilities):5d} "
        f"mean_square_energy={energy:12.0f} p>=0.5:{speech_windows:5d} "
        f"min={probabilities.min():.4f} max={probabilities.max():.4f}"
    )
    print(f"    {pcm_path} sha256={file_hash(pcm_path)}")
    print(f"    {probability_path} sha256={file_hash(probability_path)}")
    return probabilities


def file_hash(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def lcg_noise(count, seed):
    """Deterministic uniform noise in [-1, 1) from a 32-bit LCG (no numpy RNG version drift)."""
    value = np.uint32(seed)
    out = np.empty(count, dtype=np.float64)
    for index in range(count):
        value = np.uint32((np.uint64(value) * np.uint64(1664525) + np.uint64(1013904223)) & 0xFFFFFFFF)
        out[index] = (float(value >> np.uint32(8)) / 8388608.0) - 1.0
    return out


def biquad_lowpass(signal, cutoff, rate=RATE, q=0.707):
    """RBJ cookbook low-pass — used to shape the synthetic non-speech cases."""
    omega = 2.0 * np.pi * cutoff / rate
    alpha = np.sin(omega) / (2.0 * q)
    cos_omega = np.cos(omega)
    b0 = (1.0 - cos_omega) / 2.0
    b1 = 1.0 - cos_omega
    b2 = (1.0 - cos_omega) / 2.0
    a0 = 1.0 + alpha
    a1 = -2.0 * cos_omega
    a2 = 1.0 - alpha
    out = np.zeros_like(signal)
    x1 = x2 = y1 = y2 = 0.0
    for index, sample in enumerate(signal):
        y = (b0 * sample + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2) / a0
        out[index] = y
        x2, x1 = x1, sample
        y2, y1 = y1, y
    return out


def scale_to_mean_square(signal, target):
    """Scale a float signal so its i16 mean-square energy equals `target`."""
    current = (signal**2).mean()
    if current <= 0.0:
        return np.zeros_like(signal)
    return signal * np.sqrt(target / current)


def to_i16(signal):
    return np.clip(np.rint(signal), -32768, 32767).astype(np.int16)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    handle = wave.open("silero_test.wav")
    assert handle.getframerate() == RATE and handle.getnchannels() == 1
    speech = np.frombuffer(handle.readframes(handle.getnframes()), dtype="<i2")

    # --- 1. the speech corpus: 30 s of the upstream test recording -------------------------
    corpus_windows = 937  # 937 * 512 = 479_744 samples ≈ 29.98 s
    corpus = speech[: corpus_windows * WINDOW]
    write_case("neural_vad_speech", corpus)

    # --- 2. low-frequency hum ---------------------------------------------------------------
    # 50 Hz mains plus its 2nd and 3rd harmonics, the classic ground-loop / power hum an energy
    # gate cannot tell from speech. Scaled so the mean-square energy is 4x the engine's default
    # energy-VAD threshold (1_000_000), i.e. the energy detector *does* call it speech.
    length = 64 * WINDOW
    time = np.arange(length) / RATE
    hum = (
        np.sin(2 * np.pi * 50.0 * time)
        + 0.5 * np.sin(2 * np.pi * 100.0 * time)
        + 0.25 * np.sin(2 * np.pi * 150.0 * time)
    )
    write_case("neural_vad_hum", to_i16(scale_to_mean_square(hum, 4_000_000.0)))

    # --- 3. breath ---------------------------------------------------------------------------
    # Low-passed noise in slow bursts: the spectral shape and envelope of breathing into a
    # close-talking microphone. Same energy budget as the hum case.
    noise = lcg_noise(length, 0x5EED_1234)
    shaped = biquad_lowpass(biquad_lowpass(noise, 900.0), 900.0)
    envelope = np.zeros(length)
    burst = int(0.45 * RATE)
    gap = int(0.75 * RATE)
    position = int(0.2 * RATE)
    while position + burst < length:
        window_shape = np.hanning(burst)
        envelope[position : position + burst] = window_shape
        position += burst + gap
    write_case("neural_vad_breath", to_i16(scale_to_mean_square(shaped * envelope, 4_000_000.0)))

    # --- 4. acoustic echo of far-end speech --------------------------------------------------
    # A far-end talker leaking back into the near-end microphone: 40 ms bulk delay, a sparse
    # exponentially-decaying image-source reverb tail, band-limited by the loudspeaker/room.
    #
    # Two levels, because the answer differs and both matter:
    #   *coupled*  — the raw echo path, at the same level as the near-end talker. The network is a
    #                speech classifier and echo of speech IS speech, so it fires. Committed so the
    #                port is held to the reference on the case it cannot win, and so the doc claim
    #                ("the AEC is not optional under barge-in") has a number behind it.
    #   *residual* — what is left after ~42 dB of echo-return loss, i.e. a competent canceller.
    #                Here the network is silent, which is the case barge-in actually depends on.
    far_end = speech[RATE * 31 : RATE * 31 + length].astype(np.float64)
    echo = np.zeros(length)
    for delay_ms, gain in [(40, 1.0), (57, 0.55), (73, 0.36), (96, 0.22), (131, 0.13), (178, 0.07)]:
        delay = int(delay_ms * RATE / 1000)
        echo[delay:] += gain * far_end[: length - delay]
    echo = biquad_lowpass(echo, 3400.0)
    near_end_energy = (corpus.astype(np.float64) ** 2).mean()
    write_case("neural_vad_echo_coupled", to_i16(scale_to_mean_square(echo, near_end_energy)))
    write_case(
        "neural_vad_echo_residual",
        to_i16(scale_to_mean_square(echo, near_end_energy / 10.0**4.2)),
    )

    # --- 5. speech onset ---------------------------------------------------------------------
    # 1.6 s of a quiet room, then a speech onset at a known sample index, so the port can report
    # onset latency in ms rather than "it eventually fires".
    onset_window = 50  # speech starts exactly at window 50 -> sample 25_600 -> 1600 ms
    silence_samples = onset_window * WINDOW
    room = to_i16(scale_to_mean_square(lcg_noise(silence_samples, 0xC0FF_EE01), 400.0))
    # A segment of the corpus that the reference marks as speech from its very first window.
    talk = speech[RATE * 8 : RATE * 8 + 80 * WINDOW]
    onset = write_case("neural_vad_onset", np.concatenate([room, talk]))
    fired = np.flatnonzero(onset >= 0.5)
    first = int(fired[0]) if fired.size else -1
    print(
        f"    onset window={onset_window} first p>=0.5 at window {first} "
        f"(+{(first - onset_window) * WINDOW * 1000 // RATE} ms)"
    )

    print()
    print("weights blob:", file_hash("silero_vad_v5_16k.f32"))


if __name__ == "__main__":
    main()

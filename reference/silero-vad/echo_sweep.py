"""How far down does far-end speech have to be before the model stops calling it speech?

An energy gate fires on anything above an absolute threshold, so it cannot tell echo from
speech at all.  The network is a speech classifier, so it will also call *loud* echo speech —
correctly, acoustically it is speech.  This sweep finds the level at which it stops, which is
the number the docs need in order to say what the echo canceller has to deliver.
"""

import numpy as np

from make_vectors import (
    RATE,
    WINDOW,
    biquad_lowpass,
    reference_probabilities,
    scale_to_mean_square,
    to_i16,
)
import wave

handle = wave.open("silero_test.wav")
speech = np.frombuffer(handle.readframes(handle.getnframes()), dtype="<i2")

length = 64 * WINDOW
far_end = speech[RATE * 31 : RATE * 31 + length].astype(np.float64)
echo = np.zeros(length)
for delay_ms, gain in [(40, 1.0), (57, 0.55), (73, 0.36), (96, 0.22), (131, 0.13), (178, 0.07)]:
    delay = int(delay_ms * RATE / 1000)
    echo[delay:] += gain * far_end[: length - delay]
echo = biquad_lowpass(echo, 3400.0)

speech_energy = (speech[: RATE * 30].astype(np.float64) ** 2).mean()
print(f"near-end talker mean-square energy: {speech_energy:.0f}")

for erl_db in [0, 6, 12, 18, 24, 30, 36, 42]:
    target = speech_energy / (10.0 ** (erl_db / 10.0))
    case = to_i16(scale_to_mean_square(echo, target))
    probabilities = reference_probabilities(case)
    fired = int((probabilities >= 0.5).sum())
    print(
        f"echo at -{erl_db:2d} dB  mean_square={target:11.0f}  "
        f"energy-VAD(1e6) fires={target >= 1_000_000}  "
        f"neural windows>=0.5: {fired:3d}/{len(probabilities)}  max_p={probabilities.max():.4f}"
    )

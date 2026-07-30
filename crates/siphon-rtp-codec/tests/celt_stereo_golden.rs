//! Per-kernel golden checks for the CELT **stereo** kernels against instrumented libopus
//! (RFC 6716 §4.3.4; libopus `celt/bands.c`, `celt/vq.c`, `celt/celt_encoder.c`, float build).
//!
//! A round trip cannot validate these: a shared encode/decode bug passes one. So each kernel is
//! pinned to the value libopus itself produced for the same input. `reference/opus/celt_stereo_golden.c`
//! includes `bands.c`/`celt_encoder.c` directly (their stereo helpers are file-static) and prints
//! these literals; the inputs are regenerated here from the same `sig()` LCG, so only the outputs
//! travel. Everything is embedded, so this runs in CI with no reference tree — the generator only
//! has to be re-run when a kernel's expected behaviour is deliberately changed.
//!
//! Tolerance: the two builds do the same float arithmetic in the same order, but libopus dispatches
//! some reductions (`celt_inner_prod`, `dual_inner_prod`) to SSE, which re-associates the sum. The
//! comparison is therefore a tight *relative* one rather than bit-exact — the discrepancies this
//! catches (a wrong weight, a swapped channel, a missed renormalisation) are orders of magnitude
//! larger.

// The goldens are printed by the generator at full `%.9e` precision and pasted verbatim, so a
// reviewer can diff them against a fresh dump character for character. Letting clippy round them to
// the shortest f32-exact spelling would break that, for no change in value.
#![allow(clippy::excessive_precision)]

use siphon_rtp_codec::opus::celt::analysis::{
    alloc_trim_analysis, dynalloc_analysis, patch_transient_decision, stereo_analysis,
};
use siphon_rtp_codec::opus::celt::bands::{
    bitexact_cos, bitexact_log2tan, compute_channel_weights, compute_qn, frac_mul16,
    intensity_stereo, stereo_merge, stereo_split,
};
use siphon_rtp_codec::opus::celt::tables::{E_BANDS, LOG_N, NB_BANDS};
use siphon_rtp_codec::opus::celt::vq::stereo_itheta;

/// Vector-kernel case length used by the generator (`VN` in `celt_stereo_golden.c`).
const VN: usize = 8;
/// `QTHETA_OFFSET` / `QTHETA_OFFSET_TWOPHASE` (libopus `bands.c:697`).
const QTHETA_OFFSET: i32 = 4;
const QTHETA_OFFSET_TWOPHASE: i32 = 16;
const BITRES: i32 = 3;

/// The generator's deterministic input LCG (`sig()` in `celt_stereo_golden.c`), reproduced with the
/// same `unsigned` wrap-around and the same f32 rounding so both sides see identical inputs.
fn sig(seed: i32, index: usize, scale: f32) -> f32 {
    let s = (seed as u32)
        .wrapping_mul(2_654_435_761)
        .wrapping_add((index as u32).wrapping_mul(40_503));
    let s = s.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    let t = ((s >> 9) & 0xFFFF) as f32 / 32768.0 - 1.0;
    t * scale
}

/// Relative comparison against a libopus golden. `1e-5` is ~7 f32 ulps at these magnitudes — far
/// under any real algorithmic difference, far over the SSE re-association noise.
#[track_caller]
fn assert_close(got: &[f32], want: &[f32], what: &str) {
    assert_eq!(got.len(), want.len(), "{what}: length");
    for (index, (&g, &w)) in got.iter().zip(want).enumerate() {
        let tolerance = 1e-5 * w.abs().max(1e-3);
        assert!(
            (g - w).abs() <= tolerance,
            "{what}[{index}]: got {g:e}, libopus said {w:e}"
        );
    }
}

// ── stereo_itheta (libopus `vq.c:410`) ──────────────────────────────────────────────────────────

/// `(N, itheta with the stereo mid/side form, itheta with the time-split form)`.
const STEREO_ITHETA: [(usize, i32, i32); 8] = [
    (2, 10131, 1939),
    (4, 6025, 14216),
    (8, 12986, 4811),
    (16, 9020, 853),
    (24, 7185, 15194),
    (48, 13116, 5590),
    (96, 9008, 1758),
    (176, 10279, 8631),
];

#[test]
fn stereo_itheta_matches_libopus() {
    for (case, &(n, want_stereo, want_time)) in STEREO_ITHETA.iter().enumerate() {
        let case = case as i32;
        let x: Vec<f32> = (0..n).map(|j| sig(case + 1, j, 0.3)).collect();
        let y: Vec<f32> = (0..n)
            .map(|j| sig(case + 9, j, 0.3) * if case % 3 == 0 { 0.2 } else { 1.0 })
            .collect();
        // The quantised angle drives the mid/side bit split, so it must land on libopus' integer.
        // A ±1 slack covers the SSE-reassociated `celt_inner_prod` in the time-split branch.
        let got_stereo = stereo_itheta(&x, &y, true, n);
        let got_time = stereo_itheta(&x, &y, false, n);
        assert!(
            (got_stereo - want_stereo).abs() <= 1,
            "N={n}: stereo itheta {got_stereo}, libopus said {want_stereo}"
        );
        assert!(
            (got_time - want_time).abs() <= 1,
            "N={n}: time-split itheta {got_time}, libopus said {want_time}"
        );
    }
}

// ── intensity_stereo (libopus `bands.c:388`) ────────────────────────────────────────────────────

/// Band index, left/right band amplitude, and the resulting collapsed `X` for each case.
const INTENSITY_CASES: [(usize, f32, f32); 4] = [
    (0, 1.0, 0.25),
    (5, 4.5, 4.5),
    (12, 0.01, 9.0),
    (19, 30.0, 0.0),
];
const INTENSITY_GOLDEN: [[f32; VN]; 4] = [
    [
        -2.887586355e-01,
        -2.837255299e-01,
        -2.786924541e-01,
        -2.736630738e-01,
        -2.686447799e-01,
        -2.636117041e-01,
        -2.585822940e-01,
        -2.535640299e-01,
    ],
    [
        7.806270570e-02,
        8.392144740e-02,
        8.979099989e-02,
        9.566053748e-02,
        1.015084982e-01,
        1.073780358e-01,
        1.132475659e-01,
        1.191063151e-01,
    ],
    [
        3.455709219e-01,
        3.497106433e-01,
        3.538656533e-01,
        3.580206633e-01,
        3.621604145e-01,
        3.663153946e-01,
        3.704704046e-01,
        3.746253848e-01,
    ],
    [
        -3.397827148e-01,
        -3.356323242e-01,
        -3.314971924e-01,
        -3.273468018e-01,
        -3.231964111e-01,
        -3.190460205e-01,
        -3.149108887e-01,
        -3.107604980e-01,
    ],
];

#[test]
fn intensity_stereo_matches_libopus() {
    for (case, (&(band, left, right), want)) in
        INTENSITY_CASES.iter().zip(&INTENSITY_GOLDEN).enumerate()
    {
        let case = case as i32;
        let mut band_energy = [0f32; 2 * NB_BANDS];
        band_energy[band] = left;
        band_energy[band + NB_BANDS] = right;
        let mut x: Vec<f32> = (0..VN).map(|j| sig(case + 21, j, 0.5)).collect();
        let y: Vec<f32> = (0..VN).map(|j| sig(case + 31, j, 0.5)).collect();
        intensity_stereo(&mut x, &y, &band_energy, band, VN);
        assert_close(&x, want, &format!("intensity_stereo case {case}"));
    }
}

// ── stereo_split (libopus `bands.c:413`) ────────────────────────────────────────────────────────

const STEREO_SPLIT_GOLDEN: [[f32; VN]; 4] = [
    // case 0 X
    [
        -3.129154444e-01,
        -3.082198501e-01,
        -3.035414815e-01,
        -2.988458276e-01,
        -2.941502035e-01,
        -2.894631922e-01,
        -2.847762108e-01,
        -2.800805569e-01,
    ],
    // case 0 Y
    [
        -9.460315108e-03,
        -9.460315108e-03,
        -9.460315108e-03,
        -9.460315108e-03,
        -9.460330009e-03,
        -9.468942881e-03,
        -9.460300207e-03,
        -9.460315108e-03,
    ],
    // case 1 X
    [
        2.460027114e-02,
        2.929590270e-02,
        3.398290277e-02,
        3.866990283e-02,
        4.336553067e-02,
        4.806116596e-02,
        5.273953080e-02,
        5.743516237e-02,
    ],
    // case 1 Y
    [
        -9.460314177e-03,
        -9.460315108e-03,
        -9.468946606e-03,
        -9.460316040e-03,
        -9.460313246e-03,
        -9.460315108e-03,
        -9.460316971e-03,
        -9.460315108e-03,
    ],
];

#[test]
fn stereo_split_matches_libopus() {
    for case in 0..2i32 {
        let mut x: Vec<f32> = (0..VN).map(|j| sig(case + 41, j, 0.4)).collect();
        let mut y: Vec<f32> = (0..VN).map(|j| sig(case + 51, j, 0.4)).collect();
        stereo_split(&mut x, &mut y, VN);
        assert_close(
            &x,
            &STEREO_SPLIT_GOLDEN[2 * case as usize],
            &format!("stereo_split case {case} X"),
        );
        assert_close(
            &y,
            &STEREO_SPLIT_GOLDEN[2 * case as usize + 1],
            &format!("stereo_split case {case} Y"),
        );
    }
}

// ── stereo_merge (libopus `bands.c:426`) ────────────────────────────────────────────────────────

/// `mid` per case; case 3 has a zero side **and** a zero mid gain, which is the degenerate branch
/// where libopus copies mid into both channels instead of dividing by ~0.
const STEREO_MERGE_MIDS: [f32; 4] = [0.9, 0.5, 0.99, 0.0];
const STEREO_MERGE_GOLDEN: [[f32; VN]; 8] = [
    // case 0 X
    [
        3.563353792e-02,
        3.531930223e-02,
        3.500389308e-02,
        3.468848392e-02,
        3.438466415e-02,
        3.405885398e-02,
        3.374344856e-02,
        3.343960643e-02,
    ],
    // case 0 Y
    [
        -2.862262428e-01,
        -2.824139893e-01,
        -2.785876691e-01,
        -2.747613490e-01,
        -2.709424198e-01,
        -2.671227753e-01,
        -2.632964253e-01,
        -2.594775259e-01,
    ],
    // case 1 X
    [
        2.206155285e-02,
        1.959095150e-02,
        1.709289849e-02,
        1.460399572e-02,
        1.211509481e-02,
        9.635344148e-03,
        7.146442309e-03,
        4.657540470e-03,
    ],
    // case 1 Y
    [
        -2.606097050e-02,
        -1.861497760e-02,
        -1.115983911e-02,
        -3.695553169e-03,
        3.768733004e-03,
        1.120557543e-02,
        1.866986230e-02,
        2.613414824e-02,
    ],
    // case 2 X
    [
        9.807853960e-03,
        9.778303094e-03,
        9.748858400e-03,
        9.719307534e-03,
        9.689757600e-03,
        9.671082720e-03,
        9.630762041e-03,
        9.601194412e-03,
    ],
    // case 2 Y
    [
        2.590733767e-01,
        2.628254294e-01,
        2.665636539e-01,
        2.703156769e-01,
        2.740677297e-01,
        2.778128386e-01,
        2.815580070e-01,
        2.853100598e-01,
    ],
    // case 3 X (degenerate: untouched)
    [
        -2.440155149e-01,
        -2.415252775e-01,
        -2.390350401e-01,
        -2.365539670e-01,
        -2.340637296e-01,
        -2.315734923e-01,
        -2.290924191e-01,
        -2.266021818e-01,
    ],
    // case 3 Y (degenerate: mid copied into the side)
    [
        -2.440155149e-01,
        -2.415252775e-01,
        -2.390350401e-01,
        -2.365539670e-01,
        -2.340637296e-01,
        -2.315734923e-01,
        -2.290924191e-01,
        -2.266021818e-01,
    ],
];

#[test]
fn stereo_merge_matches_libopus() {
    for (case, &mid) in STEREO_MERGE_MIDS.iter().enumerate() {
        let seed = case as i32;
        let mut x: Vec<f32> = (0..VN).map(|j| sig(seed + 61, j, 0.3)).collect();
        let mut y: Vec<f32> = (0..VN)
            .map(|j| {
                if case == 3 {
                    0.0
                } else {
                    sig(seed + 71, j, 0.3)
                }
            })
            .collect();
        stereo_merge(&mut x, &mut y, mid, VN);
        assert_close(
            &x,
            &STEREO_MERGE_GOLDEN[2 * case],
            &format!("stereo_merge case {case} X"),
        );
        assert_close(
            &y,
            &STEREO_MERGE_GOLDEN[2 * case + 1],
            &format!("stereo_merge case {case} Y"),
        );
    }
}

// ── compute_channel_weights (libopus `bands.c:371`) ─────────────────────────────────────────────

/// `(Ex, Ey, w0, w1)` — the theta rate-distortion trial's per-channel distortion weights.
const CHANNEL_WEIGHTS: [(f32, f32, f32, f32); 6] = [
    (1.0, 1.0, 1.333_333_37, 1.333_333_37),
    (9.0, 3.0, 10.0, 4.0),
    (0.0, 5.0, 0.0, 5.0),
    (2.5, 0.125, 2.541_666_7, 1.666_666_7e-1),
    (1e-6, 1e-6, 1.333_333_3e-6, 1.333_333_3e-6),
    (40.0, 7.0, 4.233_333_2e1, 9.333_333_0),
];

#[test]
fn compute_channel_weights_matches_libopus() {
    for &(left, right, want0, want1) in &CHANNEL_WEIGHTS {
        let got = compute_channel_weights(left, right);
        assert_close(
            &got,
            &[want0, want1],
            &format!("compute_channel_weights({left}, {right})"),
        );
    }
}

// ── compute_qn (libopus `bands.c:664`) ──────────────────────────────────────────────────────────

/// `(band, LM, b, N, qn for a stereo split, qn for a time split)`. The two differ only at `N == 2`,
/// where the stereo form drops one degree of freedom (`bands.c:670`) — which is exactly the
/// stereo-specific behaviour the mono path never exercised.
const COMPUTE_QN: [(usize, i32, i32, i32, i32, i32); 120] = [
    (0, 0, 0, 1, 1, 1),
    (0, 0, 40, 1, 2, 2),
    (0, 0, 160, 1, 256, 256),
    (0, 0, 640, 1, 256, 256),
    (0, 0, 2000, 1, 256, 256),
    (0, 1, 0, 2, 1, 1),
    (0, 1, 40, 2, 1, 1),
    (0, 1, 160, 2, 256, 98),
    (0, 1, 640, 2, 256, 256),
    (0, 1, 2000, 2, 256, 256),
    (0, 2, 0, 4, 1, 1),
    (0, 2, 40, 4, 1, 1),
    (0, 2, 160, 4, 10, 10),
    (0, 2, 640, 4, 256, 256),
    (0, 2, 2000, 4, 256, 256),
    (0, 3, 0, 8, 1, 1),
    (0, 3, 40, 8, 1, 1),
    (0, 3, 160, 8, 4, 4),
    (0, 3, 640, 8, 76, 76),
    (0, 3, 2000, 8, 256, 256),
    (4, 0, 0, 1, 1, 1),
    (4, 0, 40, 1, 2, 2),
    (4, 0, 160, 1, 256, 256),
    (4, 0, 640, 1, 256, 256),
    (4, 0, 2000, 1, 256, 256),
    (4, 1, 0, 2, 1, 1),
    (4, 1, 40, 2, 1, 1),
    (4, 1, 160, 2, 256, 98),
    (4, 1, 640, 2, 256, 256),
    (4, 1, 2000, 2, 256, 256),
    (4, 2, 0, 4, 1, 1),
    (4, 2, 40, 4, 1, 1),
    (4, 2, 160, 4, 10, 10),
    (4, 2, 640, 4, 256, 256),
    (4, 2, 2000, 4, 256, 256),
    (4, 3, 0, 8, 1, 1),
    (4, 3, 40, 8, 1, 1),
    (4, 3, 160, 8, 4, 4),
    (4, 3, 640, 8, 76, 76),
    (4, 3, 2000, 8, 256, 256),
    (8, 0, 0, 2, 1, 1),
    (8, 0, 40, 2, 1, 1),
    (8, 0, 160, 2, 256, 98),
    (8, 0, 640, 2, 256, 256),
    (8, 0, 2000, 2, 256, 256),
    (8, 1, 0, 4, 1, 1),
    (8, 1, 40, 4, 1, 1),
    (8, 1, 160, 4, 10, 10),
    (8, 1, 640, 4, 256, 256),
    (8, 1, 2000, 4, 256, 256),
    (8, 2, 0, 8, 1, 1),
    (8, 2, 40, 8, 1, 1),
    (8, 2, 160, 8, 4, 4),
    (8, 2, 640, 8, 76, 76),
    (8, 2, 2000, 8, 256, 256),
    (8, 3, 0, 16, 1, 1),
    (8, 3, 40, 16, 1, 1),
    (8, 3, 160, 16, 4, 4),
    (8, 3, 640, 16, 16, 16),
    (8, 3, 2000, 16, 256, 256),
    (12, 0, 0, 4, 1, 1),
    (12, 0, 40, 4, 1, 1),
    (12, 0, 160, 4, 10, 10),
    (12, 0, 640, 4, 256, 256),
    (12, 0, 2000, 4, 256, 256),
    (12, 1, 0, 8, 1, 1),
    (12, 1, 40, 8, 1, 1),
    (12, 1, 160, 8, 4, 4),
    (12, 1, 640, 8, 76, 76),
    (12, 1, 2000, 8, 256, 256),
    (12, 2, 0, 16, 1, 1),
    (12, 2, 40, 16, 1, 1),
    (12, 2, 160, 16, 4, 4),
    (12, 2, 640, 16, 16, 16),
    (12, 2, 2000, 16, 256, 256),
    (12, 3, 0, 32, 1, 1),
    (12, 3, 40, 32, 1, 1),
    (12, 3, 160, 32, 4, 4),
    (12, 3, 640, 32, 10, 10),
    (12, 3, 2000, 32, 58, 58),
    (16, 0, 0, 6, 1, 1),
    (16, 0, 40, 6, 1, 1),
    (16, 0, 160, 6, 6, 6),
    (16, 0, 640, 6, 256, 256),
    (16, 0, 2000, 6, 256, 256),
    (16, 1, 0, 12, 1, 1),
    (16, 1, 40, 12, 1, 1),
    (16, 1, 160, 12, 4, 4),
    (16, 1, 640, 12, 24, 24),
    (16, 1, 2000, 12, 256, 256),
    (16, 2, 0, 24, 1, 1),
    (16, 2, 40, 24, 1, 1),
    (16, 2, 160, 24, 4, 4),
    (16, 2, 640, 24, 10, 10),
    (16, 2, 2000, 24, 128, 128),
    (16, 3, 0, 48, 1, 1),
    (16, 3, 40, 48, 1, 1),
    (16, 3, 160, 48, 6, 6),
    (16, 3, 640, 48, 8, 8),
    (16, 3, 2000, 48, 30, 30),
    (20, 0, 0, 22, 1, 1),
    (20, 0, 40, 22, 1, 1),
    (20, 0, 160, 22, 4, 4),
    (20, 0, 640, 22, 12, 12),
    (20, 0, 2000, 22, 182, 182),
    (20, 1, 0, 44, 1, 1),
    (20, 1, 40, 44, 1, 1),
    (20, 1, 160, 44, 6, 6),
    (20, 1, 640, 44, 8, 8),
    (20, 1, 2000, 44, 32, 32),
    (20, 2, 0, 88, 1, 1),
    (20, 2, 40, 88, 1, 1),
    (20, 2, 160, 88, 6, 6),
    (20, 2, 640, 88, 8, 8),
    (20, 2, 2000, 88, 18, 18),
    (20, 3, 0, 176, 1, 1),
    (20, 3, 40, 176, 1, 1),
    (20, 3, 160, 176, 10, 10),
    (20, 3, 640, 176, 10, 10),
    (20, 3, 2000, 176, 14, 14),
];

#[test]
fn compute_qn_matches_libopus_for_both_split_forms() {
    for &(band, lm, b, want_n, want_stereo, want_time) in &COMPUTE_QN {
        let n = i32::from(E_BANDS[band + 1] - E_BANDS[band]) << lm;
        assert_eq!(n, want_n, "band {band} LM {lm}: band width");
        let pulse_cap = i32::from(LOG_N[band]) + lm * (1 << BITRES);
        let offset_stereo = (pulse_cap >> 1)
            - if n == 2 {
                QTHETA_OFFSET_TWOPHASE
            } else {
                QTHETA_OFFSET
            };
        let offset_time = (pulse_cap >> 1) - QTHETA_OFFSET;
        assert_eq!(
            compute_qn(n, b, offset_stereo, pulse_cap, true),
            want_stereo,
            "band {band} LM {lm} b {b}: stereo qn"
        );
        assert_eq!(
            compute_qn(n, b, offset_time, pulse_cap, false),
            want_time,
            "band {band} LM {lm} b {b}: time-split qn"
        );
    }
}

// ── The theta gain / bit-split derivation (libopus `bands.c:870`) ───────────────────────────────

/// `(itheta, N, imid, iside, delta)`. `delta` is the mid-vs-side bit split, and it is bit-exact by
/// construction (`bitexact_cos` / `bitexact_log2tan` exist precisely so the allocation cannot drift
/// between implementations) — so this is an equality check, not a tolerance one.
const THETA_GAINS: [(i32, i32, i32, i32, i32); 32] = [
    (712, 2, 32692, 2235, -31),
    (712, 8, 32692, 2235, -217),
    (712, 32, 32692, 2235, -959),
    (712, 176, 32692, 2235, -5413),
    (2849, 2, 31553, 8839, -15),
    (2849, 8, 31553, 8839, -103),
    (2849, 32, 31553, 8839, -455),
    (2849, 176, 31553, 8839, -2567),
    (4986, 2, 29095, 15074, -8),
    (4986, 8, 29095, 15074, -53),
    (4986, 32, 29095, 15074, -235),
    (4986, 176, 29095, 15074, -1328),
    (7123, 2, 25420, 20679, -2),
    (7123, 8, 25420, 20679, -17),
    (7123, 32, 25420, 20679, -75),
    (7123, 176, 25420, 20679, -423),
    (9260, 2, 20681, 25418, 2),
    (9260, 8, 20681, 25418, 17),
    (9260, 32, 20681, 25418, 75),
    (9260, 176, 20681, 25418, 423),
    (11397, 2, 15077, 29094, 8),
    (11397, 8, 15077, 29094, 53),
    (11397, 32, 15077, 29094, 235),
    (11397, 176, 15077, 29094, 1328),
    (13534, 2, 8843, 31552, 15),
    (13534, 8, 8843, 31552, 103),
    (13534, 32, 8843, 31552, 454),
    (13534, 176, 8843, 31552, 2566),
    (15671, 2, 2238, 32692, 31),
    (15671, 8, 2238, 32692, 216),
    (15671, 32, 2238, 32692, 958),
    (15671, 176, 2238, 32692, 5410),
];

#[test]
fn theta_gains_and_bit_split_match_libopus_exactly() {
    for &(itheta, n, want_imid, want_iside, want_delta) in &THETA_GAINS {
        let imid = i32::from(bitexact_cos(itheta as i16));
        let iside = i32::from(bitexact_cos((16384 - itheta) as i16));
        assert_eq!(imid, want_imid, "itheta {itheta}: imid");
        assert_eq!(iside, want_iside, "itheta {itheta}: iside");
        let delta = frac_mul16((n - 1) << 7, bitexact_log2tan(iside, imid));
        assert_eq!(delta, want_delta, "itheta {itheta} N {n}: delta");
    }
}

// ── stereo_analysis (libopus `celt_encoder.c:889`) ──────────────────────────────────────────────

/// Inter-channel correlation per case: the right channel is `corr*L + (1-|corr|)*noise`.
const STEREO_ANALYSIS_CORRELATIONS: [f32; 6] = [1.0, 0.9, 0.5, 0.0, -0.5, -1.0];
/// `(case, LM, dual_stereo)`. Only the anti-correlated-but-not-inverted case is worth coding L/R;
/// everything else — including the *fully* inverted pair, whose mid is zero — is cheaper as mid/side.
const STEREO_ANALYSIS: [(usize, usize, bool); 24] = [
    (0, 0, false),
    (0, 1, false),
    (0, 2, false),
    (0, 3, false),
    (1, 0, false),
    (1, 1, false),
    (1, 2, false),
    (1, 3, false),
    (2, 0, false),
    (2, 1, false),
    (2, 2, false),
    (2, 3, false),
    (3, 0, false),
    (3, 1, false),
    (3, 2, false),
    (3, 3, false),
    (4, 0, true),
    (4, 1, true),
    (4, 2, true),
    (4, 3, true),
    (5, 0, false),
    (5, 1, false),
    (5, 2, false),
    (5, 3, false),
];

/// The generator's stereo spectrum for a given case and frame size.
fn stereo_spectrum(case: usize, lm: usize) -> (Vec<f32>, usize) {
    let n0 = 120usize << lm;
    let correlation = STEREO_ANALYSIS_CORRELATIONS[case];
    let mut x = vec![0f32; 2 * n0];
    for j in 0..n0 {
        let left = sig(case as i32 + 81, j, 0.4);
        x[j] = left;
        x[n0 + j] = correlation * left + (1.0 - correlation.abs()) * sig(case as i32 + 91, j, 0.4);
    }
    (x, n0)
}

#[test]
fn stereo_analysis_matches_libopus() {
    for &(case, lm, want) in &STEREO_ANALYSIS {
        let (x, n0) = stereo_spectrum(case, lm);
        assert_eq!(
            stereo_analysis(&x, lm, n0),
            want,
            "correlation {} LM {lm}: dual-stereo decision",
            STEREO_ANALYSIS_CORRELATIONS[case]
        );
    }
}

// ── alloc_trim_analysis, C == 2 (libopus `celt_encoder.c:816`) ──────────────────────────────────

/// `(case, rate index, trim, stereo_saving)` at LM 3 / N0 960, with the case's own `intensity` and
/// inter-channel correlation.
const ALLOC_TRIM_RATES: [i32; 4] = [24_000, 64_000, 72_000, 200_000];
const ALLOC_TRIM_INTENSITIES: [usize; 4] = [0, 8, 14, 21];
const ALLOC_TRIM_CORRELATIONS: [f32; 4] = [1.0, 0.5, 0.0, -0.8];
const ALLOC_TRIM: [(usize, usize, i32, f32); 16] = [
    (0, 0, 5, 3.856195509e-02),
    (0, 1, 5, 3.856195509e-02),
    (0, 2, 6, 3.856195509e-02),
    (0, 3, 6, 3.856195509e-02),
    (1, 0, 6, 4.058708728e-04),
    (1, 1, 6, 4.058708728e-04),
    (1, 2, 6, 4.058708728e-04),
    (1, 3, 7, 4.058708728e-04),
    (2, 0, 5, 4.553090315e-03),
    (2, 1, 5, 4.553090315e-03),
    (2, 2, 5, 4.553090315e-03),
    (2, 3, 6, 4.553090315e-03),
    (3, 0, 6, -6.957641453e-04),
    (3, 1, 6, -6.957641453e-04),
    (3, 2, 6, -6.957641453e-04),
    (3, 3, 7, -6.957641453e-04),
];

#[test]
fn alloc_trim_analysis_stereo_matches_libopus() {
    for &(case, rate_index, want_trim, want_saving) in &ALLOC_TRIM {
        let (lm, n0) = (3usize, 960usize);
        let correlation = ALLOC_TRIM_CORRELATIONS[case];
        let mut x = vec![0f32; 2 * n0];
        for j in 0..n0 {
            let left = sig(case as i32 + 101, j, 0.4);
            x[j] = left;
            x[n0 + j] =
                correlation * left + (1.0 - correlation.abs()) * sig(case as i32 + 111, j, 0.4);
        }
        let mut band_log_e = vec![0f32; 2 * NB_BANDS];
        for j in 0..NB_BANDS {
            band_log_e[j] = 3.0 - 0.2 * j as f32 + 0.5 * sig(case as i32 + 121, j, 1.0);
            band_log_e[NB_BANDS + j] = 2.5 - 0.15 * j as f32 + 0.5 * sig(case as i32 + 131, j, 1.0);
        }
        let mut stereo_saving = 0f32;
        let trim = alloc_trim_analysis(
            &x,
            &band_log_e,
            NB_BANDS,
            lm,
            2,
            n0,
            &mut stereo_saving,
            0.1,
            ALLOC_TRIM_INTENSITIES[case],
            ALLOC_TRIM_RATES[rate_index],
        );
        assert_eq!(
            trim, want_trim,
            "case {case} rate {}: trim",
            ALLOC_TRIM_RATES[rate_index]
        );
        assert_close(
            &[stereo_saving],
            &[want_saving],
            &format!("case {case}: stereo_saving"),
        );
    }
}

// ── dynalloc_analysis, C == 2 (libopus `celt_encoder.c:1099`) ───────────────────────────────────

/// Per case: the boosts, the TF-Viterbi importance weights, and the spreading masking weights.
/// Case 1 spikes the **left** channel's band 10, case 2 the **right** channel's — the cross-talk
/// follower must react to either, and the two must not produce identical masking.
const DYNALLOC: [([i32; NB_BANDS], [i32; NB_BANDS], [i32; NB_BANDS]); 3] = [
    ([0; NB_BANDS], [13; NB_BANDS], [32; NB_BANDS]),
    (
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        [
            13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 208, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
        ],
        [
            32, 32, 32, 32, 32, 32, 32, 16, 2, 1, 32, 1, 1, 1, 1, 4, 8, 8, 4, 2, 1,
        ],
    ),
    (
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        [
            13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 208, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
        ],
        [
            32, 32, 32, 32, 32, 32, 32, 32, 4, 1, 32, 1, 1, 1, 2, 8, 16, 16, 8, 4, 2,
        ],
    ),
];
/// `(tot_boost, max_depth)` per case.
const DYNALLOC_TOTALS: [(i32, f32); 3] = [
    (0, 2.338882256e+01),
    (1008, 3.116749954e+01),
    (1008, 3.116749954e+01),
];

#[test]
fn dynalloc_analysis_stereo_matches_libopus() {
    for case in 0..3usize {
        let mut band_log_e = vec![0f32; 2 * NB_BANDS];
        let mut band_log_e2 = vec![0f32; 2 * NB_BANDS];
        let mut old_band_e = vec![0f32; 2 * NB_BANDS];
        for j in 0..2 * NB_BANDS {
            band_log_e[j] = 4.0 - 0.1 * (j % NB_BANDS) as f32 + sig(case as i32 + 141, j, 2.0);
            band_log_e2[j] = band_log_e[j] - 0.05;
            old_band_e[j] = band_log_e[j] - 0.3;
        }
        if case == 1 {
            band_log_e[10] = 14.0;
            band_log_e2[10] = 13.95;
        }
        if case == 2 {
            band_log_e[NB_BANDS + 10] = 14.0;
            band_log_e2[NB_BANDS + 10] = 13.95;
        }
        let mut offsets = [0i32; NB_BANDS];
        let mut importance = [0i32; NB_BANDS];
        let mut spread_weight = [0i32; NB_BANDS];
        let result = dynalloc_analysis(
            &band_log_e,
            &band_log_e2,
            &old_band_e,
            0,
            NB_BANDS,
            2,
            &mut offsets,
            24,
            false,
            true,
            false,
            3,
            200,
            &mut importance,
            &mut spread_weight,
        );
        let (want_offsets, want_importance, want_spread) = &DYNALLOC[case];
        assert_eq!(&offsets, want_offsets, "case {case}: dynalloc offsets");
        assert_eq!(&importance, want_importance, "case {case}: importance");
        assert_eq!(&spread_weight, want_spread, "case {case}: spread weight");
        let (want_boost, want_depth) = DYNALLOC_TOTALS[case];
        assert_eq!(result.tot_boost, want_boost, "case {case}: tot_boost");
        assert_close(
            &[result.max_depth],
            &[want_depth],
            &format!("case {case}: max_depth"),
        );
    }
}

// ── patch_transient_decision, C == 2 (libopus `celt_encoder.c:431`) ─────────────────────────────

/// `(case, decision)`. Case 3 raises **only the right channel**, which a mono-shaped implementation
/// would miss entirely.
const PATCH_TRANSIENT: [(usize, bool); 4] = [(0, false), (1, true), (2, false), (3, true)];

#[test]
fn patch_transient_decision_stereo_matches_libopus() {
    for &(case, want) in &PATCH_TRANSIENT {
        let mut old_e = vec![0f32; 2 * NB_BANDS];
        let mut new_e = vec![0f32; 2 * NB_BANDS];
        for j in 0..2 * NB_BANDS {
            old_e[j] = 2.0 + sig(case as i32 + 151, j, 0.5);
            new_e[j] = old_e[j]
                + if case == 1 {
                    6.0
                } else if case == 2 {
                    -3.0
                } else {
                    0.0
                };
        }
        if case == 3 {
            for j in 0..NB_BANDS {
                new_e[NB_BANDS + j] = old_e[NB_BANDS + j] + 6.0;
            }
        }
        assert_eq!(
            patch_transient_decision(&new_e, &old_e, 0, NB_BANDS, 2),
            want,
            "case {case}"
        );
    }
}

//! Output conversion of the synthesis (TS 26.442 `lib_dec/syn_outp_fx.c`).

use crate::evs::cnst::{L_FRAME8K, MODE2};
use crate::evs::com::tools::copy_scale_sig;
use crate::itu::basic_ops::{
    abs_s, div_s, l_deposit_h, l_msu, l_mult, l_shr, negate, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_msu0, mac_r};

/// `syn_output_fx`: bring `synth[0..output_frame]` (scaled by `Q_syn2`) to Q0 16-bit output in
/// `synth_out`, with rounding on MODE2 and 8 kHz output and a saturating shift otherwise.
pub fn syn_output(
    codec_mode: i16,
    synth: &[i16],
    output_frame: i16,
    synth_out: &mut [i16],
    q_syn2: i16,
) {
    let tmp = q_syn2;
    if codec_mode == MODE2 || sub(output_frame, L_FRAME8K) == 0 {
        for i in 0..output_frame.max(0) as usize {
            let l_tmp = l_deposit_h(synth[i]);
            synth_out[i] = round_word(l_shr(l_tmp, tmp));
        }
    } else {
        copy_scale_sig(synth, synth_out, output_frame, negate(tmp));
    }
}

/// `unscale_AGC`: bring `x[0..n]` (Q`qx`) to Q0 in `y`, applying a slowly adapting gain
/// (`mem[0]`, Q15) that avoids saturation; `mem[1]` keeps half the last input sample.
pub fn unscale_agc(x: &[i16], qx: i16, y: &mut [i16], mem: &mut [i16], n: i16) {
    let n = n.max(1) as usize;

    // calculate AGC factor to avoid saturation
    let mut max = abs_s(x[0]);
    for &value in &x[1..n] {
        max = max.max(abs_s(value));
    }
    let tmp = shl(30000, qx); // saturation can occur here
    let mut frame_fac = 0;
    if sub(max, tmp) > 0 {
        frame_fac = sub(16384, div_s(shr(tmp, 1), max)); // frame fac in Q15
    }

    // update AGC factor (slowly)
    let mut fac = mac_r(l_mult(32440, mem[0]), 328, frame_fac);

    let mut l_tmp = l_mult(x[0], 16384);
    l_tmp = l_msu0(l_tmp, fac, x[0]);
    l_tmp = l_msu(l_tmp, fac, mem[1]);
    l_tmp = l_shr(l_tmp, -1); // saturation can occur here
    y[0] = round_word(l_tmp);

    for i in 1..n {
        fac = mac_r(l_mult(32440, fac), 328, frame_fac);
        l_tmp = l_deposit_h(x[i]);
        l_tmp = l_msu(l_tmp, fac, x[i]);
        l_tmp = l_msu(l_tmp, fac, x[i - 1]);
        y[i] = round_word(l_tmp);
    }

    mem[0] = fac;
    mem[1] = shr(x[n - 1], 1);
}

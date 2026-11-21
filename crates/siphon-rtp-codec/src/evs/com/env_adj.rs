//! Envelope adjustment of noise-filled and low-accuracy bands (TS 26.442 `lib_com/env_adj_fx.c`;
//! TS 26.445 §6.2.2.3.7).

use crate::evs::cnst::{ENV_ADJ_INV_INCL_FX, ENV_ADJ_START_FX, L_FRAME32K, MAX_16, MAX_P_ATT};
use crate::evs::rom::{ATT_STEP_FX, GAIN_ATT_FX};
use crate::itu::basic_ops::{add, l_shl, mult, mult_r, round_word, shl, shr, sub};
use crate::itu::stl2009::l_mult0;

/// `pulses[i]`, or 0 past either end. The reference reads `pulses[i + 1]` at `i == last_sfm` (a
/// band of the caller's `NB_SFM` array, inside it for every layout) and could read `pulses[-1]`
/// only for a first band wider than 16 coefficients, which no band table has.
fn pulses_at(pulses: &[i16], i: isize) -> i16 {
    usize::try_from(i)
        .ok()
        .and_then(|i| pulses.get(i))
        .copied()
        .unwrap_or(0)
}

/// Raise the attenuation of the noise-filled region `adj[start..end]` towards 1 the wider the
/// region is, but not below `env_stab`.
fn end_attenuation_region(adj: &mut [i16], start: usize, end: usize, len: i16, env_stab: i16) {
    // tmp = min(1, max(0, len-ENV_ADJ_START)*(1.0f/ENV_ADJ_INCL))
    let tmp = round_word(l_shl(
        l_mult0(sub(len, ENV_ADJ_START_FX).max(0), ENV_ADJ_INV_INCL_FX),
        16,
    )); // Q15
    let tmp_diff = sub(MAX_16, tmp); // Q15
    for value in &mut adj[start..end] {
        // adj[j] = max(tmp + (1-tmp)*adj[j],env_stab)
        *value = add(tmp, mult(tmp_diff, *value)).max(env_stab);
    }
}

/// `env_adj_fx`: the envelope adjustment factors (Q15) of bands `0..=last_sfm`. At 32 kHz the
/// noise-filled bands (no pulses) are attenuated by how isolated they are, with whole attenuation
/// regions relaxed by their width and floored at `env_stab`; at 16 kHz bands with few pulses get
/// the low-accuracy attenuation of `gain_att`.
pub fn env_adj(
    pulses: &[i16],
    length: i16,
    last_sfm: i16,
    adj: &mut [i16],
    env_stab: i16,
    sfmsize: &[i16],
) {
    let mut att_state: i16 = 0;
    let mut len: i16 = 0;
    let mut start: usize = 0;

    // Find attenuation levels
    let mut i: usize = 0;
    while (i as i16) <= last_sfm {
        let group = sub(shr(sfmsize[i], 3), 1);
        let npul = pulses[i];
        let ii = i as isize;

        if sub(length, L_FRAME32K) == 0 {
            if npul == 0 {
                // Noise filled band
                adj[i] = if sub(group, 1) <= 0 {
                    if i > 0 && pulses_at(pulses, ii - 1) != 0 && pulses_at(pulses, ii + 1) != 0 {
                        11796 // 0.36
                    } else if i > 0
                        && (pulses_at(pulses, ii - 1) == 0 || pulses_at(pulses, ii + 1) == 0)
                    {
                        17695 // 0.54
                    } else {
                        23593 // 0.72
                    }
                } else if sub(i as i16, last_sfm) < 0 {
                    if pulses_at(pulses, ii - 1) != 0 && pulses_at(pulses, ii + 1) != 0 {
                        17695 // 0.54
                    } else {
                        23593 // 0.72
                    }
                } else {
                    23593 // 0.72
                };

                if att_state == 0 {
                    start = i;
                }
                len = add(len, 1);
                att_state = 1;
            } else {
                adj[i] = MAX_16; // 1.0 (saturated)
                if sub(att_state, 1) == 0 {
                    // End of attenuation region found
                    end_attenuation_region(adj, start, i, len, env_stab);
                    len = 0;
                    att_state = 0;
                }
            }
        } else {
            // length == L_FRAME16k: calculate low accuracy band attenuation
            let mut gain_adj: i16 = 32767; // 1.0 (saturated)
            if npul > 0 && sub(npul, MAX_P_ATT) < 0 {
                // idx = (short)(npul * att_step[group] + 0.5f) - 1; group is 0..=3 for every
                // band table (widths 8..=32), idx >= 0 since att_step >= 1.0 (Q13)
                let step = ATT_STEP_FX[group.clamp(0, 3) as usize];
                let idx = sub(mult_r(shl(npul, 2), step), 1);
                if sub(idx, MAX_P_ATT) < 0 {
                    gain_adj = GAIN_ATT_FX[idx.max(0) as usize];
                }
            }
            adj[i] = gain_adj;
        }
        i += 1;
    }

    // Check if the sequence ended with an attenuation region
    if sub(att_state, 1) == 0 {
        end_attenuation_region(adj, start, i, len, env_stab);
    }
}

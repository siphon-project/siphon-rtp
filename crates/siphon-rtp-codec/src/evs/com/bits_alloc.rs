//! MODE2 ACELP configuration and bit allocation (TS 26.442 `lib_com/bits_alloc.c`; TS 26.445
//! §5.2.3.1, §6.2.1).

use crate::evs::cnst::{
    ACELP_9K60, ACELP_FIXED_CDK_NB, ACELP_MODE_MAX, FORMANT_SHARPENING_G1,
    FORMANT_SHARPENING_G1_16K, FORMANT_SHARPENING_G2, FORMANT_SHARPENING_G2_16K, INACTIVE,
    NB_SUBFR16K, RF_ALLPRED, UNVOICED,
};
use crate::evs::com::math_op::i_mult2;
use crate::evs::dec::state::AcelpConfig;
use crate::evs::rom::{
    ACELP_BPF_BITS, ACELP_BPF_MODE, ACELP_CDK_BITS, ACELP_GAINS_BITS, ACELP_GAINS_MODE,
    ACELP_LTF_BITS, ACELP_LTF_MODE, ACELP_LTP_BITS_SFR, ACELP_LTP_MODE, ACELP_NRG_BITS,
    ACELP_NRG_MODE,
};
use crate::itu::basic_ops::{add, mult_r, sub};

/// `RF_NOPRED` = `ACELP_MODE_MAX + 1` (an expression macro, so not among the generated
/// constants).
const RF_NOPRED: i16 = ACELP_MODE_MAX + 1;
/// `RF_GENPRED` = `ACELP_MODE_MAX + 2`.
const RF_GENPRED: i16 = ACELP_MODE_MAX + 2;

/// `table[mode_index][band_index][coder_type]` of an ACELP mode table; 0 past it. The indices are
/// the rate mode, the bandwidth and the coder type, all bounded by the configuration the caller
/// derives from the bit rate; the reference reads out of bounds past them.
fn mode_table(
    table: &[[[i16; 8]; 2]; 2],
    mode_index: i16,
    band_index: i16,
    coder_type: i16,
) -> i16 {
    usize::try_from(mode_index)
        .ok()
        .and_then(|mode| table.get(mode))
        .and_then(|row| row.get(usize::try_from(band_index).unwrap_or(usize::MAX)))
        .and_then(|row| row.get(usize::try_from(coder_type).unwrap_or(usize::MAX)))
        .copied()
        .unwrap_or(0)
}

/// `table[index]`; 0 past it (see [`mode_table`]).
fn at(table: &[i16], index: i16) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or(0)
}

/// `BITS_ALLOC_init_config_acelp`: the initial ACELP configuration for `bit_rate`: the rate mode
/// (above 9.6 kbit/s), the mid-frame LPC enabled and the pre-emphasis / formant-enhancement /
/// tilt settings of the rate and bandwidth, those of a 16 kHz core (`nb_subfr` 5) overriding them.
pub fn bits_alloc_init_config_acelp(
    bit_rate: i32,
    narrow_band: i8,
    nb_subfr: i16,
    config: &mut AcelpConfig,
) {
    let rate_mode_index = i8::from(bit_rate > i32::from(ACELP_9K60));

    config.mode_index = i16::from(rate_mode_index);

    // LPC: midLpc should be switched off?
    config.mid_lpc_enable = 1;

    // ACELP ICB config
    if rate_mode_index == 0 || narrow_band != 0 {
        config.pre_emphasis = 1;
        config.formant_enh = 1;
        config.formant_enh_num = FORMANT_SHARPENING_G1;
        config.formant_enh_den = FORMANT_SHARPENING_G2;
        config.formant_tilt = 0;
        config.voice_tilt = 0;
    } else {
        config.pre_emphasis = 0;
        config.formant_enh = 1;
        config.formant_enh_num = FORMANT_SHARPENING_G1;
        config.formant_enh_den = FORMANT_SHARPENING_G2;
        config.formant_tilt = 1;
        config.voice_tilt = 1;
    }

    // Wide band @ 16kHz
    if sub(nb_subfr, NB_SUBFR16K) == 0 {
        config.pre_emphasis = 1;
        config.formant_enh = 1;
        config.formant_enh_num = FORMANT_SHARPENING_G1_16K;
        config.formant_enh_den = FORMANT_SHARPENING_G2_16K;
        config.formant_tilt = 0;
        config.voice_tilt = 2;
    }
}

/// `BITS_ALLOC_config_acelp`: configure the ACELP modes of a frame of `nb_subfr` subframes of
/// coder type `coder_type` and allocate the bits: the bit demand, or -1 when `bits_frame` cannot
/// hold even the fixed parts (the reference also prints a warning for that) or the fixed codebook
/// does not fit. Sets the fixed-codebook index of every subframe in `config`.
pub fn bits_alloc_config_acelp(
    bits_frame: i16,
    coder_type: i16,
    config: &mut AcelpConfig,
    narrow_band: i16,
    nb_subfr: i16,
) -> i16 {
    let mode_index = config.mode_index;
    let band_index = i16::from(narrow_band == 0);
    let mut bits: i16 = 0;

    if band_index == 0 {
        config.formant_enh = 1;
        if sub(coder_type, INACTIVE) == 0 {
            config.formant_enh = 0;
        }
    }

    if sub(band_index, 1) == 0 && sub(nb_subfr, 4) == 0 {
        if sub(coder_type, INACTIVE) == 0 {
            config.pre_emphasis = 0;
            config.formant_enh = 0;
            config.formant_enh_num = FORMANT_SHARPENING_G1_16K;
            config.voice_tilt = 1;
            config.formant_tilt = 1;
        } else {
            config.pre_emphasis = 1;
            config.formant_enh = 1;
            config.formant_enh_num = FORMANT_SHARPENING_G1;
            config.voice_tilt = 0;
            config.formant_tilt = 0;
        }
    }
    if sub(coder_type, UNVOICED) == 0 {
        if sub(
            mode_table(&ACELP_GAINS_MODE, mode_index, band_index, coder_type),
            6,
        ) == 0
        {
            config.pitch_sharpening = 0;
            config.phase_scrambling = 1;
        } else {
            config.pitch_sharpening = 0;
            config.phase_scrambling = 0;
        }
    } else {
        config.pitch_sharpening = 1;
        config.phase_scrambling = 0;
    }

    if sub(coder_type, ACELP_MODE_MAX) > 0 {
        // keep pitch sharpening for RF_ALLPRED mode
        config.pitch_sharpening = 0;
        config.phase_scrambling = 0;
    }

    // Allocate bits and different modes
    config.bpf_mode = mode_table(&ACELP_BPF_MODE, mode_index, band_index, coder_type);
    bits = add(bits, at(&ACELP_BPF_BITS, config.bpf_mode));

    config.nrg_mode = mode_table(&ACELP_NRG_MODE, mode_index, band_index, coder_type);
    config.nrg_bits = at(&ACELP_NRG_BITS, config.nrg_mode);
    bits = add(bits, config.nrg_bits);

    config.ltp_mode = mode_table(&ACELP_LTP_MODE, mode_index, band_index, coder_type);

    config.ltp_bits = 0;

    config.ltf_mode = mode_table(&ACELP_LTF_MODE, mode_index, band_index, coder_type);

    config.ltf_bits = at(&ACELP_LTF_BITS, config.ltf_mode);
    if sub(nb_subfr, 5) == 0 && sub(config.ltf_bits, 4) == 0 {
        config.ltf_bits = add(config.ltf_bits, 1);
    }
    bits = add(bits, config.ltf_bits);

    let subframes = (nb_subfr.max(0) as usize).min(config.gains_mode.len());
    for i in 0..subframes {
        config.gains_mode[i] = mode_table(&ACELP_GAINS_MODE, mode_index, band_index, coder_type);

        // skip subframe 1, 3 gain encoding, and use from subframe 0, and 3, respectively
        if sub(coder_type, ACELP_MODE_MAX) >= 0 && (i == 1 || i == 3) {
            config.gains_mode[i] = 0;
        }

        bits = add(bits, at(&ACELP_GAINS_BITS, config.gains_mode[i]));

        let ltp_bits_sfr = usize::try_from(config.ltp_mode)
            .ok()
            .and_then(|mode| ACELP_LTP_BITS_SFR.get(mode))
            .map_or(0, |row| row[i]);
        bits = add(bits, ltp_bits_sfr);
        config.ltp_bits = add(config.ltp_bits, ltp_bits_sfr);
    }

    // Innovation

    if sub(bits_frame, bits) < 0 {
        // the reference prints "Warning: bits per frame too low"
        return -1;
    }

    if sub(coder_type, RF_ALLPRED) == 0 {
        config.fixed_cdk_index[..subframes].fill(-1);
    } else if sub(coder_type, RF_GENPRED) == 0 {
        config.fixed_cdk_index[0] = 0; // 7 bits
        config.fixed_cdk_index[1] = -1;
        config.fixed_cdk_index[2] = 0; // 7 bits
        config.fixed_cdk_index[3] = -1;
        config.fixed_cdk_index[4] = -1;
        bits = add(bits, 14);
    } else if sub(coder_type, RF_NOPRED) == 0 {
        config.fixed_cdk_index[..subframes].fill(0);
        bits = add(bits, 28);
    } else {
        bits = add(
            bits,
            bits_alloc_adjust_acelp_fixed_cdk(
                sub(bits_frame, bits),
                &mut config.fixed_cdk_index,
                nb_subfr,
            ),
        );
    }

    let remaining_bits = sub(bits_frame, bits);

    // Sanity check
    if remaining_bits < 0 {
        bits = -1;
    }

    bits
}

/// `BITS_ALLOC_adjust_generic`: choose the pulse configuration `fixed_cdk_index[sfr]` of every
/// subframe so that the bits used track the budget `bits_frame` evenly, from the per-subframe
/// costs `pulseconfigbits` (ascending, `pulseconfig_size` entries). Returns the bits used per
/// subframe, or `bits_frame + 1` when the budget cannot hold the cheapest configuration.
fn bits_alloc_adjust_generic(
    bits_frame: i16,
    fixed_cdk_index: &mut [i16],
    nb_subfr: i16,
    pulseconfigbits: &[i16],
    pulseconfig_size: i16,
) -> i16 {
    let bits_subframe2 = bits_frame;
    let mut inb_subfr: i16 = 8192; // 1.0f/NB_SUBFR Q15
    if sub(nb_subfr, NB_SUBFR16K) == 0 {
        inb_subfr = 6554; // 1.0f/NB_SUBFR16k Q15
    }

    // The configuration costs are read at a mode that stays inside the table in a valid frame;
    // anywhere else the reference reads out of bounds, which reads as 0 here.
    let cost = |k: i16| at(pulseconfigbits, k);

    if sub(bits_subframe2, i_mult2(cost(0), nb_subfr)) < 0 {
        // not in final code - not instrumented
        return add(bits_frame, 1); // Not enough bits for lowest mode. -> trigger alarm
    }

    // search cdk-index for first subframe
    let mut k: i16 = 0;
    while sub(k, sub(pulseconfig_size, 1)) < 0 {
        if i_mult2(cost(k), nb_subfr) > bits_subframe2 {
            k = sub(k, 1); // previous mode did not exceed bit-budget
            break;
        }
        k += 1;
    }

    if i_mult2(cost(k), nb_subfr) > bits_subframe2 {
        k = sub(k, 1); // previous mode did not exceed bit-budget
    }

    fixed_cdk_index[0] = k;
    let mut bitsused = i_mult2(cost(k), nb_subfr);

    for sfr in 1..nb_subfr.max(0) {
        // bits_currsubframe = (int)(((float)sfr+1.0f)*bits_subframe) - bitsused;
        let bits_currsubframe = sub(add(i_mult2(sfr, bits_subframe2), bits_subframe2), bitsused);

        // try increasing mode while below threshold
        while sub(k, pulseconfig_size - 1) < 0
            && sub(i_mult2(cost(add(k, 1)), nb_subfr), bits_currsubframe) <= 0
        {
            k = add(k, 1);
        }

        // try decreasing mode until below threshold
        while i_mult2(cost(k), nb_subfr) > bits_currsubframe {
            k = sub(k, 1);

            if k == 0 {
                break;
            }
        }

        // store mode
        if let Some(slot) = fixed_cdk_index.get_mut(sfr as usize) {
            *slot = k;
        }
        bitsused = add(bitsused, i_mult2(cost(k), nb_subfr));
    }

    mult_r(bitsused, inb_subfr)
}

/// `BITS_ALLOC_adjust_acelp_fixed_cdk`: the fixed-codebook (pulse configuration) index of every
/// subframe for the budget `bits_frame`; returns the bits used per subframe on average, or
/// `bits_frame + 1` when even the cheapest configuration does not fit.
pub fn bits_alloc_adjust_acelp_fixed_cdk(
    bits_frame: i16,
    fixed_cdk_index: &mut [i16],
    nb_subfr: i16,
) -> i16 {
    bits_alloc_adjust_generic(
        bits_frame,
        fixed_cdk_index,
        nb_subfr,
        &ACELP_CDK_BITS,
        ACELP_FIXED_CDK_NB,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_low_rate_narrow_band_config_uses_the_pre_emphasis_settings() {
        let mut config = AcelpConfig::zeroed();
        bits_alloc_init_config_acelp(9600, 0, 4, &mut config);
        assert_eq!(config.mode_index, 0);
        assert_eq!((config.pre_emphasis, config.formant_tilt), (1, 0));
        bits_alloc_init_config_acelp(13200, 0, 4, &mut config);
        assert_eq!(config.mode_index, 1);
        assert_eq!((config.pre_emphasis, config.formant_tilt), (0, 1));
        bits_alloc_init_config_acelp(13200, 0, 5, &mut config);
        assert_eq!(config.voice_tilt, 2);
        assert_eq!(config.formant_enh_num, FORMANT_SHARPENING_G1_16K);
    }

    #[test]
    fn too_small_a_budget_is_refused_and_an_ample_one_is_spent_per_subframe() {
        let mut config = AcelpConfig::zeroed();
        bits_alloc_init_config_acelp(13200, 0, 4, &mut config);
        assert_eq!(bits_alloc_config_acelp(8, 3, &mut config, 0, 4), -1);
        let mut config = AcelpConfig::zeroed();
        bits_alloc_init_config_acelp(13200, 0, 4, &mut config);
        let bits = bits_alloc_config_acelp(300, 3, &mut config, 0, 4);
        assert!(bits > 0 && bits <= 300);
        assert!(config.fixed_cdk_index[..4].iter().all(|&index| index >= 0));
    }

    #[test]
    fn fixed_codebook_choice_never_exceeds_the_budget_it_reports() {
        let mut index = [0i16; 5];
        let used = bits_alloc_adjust_acelp_fixed_cdk(100, &mut index, 4);
        assert!(used <= 100);
        assert_eq!(bits_alloc_adjust_acelp_fixed_cdk(0, &mut index, 4), 1);
    }
}

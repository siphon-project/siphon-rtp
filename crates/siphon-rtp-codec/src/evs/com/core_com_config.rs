//! Core configuration helpers shared by encoder and decoder (TS 26.442 `lib_com/core_com_config_fx.c`).

use crate::evs::cnst::{
    FB, FSCALE_DENOM, HQ_16K40, LPC_SHAPED_ARI_MAX_RATE, NB, PIT_FR1_12K8, PIT_FR1_16K,
    PIT_FR1_25K6, PIT_FR1_32K, PIT_FR1_8B_12K8, PIT_FR1_8B_16K, PIT_FR1_8B_25K6, PIT_FR1_8B_32K,
    PIT_FR2_12K8, PIT_FR2_16K, PIT_FR2_25K6, PIT_FR2_32K, PIT_MAX_12K8, PIT_MAX_16K, PIT_MAX_25K6,
    PIT_MAX_32K, PIT_MIN_12K8, PIT_MIN_16K, PIT_MIN_25K6, PIT_MIN_32K, SWB, WB,
};

/// `HQ_32k`.
const HQ_32K: i32 = 32000;

/// `getTcxonly`: whether the bit rate runs the TCX-only (no ACELP) MODE2 configuration.
#[must_use]
pub fn get_tcxonly(bitrate: i32) -> i8 {
    i8::from(bitrate > 32000)
}

/// `getCtxHm`: whether the context-based harmonic model is used.
#[must_use]
pub fn get_ctx_hm(bitrate: i32, rf_flag: i16) -> i8 {
    i8::from(bitrate > i32::from(LPC_SHAPED_ARI_MAX_RATE) && bitrate <= 64000 && rf_flag == 0)
}

/// `getResq`: whether residual quantisation is used.
#[must_use]
pub fn get_resq(bitrate: i32) -> i8 {
    i8::from(bitrate <= 64000)
}

/// `getTnsAllowed`: whether TNS is allowed.
#[must_use]
pub fn get_tns_allowed(bitrate: i32, igf: i16) -> i8 {
    if igf != 0 {
        i8::from(bitrate > i32::from(HQ_16K40))
    } else {
        i8::from(bitrate > HQ_32K)
    }
}

/// `sr2fscale`: a sampling rate as a multiple of 12.8 kHz, in units of `1/FSCALE_DENOM`.
///
/// The reference asserts on any other rate; this returns 0 there, as its release build does.
#[must_use]
pub fn sr2fscale(sr: i32) -> i16 {
    let denom = i32::from(FSCALE_DENOM);
    let fscale = match sr {
        8000 | 12800 | 16000 | 25600 | 32000 | 48000 => denom * sr / 12800,
        _ => 0,
    };
    fscale as i16
}

/// `getCoreSamplerateMode2`: the MODE2 core sampling rate for a bit rate and bandwidth. The
/// reference asserts on a combination that has none; this returns its initial `-1` there.
#[must_use]
pub fn get_core_samplerate_mode2(bitrate: i32, bandwidth: i16, rf_mode: i16) -> i32 {
    let swb_or_fb = bandwidth == SWB || bandwidth == FB;
    if bandwidth == NB
        || (bandwidth == WB && bitrate < 13200)
        || (bandwidth == SWB && bitrate <= 13200)
        || rf_mode == 1
    {
        12800
    } else if bandwidth == WB || (bitrate <= 32000 && swb_or_fb) {
        16000
    } else if swb_or_fb && bitrate <= 64000 {
        25600
    } else if swb_or_fb {
        32000
    } else {
        -1
    }
}

/// `getTcxBandwidth`: the TCX bandwidth as a fraction of the core rate (Q15).
#[must_use]
pub fn get_tcx_bandwidth(bandwidth: i16) -> i16 {
    if bandwidth == NB {
        10240
    } else {
        16384
    }
}

/// `getTcxLtp`: whether the TCX long-term postfilter runs at this core rate.
#[must_use]
pub fn get_tcx_ltp(sr_core: i32) -> i8 {
    i8::from(sr_core <= 25600)
}

/// Pitch lag limits for one core sampling rate, as `initPitchLagParameters` returns them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PitchLagParameters {
    pub pit_min: i16,
    pub pit_fr1: i16,
    pub pit_fr1b: i16,
    pub pit_fr2: i16,
    pub pit_max: i16,
    /// The function's return value, the maximum pitch resolution.
    pub pit_res_max: i16,
}

/// `initPitchLagParameters`: the pitch lag limits and resolution for a core sampling rate.
#[must_use]
pub fn init_pitch_lag_parameters(sr_core: i32) -> PitchLagParameters {
    match sr_core {
        12800 => PitchLagParameters {
            pit_min: PIT_MIN_12K8,
            pit_fr1: PIT_FR1_12K8,
            pit_fr1b: PIT_FR1_8B_12K8,
            pit_fr2: PIT_FR2_12K8,
            pit_max: PIT_MAX_12K8,
            pit_res_max: 4,
        },
        16000 => PitchLagParameters {
            pit_min: PIT_MIN_16K,
            pit_fr1: PIT_FR1_16K,
            pit_fr1b: PIT_FR1_8B_16K,
            pit_fr2: PIT_FR2_16K,
            pit_max: PIT_MAX_16K,
            pit_res_max: 6,
        },
        25600 => PitchLagParameters {
            pit_min: PIT_MIN_25K6,
            pit_fr1: PIT_FR1_25K6,
            pit_fr1b: PIT_FR1_8B_25K6,
            pit_fr2: PIT_FR2_25K6,
            pit_max: PIT_MAX_25K6,
            pit_res_max: 4,
        },
        // sr_core == 32000
        _ => PitchLagParameters {
            pit_min: PIT_MIN_32K,
            pit_fr1: PIT_FR1_32K,
            pit_fr1b: PIT_FR1_8B_32K,
            pit_fr2: PIT_FR2_32K,
            pit_max: PIT_MAX_32K,
            pit_res_max: 6,
        },
    }
}

/// `getNumTcxCodedLines`: MDCT lines TCX codes for a bandwidth (0 for an unknown one).
#[must_use]
pub fn get_num_tcx_coded_lines(bwidth: i16) -> i16 {
    match bwidth {
        NB => 160,
        WB => 320,
        SWB => 640,
        FB => 960,
        _ => 0,
    }
}

/// `getTcxLpcShapedAri`: whether TCX uses the LPC-shaped arithmetic coder. `bwidth` is unused by
/// the reference too.
#[must_use]
pub fn get_tcx_lpc_shaped_ari(total_brate: i32, _bwidth: i16, rf_mode: i16) -> i16 {
    i16::from(total_brate <= i32::from(LPC_SHAPED_ARI_MAX_RATE) || rf_mode != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode2_core_rates_follow_the_bandwidth_table() {
        assert_eq!(get_core_samplerate_mode2(9600, WB, 0), 12800);
        assert_eq!(get_core_samplerate_mode2(16400, WB, 0), 16000);
        assert_eq!(get_core_samplerate_mode2(48000, SWB, 0), 25600);
        assert_eq!(get_core_samplerate_mode2(96000, FB, 0), 32000);
        assert_eq!(get_core_samplerate_mode2(96000, 7, 0), -1);
        assert_eq!(sr2fscale(16000), 640);
        assert_eq!(sr2fscale(44100), 0);
        assert_eq!(init_pitch_lag_parameters(16000).pit_res_max, 6);
    }
}

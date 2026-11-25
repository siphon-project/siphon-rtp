//! The AMR-WB IO high band of `lib_dec/hf_synth_fx.c` (`AdaptiveStartBand_fx`, `envelope_fx` with
//! `EnhanceClass_fx`, `hf_synth_amr_wb_reset_fx`, `hf_synth_amr_wb_fx` with `hf_synthesis_amr_wb_fx`)
//! against `fn_p4io_hf_synth`.

use siphon_rtp_codec::evs::dec::hf_synth::{
    adaptive_start_band, envelope, hf_synth_amr_wb, hf_synth_amr_wb_reset, HfSynthAmrWbState,
};

use crate::common::{corpus, mismatch};

#[test]
fn adaptive_start_band_matches_the_reference() {
    let Some(cases) = corpus("p4io_hf_synth", "adaptive_start_band") else {
        return;
    };
    for case in &cases {
        let mut start_band = -1;
        let mut voicing_flag = case.i16("voicing_flag");
        let mut start_band_old = case.i16("start_band_old");
        let mut opt_crit_old = case.i32("opt_crit_old");
        adaptive_start_band(
            &mut start_band,
            case.i32("rate"),
            &case.i16s("lsf"),
            case.i16("voicing_fac"),
            case.i16("clas"),
            &mut voicing_flag,
            &mut start_band_old,
            &mut opt_crit_old,
        );
        let message = mismatch(case, "start_band", &start_band, &case.out_i16("start_band"))
            .or_else(|| {
                mismatch(
                    case,
                    "voicing_flag",
                    &voicing_flag,
                    &case.out_i16("voicing_flag"),
                )
            })
            .or_else(|| {
                mismatch(
                    case,
                    "start_band_old",
                    &start_band_old,
                    &case.out_i16("start_band_old"),
                )
            })
            .or_else(|| {
                mismatch(
                    case,
                    "opt_crit_old",
                    &opt_crit_old,
                    &case.out_i32("opt_crit_old"),
                )
            });
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}

#[test]
fn envelope_matches_the_reference() {
    let Some(cases) = corpus("p4io_hf_synth", "envelope") else {
        return;
    };
    for case in &cases {
        let mut ap = [0i16; 17];
        let mut sub_gain = -1;
        let mut prev_r = case.i16("prev_r");
        let mut voice_fac = case.i16("voice_fac");
        let mut unvoicing = case.i16("unvoicing");
        let mut unvoicing_sm = case.i16("unvoicing_sm");
        let mut unvoicing_flag = case.i16("unvoicing_flag");
        envelope(
            case.i32("rate"),
            &case.i16s("aq"),
            &mut ap,
            &mut sub_gain,
            case.i16("tilt0"),
            case.i16("tilt"),
            case.i16("voice_factor"),
            &mut prev_r,
            &mut voice_fac,
            &mut unvoicing,
            &mut unvoicing_sm,
            &mut unvoicing_flag,
        );
        let message = mismatch(case, "ap", &ap.to_vec(), &case.out_i16s("ap"))
            .or_else(|| mismatch(case, "sub_gain", &sub_gain, &case.out_i16("sub_gain")))
            .or_else(|| mismatch(case, "prev_r", &prev_r, &case.out_i16("prev_r")))
            .or_else(|| mismatch(case, "voice_fac", &voice_fac, &case.out_i16("voice_fac")))
            .or_else(|| mismatch(case, "unvoicing", &unvoicing, &case.out_i16("unvoicing")))
            .or_else(|| {
                mismatch(
                    case,
                    "unvoicing_sm",
                    &unvoicing_sm,
                    &case.out_i16("unvoicing_sm"),
                )
            })
            .or_else(|| {
                mismatch(
                    case,
                    "unvoicing_flag",
                    &unvoicing_flag,
                    &case.out_i16("unvoicing_flag"),
                )
            });
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}

/// The scalar memories of the high band as the oracle names them.
struct Memories {
    prev_r: i16,
    fmerit_w_sm: i16,
    frame_count: i16,
    ne_min: i16,
    fmerit_m_sm: i16,
    voice_fac: i16,
    unvoicing: i16,
    unvoicing_sm: i16,
    unvoicing_flag: i16,
    voicing_flag: i16,
    start_band_old: i16,
    opt_crit_old: i32,
}

impl Memories {
    fn compare(&self, case: &crate::common::Case) -> Option<String> {
        let scalars = [
            ("prev_r", self.prev_r),
            ("frame_count", self.frame_count),
            ("ne_min", self.ne_min),
            ("voice_fac", self.voice_fac),
            ("unvoicing", self.unvoicing),
            ("unvoicing_sm", self.unvoicing_sm),
            ("unvoicing_flag", self.unvoicing_flag),
            ("voicing_flag", self.voicing_flag),
            ("start_band_old", self.start_band_old),
            ("fmerit_w_sm", self.fmerit_w_sm),
            ("fmerit_m_sm", self.fmerit_m_sm),
        ];
        for (name, value) in scalars {
            if let Some(message) = mismatch(case, name, &value, &case.out_i16(name)) {
                return Some(message);
            }
        }
        mismatch(
            case,
            "opt_crit_old",
            &self.opt_crit_old,
            &case.out_i32("opt_crit_old"),
        )
    }
}

#[test]
fn hf_synth_amr_wb_reset_matches_the_reference() {
    let Some(cases) = corpus("p4io_hf_synth", "reset") else {
        return;
    };
    for case in &cases {
        let mut seed2 = case.i16("seed2");
        let mut mem_syn_hf = case.i16s("mem_syn_hf");
        let mut mem_hp_interp = case.i16s("mem_hp_interp");
        let mut delay_syn_hf = case.i16s("delay_syn_hf");
        let mut memories = Memories {
            prev_r: 9,
            fmerit_w_sm: 9,
            frame_count: 9,
            ne_min: 9,
            fmerit_m_sm: 9,
            voice_fac: 9,
            unvoicing: 9,
            unvoicing_sm: 9,
            unvoicing_flag: 9,
            voicing_flag: 9,
            start_band_old: 9,
            opt_crit_old: 9,
        };
        let mut state = HfSynthAmrWbState {
            mem_syn_hf: &mut mem_syn_hf,
            delay_syn_hf: &mut delay_syn_hf,
            prev_r: &mut memories.prev_r,
            fmerit_w_sm: &mut memories.fmerit_w_sm,
            mem_hp_interp: &mut mem_hp_interp,
            frame_count: &mut memories.frame_count,
            ne_min: &mut memories.ne_min,
            fmerit_m_sm: &mut memories.fmerit_m_sm,
            voice_fac: &mut memories.voice_fac,
            unvoicing: &mut memories.unvoicing,
            unvoicing_sm: &mut memories.unvoicing_sm,
            unvoicing_flag: &mut memories.unvoicing_flag,
            voicing_flag: &mut memories.voicing_flag,
            start_band_old: &mut memories.start_band_old,
            opt_crit_old: &mut memories.opt_crit_old,
        };
        hf_synth_amr_wb_reset(&mut seed2, &mut state);
        let message = mismatch(case, "seed2", &seed2, &case.out_i16("seed2"))
            .or_else(|| {
                mismatch(
                    case,
                    "mem_syn_hf",
                    &mem_syn_hf,
                    &case.out_i16s("mem_syn_hf"),
                )
            })
            .or_else(|| {
                mismatch(
                    case,
                    "mem_hp_interp",
                    &mem_hp_interp,
                    &case.out_i16s("mem_hp_interp"),
                )
            })
            .or_else(|| {
                mismatch(
                    case,
                    "delay_syn_hf",
                    &delay_syn_hf,
                    &case.out_i16s("delay_syn_hf"),
                )
            })
            .or_else(|| memories.compare(case));
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}

#[test]
fn hf_synth_amr_wb_matches_the_reference() {
    let Some(cases) = corpus("p4io_hf_synth", "hf_synth_amr_wb") else {
        return;
    };
    for case in &cases {
        let mut synth = case.i16s("synth");
        let mut synth_out = case.i16s("synth_out");
        let mut mem_syn_hf = case.i16s("mem_syn_hf");
        let mut delay_syn_hf = case.i16s("delay_syn_hf");
        let mut mem_hp_interp = case.i16s("mem_hp_interp");
        let mut memories = Memories {
            prev_r: case.i16("prev_r"),
            fmerit_w_sm: case.i16("fmerit_w_sm"),
            frame_count: case.i16("frame_count"),
            ne_min: case.i16("ne_min"),
            fmerit_m_sm: case.i16("fmerit_m_sm"),
            voice_fac: case.i16("voice_fac"),
            unvoicing: case.i16("unvoicing"),
            unvoicing_sm: case.i16("unvoicing_sm"),
            unvoicing_flag: case.i16("unvoicing_flag"),
            voicing_flag: case.i16("voicing_flag"),
            start_band_old: case.i16("start_band_old"),
            opt_crit_old: case.i32("opt_crit_old"),
        };
        {
            let mut state = HfSynthAmrWbState {
                mem_syn_hf: &mut mem_syn_hf,
                delay_syn_hf: &mut delay_syn_hf,
                prev_r: &mut memories.prev_r,
                fmerit_w_sm: &mut memories.fmerit_w_sm,
                mem_hp_interp: &mut mem_hp_interp,
                frame_count: &mut memories.frame_count,
                ne_min: &mut memories.ne_min,
                fmerit_m_sm: &mut memories.fmerit_m_sm,
                voice_fac: &mut memories.voice_fac,
                unvoicing: &mut memories.unvoicing,
                unvoicing_sm: &mut memories.unvoicing_sm,
                unvoicing_flag: &mut memories.unvoicing_flag,
                voicing_flag: &mut memories.voicing_flag,
                start_band_old: &mut memories.start_band_old,
                opt_crit_old: &mut memories.opt_crit_old,
            };
            hf_synth_amr_wb(
                case.i32("rate"),
                case.i16("output_frame"),
                &case.i16s("aq"),
                &case.i16s("exc"),
                &mut synth,
                &mut state,
                case.i16("amr_io_class"),
                &mut synth_out,
                case.i16("fmerit"),
                &case.i16s("hf_gain"),
                &case.i16s("voice_factors"),
                &case.i16s("pitch_buf"),
                case.i16("ng_ener_st"),
                &case.i16s("lsf_new"),
                case.i16("q_exc"),
                0,
            );
        }
        let message = mismatch(case, "synth", &synth, &case.out_i16s("synth"))
            .or_else(|| mismatch(case, "synth_out", &synth_out, &case.out_i16s("synth_out")))
            .or_else(|| {
                mismatch(
                    case,
                    "mem_syn_hf",
                    &mem_syn_hf,
                    &case.out_i16s("mem_syn_hf"),
                )
            })
            .or_else(|| {
                mismatch(
                    case,
                    "delay_syn_hf",
                    &delay_syn_hf,
                    &case.out_i16s("delay_syn_hf"),
                )
            })
            .or_else(|| {
                mismatch(
                    case,
                    "mem_hp_interp",
                    &mem_hp_interp,
                    &case.out_i16s("mem_hp_interp"),
                )
            })
            .or_else(|| memories.compare(case));
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}

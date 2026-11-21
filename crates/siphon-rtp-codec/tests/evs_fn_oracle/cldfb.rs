//! `lib_com/cldfb.c` against `fn_cldfb`. The static helpers (`cplxMult*`, `cplxMultAdd*`,
//! `calcModulation`, `calcModulationAndFolding`, `cldfb_init_proto_and_twiddles`,
//! `cldfb_get_memory_length`) are proven through the public functions: analysis runs at every band
//! count (10, 16, 20, 32, 40, 60), synthesis at every synthesis band count (10, 20, 40, 60), each
//! over one to four consecutive frames on the same bank so the state memory carries over.
//! `resampleCldfb` runs the decoder's sequence (open at 48 or 16 kHz, first-frame resample, then
//! rate switches with analysis frames between); `cldfb_restore_memory` follows a save and a
//! perturbation, half the time with the band count changed so its `lerp` branch runs.

use siphon_rtp_codec::evs::com::cldfb::{
    cldfb_analysis_filtering, cldfb_reset_memory, cldfb_restore_memory, cldfb_save_memory,
    cldfb_synthesis_filtering, configure_cldfb, delete_cldfb, open_cldfb, resample_cldfb,
    CLDFB_ROW,
};
use siphon_rtp_codec::evs::dec::state::{CldfbFilterBank, CldfbScaleFactor};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn open(r#type: i16, bands: i16, frame: i16) -> Box<CldfbFilterBank> {
    let mut handle = None;
    open_cldfb(&mut handle, r#type, bands, frame);
    handle.expect("open_cldfb leaves a bank")
}

#[test]
fn open_and_configure_match_the_reference() {
    let Some(cases) = corpus("cldfb", "open") else {
        return;
    };
    for case in &cases {
        let mut bank = open(case.i16("type"), case.i16("bands"), case.i16("frame"));
        if case.i16("reconfigure") == 1 {
            configure_cldfb(&mut bank, case.i16("bands2"), case.i16("frame2"));
        }
        let scalars = [
            ("no_channels", bank.no_channels),
            ("no_col", bank.no_col),
            ("p_filter_length", bank.p_filter_length),
            ("filter_scale", bank.filter_scale),
            ("syn_gain", bank.syn_gain),
            ("lsb", bank.lsb),
            ("usb", bank.usb),
            ("zeros", bank.zeros),
            ("ana_scalefactor", bank.ana_scalefactor),
            ("syn_scalefactor", bank.syn_scalefactor),
            ("out_scalefactor", bank.out_scalefactor),
            ("syn_filter_headroom", bank.syn_filter_headroom),
            ("flags", bank.flags as i16),
            ("bands_to_zero", bank.bands_to_zero),
            ("filtermode", bank.filtermode),
            ("type", bank.r#type),
            ("memory_length", bank.memory_length),
            ("scale", bank.scale),
            ("eg", bank.filter_states_eg),
        ];
        for (name, value) in scalars {
            check(case, name, &value, &case.out_i16(name));
        }
        let m = bank.no_channels as usize;
        check(
            case,
            "states_e",
            &bank.filter_states_e.to_vec(),
            &case.out_i16s("states_e"),
        );
        check(
            case,
            "p_filter",
            &bank.p_filter[..10 * m].to_vec(),
            &case.out_i16s("p_filter"),
        );
        check(
            case,
            "r_rot",
            &bank.r_rot_vctr[..m / 2].to_vec(),
            &case.out_i16s("r_rot"),
        );
        check(
            case,
            "i_rot",
            &bank.i_rot_vctr[..m / 2].to_vec(),
            &case.out_i16s("i_rot"),
        );
        assert!(bank.filter_states.iter().all(|&v| v == 0), "{}", case.line);
        let mut handle = Some(bank);
        delete_cldfb(&mut handle);
        assert!(handle.is_none());
    }
}

fn rows(values: &[i32], slots: usize, m: usize) -> Vec<[i32; CLDFB_ROW]> {
    let mut rows = vec![[0i32; CLDFB_ROW]; 16];
    for k in 0..slots {
        rows[k][..m].copy_from_slice(&values[k * m..(k + 1) * m]);
    }
    rows
}

fn flatten(rows: &[[i32; CLDFB_ROW]], slots: usize, m: usize) -> Vec<i32> {
    rows[..slots]
        .iter()
        .flat_map(|row| row[..m].iter().copied())
        .collect()
}

#[test]
fn analysis_matches_the_reference_over_consecutive_frames() {
    let Some(cases) = corpus("cldfb", "analysis") else {
        return;
    };
    for case in &cases {
        let m = case.i16("m");
        let max_bands = case.i16("max_bands");
        let from_60 = max_bands != m;
        let mut bank = open(
            siphon_rtp_codec::evs::cnst::CLDFB_ANALYSIS,
            max_bands,
            if from_60 { 320 } else { 16 * m },
        );
        if from_60 {
            configure_cldfb(&mut bank, m, 16 * m);
        }
        bank.filter_states.copy_from_slice(&case.i16s("states"));
        bank.filter_states_e.copy_from_slice(&case.i16s("states_e"));
        bank.filter_states_eg = case.i16("eg");
        let mut scale_factor = CldfbScaleFactor::zeroed();
        scale_factor.lb_scale = case.i16("lb_scale");
        let mu = m as usize;
        for frame in 0..case.i16("frames") {
            let slots = case.i16(&format!("slots{frame}"));
            let mut r = vec![[0i32; CLDFB_ROW]; 16];
            let mut i = vec![[0i32; CLDFB_ROW]; 16];
            cldfb_analysis_filtering(
                &mut bank,
                &mut r,
                &mut i,
                &mut scale_factor,
                &case.i16s(&format!("time{frame}")),
                case.i16(&format!("time_e{frame}")),
                slots,
            );
            let slots = slots as usize;
            check(
                case,
                &format!("r{frame}"),
                &flatten(&r, slots, mu),
                &case.out_i32s(&format!("r{frame}")),
            );
            check(
                case,
                &format!("i{frame}"),
                &flatten(&i, slots, mu),
                &case.out_i32s(&format!("i{frame}")),
            );
            check(
                case,
                &format!("lb_scale{frame}"),
                &scale_factor.lb_scale,
                &case.out_i16(&format!("lb_scale{frame}")),
            );
        }
        check(
            case,
            "states",
            &bank.filter_states,
            &case.out_i16s("states"),
        );
        check(
            case,
            "states_e",
            &bank.filter_states_e.to_vec(),
            &case.out_i16s("states_e"),
        );
        check(case, "eg", &bank.filter_states_eg, &case.out_i16("eg"));
    }
}

#[test]
fn synthesis_matches_the_reference_over_consecutive_frames() {
    let Some(cases) = corpus("cldfb", "synthesis") else {
        return;
    };
    for case in &cases {
        let m = case.i16("m");
        let mu = m as usize;
        let mut bank = open(siphon_rtp_codec::evs::cnst::CLDFB_SYNTHESIS, m, 16 * m);
        bank.filter_states.copy_from_slice(&case.i16s("states"));
        bank.filter_states_eg = case.i16("eg");
        for frame in 0..case.i16("frames") {
            bank.lsb = case.i16(&format!("lsb{frame}"));
            bank.usb = case.i16(&format!("usb{frame}"));
            bank.bands_to_zero = case.i16(&format!("bz{frame}"));
            let mut scale_factor = CldfbScaleFactor::zeroed();
            scale_factor.lb_scale = case.i16(&format!("lb_scale{frame}"));
            scale_factor.hb_scale = case.i16(&format!("hb_scale{frame}"));
            let slots = case.i16(&format!("slots{frame}"));
            let r = rows(&case.i32s(&format!("r{frame}")), slots as usize, mu);
            let i = rows(&case.i32s(&format!("i{frame}")), slots as usize, mu);
            let mut out = vec![0i16; 16 * mu];
            cldfb_synthesis_filtering(
                &mut bank,
                &r,
                &i,
                &scale_factor,
                &mut out,
                case.i16(&format!("time_e{frame}")),
                slots,
            );
            out.truncate(slots as usize * mu);
            check(
                case,
                &format!("out{frame}"),
                &out,
                &case.out_i16s(&format!("out{frame}")),
            );
        }
        check(
            case,
            "states",
            &bank.filter_states,
            &case.out_i16s("states"),
        );
        check(case, "eg", &bank.filter_states_eg, &case.out_i16("eg"));
    }
}

fn prepared(case: &Case) -> Box<CldfbFilterBank> {
    let m = case.i16("m");
    let mut bank = open(case.i16("type"), m, 16 * m);
    bank.filter_states.copy_from_slice(&case.i16s("states"));
    bank.filter_states_e.copy_from_slice(&case.i16s("states_e"));
    bank.filter_states_eg = case.i16("eg");
    bank
}

#[test]
fn save_memory_matches_the_reference() {
    let Some(cases) = corpus("cldfb", "save_memory") else {
        return;
    };
    for case in &cases {
        let mut bank = prepared(case);
        cldfb_save_memory(&mut bank);
        check(
            case,
            "memory_length",
            &bank.memory_length,
            &case.out_i16("memory_length"),
        );
        check(case, "memory", &bank.memory, &case.out_i16s("memory"));
        check(
            case,
            "states",
            &bank.filter_states,
            &case.out_i16s("states"),
        );
    }
}

#[test]
fn reset_memory_matches_the_reference() {
    let Some(cases) = corpus("cldfb", "reset_memory") else {
        return;
    };
    for case in &cases {
        let mut bank = prepared(case);
        cldfb_reset_memory(&mut bank);
        check(
            case,
            "states",
            &bank.filter_states,
            &case.out_i16s("states"),
        );
        check(
            case,
            "states_e",
            &bank.filter_states_e.to_vec(),
            &case.out_i16s("states_e"),
        );
        check(case, "eg", &bank.filter_states_eg, &case.out_i16("eg"));
    }
}

#[test]
fn resample_matches_the_reference_over_rate_switches() {
    let Some(cases) = corpus("cldfb", "resample") else {
        return;
    };
    for case in &cases {
        let max_bands = case.i16("max_bands");
        let mut bank = open(siphon_rtp_codec::evs::cnst::CLDFB_ANALYSIS, max_bands, 320);
        let bands = case.i16("bands");
        resample_cldfb(&mut bank, bands, 16 * bands, 1);
        let mut scale_factor = CldfbScaleFactor::zeroed();
        let time_e = case.i16("time_e");
        for step in 0..case.i16("steps") {
            let mut r = vec![[0i32; CLDFB_ROW]; 16];
            let mut i = vec![[0i32; CLDFB_ROW]; 16];
            cldfb_analysis_filtering(
                &mut bank,
                &mut r,
                &mut i,
                &mut scale_factor,
                &case.i16s(&format!("time{step}")),
                time_e,
                16,
            );
            let next = case.i16(&format!("next{step}"));
            resample_cldfb(&mut bank, next, 16 * next, 0);
        }
        check(
            case,
            "no_channels",
            &bank.no_channels,
            &case.out_i16("no_channels"),
        );
        check(case, "no_col", &bank.no_col, &case.out_i16("no_col"));
        check(case, "flags", &(bank.flags as i16), &case.out_i16("flags"));
        check(
            case,
            "states",
            &bank.filter_states,
            &case.out_i16s("states"),
        );
        check(
            case,
            "states_e",
            &bank.filter_states_e.to_vec(),
            &case.out_i16s("states_e"),
        );
        check(case, "eg", &bank.filter_states_eg, &case.out_i16("eg"));
    }
}

#[test]
fn restore_memory_matches_the_reference() {
    let Some(cases) = corpus("cldfb", "restore_memory") else {
        return;
    };
    for case in &cases {
        let m = case.i16("m");
        let mut bank = open(case.i16("type"), 60, 960);
        configure_cldfb(&mut bank, m, 16 * m);
        bank.filter_states.copy_from_slice(&case.i16s("states"));
        bank.filter_states_e.copy_from_slice(&case.i16s("states_e"));
        bank.filter_states_eg = case.i16("eg");
        cldfb_save_memory(&mut bank);
        bank.filter_states
            .copy_from_slice(&case.i16s("states_between"));
        bank.filter_states_e
            .copy_from_slice(&case.i16s("states_e_between"));
        bank.filter_states_eg = case.i16("eg_between");
        bank.no_channels = case.i16("m2");
        cldfb_restore_memory(&mut bank);
        check(
            case,
            "states",
            &bank.filter_states,
            &case.out_i16s("states"),
        );
        check(
            case,
            "states_e",
            &bank.filter_states_e.to_vec(),
            &case.out_i16s("states_e"),
        );
        check(case, "eg", &bank.filter_states_eg, &case.out_i16("eg"));
        check(
            case,
            "memory_length",
            &bank.memory_length,
            &case.out_i16("memory_length"),
        );
        assert!(bank.memory.is_empty(), "{}", case.line);
    }
}

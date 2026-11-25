//! The IGF decoder (`lib_com/igf_base.c`, `lib_dec/igf_scf_dec.c`, `lib_dec/igf_dec.c`) against
//! `fn_m2igf_igf`. The state functions compare the whole decoder state after the call
//! (`state_capture.h`), the direct ones their buffers. `IGF_gridSetUp`, `IGF_MapBitRateToIndex`,
//! `IGF_ApplyTransFac` are proven through `set_mode` (every grid field is in the state);
//! `IGF_prep`, `IGF_calc`, `IGF_appl`, `IGF_getWhiteSpectralData`, `IGF_replaceTCXNoise_*`,
//! `IGF_getScaleFactor32Cond`, `IGF_setLinesToZero` through `apply_mono`; `IGF_RefineGrid` through
//! `set_mode`; the SCF arithmetic decoder (`IGFSCFDecoderOpen`, `Decode`, `Reset` and the static
//! `decode_sfe_vector_fx`, `arith_decode_residual_fx`, `arith_decode_bits_fx`, `quant_ctx_fx`)
//! through `read_level`.

use siphon_rtp_codec::evs::com::core_com_config::{get_cna_present, get_igf_present};
use siphon_rtp_codec::evs::com::igf_base::{
    igf_common_funcs_calc_sfb_energy_power_spec, igf_common_funcs_igf_get_cf_tables,
    igf_common_funcs_mdct_square_spec, IgfCfTables,
};
use siphon_rtp_codec::evs::dec::igf_dec::{
    igf_dec_apply_mono, igf_dec_copy_lpc_flat_spectrum, igf_dec_read_data, igf_dec_read_level,
    igf_dec_restore_tcx10_sub_frame_data, igf_dec_set_mode, igf_dec_store_tcx10_sub_frame_data,
    igf_dec_update_info,
};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus_sized, mismatch, Case};
use crate::state_case::{decoder_before, state_after};
use crate::state_dump;

const MODULE: &str = "m2igf_igf";

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

/// Select the SCF coder's ROM tables, which a state load does not restore (`init` sets them and
/// `IGFDecSetMode` points them at the bit rate's rows).
fn select_tables(st: &mut DecoderState, case: &Case) {
    let mut tables = IgfCfTables::empty();
    igf_common_funcs_igf_get_cf_tables(
        case.i32("rate"),
        case.i16("mode"),
        case.i16("rf"),
        &mut tables,
    );
    let decoder = &mut st.h_igf_dec.igf_data.h_arith_sc_fdec;
    decoder.cf_se00 = tables.cf_se00;
    decoder.cf_se01 = tables.cf_se01;
    decoder.cf_off_se01 = tables.cf_off_se01;
    decoder.cf_se02 = tables.cf_se02;
    decoder.cf_off_se02 = tables.cf_off_se02;
    decoder.cf_se10 = tables.cf_se10;
    decoder.cf_off_se10 = tables.cf_off_se10;
    decoder.cf_se11 = tables.cf_se11;
    decoder.cf_off_se11 = tables.cf_off_se11;
}

/// Replay `function` on `count` cases: build the "before" decoder, run `call`, compare the whole
/// state. Returns the number of cases compared and skipped (the reference did not return), or
/// `None` when the oracle is not built.
fn run_state(
    function: &str,
    count: usize,
    tables: bool,
    call: impl Fn(&mut DecoderState, &Case),
) -> Option<usize> {
    let cases = corpus_sized(MODULE, function, count)?;
    let mut compared = 0;
    for (index, case) in cases.iter().enumerate() {
        if case.outputs.contains_key("skip") {
            continue;
        }
        let mut st = decoder_before(case);
        if tables {
            select_tables(&mut st, case);
        }
        call(&mut st, case);
        let context = format!("{function} case {index}");
        state_dump::check(&mut st, &state_after(case), "st.", &context);
        compared += 1;
    }
    Some(compared)
}

#[test]
fn set_mode_matches_the_reference_on_the_whole_state() {
    let Some(compared) = run_state("set_mode", 300, false, |st, case| {
        igf_dec_set_mode(
            &mut st.h_igf_dec,
            case.i32("rate"),
            case.i16("mode"),
            case.i16("default_start"),
            case.i16("default_stop"),
            case.i16("rf"),
        );
    }) else {
        return;
    };
    assert_eq!(compared, 300);
}

#[test]
fn update_info_matches_the_reference_on_the_whole_state() {
    let Some(compared) = run_state("update_info", 200, true, |st, case| {
        igf_dec_update_info(&mut st.h_igf_dec, case.i16("idx"));
    }) else {
        return;
    };
    assert_eq!(compared, 200);
}

#[test]
fn copy_lpc_flat_spectrum_matches_the_reference_on_the_whole_state() {
    let Some(compared) = run_state("copy_flat", 200, true, |st, case| {
        igf_dec_copy_lpc_flat_spectrum(
            &mut st.h_igf_dec,
            &case.i32s("flat"),
            case.i16("flat_exp"),
            case.i16("idx"),
        );
    }) else {
        return;
    };
    assert_eq!(compared, 200);
}

#[test]
fn tcx10_subframe_store_and_restore_match_the_reference_on_the_whole_state() {
    let Some(compared) = run_state("store_restore", 200, true, |st, case| {
        if case.i16("restore") != 0 {
            igf_dec_restore_tcx10_sub_frame_data(&mut st.h_igf_dec, case.i16("sub_frame"));
        } else {
            igf_dec_store_tcx10_sub_frame_data(&mut st.h_igf_dec, case.i16("sub_frame"));
        }
    }) else {
        return;
    };
    assert_eq!(compared, 200);
}

#[test]
fn read_data_matches_the_reference_on_the_whole_state() {
    let Some(compared) = run_state("read_data", 300, true, |st, case| {
        igf_dec_read_data(st, case.i16("idx"), case.i16("indep"));
    }) else {
        return;
    };
    assert_eq!(compared, 300);
}

#[test]
fn read_level_matches_the_reference_on_the_whole_state() {
    let Some(compared) = run_state("read_level", 400, true, |st, case| {
        igf_dec_read_level(st, case.i16("idx"), case.i16("indep"));
    }) else {
        return;
    };
    assert!(compared > 380, "{compared} compared");
}

#[test]
fn apply_mono_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized(MODULE, "apply_mono", 600) else {
        return;
    };
    let mut compared = 0;
    let mut active = 0;
    for (index, case) in cases.iter().enumerate() {
        if case.outputs.contains_key("skip") {
            continue;
        }
        let mut st = decoder_before(case);
        select_tables(&mut st, case);
        let mut spectrum = case.i32s("spectrum");
        let mut spectrum_e = case.i16("spectrum_e");
        if st.h_igf_dec.info_igf_all_zero == 0 {
            active += 1;
        }
        igf_dec_apply_mono(
            &mut st.h_igf_dec,
            &mut spectrum,
            &mut spectrum_e,
            case.i16("idx"),
            case.i16("bfi"),
        );
        check(case, "spectrum", &spectrum, &case.out_i32s("spectrum"));
        check(case, "spectrum_e", &spectrum_e, &case.out_i16("spectrum_e"));
        let context = format!("apply_mono case {index}");
        state_dump::check(&mut st, &state_after(case), "st.", &context);
        compared += 1;
    }
    assert!(compared > 580, "{compared} compared");
    assert!(active > 400, "{active} cases ran IGF");
}

#[test]
fn config_tables_match_the_reference() {
    let Some(cases) = corpus_sized(MODULE, "config_tables", 300) else {
        return;
    };
    let (mut known, mut unknown) = (0, 0);
    for case in &cases {
        let mut tables = IgfCfTables::empty();
        let ret = igf_common_funcs_igf_get_cf_tables(
            case.i32("rate"),
            case.i16("mode"),
            case.i16("rf"),
            &mut tables,
        );
        check(case, "ret", &ret, &case.out_i16("ret"));
        if ret == 0 {
            unknown += 1;
            continue;
        }
        known += 1;
        check(
            case,
            "cf_se00",
            &tables.cf_se00[..28].to_vec(),
            &case.out_i16s("cf_se00"),
        );
        check(
            case,
            "cf_se01",
            &tables.cf_se01[..28].to_vec(),
            &case.out_i16s("cf_se01"),
        );
        check(
            case,
            "cf_off_se01",
            &tables.cf_off_se01,
            &case.out_i16("cf_off_se01"),
        );
        check(
            case,
            "cf_se02",
            &tables.cf_se02[..196].to_vec(),
            &case.out_i16s("cf_se02"),
        );
        check(
            case,
            "cf_off_se02",
            &tables.cf_off_se02[..7].to_vec(),
            &case.out_i16s("cf_off_se02"),
        );
        check(
            case,
            "cf_se10",
            &tables.cf_se10[..28].to_vec(),
            &case.out_i16s("cf_se10"),
        );
        check(
            case,
            "cf_off_se10",
            &tables.cf_off_se10,
            &case.out_i16("cf_off_se10"),
        );
        check(
            case,
            "cf_se11",
            &tables.cf_se11[..1372].to_vec(),
            &case.out_i16s("cf_se11"),
        );
        check(
            case,
            "cf_off_se11",
            &tables.cf_off_se11[..49].to_vec(),
            &case.out_i16s("cf_off_se11"),
        );
    }
    assert!(
        known > 200 && unknown > 10,
        "known {known}, unknown {unknown}"
    );
}

#[test]
fn mdct_square_spec_matches_the_reference() {
    let Some(cases) = corpus_sized(MODULE, "square_spec", 1000) else {
        return;
    };
    for case in &cases {
        let begin = case.i16("begin");
        let count = case.i16("count");
        let mut out = case.i32s("out");
        let mut out_e = case.i16("out_e");
        igf_common_funcs_mdct_square_spec(
            begin,
            begin + count,
            &case.i32s("spec"),
            case.i16("spec_e"),
            &mut out,
            &mut out_e,
            case.i16("offset"),
        );
        check(case, "out", &out, &case.out_i32s("out"));
        check(case, "out_e", &out_e, &case.out_i16("out_e"));
    }
}

#[test]
fn sfb_energy_matches_the_reference() {
    let Some(cases) = corpus_sized(MODULE, "sfb_energy", 1000) else {
        return;
    };
    for case in &cases {
        let power = case.i32s("power");
        let mut energy = case.i32s("energy");
        let mut energy_e = case.i16s("energy_e");
        igf_common_funcs_calc_sfb_energy_power_spec(
            case.i16("start"),
            case.i16("stop"),
            &case.i16s("offsets"),
            (case.i16("null_spectrum") == 0).then_some(power.as_slice()),
            &case.i16("power_e"),
            &mut energy,
            &mut energy_e,
        );
        check(case, "energy", &energy, &case.out_i32s("energy"));
        check(case, "energy_e", &energy_e, &case.out_i16s("energy_e"));
    }
}

#[test]
fn igf_and_cna_presence_match_the_reference() {
    let Some(cases) = corpus_sized(MODULE, "present", 1000) else {
        return;
    };
    let mut present = 0;
    for case in &cases {
        let (rate, bandwidth) = (case.i32("rate"), case.i16("bandwidth"));
        let igf = get_igf_present(rate, bandwidth, case.i16("rf"));
        check(
            case,
            "igf",
            &i64::from(igf),
            &i64::from(case.out_i16("igf")),
        );
        let cna = get_cna_present(rate, bandwidth);
        check(
            case,
            "cna",
            &i64::from(cna),
            &i64::from(case.out_i16("cna")),
        );
        present += usize::from(igf != 0);
    }
    assert!(present > 100 && present < 900, "{present} with IGF");
}

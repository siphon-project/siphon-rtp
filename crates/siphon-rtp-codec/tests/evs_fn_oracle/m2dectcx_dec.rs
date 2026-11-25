//! `lib_dec/dec_tcx.c` (`decoder_tcx`, `decoder_tcx_post`, and through them `IMDCT` and
//! `CalculateAbsEnergy`) against `fn_m2dectcx_dec`: the whole decoder state and the synthesis
//! after one call, on frames the reference's own `dec_prm` read (TCX-20 and TCX-10, every MODE2
//! rate, NB to FB, IGF and LTP on and off, the first frame after ACELP) and on concealed frames.

use siphon_rtp_codec::evs::com::core_com_config::get_igf_present;
use siphon_rtp_codec::evs::dec::core_dec_init::open_decoder_lpd;
use siphon_rtp_codec::evs::dec::dec_tcx::{decoder_tcx, decoder_tcx_post};
use siphon_rtp_codec::evs::dec::igf_dec::igf_dec_set_mode;
use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{mismatch, stream_cases, Case, SEED};
use crate::state_case::state_after;
use crate::state_dump;

static FLATTEN_TCX10: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static FLATTEN_TCX10_BELOW: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const MODULE: &str = "m2dectcx_dec";
const ACELP_CORE: i16 = 0;
const TCX_10_CORE: i16 = 2;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!(
            "{}",
            message
                .lines()
                .skip(2)
                .collect::<Vec<_>>()
                .join("\n")
                .chars()
                .take(600)
                .collect::<String>()
        );
    }
}

/// A vector compared with the first differing index named.
fn check_vec(name: &str, context: &str, rust: &[i16], reference: &[i16]) {
    assert_eq!(rust.len(), reference.len(), "{name} length ({context})");
    if let Some(at) = rust.iter().zip(reference).position(|(a, b)| a != b) {
        let lo = at.saturating_sub(3);
        let hi = (at + 4).min(rust.len());
        panic!(
            "{name} differs at {at} of {} ({context}): rust {:?}, reference {:?}",
            rust.len(),
            &rust[lo..hi],
            &reference[lo..hi]
        );
    }
}

/// The decoder of the case: configured for the rate and bandwidth as `mode_switch_decoder_LPD`
/// does (so the ROM window and table pointers are the reference's), then loaded with the "before"
/// state.
fn decoder_for(case: &Case) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    st.output_fs = case.i32("output_fs");
    st.output_frame = case.i16("output_frame");
    init_decoder(&mut st);
    let (rate, bandwidth) = (case.i32("rate"), case.i16("bw"));
    st.bwidth = bandwidth;
    st.total_brate = rate;
    st.rf_flag = 0;
    st.igf = i16::from(get_igf_present(rate, bandwidth, 0));
    st.h_igf_dec.info_igf_stop_freq = -1;
    if st.igf != 0 {
        igf_dec_set_mode(&mut st.h_igf_dec, rate, bandwidth, -1, -1, 0);
    }
    open_decoder_lpd(&mut st, rate, bandwidth);
    state_dump::load(&mut st, &case.inputs, "in.");
    st.stl.carry = case.i16("carry") != 0;
    st.stl.overflow = case.i16("overflow") != 0;
    st
}

/// How many cases exercised what, so a corpus that stopped covering something fails the test.
#[derive(Default, Debug)]
struct Coverage {
    cases: usize,
    lost: usize,
    tcx10: usize,
    tcx10_second: usize,
    igf: usize,
    after_acelp: usize,
    ltp: usize,
    tns: usize,
    high_rate: usize,
    low_rate: usize,
    flattening: usize,
    tcx10_igf: usize,
    lost_tcx10: usize,
    lost_waveadjust: usize,
    lost_tonal: usize,
    lpc_shaped: usize,
    ctx_hm: usize,
    old_coder: usize,
    resq: usize,
    narrow: usize,
    tcx5_energy: usize,
    acelp_plc_then_tcx: usize,
    after_cng: usize,
    acelp_then_tcx: usize,
    by_overlap: std::collections::BTreeMap<(i16, i16, i16), usize>,
}

impl Coverage {
    fn note(&mut self, case: &Case, st: &DecoderState) {
        self.cases += 1;
        self.lost += usize::from(case.i16("bfi") != 0);
        self.tcx10 += usize::from(st.core == TCX_10_CORE);
        self.tcx10_second +=
            usize::from(st.core == TCX_10_CORE && case.inputs.get("frame_cnt") == Some(&vec![1]));
        self.igf += usize::from(st.igf != 0);
        self.after_acelp += usize::from(case.i16("bfi") == 0 && st.last_core_bs == ACELP_CORE);
        self.ltp += usize::from(st.tcxltp_gain > 0);
        self.tns += usize::from(st.tcx_cfg.f_is_tns_allowed != 0);
        self.high_rate += usize::from(case.i32("rate") > 32000);
        self.low_rate += usize::from(case.i32("rate") <= 13200);
        self.flattening += usize::from(st.igf != 0 && st.h_igf_dec.flattening_trigger != 0);
        self.tcx10_igf += usize::from(st.igf != 0 && st.core == TCX_10_CORE);
        self.lost_tcx10 += usize::from(case.i16("bfi") != 0 && st.core == TCX_10_CORE);
        self.lost_waveadjust += usize::from(case.i16("bfi") != 0 && st.enable_plc_waveadjust != 0);
        self.lost_tonal += usize::from(case.i16("bfi") != 0 && st.tonal_mdct_plc_active != 0);
        self.lpc_shaped += usize::from(st.tcx_lpc_shaped_ari != 0);
        self.ctx_hm += usize::from(st.tcx_cfg.ctx_hm != 0);
        self.old_coder += usize::from(st.tcx_lpc_shaped_ari == 0);
        self.resq += usize::from(st.tcx_cfg.resq != 0);
        self.narrow += usize::from(case.i16("bw") == 0);
        self.acelp_plc_then_tcx +=
            usize::from(case.i16("bfi") == 0 && st.last_core_bfi == ACELP_CORE && st.prev_bfi != 0);
        self.after_cng += usize::from(case.i16("bfi") == 0 && st.last_is_cng != 0);
        self.acelp_then_tcx += usize::from(case.i16("bfi") == 0 && st.last_core_bfi == ACELP_CORE);
        self.tcx5_energy += usize::from(
            case.i16("bfi") != 0
                && st.core == TCX_10_CORE
                && case.inputs.get("frame_cnt") == Some(&vec![0])
                && st.nb_lost_cmpt == 1
                && st.tcxonly != 0
                && st.tonal_mdct_plc_active == 0
                && st.tcx_cfg.tcx_last_overlap_mode != 0
                && st.tcx_cfg.tcx_curr_overlap_mode != 0,
        );
        *self
            .by_overlap
            .entry((
                st.core,
                st.tcx_cfg.tcx_last_overlap_mode,
                st.tcx_cfg.tcx_curr_overlap_mode,
            ))
            .or_default() += usize::from(case.i16("bfi") == 0);
    }
}

fn coverage_is_broad(coverage: &Coverage, cases: usize) -> bool {
    let each = cases / 20;
    coverage.lost >= each
        && coverage.tcx10 >= each
        && coverage.igf >= each
        && coverage.after_acelp >= each / 2
        && coverage.ltp >= each
        && coverage.tns >= each
        && coverage.high_rate >= each
        && coverage.low_rate >= each
}

#[test]
fn decoder_tcx_matches_the_reference_on_the_whole_state() {
    const CASES: usize = 1200;
    let mut coverage = Coverage::default();
    let seen = stream_cases(MODULE, "decoder_tcx", CASES, SEED, |case| {
        let mut st = decoder_for(case);
        coverage.note(case, &st);
        let flatten_tcx10 = st.igf != 0
            && st.h_igf_dec.flattening_trigger != 0
            && st.core == TCX_10_CORE
            && case.i16("bfi") == 0;
        let mut prm = case.i16s("prm");
        let l_frame_glob = case.i16("l_frame_glob");
        let l_frame_tcx_glob = case.i16("l_frame_tcx_glob");
        let mut synth = vec![0i16; l_frame_glob as usize];
        let mut synth_fb = vec![0i16; l_frame_tcx_glob as usize];
        decoder_tcx(
            &mut prm,
            &case.i16s("a"),
            &case.i16s("a_ind"),
            l_frame_glob,
            l_frame_tcx_glob,
            case.i16("l_spec"),
            &mut synth,
            &mut synth_fb,
            &mut st,
            case.i16("coder_type"),
            case.i16("bfi"),
            case.i16("frame_cnt"),
            case.i16("stab_fac"),
        );
        let context = format!(
            "rate {}, bandwidth {}, core {}, bfi {}, frame_cnt {}, output_fs {}",
            case.i32("rate"),
            case.i16("bw"),
            case.i16("core"),
            case.i16("bfi"),
            case.i16("frame_cnt"),
            case.i32("output_fs")
        );
        state_dump::check(&mut st, &state_after(case), "st.", &context);
        check_vec("synth", &context, &synth, &case.out_i16s("synth"));
        check_vec("synth_fb", &context, &synth_fb, &case.out_i16s("synth_fb"));
        check(
            case,
            "carry",
            &i16::from(st.stl.carry),
            &case.out_i16("carry_out"),
        );
        if flatten_tcx10 && st.last_tns_active == 0 {
            FLATTEN_TCX10.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if st.h_igf_dec.info_igf_start_line < 164 {
                FLATTEN_TCX10_BELOW.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });
    let Some(seen) = seen else {
        return;
    };
    eprintln!("{coverage:#?}");
    eprintln!(
        "flatten in TCX-10 after the call: {}, with the IGF start below IGF_START_MN: {}",
        FLATTEN_TCX10.load(std::sync::atomic::Ordering::Relaxed),
        FLATTEN_TCX10_BELOW.load(std::sync::atomic::Ordering::Relaxed)
    );
    assert!(coverage_is_broad(&coverage, seen), "{coverage:?}");
}

#[test]
fn decoder_tcx_post_matches_the_reference_on_the_whole_state() {
    const CASES: usize = 300;
    let mut coverage = Coverage::default();
    let seen = stream_cases(MODULE, "decoder_tcx_post", CASES, SEED, |case| {
        let mut st = decoder_for(case);
        coverage.note(case, &st);
        let mut synth = case.i16s("synth");
        let mut synth_fb = case.i16s("synth_fb");
        decoder_tcx_post(
            &mut st,
            &mut synth,
            &mut synth_fb,
            &case.i16s("a"),
            case.i16("bfi"),
        );
        let context = format!(
            "rate {}, bandwidth {}, bfi {}, output_fs {}",
            case.i32("rate"),
            case.i16("bw"),
            case.i16("bfi"),
            case.i32("output_fs")
        );
        state_dump::check(&mut st, &state_after(case), "st.", &context);
        check_vec("synth", &context, &synth, &case.out_i16s("synth"));
        check_vec("synth_fb", &context, &synth_fb, &case.out_i16s("synth_fb"));
        check(
            case,
            "carry",
            &i16::from(st.stl.carry),
            &case.out_i16("carry_out"),
        );
    });
    let Some(seen) = seen else {
        return;
    };
    assert!(seen > 0);
    assert!(coverage.lost >= seen / 20, "{coverage:?}");
}

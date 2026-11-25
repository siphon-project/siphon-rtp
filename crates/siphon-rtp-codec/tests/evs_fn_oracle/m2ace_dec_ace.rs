//! `lib_dec/dec_ace.c` (`decoder_acelp`, the MODE2 ACELP frame decoder) and the lower-case
//! `rescale_mem` of `lib_com/scale_mem_fx.c` against `fn_m2ace_dec_ace`.
//!
//! `decoder_acelp` is proven on the whole decoder state: every case loads the state the oracle
//! printed before the call (a configured MODE2 decoder, the frame's ACELP configuration and
//! memories), runs the port, and compares the outputs and every state field afterwards, so a field
//! the port forgets to write, or writes when it should not, is a difference. The cases cover
//! 9.6 to 32 kbit/s at 12.8 and 16 kHz cores, every ACELP coder type, good / lost / concealed-TCX
//! previous frames, bit-error frames and the channel-aware partial copies (NELP included).

use siphon_rtp_codec::evs::com::scale_mem::rescale_mem_syn;
use siphon_rtp_codec::evs::dec::dec_ace::decoder_acelp;

use crate::common::{corpus, corpus_sized, mismatch, Case};
use crate::state_case::{decoder_before, state_after};
use crate::state_dump;

const BWE_EXC_AT: usize = 289 * 2;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

/// How many cases of each kind a corpus holds, so the test fails if the oracle stops drawing one.
#[derive(Default, Debug)]
struct Coverage {
    cases: usize,
    skipped: usize,
    five_subframes: usize,
    igf: usize,
    bit_error: usize,
    partial_copy: usize,
    nelp: usize,
    prev_lost: usize,
    last_con_tcx: usize,
    last_core_tcx: usize,
    coder_type: [usize; 4],
    gplc: usize,
}

#[test]
fn decoder_acelp_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized("m2ace_dec_ace", "decoder_acelp", 1500) else {
        return;
    };
    let mut coverage = Coverage::default();
    for (index, case) in cases.iter().enumerate() {
        coverage.cases += 1;
        if case.outputs.contains_key("skip") {
            coverage.skipped += 1;
            continue;
        }
        let mut st = decoder_before(case);
        let coder_type = case.i16("coder_type");
        let prm = case.i16s("prm");
        let a = case.i16s("a");
        let mut bwe_exc = case.i16s("bwe_exc");
        let mut synth = vec![-3i16; 320];
        let mut p_t = [-4i16; 5];
        let mut pgain_t = [-5i16; 5];
        let mut pitch_buffer = [-6i16; 5];
        let mut voice_factors = [-7i16; 5];
        let context = format!(
            "case {index}: L_frame {}, nb_subfr {}, rate {}, coder_type {coder_type}, igf {}, partial copy {} (type {}), ber {}, prev_bfi {}, last_con_tcx {}",
            st.l_frame,
            st.nb_subfr,
            st.total_brate,
            st.igf,
            st.use_partial_copy,
            st.rf_frame_type,
            st.ber_detect,
            st.prev_bfi,
            st.last_con_tcx
        );

        coverage.five_subframes += usize::from(st.nb_subfr == 5);
        coverage.igf += usize::from(st.igf != 0);
        coverage.bit_error += usize::from(st.ber_detect != 0);
        coverage.partial_copy += usize::from(st.use_partial_copy != 0);
        coverage.nelp += usize::from(st.use_partial_copy != 0 && st.rf_frame_type == 7);
        coverage.prev_lost += usize::from(st.prev_bfi != 0);
        coverage.last_con_tcx += usize::from(st.last_con_tcx != 0);
        coverage.last_core_tcx += usize::from(st.last_core != 0);
        coverage.gplc += usize::from(st.enable_gplc != 0);
        if let Some(count) = coverage.coder_type.get_mut(coder_type as usize) {
            *count += 1;
        }

        decoder_acelp(
            &mut st,
            coder_type,
            &prm,
            &a,
            &mut synth,
            &mut p_t,
            &mut pgain_t,
            case.i16("stab_fac"),
            &mut pitch_buffer,
            &mut voice_factors,
            case.i16("lsf_q_prediction"),
            &mut bwe_exc,
            BWE_EXC_AT,
        );

        check(case, "synth", &synth, &case.out_i16s("synth"));
        check(case, "p_t", &p_t.to_vec(), &case.out_i16s("p_t"));
        check(
            case,
            "pgain_t",
            &pgain_t.to_vec(),
            &case.out_i16s("pgain_t"),
        );
        check(
            case,
            "pitch_buffer",
            &pitch_buffer.to_vec(),
            &case.out_i16s("pitch_buffer"),
        );
        check(
            case,
            "voice_factors",
            &voice_factors.to_vec(),
            &case.out_i16s("voice_factors"),
        );
        check(case, "bwe_exc", &bwe_exc, &case.out_i16s("bwe_exc"));
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
    assert!(
        coverage.skipped * 20 <= coverage.cases,
        "too many frames the reference did not return from: {coverage:?}"
    );
    assert!(
        coverage.five_subframes > 100
            && coverage.igf > 100
            && coverage.bit_error > 30
            && coverage.partial_copy > 100
            && coverage.nelp > 20
            && coverage.prev_lost > 100
            && coverage.last_con_tcx > 100
            && coverage.last_core_tcx > 100
            && coverage.gplc > 20
            && coverage.coder_type.iter().all(|&count| count > 50),
        "corpus does not cover every path: {coverage:?}"
    );
}

#[test]
fn rescale_mem_syn_matches_the_reference() {
    let Some(cases) = corpus("m2ace_dec_ace", "rescale_mem") else {
        return;
    };
    for case in &cases {
        let mut mem = case.i16s("mem");
        let mut syn = case.i16s("syn");
        let mut prev_q_syn = case.i16("prev_q_syn");
        let mut q_syn = case.i16("q_syn");
        let with_syn = case.i16("with_syn") != 0;
        let r = rescale_mem_syn(
            case.i16("q_exc"),
            &mut prev_q_syn,
            &mut q_syn,
            &mut mem,
            with_syn.then_some(syn.as_mut_slice()),
            case.i16("mem_len"),
            case.i16("i_subfr"),
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "prev_q_syn", &prev_q_syn, &case.out_i16("prev_q_syn"));
        check(case, "q_syn", &q_syn, &case.out_i16("q_syn"));
        check(case, "mem", &mem, &case.out_i16s("mem"));
        check(case, "syn", &syn, &case.out_i16s("syn"));
    }
}

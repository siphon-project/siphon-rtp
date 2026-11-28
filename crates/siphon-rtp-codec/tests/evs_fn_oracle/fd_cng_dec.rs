//! `lib_dec/fd_cng_dec.c` against `fn_fd_cng_dec`. Every case builds the FD-CNG state through
//! `createFdCngDec` / `initFdCngDec` / `configureFdCngDec` on both sides (so the configuration is
//! compared on every case, and directly by `configure`). The noise estimation runs 48 consecutive
//! frames; the pipeline drives the decoder's FD-CNG sequence (SID decoding, comfort noise,
//! noisy-speech detection, `ApplyFdCng`, masking noise) over 24 frames of talk spurts and DTX.

use siphon_rtp_codec::evs::com::cldfb::CLDFB_ROW;
use siphon_rtp_codec::evs::com::rom_basop_util::get_sine_window_table;
use siphon_rtp_codec::evs::dec::fd_cng_dec::{
    apply_fd_cng, configure_fd_cng_dec, create_fd_cng_dec, fd_cng_decode_sid,
    generate_comfort_noise_dec, generate_comfort_noise_dec_hf, generate_masking_noise,
    generate_masking_noise_mdct, generate_masking_noise_update_seed, init_fd_cng_dec,
    noisy_speech_detection, perform_noise_estimation_dec, CldfbBuffers,
};
use siphon_rtp_codec::evs::dec::state::{DecoderState, FdCngCom, FdCngDec};

use crate::common::{corpus_sized, mismatch, Case};

const ACTIVE_FRAME: i16 = 255;
const SID_FRAME: i16 = 250;
const FD_CNG: i16 = 1;
const COLS: usize = 16;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn check16(case: &Case, name: &str, rust: &[i16]) {
    let reference = case.out_i16s(name);
    check(case, name, &rust[..reference.len()].to_vec(), &reference);
}

fn check32(case: &Case, name: &str, rust: &[i32]) {
    let reference = case.out_i32s(name);
    check(case, name, &rust[..reference.len()].to_vec(), &reference);
}

fn check1(case: &Case, name: &str, rust: i64) {
    check(case, name, &rust, &i64::from(case.out_i32(name)));
}

/// A decoder state holding a FD-CNG instance configured as the oracle's.
fn make_state(case: &Case) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    create_fd_cng_dec(&mut st.h_fd_cng_dec);
    let hs = st.h_fd_cng_dec.as_deref_mut().unwrap();
    init_fd_cng_dec(hs, case.i16("scale"));
    configure_fd_cng_dec(
        hs,
        case.i16("bandwidth"),
        case.i32("bitrate"),
        case.i16("L_frame"),
    );
    st
}

fn dec(st: &mut DecoderState) -> &mut FdCngDec {
    st.h_fd_cng_dec.as_deref_mut().unwrap()
}

fn com(st: &mut DecoderState) -> &mut FdCngCom {
    dec(st).h_fd_cng_com.as_deref_mut().unwrap()
}

/// The decoder-state fields `random_decoder` sets in the oracle.
fn load_decoder(case: &Case, st: &mut DecoderState) {
    let l_frame = case.i16("L_frame");
    st.l_frame = l_frame;
    st.sr_core = if l_frame == 256 { 12800 } else { 16000 };
    st.bwidth = case.i16("st_bwidth");
    st.cng_mode = case.i16("st_cng_mode");
    st.lp_ener = case.i32("st_lp_ener");
    st.q_exc = case.i16("st_q_exc");
    st.q_syn = case.i16("st_q_syn");
    st.codec_mode = case.i16("st_codec_mode");
    st.last_core_bfi = case.i16("st_last_core_bfi");
    st.preemph_fac = case.i16("st_preemph_fac");
    st.old_exc.copy_from_slice(&case.i16s("st_old_exc"));
    st.mem_syn2.copy_from_slice(&case.i16s("st_mem_syn2"));
    st.syn.copy_from_slice(&case.i16s("st_syn"));
    st.old_aq_12_8.copy_from_slice(&case.i16s("st_old_aq"));
    let cfg = &mut st.tcx_cfg;
    cfg.tcx_mdct_window_length = case.i16("st_win_length");
    cfg.tcx_mdct_window_half_length = case.i16("st_win_half_length");
    cfg.tcx_mdct_window_min_length = case.i16("st_win_min_length");
    cfg.tcx_mdct_window = get_sine_window_table(cfg.tcx_mdct_window_length).unwrap();
    cfg.tcx_mdct_window_half = get_sine_window_table(cfg.tcx_mdct_window_half_length).unwrap();
    cfg.tcx_mdct_window_minimum = get_sine_window_table(cfg.tcx_mdct_window_min_length).unwrap();
    cfg.tcx_offset = case.i16("st_tcx_offset");
    cfg.last_aldo = case.i16("st_last_aldo");
    cfg.tcx_last_overlap_mode = case.i16("st_last_overlap_mode");
    st.old_out_lb.copy_from_slice(&case.i16s("st_old_out_lb"));
    st.q_old_wtda_lb = case.i16("st_q_old_wtda_lb");
    st.syn_overl.copy_from_slice(&case.i16s("st_syn_overl"));
    st.cng_type = case.i16("st_cng_type");
    st.ber_detect = case.i16("st_ber_detect");
    st.lspold_cng.copy_from_slice(&case.i16s("st_lspold_cng"));
    st.lsf_cng.copy_from_slice(&case.i16s("st_lsf_cng"));
}

/// The levels and buffers `prime_levels` sets in the oracle.
fn load_primed(case: &Case, st: &mut DecoderState) {
    let hs = dec(st);
    hs.olap_buffer_synth2
        .copy_from_slice(&case.i16s("p_olap_synth2"));
    let c = hs.h_fd_cng_com.as_deref_mut().unwrap();
    c.cng_noise_level.copy_from_slice(&case.i32s("p_cng_level"));
    c.cng_noise_level_exp = case.i16("p_cng_exp");
    c.seed = case.i16("p_seed");
    c.likelihood_noisy_speech = case.i16("p_likelihood");
    c.a_cng.copy_from_slice(&case.i16s("p_a_cng"));
    c.frame_type_previous = case.i16("p_frame_type_previous");
    c.olap_buffer_synth
        .copy_from_slice(&case.i16s("p_olap_synth"));
}

/// `put_fd_cng(prefix)`: the FD-CNG state after a call.
fn check_fd_cng(case: &Case, prefix: &str, st: &mut DecoderState) {
    let hs = dec(st);
    let n = |field: &str| format!("{prefix}_{field}");
    {
        let c = hs.h_fd_cng_com.as_deref().unwrap();
        check32(case, &n("c->cngNoiseLevel"), &c.cng_noise_level);
        check1(
            case,
            &n("c->cngNoiseLevelExp"),
            i64::from(c.cng_noise_level_exp),
        );
        check1(case, &n("c->seed"), i64::from(c.seed));
        check16(case, &n("c->A_cng"), &c.a_cng);
        check16(case, &n("c->exc_cng"), &c.exc_cng);
        check16(case, &n("c->timeDomainBuffer"), &c.time_domain_buffer);
        check32(case, &n("c->fftBuffer"), &c.fft_buffer);
        check16(case, &n("c->olapBufferSynth"), &c.olap_buffer_synth);
        check32(case, &n("c->sidNoiseEst"), &c.sid_noise_est);
        check1(
            case,
            &n("c->sidNoiseEstExp"),
            i64::from(c.sid_noise_est_exp),
        );
        check1(
            case,
            &n("c->inactive_frame_counter"),
            i64::from(c.inactive_frame_counter),
        );
        check1(
            case,
            &n("c->sid_frame_counter"),
            i64::from(c.sid_frame_counter),
        );
        check1(
            case,
            &n("c->flag_noisy_speech"),
            i64::from(c.flag_noisy_speech),
        );
        check1(
            case,
            &n("c->likelihood_noisy_speech"),
            i64::from(c.likelihood_noisy_speech),
        );
        check32(case, &n("c->periodog"), &c.periodog);
        check1(case, &n("c->periodog_exp"), i64::from(c.periodog_exp));
        check1(
            case,
            &n("c->msFrCnt_init_counter"),
            i64::from(c.ms_fr_cnt_init_counter),
        );
        check1(case, &n("c->msFrCnt"), i64::from(c.ms_fr_cnt));
        check1(case, &n("c->init_old"), i64::from(c.init_old));
        check1(case, &n("c->offsetflag"), i64::from(c.offsetflag));
    }
    check32(case, &n("hs->msNoiseEst"), &hs.ms_noise_est);
    check1(
        case,
        &n("hs->msNoiseEst_exp"),
        i64::from(hs.ms_noise_est_exp),
    );
    check16(case, &n("hs->msLogNoiseEst"), &hs.ms_log_noise_est);
    check32(case, &n("hs->msPeriodog"), &hs.ms_periodog);
    check1(
        case,
        &n("hs->msPeriodog_exp"),
        i64::from(hs.ms_periodog_exp),
    );
    check1(
        case,
        &n("hs->msPeriodog_exp_fft"),
        i64::from(hs.ms_periodog_exp_fft),
    );
    check1(
        case,
        &n("hs->msPeriodog_exp_cldfb"),
        i64::from(hs.ms_periodog_exp_cldfb),
    );
    check32(case, &n("hs->bandNoiseShape"), &hs.band_noise_shape);
    check1(
        case,
        &n("hs->bandNoiseShape_exp"),
        i64::from(hs.band_noise_shape_exp),
    );
    check32(case, &n("hs->partNoiseShape"), &hs.part_noise_shape);
    check1(
        case,
        &n("hs->partNoiseShape_exp"),
        i64::from(hs.part_noise_shape_exp),
    );
    check1(case, &n("hs->flag_dtx_mode"), i64::from(hs.flag_dtx_mode));
    check1(case, &n("hs->lp_noise"), i64::from(hs.lp_noise));
    check1(case, &n("hs->lp_speech"), i64::from(hs.lp_speech));
    check16(case, &n("hs->olapBufferAna"), &hs.olap_buffer_ana);
    check16(case, &n("hs->olapBufferSynth2"), &hs.olap_buffer_synth2);
}

fn flat(window: &[siphon_rtp_codec::evs::rom::types::PWord16]) -> Vec<i16> {
    window.iter().flat_map(|w| [w.v.re, w.v.im]).collect()
}

#[test]
fn configure_fd_cng_dec_matches_the_reference() {
    let Some(cases) = corpus_sized("fd_cng_dec", "configure", 2000) else {
        return;
    };
    for case in &cases {
        let mut st = make_state(case);
        let hs = dec(&mut st);
        if case.i16("twice") != 0 {
            configure_fd_cng_dec(
                hs,
                case.i16("bandwidth2"),
                case.i32("bitrate2"),
                case.i16("L_frame2"),
            );
        }
        let c = hs.h_fd_cng_com.as_deref().unwrap();
        let np = c.npart as usize;
        let ncl = c.n_cldf_bpart.max(0) as usize;
        let nsh = hs.npart_shaping as usize;
        let got: Vec<(&str, Vec<i64>)> = vec![
            ("cng_bandwidth", vec![c.cng_bandwidth.into()]),
            ("cng_bitrate", vec![c.cng_bitrate.into()]),
            ("num_slots", vec![c.num_slots.into()]),
            ("setup_fftlen", vec![c.fd_cng_setup.fftlen.into()]),
            ("setup_stop", vec![c.fd_cng_setup.stop_fftbin.into()]),
            (
                "setup_num_partitions",
                vec![c.fd_cng_setup.num_partitions.into()],
            ),
            (
                "setup_num_shaping",
                vec![c.fd_cng_setup.num_shaping_partitions.into()],
            ),
            ("num_core_bands", vec![c.num_core_bands.into()]),
            ("regular_stop_band", vec![c.regular_stop_band.into()]),
            ("fftlen", vec![c.fftlen.into()]),
            ("stop_fft_bin", vec![c.stop_ff_tbin.into()]),
            ("start_band", vec![c.start_band.into()]),
            ("stop_band", vec![c.stop_band.into()]),
            ("npart", vec![c.npart.into()]),
            ("part", c.part[..np].iter().map(|&v| v.into()).collect()),
            (
                "midband",
                c.midband[..np].iter().map(|&v| v.into()).collect(),
            ),
            ("psize", c.psize[..np].iter().map(|&v| v.into()).collect()),
            (
                "psize_norm",
                c.psize_norm[..np].iter().map(|&v| v.into()).collect(),
            ),
            ("psize_norm_exp", vec![c.psize_norm_exp.into()]),
            (
                "psize_inv",
                c.psize_inv[..np].iter().map(|&v| v.into()).collect(),
            ),
            ("n_fft_part", vec![c.n_ff_tpart.into()]),
            ("n_cldfb_part", vec![c.n_cldf_bpart.into()]),
            (
                "cldfb_part",
                c.cldf_bpart[..ncl].iter().map(|&v| v.into()).collect(),
            ),
            (
                "cldfb_psize_inv",
                c.cldf_bpsize_inv[..ncl].iter().map(|&v| v.into()).collect(),
            ),
            ("npart_shaping", vec![hs.npart_shaping.into()]),
            ("n_fft_part_shaping", vec![hs.n_ff_tpart_shaping.into()]),
            (
                "part_shaping",
                hs.part_shaping[..nsh].iter().map(|&v| v.into()).collect(),
            ),
            (
                "midband_shaping",
                hs.midband_shaping[..nsh]
                    .iter()
                    .map(|&v| v.into())
                    .collect(),
            ),
            (
                "psize_shaping",
                hs.psize_shaping[..nsh].iter().map(|&v| v.into()).collect(),
            ),
            (
                "psize_shaping_norm",
                hs.psize_shaping_norm[..nsh]
                    .iter()
                    .map(|&v| v.into())
                    .collect(),
            ),
            (
                "psize_shaping_norm_exp",
                vec![hs.psize_shaping_norm_exp.into()],
            ),
            (
                "psize_inv_shaping",
                hs.psize_inv_shaping[..nsh]
                    .iter()
                    .map(|&v| v.into())
                    .collect(),
            ),
            ("fftlen_shift", vec![c.fftlen_shift.into()]),
            ("fftlen_fac", vec![c.fftlen_fac.into()]),
            ("frame_size", vec![c.frame_size.into()]),
            (
                "win_ana",
                flat(&c.olap_win_ana[..(c.fftlen / 4) as usize])
                    .iter()
                    .map(|&v| v.into())
                    .collect(),
            ),
            (
                "win_syn",
                flat(&c.olap_win_syn[..(c.fftlen / 8) as usize])
                    .iter()
                    .map(|&v| v.into())
                    .collect(),
            ),
            ("inv_scaling_factor", vec![c.inv_scaling_factor.into()]),
            ("lp_noise", vec![hs.lp_noise.into()]),
            ("lp_speech", vec![hs.lp_speech.into()]),
            (
                "ms_min_buf",
                hs.ms_min_buf.iter().map(|&v| v.into()).collect(),
            ),
        ];
        for (name, values) in got {
            check(case, name, &values, &case.outputs[name]);
        }
    }
}

#[test]
fn perform_noise_estimation_dec_matches_the_reference() {
    let Some(cases) = corpus_sized("fd_cng_dec", "noise_estimation", 300) else {
        return;
    };
    for case in &cases {
        let mut st = make_state(case);
        let q = case.i16s("q");
        for (f, &q) in q.iter().enumerate() {
            let x = case.i16s(&format!("x{f}"));
            perform_noise_estimation_dec(&x, q, dec(&mut st));
            let hs = dec(&mut st);
            check32(case, &format!("est{f}"), &hs.ms_noise_est);
            check1(case, &format!("est_exp{f}"), i64::from(hs.ms_noise_est_exp));
        }
        check_fd_cng(case, "end", &mut st);
    }
}

#[test]
fn fd_cng_decode_sid_matches_the_reference() {
    let Some(cases) = corpus_sized("fd_cng_dec", "decode_sid", 1000) else {
        return;
    };
    for case in &cases {
        let mut st = make_state(case);
        st.preemph_fac = case.i16("preemph_fac");
        let bits = case.i16s("bits");
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
            *slot = bit as u16;
        }
        st.total_num_bits = bits.len() as i16;
        st.codec_mode = 1;
        fd_cng_decode_sid(&mut st);
        check1(case, "next_bit_pos", i64::from(st.next_bit_pos));
        check_fd_cng(case, "end", &mut st);
    }
}

#[test]
fn noisy_speech_detection_matches_the_reference() {
    let Some(cases) = corpus_sized("fd_cng_dec", "noisy_speech_detection", 2000) else {
        return;
    };
    for case in &cases {
        let mut st = make_state(case);
        let hs = dec(&mut st);
        let mut lp_noise = case.i32("lp_noise");
        let mut lp_speech = case.i32("lp_speech");
        let mut flag: i16 = -5;
        noisy_speech_detection(
            case.i16("vad"),
            &case.i16s("x"),
            case.i16("L_frame"),
            case.i16("q"),
            &case.i32s("est"),
            case.i16("est_exp"),
            &hs.psize_shaping_norm,
            hs.psize_shaping_norm_exp,
            hs.n_ff_tpart_shaping,
            &mut lp_noise,
            &mut lp_speech,
            &mut flag,
        );
        check1(case, "lp_noise", i64::from(lp_noise));
        check1(case, "lp_speech", i64::from(lp_speech));
        check1(case, "flag", i64::from(flag));
    }
}

/// The oracle primes the levels with a few frames of noise estimation it does not print; what the
/// comfort and masking noise read of the result is printed and loaded here, and the estimation
/// state itself is not compared in those cases.
fn primed_state(case: &Case) -> Box<DecoderState> {
    let mut st = make_state(case);
    load_primed(case, &mut st);
    st
}

fn cldfb_rows() -> (Vec<[i32; CLDFB_ROW]>, Vec<[i32; CLDFB_ROW]>) {
    (vec![[7; CLDFB_ROW]; COLS], vec![[7; CLDFB_ROW]; COLS])
}

fn check_rows(case: &Case, real: &[[i32; CLDFB_ROW]], imag: &[[i32; CLDFB_ROW]]) {
    for i in 0..COLS {
        check32(case, &format!("real{i}"), &real[i]);
        check32(case, &format!("imag{i}"), &imag[i]);
    }
}

#[test]
fn generate_comfort_noise_dec_matches_the_reference() {
    let Some(cases) = corpus_sized("fd_cng_dec", "comfort_noise", 500) else {
        return;
    };
    for case in &cases {
        let mut st = primed_state(case);
        load_decoder(case, &mut st);
        let (mut real, mut imag) = cldfb_rows();
        let mut scale: i16 = -99;
        let cldfb = (case.i16("with_cldfb") != 0).then(|| CldfbBuffers {
            real: &mut real,
            imag: &mut imag,
            scale: Some(&mut scale),
        });
        generate_comfort_noise_dec(cldfb, &mut st, 2);
        check_fd_cng_generated(case, &mut st);
        check1(case, "q_exc", i64::from(st.q_exc));
        check1(case, "lp_ener", i64::from(st.lp_ener));
        check1(case, "scale", i64::from(scale));
        check16(case, "syn_overl", &st.syn_overl);
        check_rows(case, &real, &imag);
    }
}

/// The parts of the state comfort noise generation writes (the estimation state is primed on the
/// oracle side and not reproduced here).
fn check_fd_cng_generated(case: &Case, st: &mut DecoderState) {
    let hs = dec(st);
    check16(case, "end_hs->olapBufferSynth2", &hs.olap_buffer_synth2);
    let c = hs.h_fd_cng_com.as_deref().unwrap();
    check32(case, "end_c->cngNoiseLevel", &c.cng_noise_level);
    check1(case, "end_c->seed", i64::from(c.seed));
    check16(case, "end_c->exc_cng", &c.exc_cng);
    check16(case, "end_c->timeDomainBuffer", &c.time_domain_buffer);
    check32(case, "end_c->fftBuffer", &c.fft_buffer);
    check16(case, "end_c->olapBufferSynth", &c.olap_buffer_synth);
}

#[test]
fn generate_comfort_noise_dec_hf_matches_the_reference() {
    let Some(cases) = corpus_sized("fd_cng_dec", "comfort_noise_hf", 500) else {
        return;
    };
    for case in &cases {
        let mut st = primed_state(case);
        let (mut real, mut imag) = cldfb_rows();
        let mut scale: i16 = -99;
        generate_comfort_noise_dec_hf(
            CldfbBuffers {
                real: &mut real,
                imag: &mut imag,
                scale: Some(&mut scale),
            },
            &mut st,
        );
        check1(case, "seed", i64::from(com(&mut st).seed));
        check1(case, "scale", i64::from(scale));
        check_rows(case, &real, &imag);
    }
}

#[test]
fn generate_masking_noise_matches_the_reference() {
    let Some(cases) = corpus_sized("fd_cng_dec", "masking_noise", 500) else {
        return;
    };
    for case in &cases {
        let mut st = primed_state(case);
        com(&mut st).cng_bitrate = case.i32("cng_bitrate");
        let mut x = case.i16s("x");
        let hs = dec(&mut st);
        let c = hs.h_fd_cng_com.as_deref_mut().unwrap();
        generate_masking_noise(
            &mut x,
            case.i16("q"),
            c,
            &mut hs.olap_buffer_synth2,
            case.i16("length"),
            case.i16("core"),
        );
        check16(case, "x", &x);
        check_fd_cng_generated(case, &mut st);
    }
}

#[test]
fn generate_masking_noise_mdct_matches_the_reference() {
    let Some(cases) = corpus_sized("fd_cng_dec", "masking_noise_mdct", 1000) else {
        return;
    };
    for case in &cases {
        let mut st = primed_state(case);
        let mut mdct = case.i32s("mdct");
        let mut e = case.i16("e");
        generate_masking_noise_mdct(&mut mdct, &mut e, com(&mut st), case.i16("L_frame"));
        check32(case, "mdct", &mdct);
        check1(case, "e", i64::from(e));
        check1(case, "seed", i64::from(com(&mut st).seed));
    }
}

#[test]
fn generate_masking_noise_update_seed_matches_the_reference() {
    let Some(cases) = corpus_sized("fd_cng_dec", "update_seed", 2000) else {
        return;
    };
    for case in &cases {
        let mut st = make_state(case);
        let c = com(&mut st);
        c.seed = case.i16("seed");
        c.start_band = case.i16("start_band");
        generate_masking_noise_update_seed(c);
        check1(case, "seed", i64::from(c.seed));
    }
}

#[test]
fn fd_cng_pipeline_matches_the_reference() {
    let Some(cases) = corpus_sized("fd_cng_dec", "pipeline", 200) else {
        return;
    };
    for case in &cases {
        let mut st = make_state(case);
        load_decoder(case, &mut st);
        let l_frame = case.i16("L_frame");
        let types = case.i16s("types");
        let vad = case.i16s("vad");
        let conceal = case.i16s("conceal");
        let lost = case.i16s("lost");
        let music = case.i16s("music");
        let cna = case.i16s("cna");
        for f in 0..types.len() {
            let mut syn = case.i16s(&format!("syn{f}"));
            st.m_frame_type = types[f];
            st.vad = vad[f] as i8;
            st.nb_lost_cmpt = lost[f];
            if types[f] != ACTIVE_FRAME && st.cng_type == FD_CNG {
                if types[f] == SID_FRAME {
                    let bits = case.i16s(&format!("sid_bits{f}"));
                    for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
                        *slot = bit as u16;
                    }
                    st.total_num_bits = 48;
                    st.next_bit_pos = 0;
                    fd_cng_decode_sid(&mut st);
                }
                generate_comfort_noise_dec(None, &mut st, 2);
            }
            {
                let q_syn = st.q_syn;
                let vad = i16::from(st.vad);
                let hs = dec(&mut st);
                let c = hs.h_fd_cng_com.as_deref_mut().unwrap();
                noisy_speech_detection(
                    vad,
                    &syn,
                    l_frame,
                    q_syn,
                    &hs.ms_noise_est,
                    hs.ms_noise_est_exp,
                    &hs.psize_shaping_norm,
                    hs.psize_shaping_norm_exp,
                    hs.n_ff_tpart_shaping,
                    &mut hs.lp_noise,
                    &mut hs.lp_speech,
                    &mut c.flag_noisy_speech,
                );
                c.likelihood_noisy_speech =
                    siphon_rtp_codec::itu::basic_ops::mult_r(c.likelihood_noisy_speech, 32440);
                if c.flag_noisy_speech != 0 {
                    c.likelihood_noisy_speech =
                        siphon_rtp_codec::itu::basic_ops::add(c.likelihood_noisy_speech, 328);
                }
            }
            let (mut real, mut imag) = cldfb_rows();
            let mut scale: i16 = -99;
            let q_syn = st.q_syn;
            let r = apply_fd_cng(
                &syn.clone(),
                q_syn,
                Some(CldfbBuffers {
                    real: &mut real,
                    imag: &mut imag,
                    scale: Some(&mut scale),
                }),
                types[f],
                &mut st,
                conceal[f],
                music[f],
            );
            {
                let hs = dec(&mut st);
                let c = hs.h_fd_cng_com.as_deref_mut().unwrap();
                if cna[f] == 1 {
                    let frame_size = c.frame_size;
                    generate_masking_noise(
                        &mut syn,
                        q_syn,
                        c,
                        &mut hs.olap_buffer_synth2,
                        frame_size,
                        0,
                    );
                } else if cna[f] == 2 {
                    generate_masking_noise_update_seed(c);
                }
                c.frame_type_previous = types[f];
            }
            check1(case, &format!("r{f}"), i64::from(r));
            check16(case, &format!("out{f}"), &syn);
            let c = com(&mut st);
            check32(case, &format!("level{f}"), &c.cng_noise_level);
            check1(
                case,
                &format!("level_exp{f}"),
                i64::from(c.cng_noise_level_exp),
            );
            check16(case, &format!("tdb{f}"), &c.time_domain_buffer);
            check16(case, &format!("exc{f}"), &c.exc_cng);
            check1(case, &format!("seed{f}"), i64::from(c.seed));
            check1(case, &format!("td{f}"), i64::from(st.cng_td_level));
            check1(case, &format!("td_e{f}"), i64::from(st.cng_td_level_e));
            check1(case, &format!("lp_ener{f}"), i64::from(st.lp_ener));
            check1(case, &format!("q_exc{f}"), i64::from(st.q_exc));
            check16(case, &format!("lsf_cng{f}"), &st.lsf_cng);
            check1(
                case,
                &format!("plc{f}"),
                i64::from(st.plc_background_noise_updated),
            );
            check1(case, &format!("scale{f}"), i64::from(scale));
            check32(case, &format!("real{f}"), &real[3]);
            check32(case, &format!("imag{f}"), &imag[15]);
        }
        check_fd_cng(case, "end", &mut st);
        check16(case, "lspold_cng", &st.lspold_cng);
    }
}

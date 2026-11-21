//! `lib_com/fd_cng_com.c` against `fn_fd_cng_com`. `minimum_statistics` runs 40 consecutive
//! frames per case through one state, through the initial frames, the sub-window updates and the
//! buffer rotations; the STFTs run two consecutive frames through their overlap buffers.

use siphon_rtp_codec::evs::com::fd_cng_com::{
    analysis_stft, bandcombinepow, compress_range, create_fd_cng_com, delete_fd_cng_com,
    expand_range, getmidbands, init_fd_cng_com, init_partitions, lpc_from_spectrum, mhvals,
    minimum_statistics, msvq_decoder, rand_gauss, scalebands, synthesis_stft, StftOverlap,
    StftSpectrum,
};
use siphon_rtp_codec::evs::com::rom_basop_util::basop_get_tables;
use siphon_rtp_codec::evs::dec::state::FdCngCom;
use siphon_rtp_codec::evs::rom::{CDK_37BITS, MAXN_37BITS, STAGES_37BITS};

use crate::common::{corpus, corpus_sized, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn rand_gauss_matches_the_reference() {
    let Some(cases) = corpus("fd_cng_com", "rand_gauss") else {
        return;
    };
    for case in &cases {
        let mut seed = case.i16("seed");
        let r = rand_gauss(&mut seed);
        check(case, "r", &r, &case.out_i32("r"));
        check(case, "seed", &seed, &case.out_i16("seed"));
    }
}

#[test]
fn mhvals_matches_the_reference() {
    let Some(cases) = corpus("fd_cng_com", "mhvals") else {
        return;
    };
    for case in &cases {
        let mut m = -1;
        mhvals(case.i16("d"), &mut m);
        check(case, "m", &m, &case.out_i16("m"));
    }
}

#[test]
fn init_fd_cng_com_matches_the_reference() {
    let Some(cases) = corpus("fd_cng_com", "init") else {
        return;
    };
    for case in &cases {
        let mut handle = None;
        create_fd_cng_com(&mut handle);
        let hs = handle.as_mut().unwrap();
        init_fd_cng_com(hs, case.i16("scale"));
        check(
            case,
            "inv_scaling_factor",
            &hs.inv_scaling_factor,
            &case.out_i16("inv_scaling_factor"),
        );
        check(
            case,
            "scaling_factor",
            &hs.scaling_factor,
            &case.out_i16("scaling_factor"),
        );
        check(case, "ms_m_win", &hs.ms_m_win, &case.out_i16("ms_m_win"));
        check(
            case,
            "ms_m_subwin",
            &hs.ms_m_subwin,
            &case.out_i16("ms_m_subwin"),
        );
        check(case, "a_cng", &hs.a_cng.to_vec(), &case.out_i16s("a_cng"));
        check(
            case,
            "frame_type_previous",
            &hs.frame_type_previous,
            &case.out_i16("frame_type_previous"),
        );
        check(
            case,
            "ms_alpha_cor",
            &hs.ms_alpha_cor.to_vec(),
            &case.out_i32s("ms_alpha_cor"),
        );
        check(case, "ms_fr_cnt", &hs.ms_fr_cnt, &case.out_i16("ms_fr_cnt"));
        check(
            case,
            "ms_fr_cnt_init_thresh",
            &hs.ms_fr_cnt_init_thresh,
            &case.out_i16("ms_fr_cnt_init_thresh"),
        );
        delete_fd_cng_com(&mut handle);
        assert!(handle.is_none());
    }
}

#[test]
fn compress_range_matches_the_reference() {
    let Some(cases) = corpus("fd_cng_com", "compress_range") else {
        return;
    };
    for case in &cases {
        let len = case.i16("len");
        let mut out = vec![0i16; len as usize];
        compress_range(&case.i32s("in"), case.i16("in_exp"), &mut out, len);
        check(case, "out", &out, &case.out_i16s("out"));
    }
}

#[test]
fn expand_range_matches_the_reference() {
    let Some(cases) = corpus("fd_cng_com", "expand_range") else {
        return;
    };
    for case in &cases {
        let len = case.i16("len");
        let mut out = vec![0i32; len as usize];
        let mut out_exp = -99;
        expand_range(&case.i16s("in"), &mut out, &mut out_exp, len);
        check(case, "out", &out, &case.out_i32s("out"));
        check(case, "out_exp", &out_exp, &case.out_i16("out_exp"));
    }
}

#[test]
fn init_partitions_matches_the_reference() {
    let Some(cases) = corpus("fd_cng_com", "init_partitions") else {
        return;
    };
    for case in &cases {
        let (mut part, mut midband, mut psize, mut psize_norm, mut psize_inv) =
            ([0i16; 62], [0i16; 62], [0i16; 62], [0i16; 62], [0i16; 62]);
        let (mut npart, mut psize_norm_exp) = (-1, -1);
        let part_in = case.i16s("part_in");
        init_partitions(
            (case.i16("with_table") != 0).then_some(&part_in[..]),
            case.i16("npart_in"),
            case.i16("start_band"),
            case.i16("stop_band"),
            &mut part,
            &mut npart,
            &mut midband,
            &mut psize,
            &mut psize_norm,
            &mut psize_norm_exp,
            &mut psize_inv,
            case.i16("stop_band_fr"),
        );
        check(case, "npart", &npart, &case.out_i16("npart"));
        let n = npart as usize;
        check(case, "part", &part[..n].to_vec(), &case.out_i16s("part"));
        check(
            case,
            "midband",
            &midband[..n].to_vec(),
            &case.out_i16s("midband"),
        );
        check(case, "psize", &psize[..n].to_vec(), &case.out_i16s("psize"));
        check(
            case,
            "psize_norm",
            &psize_norm[..n].to_vec(),
            &case.out_i16s("psize_norm"),
        );
        check(
            case,
            "psize_norm_exp",
            &psize_norm_exp,
            &case.out_i16("psize_norm_exp"),
        );
        check(
            case,
            "psize_inv",
            &psize_inv[..n].to_vec(),
            &case.out_i16s("psize_inv"),
        );
    }
}

#[test]
fn getmidbands_matches_the_reference() {
    let Some(cases) = corpus("fd_cng_com", "getmidbands") else {
        return;
    };
    for case in &cases {
        let npart = case.i16("npart");
        let n = npart as usize;
        let (mut midband, mut psize, mut psize_norm, mut psize_inv) =
            (vec![0i16; n], vec![0i16; n], vec![0i16; n], vec![0i16; n]);
        let mut psize_norm_exp = -1;
        getmidbands(
            &case.i16s("part"),
            npart,
            &mut midband,
            &mut psize,
            &mut psize_norm,
            &mut psize_norm_exp,
            &mut psize_inv,
        );
        check(case, "midband", &midband, &case.out_i16s("midband"));
        check(case, "psize", &psize, &case.out_i16s("psize"));
        check(
            case,
            "psize_norm",
            &psize_norm,
            &case.out_i16s("psize_norm"),
        );
        check(
            case,
            "psize_norm_exp",
            &psize_norm_exp,
            &case.out_i16("psize_norm_exp"),
        );
        check(case, "psize_inv", &psize_inv, &case.out_i16s("psize_inv"));
    }
}

#[test]
fn bandcombinepow_matches_the_reference() {
    let Some(cases) = corpus("fd_cng_com", "bandcombinepow") else {
        return;
    };
    for case in &cases {
        let npart = case.i16("npart");
        let mut partpow = vec![0i32; npart as usize];
        let mut exp_partpow = -99;
        bandcombinepow(
            &case.i32s("bandpow"),
            case.i16("exp_bandpow"),
            case.i16("nband"),
            &case.i16s("part"),
            npart,
            &case.i16s("psize_inv"),
            &mut partpow,
            &mut exp_partpow,
        );
        check(case, "partpow", &partpow, &case.out_i32s("partpow"));
        check(
            case,
            "exp_partpow",
            &exp_partpow,
            &case.out_i16("exp_partpow"),
        );
    }
}

#[test]
fn scalebands_matches_the_reference() {
    let Some(cases) = corpus("fd_cng_com", "scalebands") else {
        return;
    };
    for case in &cases {
        let nband = case.i16("nband");
        let mut bandpow = vec![12345i32; 320];
        scalebands(
            &case.i32s("partpow"),
            &case.i16s("part"),
            case.i16("npart"),
            &case.i16s("midband"),
            case.i16("nfftpart"),
            nband,
            &mut bandpow,
            case.i16("flag"),
        );
        check(
            case,
            "bandpow",
            &bandpow[..nband as usize].to_vec(),
            &case.out_i32s("bandpow"),
        );
    }
}

#[test]
fn minimum_statistics_matches_the_reference() {
    let Some(cases) = corpus_sized("fd_cng_com", "minimum_statistics", 300) else {
        return;
    };
    for case in &cases {
        let len = case.i16("len");
        let n = len as usize;
        let mut st = FdCngCom::zeroed();
        init_fd_cng_com(&mut st, 16384);
        st.start_band = case.i16("start_band");
        st.stop_ff_tbin = case.i16("stop_fft_bin");
        st.stop_band = case.i16("stop_band");
        st.init_old = case.i16("init_old");
        check(case, "ms_m_win", &st.ms_m_win, &case.i16("ms_m_win"));
        check(
            case,
            "ms_m_subwin",
            &st.ms_m_subwin,
            &case.i16("ms_m_subwin"),
        );
        let psize = case.i16s("psize");
        let (mut noise_floor, mut est, mut psd, mut first_moment) = (
            vec![0i16; 62],
            vec![0i16; 62],
            vec![0i16; 62],
            vec![0i16; 62],
        );
        let (mut alpha, mut second_moment, mut bmin_win, mut bmin_sub_win) = (
            vec![0i32; 62],
            vec![0i32; 62],
            vec![0i32; 62],
            vec![0i32; 62],
        );
        let (mut current_min, mut current_min_out, mut current_min_sub_window) =
            (vec![0i32; 62], vec![0i32; 62], vec![0i32; 62]);
        let mut min_buf = vec![0i32; 372];
        let (mut local_min_flag, mut new_min_flag) = (vec![0i16; 62], vec![0i16; 62]);
        let mut periodog_buf = vec![0i16; 310];
        let mut periodog_buf_ptr = 0i16;
        for f in 0..40 {
            minimum_statistics(
                len,
                case.i16("len_fft"),
                &psize,
                &case.i16s(&format!("periodog{f}")),
                &mut noise_floor,
                &mut est,
                &mut alpha,
                &mut psd,
                &mut first_moment,
                &mut second_moment,
                &mut min_buf,
                &mut bmin_win,
                &mut bmin_sub_win,
                &mut current_min,
                &mut current_min_out,
                &mut current_min_sub_window,
                &mut local_min_flag,
                &mut new_min_flag,
                &mut periodog_buf,
                &mut periodog_buf_ptr,
                &mut st,
            );
            let name = format!("est{f}");
            check(case, &name, &est[..n].to_vec(), &case.out_i16s(&name));
        }
        for (name, rust) in [
            ("noise_floor", &noise_floor[..n]),
            ("psd", &psd[..n]),
            ("first_moment", &first_moment[..n]),
            ("local_min_flag", &local_min_flag[..n]),
            ("new_min_flag", &new_min_flag[..n]),
            ("periodog_buf", &periodog_buf[..5 * n]),
            ("slope", &st.ms_slope[..]),
        ] {
            check(case, name, &rust.to_vec(), &case.out_i16s(name));
        }
        for (name, rust) in [
            ("alpha", &alpha[..n]),
            ("second_moment", &second_moment[..n]),
            ("min_buf", &min_buf[..6 * n]),
            ("bmin_win", &bmin_win[..n]),
            ("bmin_sub_win", &bmin_sub_win[..n]),
            ("current_min", &current_min[..n]),
            ("current_min_out", &current_min_out[..n]),
            ("current_min_sub_window", &current_min_sub_window[..n]),
            ("periodog_sum", &st.ms_periodog_sum[..]),
            ("psd_sum", &st.ms_psd_sum[..]),
            ("alpha_cor", &st.ms_alpha_cor[..]),
            ("qeq_inv_av", &st.ms_qeq_inv_av[..]),
        ] {
            check(case, name, &rust.to_vec(), &case.out_i32s(name));
        }
        for (name, rust) in [
            ("periodog_buf_ptr", periodog_buf_ptr),
            ("fr_cnt", st.ms_fr_cnt),
            ("min_buffer_ptr", st.ms_min_buffer_ptr),
            ("offsetflag", st.offsetflag),
            ("init_old", st.init_old),
            ("init_counter", st.ms_fr_cnt_init_counter),
        ] {
            check(case, name, &rust, &case.out_i16(name));
        }
    }
}

#[test]
fn analysis_stft_matches_the_reference() {
    let Some(cases) = corpus("fd_cng_com", "analysis_stft") else {
        return;
    };
    for case in &cases {
        let mut st = FdCngCom::zeroed();
        init_fd_cng_com(&mut st, 16384);
        st.fftlen = case.i16("fftlen");
        st.frame_size = st.fftlen / 2;
        st.olap_buffer_ana = Some(0);
        st.olap_win_ana = basop_get_tables(st.fftlen / 2).twiddle;
        let mut olap = vec![0i16; 320];
        let olap_in = case.i16s("olap");
        olap[..olap_in.len()].copy_from_slice(&olap_in);
        for f in 0..2 {
            let mut fft = vec![0i32; 640];
            let mut exp = -99;
            analysis_stft(
                &case.i16s(&format!("input{f}")),
                case.i16("Q"),
                &mut fft,
                &mut exp,
                &st,
                &mut olap,
            );
            let name = format!("fft{f}");
            check(
                case,
                &name,
                &fft[..st.fftlen as usize].to_vec(),
                &case.out_i32s(&name),
            );
            let name = format!("exp{f}");
            check(case, &name, &exp, &case.out_i16(&name));
        }
        check(
            case,
            "olap",
            &olap[..olap_in.len()].to_vec(),
            &case.out_i16s("olap"),
        );
    }
}

#[test]
fn synthesis_stft_matches_the_reference() {
    let Some(cases) = corpus("fd_cng_com", "synthesis_stft") else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = FdCngCom::zeroed();
        init_fd_cng_com(&mut st, 16384);
        st.fftlen = case.i16("fftlen");
        st.frame_size = st.fftlen / 2;
        st.fftlen_shift = if st.fftlen == 512 { 8 } else { 9 };
        st.fftlen_fac = if st.fftlen == 512 { 32767 } else { 20480 };
        let fl = st.fftlen as usize;
        let window = basop_get_tables(st.fftlen / 4).twiddle;
        st.a_cng.copy_from_slice(&case.i16s("A_cng"));
        let gen_exc = case.i16("gen_exc");
        let mut q_new = case.i16("Q_new");
        // Alternate between the state's own buffers and external ones: the reference passes
        // both shapes (st->fftBuffer with olapBufferSynth2, a local spectrum with olapBufferSynth).
        let external = index % 2 == 1;
        let mut olap = vec![0i16; 640];
        olap[..fl].copy_from_slice(&case.i16s("olap"));
        st.olap_buffer_synth[..fl].copy_from_slice(&olap[..fl]);
        for f in 0..2 {
            let mut out = vec![0i16; 320];
            let mut local = case.i32s(&format!("fft{f}"));
            let exp = case.i16(&format!("exp{f}"));
            let tcx_transition = case.i16(&format!("tcx_transition{f}"));
            if external {
                synthesis_stft(
                    StftSpectrum::Local(&mut local),
                    exp,
                    &mut out,
                    StftOverlap::External(&mut olap),
                    window,
                    tcx_transition,
                    &mut st,
                    gen_exc,
                    &mut q_new,
                );
            } else {
                st.fft_buffer[..fl].copy_from_slice(&local);
                synthesis_stft(
                    StftSpectrum::Common,
                    exp,
                    &mut out,
                    StftOverlap::Common,
                    window,
                    tcx_transition,
                    &mut st,
                    gen_exc,
                    &mut q_new,
                );
            }
            let name = format!("out{f}");
            check(case, &name, &out[..fl / 2].to_vec(), &case.out_i16s(&name));
            let name = format!("exc{f}");
            check(
                case,
                &name,
                &st.exc_cng[..fl / 2].to_vec(),
                &case.out_i16s(&name),
            );
            let name = format!("q{f}");
            check(case, &name, &q_new, &case.out_i16(&name));
        }
        let olap_out = if external {
            olap[..fl].to_vec()
        } else {
            st.olap_buffer_synth[..fl].to_vec()
        };
        check(case, "olap", &olap_out, &case.out_i16s("olap"));
    }
}

#[test]
fn lpc_from_spectrum_matches_the_reference() {
    let Some(cases) = corpus("fd_cng_com", "lpc_from_spectrum") else {
        return;
    };
    for case in &cases {
        let mut a = [0i16; 17];
        lpc_from_spectrum(
            &case.i32s("powspec"),
            case.i16("exp"),
            case.i16("start"),
            case.i16("stop"),
            case.i16("fftlen"),
            &mut a,
            16,
            case.i16("preemph"),
        );
        check(case, "a", &a.to_vec(), &case.out_i16s("a"));
    }
}

#[test]
fn msvq_decoder_matches_the_reference() {
    let Some(cases) = corpus("fd_cng_com", "msvq_decoder") else {
        return;
    };
    for case in &cases {
        let n = case.i16("n");
        let mut uq = vec![0i16; n as usize];
        msvq_decoder(
            &CDK_37BITS,
            STAGES_37BITS,
            n,
            MAXN_37BITS,
            &case.i16s("idx"),
            &mut uq,
        );
        check(case, "uq", &uq, &case.out_i16s("uq"));
    }
}

#[test]
fn fd_cng_exc_matches_the_reference() {
    use siphon_rtp_codec::evs::com::fd_cng_com::fd_cng_exc;
    use siphon_rtp_codec::evs::dec::state::FdCngCom;

    let Some(cases) = corpus("fd_cng_com", "fd_cng_exc") else {
        return;
    };
    for case in &cases {
        let mut hs = Box::new(FdCngCom::zeroed());
        hs.a_cng.copy_from_slice(&case.i16s("a_cng"));
        hs.exc_cng.copy_from_slice(&case.i16s("exc_cng"));
        let mut mode = 7;
        let mut lsp_cng = case.i16s("lsp_cng");
        let mut aq = vec![-12345i16; 85];
        let (mut lsp_new, mut lsf_new) = ([0i16; 16], [0i16; 16]);
        let (mut exc, mut exc2) = (vec![-12345i16; 320], vec![-12345i16; 320]);
        let mut bwe_exc = vec![-12345i16; 640];
        fd_cng_exc(
            &hs,
            &mut mode,
            case.i16("L_frame"),
            &case.i16s("lsp_old"),
            case.i16("first_CNG"),
            &mut lsp_cng,
            &mut aq,
            &mut lsp_new,
            &mut lsf_new,
            &mut exc,
            &mut exc2,
            &mut bwe_exc,
        );
        let check = |name: &str, rust: &Vec<i16>| {
            if let Some(message) = mismatch(case, name, rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        };
        check("mode", &vec![mode]);
        check("Aq", &aq);
        check("lsp_new", &lsp_new.to_vec());
        check("lsf_new", &lsf_new.to_vec());
        check("lsp_cng", &lsp_cng);
        check("exc", &exc);
        check("exc2", &exc2);
        check("bwe_exc", &bwe_exc);
    }
}

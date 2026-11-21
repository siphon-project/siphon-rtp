//! `lib_com/bitstream_fx.c` (decoder half) against `fn_bitstream`.

use siphon_rtp_codec::evs::com::bitstream::{
    bit_alloc_idx, bit_alloc_idx_16khz, brate2idx, brate2idx16k, dec_prm_core,
    decision_matrix_core_dec, get_indice, get_indice_1, get_next_indice, get_next_indice_1,
    get_next_indice_tmp, get_partial_copy_info, rate2evs_mode, read_indices, read_indices_frame,
};
use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::g192::G192Reader;

use crate::common::{corpus, mismatch, Case};

fn fresh_state() -> Box<DecoderState> {
    Box::new(DecoderState::zeroed())
}

fn bits_into(st: &mut DecoderState, bits: &[i16]) {
    for (slot, &bit) in st.bit_stream.iter_mut().zip(bits) {
        *slot = bit as u16;
    }
}

/// The reader-state fields the oracle prints after a call, in its order.
fn state_fields(st: &DecoderState) -> Vec<(&'static str, i64)> {
    vec![
        ("bfi", st.bfi.into()),
        ("ber_detect", st.ber_detect.into()),
        ("mdct_sw_enable", st.mdct_sw_enable.into()),
        ("mdct_sw", st.mdct_sw.into()),
        ("next_bit_pos", st.next_bit_pos.into()),
        ("total_num_bits", st.total_num_bits.into()),
        ("total_brate", st.total_brate.into()),
        ("codec_mode", st.codec_mode.into()),
        ("last_codec_mode", st.last_codec_mode.into()),
        ("opt_amr_wb", st.opt_amr_wb.into()),
        ("cng", st.cng.into()),
        ("prev_ft_speech", st.prev_ft_speech.into()),
        ("cng_type", st.cng_type.into()),
        ("last_cng_type", st.last_cng_type.into()),
        ("core", st.core.into()),
        ("bwidth", st.bwidth.into()),
        ("m_frame_type", st.m_frame_type.into()),
    ]
}

fn check_state(case: &Case, st: &DecoderState, stream_bits: Option<usize>) {
    for (name, value) in state_fields(st) {
        if let Some(message) = mismatch(case, name, &value, &case.outputs[name][0]) {
            panic!("{message}");
        }
    }
    if let Some(count) = stream_bits {
        let rust: Vec<i64> = st.bit_stream[..count].iter().map(|&b| b.into()).collect();
        if let Some(message) = mismatch(case, "bit_stream", &rust, &case.outputs["bit_stream"]) {
            panic!("{message}");
        }
    }
}

#[test]
fn read_indices_matches_the_reference() {
    let Some(cases) = corpus("bitstream", "read_indices") else {
        return;
    };
    for case in &cases {
        let mut st = fresh_state();
        st.ini_frame = case.i16("ini_frame");
        st.last_codec_mode = case.i16("last_codec_mode");
        st.codec_mode = case.i16("codec_mode");
        st.core = case.i16("core");
        st.bwidth = case.i16("bwidth");
        st.prev_ft_speech = case.i16("prev_ft_speech");
        st.cng = case.i16("cng");
        st.opt_amr_wb = case.i16("opt_amr_wb");
        st.last_total_brate = case.i32("last_total_brate");
        st.cng_type = case.i16("cng_type");
        st.last_cng_type = case.i16("last_cng_type");
        let bits: Vec<u8> = case.i16s("bits").iter().map(|&b| b as u8).collect();
        read_indices(&mut st, case.i16("good") != 0, &bits).expect("valid frame");
        assert_eq!(case.out_i16("ok"), 1);
        check_state(case, &st, Some(bits.len() + 16));
    }
}

#[test]
fn bit_readers_match_the_reference() {
    let Some(cases) = corpus("bitstream", "readers") else {
        return;
    };
    for case in &cases {
        let mut st = fresh_state();
        bits_into(&mut st, &case.i16s("bits"));
        st.total_num_bits = case.i16("total_num_bits");
        st.codec_mode = case.i16("codec_mode");
        st.next_bit_pos = case.i16("next_bit_pos");
        let ops = case.i16s("ops");
        let (mut results, mut positions, mut ber) = (Vec::new(), Vec::new(), Vec::new());
        for op in ops.chunks(3) {
            let (a, b) = (op[1], op[2]);
            let result = match op[0] {
                0 => get_next_indice(&mut st, a) as i16,
                1 => get_next_indice_1(&mut st) as i16,
                2 => get_indice(&mut st, b, a) as i16,
                3 => get_indice_1(&mut st, b) as i16,
                _ => {
                    get_next_indice_tmp(&mut st, a % 4);
                    0
                }
            };
            results.push(result);
            positions.push(st.next_bit_pos);
            ber.push(st.ber_detect);
        }
        for (name, rust) in [("results", results), ("positions", positions), ("ber", ber)] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
    }
}

#[test]
fn core_signalling_read_ahead_matches_the_reference() {
    let Some(cases) = corpus("bitstream", "core_dec") else {
        return;
    };
    for case in &cases {
        let mut st = fresh_state();
        let bits = case.i16s("bits");
        bits_into(&mut st, &bits);
        st.total_brate = case.i32("total_brate");
        st.total_num_bits = bits.len() as i16;
        let mode2 = case.i16("which") != 0;
        st.codec_mode = if mode2 { 2 } else { 1 };
        if mode2 {
            dec_prm_core(&mut st);
        } else {
            decision_matrix_core_dec(&mut st);
        }
        let rust = [
            st.core,
            st.bwidth,
            st.m_frame_type,
            st.next_bit_pos,
            st.ber_detect,
        ];
        let reference = [
            case.out_i16("core"),
            case.out_i16("bwidth"),
            case.out_i16("m_frame_type"),
            case.out_i16("next_bit_pos"),
            case.out_i16("ber_detect"),
        ];
        if let Some(message) = mismatch(case, "core/bwidth/type/pos/ber", &rust, &reference) {
            panic!("{message}");
        }
    }
}

#[test]
fn partial_copy_info_matches_the_reference() {
    let Some(cases) = corpus("bitstream", "partial_copy") else {
        return;
    };
    for case in &cases {
        let mut st = fresh_state();
        let bits = case.i16s("bits");
        bits_into(&mut st, &bits);
        st.total_brate = case.i32("total_brate");
        st.total_num_bits = bits.len() as i16;
        st.bfi = case.i16("bfi");
        st.codec_mode = 1;
        st.use_partial_copy = case.i16("use_partial_copy");
        st.last_bwidth = case.i16("last_bwidth");
        st.bwidth = case.i16("bwidth");
        st.core = case.i16("core");
        st.rf_target_bits = case.i16("rf_target_bits");
        let mut coder_type = case.i16("coder_type");
        let mut sharp_flag = case.i16("sharp_flag");
        get_partial_copy_info(&mut st, &mut coder_type, &mut sharp_flag);
        let rust = [
            st.rf_flag,
            st.rf_frame_type,
            st.rf_fec_offset,
            st.rf_target_bits,
            coder_type,
            sharp_flag,
            st.bwidth,
            st.codec_mode,
            st.bfi,
            st.core,
            st.use_partial_copy,
            st.ber_detect,
            st.next_bit_pos,
        ];
        let names = [
            "rf_flag",
            "rf_frame_type",
            "rf_fec_offset",
            "rf_target_bits",
            "coder_type",
            "sharp_flag",
            "bwidth",
            "codec_mode",
            "bfi",
            "core",
            "use_partial_copy",
            "ber_detect",
            "next_bit_pos",
        ];
        let reference: Vec<i16> = names.iter().map(|name| case.out_i16(name)).collect();
        if let Some(message) = mismatch(case, "rf fields", &rust.to_vec(), &reference) {
            panic!("{message}");
        }
    }
}

#[test]
fn bit_allocation_indices_match_the_reference() {
    let Some(cases) = corpus("bitstream", "bit_alloc_idx") else {
        return;
    };
    for case in &cases {
        let (brate, ctype, sfrm, tc) = (
            case.i32("brate"),
            case.i16("ctype"),
            case.i16("sfrm"),
            case.i16("tc"),
        );
        let rust = [
            bit_alloc_idx(brate, ctype, sfrm, tc),
            bit_alloc_idx_16khz(brate, ctype, sfrm, tc),
            brate2idx(brate).into(),
            brate2idx16k(brate).into(),
        ];
        let reference = [
            case.out_i32("idx"),
            case.out_i32("idx16k"),
            case.out_i32("brate2idx"),
            case.out_i32("brate2idx16k"),
        ];
        if let Some(message) = mismatch(case, "idx/idx16k/brate2idx/16k", &rust, &reference) {
            panic!("{message}");
        }
    }
}

#[test]
fn rate2evs_mode_matches_the_reference() {
    let Some(cases) = corpus("bitstream", "bit_alloc_idx") else {
        return;
    };
    for case in &cases {
        let rust = i64::from(rate2evs_mode(case.i32("any_rate")));
        if let Some(message) = mismatch(
            case,
            "rate2evs_mode",
            &rust,
            &case.outputs["rate2evs_mode"][0],
        ) {
            panic!("{message}");
        }
    }
}

/// One `fn_bitstream stream` line as a [`Case`].
fn parse_line(line: &str) -> Case {
    let side = |text: &str| {
        text.split_whitespace()
            .map(|pair| {
                let (name, values) = pair.split_once('=').expect("name=values");
                let values = if values.is_empty() {
                    Vec::new()
                } else {
                    values
                        .split(',')
                        .map(|v| v.parse().expect("integer"))
                        .collect()
                };
                (name.to_owned(), values)
            })
            .collect()
    };
    let (inputs, outputs) = line.split_once(" ->").expect("arrow");
    Case {
        line: line.to_owned(),
        inputs: side(inputs),
        outputs: side(outputs),
    }
}

/// Every frame of a real conformance bitstream through `read_indices`, one persistent state, against
/// `fn_bitstream stream`. Needs the TS 26.444 sequences (`$SIPHON_RTP_EVS_VECTORS` or
/// `reference/evs/testvec`); skips without them, since they are not this oracle's to build.
#[test]
fn read_indices_follows_real_bitstreams() {
    let vectors = std::env::var_os("SIPHON_RTP_EVS_VECTORS").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/testvec"),
        std::path::PathBuf::from,
    );
    let oracle = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../reference/evs/build/fn_bitstream");
    if !vectors.is_dir() || !oracle.is_file() {
        eprintln!("skipping: no conformance bitstreams or fn_bitstream");
        return;
    }
    let mut checked = 0;
    for name in [
        "wb/stv16c_7200_16kHz.COD",
        "wb/stv16c_8000_16kHz.COD",
        "wb/stv16c_dtx_8000_16kHz.b10.COD",
        "wb/stv16c_7200_16kHz.b10.COD",
        "wb/stv16c_13200_16kHz.b10.COD",
        "wb/stv16c_24400_16kHz.f06.COD",
        "swb/stv32c_32000_32kHz.b10.COD",
        "amrwb/Dtx1_dtx_12650_16kHz.b10.COD",
    ] {
        let path = vectors.join("testv/bitstreams").join(name);
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let output = std::process::Command::new(&oracle)
            .arg("stream")
            .arg(&path)
            .output()
            .expect("run fn_bitstream");
        let text = String::from_utf8(output.stdout).expect("ASCII");
        let lines: Vec<&str> = text.lines().collect();
        let mut st = fresh_state();
        st.codec_mode = 1;
        st.last_codec_mode = 1;
        st.core = -1;
        st.prev_ft_speech = 1;
        let mut frames = 0;
        for (index, frame) in G192Reader::new(&bytes).enumerate() {
            let frame = frame.expect("valid G.192");
            read_indices_frame(&mut st, &frame).expect("valid frame");
            let line = lines.get(index).expect("oracle printed every frame");
            let case = parse_line(line);
            let stream = (st.bfi == 0).then(|| st.total_num_bits as usize + 16);
            check_state(&case, &st, stream);
            st.ini_frame = 1;
            st.last_codec_mode = st.codec_mode;
            if st.bfi == 0 {
                st.last_total_brate = st.total_brate;
            }
            frames += 1;
        }
        assert_eq!(frames, lines.len(), "{name}");
        checked += 1;
    }
    eprintln!("read_indices followed {checked} real bitstreams");
}

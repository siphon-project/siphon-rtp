//! Bit-exact error-concealment tests for the AMR-NB decoder (3GPP TS 26.091 via the TS 26.073
//! reference decoder).
//!
//! Each case replays a TS 26.074 NODTX `.COD` vector with chosen frames turned into a lost frame
//! (`RX_NO_DATA`, no bits) or a damaged frame (`RX_SPEECH_BAD`, bits kept), runs the whole stream
//! through [`SpeechDecoder`], and compares a 64-bit FNV-1a hash of the PCM against the one produced
//! by the unmodified TS 26.073 C reference decoder (`decoder -rxframetype`) fed the identical frame
//! sequence. The hashes were generated once, outside the repository; the vectors are gitignored, so
//! every test skips when they are absent from the checkout.

use super::constants::L_FRAME;
use super::dec_main::SpeechDecoder;
use std::path::PathBuf;

/// What happens to a frame of the replayed stream.
#[derive(Clone, Copy)]
enum Loss {
    /// `RX_NO_DATA`: the frame never arrived.
    Lost,
    /// `RX_SPEECH_BAD`: the frame arrived with its bits damaged.
    Bad,
}

/// `first + i * stride` for `i` in `0..count` suffers `loss`; later events override earlier ones.
struct Event {
    first: usize,
    count: usize,
    stride: usize,
    loss: Loss,
}

/// The named loss patterns of the table below.
#[derive(Clone, Copy, Debug)]
enum Case {
    /// One lost frame.
    Single,
    /// Three consecutive lost frames.
    Burst3,
    /// Seven consecutive lost frames: the state machine reaches its deepest state (6).
    Burst7,
    /// Two consecutive and one further damaged frame, bits kept.
    Bad,
    /// Periodic losses mixed with periodic damaged frames over the whole vector.
    Mixed,
}

const fn event(first: usize, count: usize, stride: usize, loss: Loss) -> Event {
    Event {
        first,
        count,
        stride,
        loss,
    }
}

static SINGLE: [Event; 1] = [event(40, 1, 1, Loss::Lost)];
static BURST3: [Event; 1] = [event(60, 3, 1, Loss::Lost)];
static BURST7: [Event; 1] = [event(80, 7, 1, Loss::Lost)];
static BAD: [Event; 2] = [event(100, 2, 1, Loss::Bad), event(130, 1, 1, Loss::Bad)];
static MIXED: [Event; 2] = [event(20, 40, 5, Loss::Lost), event(22, 20, 9, Loss::Bad)];

impl Case {
    fn events(self) -> &'static [Event] {
        match self {
            Case::Single => &SINGLE,
            Case::Burst3 => &BURST3,
            Case::Burst7 => &BURST7,
            Case::Bad => &BAD,
            Case::Mixed => &MIXED,
        }
    }

    fn loss_of(self, frame: usize) -> Option<Loss> {
        let mut found = None;
        for event in self.events() {
            for index in 0..event.count {
                if event.first + index * event.stride == frame {
                    found = Some(event.loss);
                }
            }
        }
        found
    }
}

/// FNV-1a over the little-endian bytes of the samples.
fn fnv1a(samples: &[i16]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for sample in samples {
        for byte in sample.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

/// Read a `.COD` vector as `Word16`s; `None` when the (gitignored) vectors are absent.
fn read_cod(tag: &str, file: &str) -> Option<Vec<i16>> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(format!(
        "../../reference/amr-nb/testv/NODTX/T_{tag}/{file}_{tag}.COD"
    ));
    let bytes = std::fs::read(path).ok()?;
    Some(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| i16::from_le_bytes(*pair))
            .collect(),
    )
}

/// Replay `words` (250 per frame: type, 244 bits, mode, 4 unused) through a fresh decoder with the
/// losses of `case` applied; return the PCM.
fn replay(words: &[i16], mode: usize, case: Case) -> Vec<i16> {
    const FRAME_WORDS: usize = 250;
    let mut decoder = SpeechDecoder::new();
    let mut pcm = Vec::new();
    let mut synth = [0i16; L_FRAME];
    for (frame, words) in words.as_chunks::<FRAME_WORDS>().0.iter().enumerate() {
        let bits = &words[1..245];
        match case.loss_of(frame) {
            Some(Loss::Lost) => decoder.conceal_frame(&mut synth),
            Some(Loss::Bad) => decoder.decode_bad_frame(mode, bits, &mut synth),
            None => decoder.decode_frame(mode, bits, &mut synth),
        }
        pcm.extend_from_slice(&synth);
    }
    pcm
}

/// (vector, mode index, mode tag, loss pattern, FNV-1a of the reference decoder's PCM).
#[rustfmt::skip]
const REFERENCE: &[(&str, usize, &str, Case, u64)] = &[
    ("T00", 0, "475", Case::Single, 0x1608_72ed_c13d_e2d4),
    ("T00", 0, "475", Case::Burst3, 0x32dc_60fa_5f77_9f47),
    ("T00", 0, "475", Case::Burst7, 0x923b_a0f3_dec1_7e16),
    ("T00", 0, "475", Case::Bad, 0x1d3e_bcfd_643d_6814),
    ("T00", 0, "475", Case::Mixed, 0x98a3_aa0b_18d3_ff4a),
    ("T00", 1, "515", Case::Single, 0x8676_ee08_9128_7403),
    ("T00", 1, "515", Case::Burst3, 0x8445_c853_2ca2_cd34),
    ("T00", 1, "515", Case::Burst7, 0x636a_147b_66fb_b643),
    ("T00", 1, "515", Case::Bad, 0x032a_4565_81a2_93c4),
    ("T00", 1, "515", Case::Mixed, 0x8b45_c90f_9b6c_0e2c),
    ("T00", 2, "59", Case::Single, 0x8634_a8bb_9d97_e321),
    ("T00", 2, "59", Case::Burst3, 0x9579_fb6f_038f_5ff7),
    ("T00", 2, "59", Case::Burst7, 0xe769_d01d_a511_ca43),
    ("T00", 2, "59", Case::Bad, 0x52e4_d9ae_fee1_33f8),
    ("T00", 2, "59", Case::Mixed, 0x6b25_284c_d335_2c98),
    ("T00", 3, "67", Case::Single, 0x0297_426d_a944_1ccb),
    ("T00", 3, "67", Case::Burst3, 0x1036_f75a_e249_8d5b),
    ("T00", 3, "67", Case::Burst7, 0xa393_a207_a62c_e4d8),
    ("T00", 3, "67", Case::Bad, 0x50b5_d5ca_3773_9da4),
    ("T00", 3, "67", Case::Mixed, 0x56d3_b666_4981_26c0),
    ("T00", 4, "74", Case::Single, 0x3507_75fa_f2ad_f514),
    ("T00", 4, "74", Case::Burst3, 0xfa35_d1b1_3993_a314),
    ("T00", 4, "74", Case::Burst7, 0xeed4_7d63_f922_345a),
    ("T00", 4, "74", Case::Bad, 0x1564_5f9c_02f4_fcc0),
    ("T00", 4, "74", Case::Mixed, 0x4a70_9fcb_c618_af25),
    ("T00", 5, "795", Case::Single, 0x644f_e089_c63f_1050),
    ("T00", 5, "795", Case::Burst3, 0xa0ba_56da_dcf9_8d66),
    ("T00", 5, "795", Case::Burst7, 0xa102_81b2_4d6a_de86),
    ("T00", 5, "795", Case::Bad, 0xcf0b_9c68_6d69_7f88),
    ("T00", 5, "795", Case::Mixed, 0xa2e2_d79c_f6f3_7bc7),
    ("T00", 6, "102", Case::Single, 0x71b3_5609_f435_c8f8),
    ("T00", 6, "102", Case::Burst3, 0x434f_64bc_1ab5_293d),
    ("T00", 6, "102", Case::Burst7, 0xdb44_be7c_1531_dd86),
    ("T00", 6, "102", Case::Bad, 0x70c1_6425_f4b5_adfe),
    ("T00", 6, "102", Case::Mixed, 0x0d41_3dc1_c3f5_b5e1),
    ("T00", 7, "122", Case::Single, 0x0fb1_1991_2579_ddf3),
    ("T00", 7, "122", Case::Burst3, 0xa58d_e6d0_9364_6e64),
    ("T00", 7, "122", Case::Burst7, 0x36c3_d58d_4ab1_47cd),
    ("T00", 7, "122", Case::Bad, 0x1c38_e365_e80e_be96),
    ("T00", 7, "122", Case::Mixed, 0xf114_b462_b21e_46df),
    ("T01", 0, "475", Case::Single, 0xa4fd_91e3_ff81_339b),
    ("T01", 0, "475", Case::Burst3, 0x8115_6400_95ad_1e46),
    ("T01", 0, "475", Case::Burst7, 0xc55d_062c_0bb9_225d),
    ("T01", 0, "475", Case::Bad, 0xbe00_cc25_1ecd_8fca),
    ("T01", 0, "475", Case::Mixed, 0xfb9b_edf7_4030_549b),
    ("T01", 1, "515", Case::Single, 0x1b43_4c0b_9adb_f478),
    ("T01", 1, "515", Case::Burst3, 0x962e_1049_40f9_cacf),
    ("T01", 1, "515", Case::Burst7, 0x0011_bcca_d962_0a93),
    ("T01", 1, "515", Case::Bad, 0xe490_4214_64b3_f502),
    ("T01", 1, "515", Case::Mixed, 0x9fb0_d366_fdf2_54cd),
    ("T01", 2, "59", Case::Single, 0x05dc_9d95_a60c_a086),
    ("T01", 2, "59", Case::Burst3, 0xed2b_b9a3_1c26_b5bd),
    ("T01", 2, "59", Case::Burst7, 0x5fb4_8ffe_d6bd_b89e),
    ("T01", 2, "59", Case::Bad, 0x7650_8760_a65b_d959),
    ("T01", 2, "59", Case::Mixed, 0x6273_64bf_f955_1ee9),
    ("T01", 3, "67", Case::Single, 0x3144_b88d_52c1_0c14),
    ("T01", 3, "67", Case::Burst3, 0xbb5b_7ee8_ff33_8b16),
    ("T01", 3, "67", Case::Burst7, 0x7f7c_c433_bba6_caaf),
    ("T01", 3, "67", Case::Bad, 0xde4d_a078_7298_1cd7),
    ("T01", 3, "67", Case::Mixed, 0x425a_64b4_e808_0678),
    ("T01", 4, "74", Case::Single, 0xb70c_c55a_4f6b_4299),
    ("T01", 4, "74", Case::Burst3, 0x81c7_9342_f7bf_9e4a),
    ("T01", 4, "74", Case::Burst7, 0x8d85_7a78_a042_f9b3),
    ("T01", 4, "74", Case::Bad, 0x8bed_26f1_8cc1_8a80),
    ("T01", 4, "74", Case::Mixed, 0xda7a_6d35_3458_9e01),
    ("T01", 5, "795", Case::Single, 0xb961_2d35_ef1b_2f49),
    ("T01", 5, "795", Case::Burst3, 0x86a5_1ebb_83b9_5fc3),
    ("T01", 5, "795", Case::Burst7, 0x7e6b_d363_48ec_3de0),
    ("T01", 5, "795", Case::Bad, 0x55ee_cab5_e5c7_de4c),
    ("T01", 5, "795", Case::Mixed, 0xf28a_bcab_3e89_a5ab),
    ("T01", 6, "102", Case::Single, 0xc4af_cb2f_e9fc_d762),
    ("T01", 6, "102", Case::Burst3, 0xc70c_fffe_4a64_c91d),
    ("T01", 6, "102", Case::Burst7, 0x1f10_5185_60cc_36b1),
    ("T01", 6, "102", Case::Bad, 0x7135_7596_6549_9a5f),
    ("T01", 6, "102", Case::Mixed, 0x76e3_7577_d74a_4e0b),
    ("T01", 7, "122", Case::Single, 0xd1ac_e813_7074_1331),
    ("T01", 7, "122", Case::Burst3, 0xac64_afa6_86f8_b47d),
    ("T01", 7, "122", Case::Burst7, 0x9da6_ec8e_29ce_40fc),
    ("T01", 7, "122", Case::Bad, 0x292d_9ae0_a1ff_5aef),
    ("T01", 7, "122", Case::Mixed, 0x17d5_449d_a807_22f1),
];

#[test]
fn concealed_streams_match_the_reference_decoder_bit_exact() {
    let mut checked = 0usize;
    for &(file, mode, tag, case, expected) in REFERENCE {
        let Some(words) = read_cod(tag, file) else {
            eprintln!("AMR-NB vectors absent, skipping concealment case {file} {tag} {case:?}");
            continue;
        };
        let pcm = replay(&words, mode, case);
        assert_eq!(
            fnv1a(&pcm),
            expected,
            "{file} mode {tag} {case:?}: PCM differs from the reference decoder"
        );
        checked += 1;
    }
    eprintln!("{checked} AMR-NB concealment cases bit-exact");
}

#[test]
fn every_loss_pattern_is_in_every_mode_of_the_table() {
    // Guards the table itself: 2 vectors x 8 modes x 5 patterns.
    assert_eq!(REFERENCE.len(), 80);
    for mode in 0..8 {
        for case in [
            Case::Single,
            Case::Burst3,
            Case::Burst7,
            Case::Bad,
            Case::Mixed,
        ] {
            let count = REFERENCE
                .iter()
                .filter(|entry| entry.1 == mode && format!("{:?}", entry.3) == format!("{case:?}"))
                .count();
            assert_eq!(count, 2, "mode {mode} {case:?}");
        }
    }
}

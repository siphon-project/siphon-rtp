//! Reading the decoder's bitstream (TS 26.442 `lib_com/bitstream_fx.c`): the G.192 frame reader
//! with its RX DTX handler, the bit readers every decoding stage calls, the MODE1/MODE2 codec
//! selection, and the channel-aware (RF) signalling readers.
//!
//! The encoder half of the file (`push_indice_fx`, `write_indices_fx`, ...) and the MIME / RTP /
//! jitter-buffer readers are not ported: the decoder here is driven by G.192 frames only.

use crate::evs::cnst::{
    ACELP_13K20, ACELP_16K40, ACELP_24K40, ACELP_64K, ACELP_CORE, ACELP_MODE_MAX, ACTIVE_FRAME,
    AMR_WB_CORE, FB, FD_CNG, FRAME_NO_DATA, FRAME_SIZE_NB, GENERIC, HQ_CORE, INACTIVE, LP_CNG,
    LR_MDCT, MAX_BITS_PER_FRAME, MODE1, MODE2, NB, PPP_NELP_2K80, RF_ALLPRED, RF_NO_DATA, RF_TCXFD,
    RF_TCXTD1, RF_TCXTD2, SID_1K75, SID_2K40, SID_FRAME, SWB, TCX_20_CORE, TRANSITION, WB,
    ZERO_FRAME,
};
use crate::evs::dec::state::DecoderState;
use crate::evs::g192::G192Frame;
use crate::evs::rom::{ACELP_SIG_TBL, BIT_RATES_16K_DIV50, BIT_RATES_DIV50, FRAMESIZECONFIG};
use crate::itu::basic_ops::{add, extract_l, l_add, l_shr, shl, shr, sub};
use crate::itu::stl2009::{l_mac0, l_msu0, lshl, mpy_32_16_ss};
use crate::CodecError;

/// `FRAMEMODE_NORMAL` (`lib_dec/stat_dec_fx.h` enum): frame available.
pub const FRAMEMODE_NORMAL: i16 = 0;
/// `FRAMEMODE_MISSING`: frame missing, conceal.
pub const FRAMEMODE_MISSING: i16 = 1;
/// `FRAMEMODE_FUTURE`: a future frame carrying a partial copy (channel-aware mode).
pub const FRAMEMODE_FUTURE: i16 = 2;

// `RF_NOPRED` / `RF_GENPRED` / `RF_NELP` are `ACELP_MODE_MAX + n` macros, written out where the
// reference pastes them (a `case` label, so the sum is the value).
const RF_NOPRED: i16 = ACELP_MODE_MAX + 1;
const RF_GENPRED: i16 = ACELP_MODE_MAX + 2;
const RF_NELP: i16 = ACELP_MODE_MAX + 3;

// The bit rates the reference names in its rate switches that `cnst` exports as i32 or not at all.
const ACELP_6K60: i32 = 6600;
const ACELP_8K85: i32 = 8850;
const ACELP_12K65: i32 = 12650;
const ACELP_14K25: i32 = 14250;
const ACELP_15K85: i32 = 15850;
const ACELP_18K25: i32 = 18250;
const ACELP_19K85: i32 = 19850;
const ACELP_23K05: i32 = 23050;
const ACELP_23K85: i32 = 23850;
const ACELP_32K: i32 = 32000;
const ACELP_14K80: i32 = 14800;

/// `rate2AMRWB_IOmode`: the AMR-WB IO mode index of a bit rate (`lib_com/cnst_fx.h` enum order), or
/// -1.
fn rate2amrwb_io_mode(rate: i32) -> i16 {
    match rate {
        1750 => 9, // AMRWB_IO_SID
        ACELP_6K60 => 0,
        ACELP_8K85 => 1,
        ACELP_12K65 => 2,
        ACELP_14K25 => 3,
        ACELP_15K85 => 4,
        ACELP_18K25 => 5,
        ACELP_19K85 => 6,
        ACELP_23K05 => 7,
        ACELP_23K85 => 8,
        _ => -1,
    }
}

/// `rate2EVSmode`: the EVS primary mode index of a bit rate (`PRIMARY_2800` = 0 ... `PRIMARY_SID`
/// = 12, `NO_DATA_TYPE` = 15), else its AMR-WB IO mode, else -1 for a rate neither has.
#[must_use]
pub fn rate2evs_mode(rate: i32) -> i16 {
    match rate {
        0 => 15, // NO_DATA_TYPE
        2400 => 12,
        2800 => 0,
        7200 => 1,
        8000 => 2,
        9600 => 3,
        13200 => 4,
        16400 => 5,
        24400 => 6,
        32000 => 7,
        48000 => 8,
        64000 => 9,
        96000 => 10,
        128000 => 11,
        _ => rate2amrwb_io_mode(rate),
    }
}

/// One bit of the frame. The reference indexes `bit_stream_fx` directly; every caller has checked
/// the position against `total_num_bits` (at most `MAX_BITS_PER_FRAME + 16`, the buffer's size), so
/// the zero fallback is unreachable and only keeps a corrupted position from panicking.
fn bit_at(st: &DecoderState, pos: i32) -> u16 {
    usize::try_from(pos)
        .ok()
        .and_then(|pos| st.bit_stream.get(pos))
        .copied()
        .unwrap_or(0)
}

/// `get_next_indice_fx`: read the next `nb_bits` (at most 16) bits, MSB first. Past the end of the
/// frame it flags `BER_detect` and returns 0 without advancing.
pub fn get_next_indice(st: &mut DecoderState, nb_bits: i16) -> u16 {
    // detect corrupted bitstream
    if sub(add(st.next_bit_pos, nb_bits), st.total_num_bits) > 0 {
        st.ber_detect = 1;
        return 0;
    }
    let mut value: u16 = 0;
    for i in 0..nb_bits {
        value = lshl(value as i16, 1) as u16;
        value = add(
            value as i16,
            bit_at(st, i32::from(st.next_bit_pos) + i32::from(i)) as i16,
        ) as u16;
    }
    // update the position in the bitstream
    st.next_bit_pos = add(st.next_bit_pos, nb_bits);
    value
}

/// `get_next_indice_1_fx`: read the next bit. MODE2 may read 16 bits past the frame, into the
/// zero flush the arithmetic coder relies on.
pub fn get_next_indice_1(st: &mut DecoderState) -> u16 {
    if (sub(add(st.next_bit_pos, 1), st.total_num_bits) > 0 && st.codec_mode == MODE1)
        || (sub(add(st.next_bit_pos, 1), add(st.total_num_bits, 2 * 8)) > 0
            && st.codec_mode == MODE2)
    {
        st.ber_detect = 1;
        return 0;
    }
    let bit = bit_at(st, i32::from(st.next_bit_pos));
    st.next_bit_pos = st.next_bit_pos.wrapping_add(1);
    bit
}

/// `get_next_indice_tmp_fx`: skip `nb_bits` bits.
pub fn get_next_indice_tmp(st: &mut DecoderState, nb_bits: i16) {
    st.next_bit_pos = add(st.next_bit_pos, nb_bits);
}

/// `get_indice_fx`: read `nb_bits` bits at absolute position `pos` without moving the read
/// position. Past the end of the frame it flags `BER_detect` and returns 0.
pub fn get_indice(st: &mut DecoderState, pos: i16, nb_bits: i16) -> u16 {
    if sub(add(pos, nb_bits), st.total_num_bits) > 0 {
        st.ber_detect = 1;
        return 0;
    }
    let mut value: u16 = 0;
    for i in 0..nb_bits {
        value = lshl(value as i16, 1) as u16;
        value = add(
            value as i16,
            bit_at(st, i32::from(pos) + i32::from(i)) as i16,
        ) as u16;
    }
    value
}

/// `get_indice_1_fx`: the bit at absolute position `pos`.
pub fn get_indice_1(st: &mut DecoderState, pos: i16) -> u16 {
    if sub(add(pos, 1), st.total_num_bits) > 0 {
        st.ber_detect = 1;
        return 0;
    }
    bit_at(st, i32::from(pos))
}

/// `reset_indices_dec_fx`: rewind the read position to the start of the frame.
pub fn reset_indices_dec(st: &mut DecoderState) {
    st.next_bit_pos = 0;
}

/// `decoder_selectCodec`: AMR-WB IO or EVS, MODE1 or MODE2, and the SID's CNG type, from the
/// frame's bit rate and (for an EVS SID) its first bit (`bit0_is_zero`: the reference compares the
/// first G.192 word with `G192_BIN0`). An unknown bit rate marks the frame bad.
pub fn decoder_select_codec(st: &mut DecoderState, total_brate: i32, bit0_is_zero: bool) {
    // check if we are in AMR-WB IO mode
    if rate2amrwb_io_mode(total_brate) >= 0 {
        st.opt_amr_wb = 1;
    } else if total_brate != i32::from(FRAME_NO_DATA) {
        st.opt_amr_wb = 0;
    }

    // select MODE1 or MODE2
    if st.opt_amr_wb != 0 {
        st.codec_mode = MODE1;
    } else {
        match total_brate {
            0 | 2400 => st.codec_mode = st.last_codec_mode,
            2800 | 7200 | 8000 | 13200 | 32000 | 64000 => st.codec_mode = MODE1,
            9600 | 16400 | 24400 | 48000 | 96000 | 128000 => st.codec_mode = MODE2,
            _ => {
                // validate that total_brate (derived from RTP packet or a file header) is one of
                // the defined bit rates
                st.codec_mode = st.last_codec_mode;
                st.bfi = 1;
            }
        }
    }

    if st.ini_frame == 0 {
        if st.codec_mode == -1 {
            st.codec_mode = MODE1;
        }
        st.last_codec_mode = st.codec_mode;
    }

    // set SID/CNG type
    if total_brate == i32::from(SID_2K40) {
        if bit0_is_zero {
            st.cng_type = LP_CNG;
            // force MODE1 when selecting LP_CNG
            st.codec_mode = MODE1;
        } else {
            st.cng_type = FD_CNG;
            if st.last_codec_mode == MODE2 && st.last_total_brate == 13200 {
                st.codec_mode = MODE1;
            }
        }
        // CNG type switching at the first correctly received SID frame
        st.last_cng_type = st.cng_type;
    }
}

/// `total_brate / 50` the way the reference computes it (`Mpy_32_16_ss` by 1/50 in Q18).
fn brate_to_bits(total_brate: i32) -> i16 {
    let (l_tmp, _) = mpy_32_16_ss(total_brate, 5243);
    extract_l(l_shr(l_tmp, 3))
}

/// The index just past the bit rate `brate` in `acelp_sig_tbl`, or `None` when the table has no
/// section for it (the reference loops off the table's end then).
fn acelp_sig_section(brate: i32) -> Option<usize> {
    ACELP_SIG_TBL
        .iter()
        .position(|&entry| entry == brate)
        .map(|index| index + 1)
}

/// `acelp_sig_tbl[index]`, 0 past the end (only a hostile index gets there).
fn acelp_sig_entry(index: usize) -> i32 {
    ACELP_SIG_TBL.get(index).copied().unwrap_or(0)
}

/// `dec_prm_core`: the MODE2 read-ahead of the bandwidth and core (ACELP / TCX / HQ) signalling.
pub fn dec_prm_core(st: &mut DecoderState) {
    st.core = -1;
    if st.total_brate == i32::from(FRAME_NO_DATA) {
        st.m_frame_type = ZERO_FRAME;
    } else if st.total_brate == i32::from(SID_2K40) {
        st.m_frame_type = SID_FRAME;
    } else {
        st.m_frame_type = ACTIVE_FRAME;
        let num_bits = brate_to_bits(st.total_brate);
        let Some(config) = FRAMESIZECONFIG
            .iter()
            .take(FRAME_SIZE_NB as usize)
            .find(|config| config.frame_bits == num_bits)
        else {
            // The reference would read FrameSizeConfig[-1]; only a rate that is not a MODE2 frame
            // size gets here, which read_indices never lets through.
            st.ber_detect = 1;
            return;
        };
        // Get bandwidth mode
        st.bwidth = get_next_indice(st, i16::from(config.bandwidth_bits)) as i16;
        st.bwidth = add(st.bwidth, i16::from(config.bandwidth_min));
        if st.bwidth > FB {
            st.bwidth = FB;
            st.ber_detect = 1;
        }
        if st.bwidth > SWB && st.total_brate < i32::from(ACELP_16K40) {
            st.bwidth = SWB;
            st.ber_detect = 1;
        }
        // Skip reserved bit
        get_next_indice_tmp(st, i16::from(config.reserved_bits));
        if get_next_indice_1(st) != 0 {
            // TCX
            st.core = TCX_20_CORE;
            if get_next_indice_1(st) != 0 {
                st.core = HQ_CORE;
            }
        } else {
            // ACELP
            st.core = ACELP_CORE;
        }
    }
}

/// `decision_matrix_core_dec`: the MODE1 read-ahead of the core signalling; sets `core`, and
/// `bwidth` where it is signalled with the core.
pub fn decision_matrix_core_dec(st: &mut DecoderState) {
    st.core = -1;
    st.bwidth = -1;

    if st.total_brate == i32::from(FRAME_NO_DATA) || st.total_brate == i32::from(SID_2K40) {
        st.core = ACELP_CORE;
    } else if st.total_brate == i32::from(PPP_NELP_2K80) {
        // SC-VBR
        st.core = ACELP_CORE;
        return;
    }

    // ACELP/HQ core selection
    if st.total_brate < i32::from(ACELP_24K40) {
        st.core = ACELP_CORE;
    } else if st.total_brate <= ACELP_64K {
        // read the ACELP/HQ core selection bit (imult1616 of a bit by HQ_CORE)
        st.core = get_next_indice(st, 1) as i16 * HQ_CORE;
    } else {
        st.core = HQ_CORE;
    }

    // Read ACELP signalling bits from the bitstream
    if st.core == ACELP_CORE {
        let Some(mut start_idx) = acelp_sig_section(st.total_brate) else {
            // No ACELP section for this rate: the reference would run off acelp_sig_tbl.
            st.ber_detect = 1;
            return;
        };
        // retrieve the number of bits
        let n_bits = extract_l(acelp_sig_entry(start_idx));
        start_idx += 1;
        // retrieve the signalling indice
        let ind = acelp_sig_entry(start_idx + usize::from(get_next_indice(st, n_bits)));
        st.bwidth = extract_l((ind >> 3) & 0x7);
        // convert signalling indice into signalling information
        if ind & 0x7 == i32::from(LR_MDCT) {
            st.core = HQ_CORE;
        }
    }

    // Read HQ signalling bits from the bitstream; set HQ core type
    if st.core == HQ_CORE {
        // read the HQ/TCX core switching flag
        if get_next_indice(st, 1) != 0 {
            st.core = TCX_20_CORE;
        }
        // For TCX: read/set band-width (needed for different I/O sampling rate support)
        if st.core == TCX_20_CORE && st.total_brate > i32::from(ACELP_16K40) {
            st.bwidth = match get_next_indice(st, 2) {
                0 => NB,
                1 => WB,
                2 => SWB,
                _ => FB,
            };
        }
    }
}

/// `mdct_switching_dec`: at the rates where MODE1 and MODE2 share an MDCT core, read the core
/// signalling ahead and hand the frame to the other mode's MDCT decoder when it says so.
pub fn mdct_switching_dec(st: &mut DecoderState) {
    if st.opt_amr_wb != 0 {
        return;
    }
    if st.total_brate == i32::from(ACELP_13K20) || st.total_brate == ACELP_32K {
        st.mdct_sw_enable = MODE1;
    } else if i32::from(ACELP_16K40) <= st.total_brate && st.total_brate <= i32::from(ACELP_24K40) {
        st.mdct_sw_enable = MODE2;
    }

    if st.codec_mode == MODE1 && st.mdct_sw_enable == MODE1 {
        // Read ahead core mode signaling
        let next_bit_pos_save = st.next_bit_pos;
        let core_save = st.core;
        let bwidth_save = st.bwidth;
        decision_matrix_core_dec(st); // sets st->core
        if st.core == TCX_20_CORE {
            // Trigger TCX
            st.codec_mode = MODE2;
            st.mdct_sw = MODE1;
        } else {
            // Rewind bitstream
            st.next_bit_pos = next_bit_pos_save;
            if st.bfi != 0 {
                st.core = core_save;
                st.bwidth = bwidth_save;
            }
        }
    } else if st.codec_mode == MODE2 && st.mdct_sw_enable == MODE2 {
        // Read ahead core mode signaling
        let next_bit_pos_save = st.next_bit_pos;
        let core_save = st.core;
        let bwidth_save = st.bwidth;
        dec_prm_core(st); // sets st->core
        if st.core == HQ_CORE {
            // Trigger HQ_CORE
            st.codec_mode = MODE1;
            st.mdct_sw = MODE2;
        } else {
            // Rewind bitstream
            st.next_bit_pos = next_bit_pos_save;
            if st.bfi != 0 {
                st.core = core_save;
            }
            // always reset bwidth, to not interfere with BER logic
            st.bwidth = bwidth_save;
        }
    }
}

/// `L_msu0(brate, table[index], 50)`; the index is clamped into the table, which a bit rate the
/// codec defines never needs (the search converges inside it).
fn rate_distance(brate: i32, table: &[i16], index: i32) -> i32 {
    let last = table.len().saturating_sub(1);
    let index = usize::try_from(index).unwrap_or(0).min(last);
    l_msu0(brate, table.get(index).copied().unwrap_or(0), 50)
}

/// `BRATE2IDX_fx`: the index of a bit rate in `bit_rates_div50`, by a branch-free binary search.
#[must_use]
pub fn brate2idx(brate: i32) -> i16 {
    const START: i32 = 9;
    let table = &BIT_RATES_DIV50[..];
    let mut l_temp = rate_distance(brate, table, START).clamp(-6, 6);
    let mut l_idx = l_add(l_temp, START);
    l_temp = rate_distance(brate, table, l_idx).clamp(-3, 3);
    l_idx = l_add(l_temp, l_idx);
    l_temp = rate_distance(brate, table, l_idx).clamp(-2, 1);
    l_idx = l_add(l_temp, l_idx);
    l_temp = rate_distance(brate, table, l_idx);
    if l_temp != 0 {
        l_idx = l_add(l_idx, 1);
    }
    l_idx as i16
}

/// `BRATE2IDX16k_fx`: [`brate2idx`] over the 16 kHz core's `bit_rates_16k_div50`.
#[must_use]
pub fn brate2idx16k(mut brate: i32) -> i16 {
    const START_16K: i32 = 5;
    let table = &BIT_RATES_16K_DIV50[..];
    if brate == i32::from(ACELP_16K40) {
        brate = ACELP_14K80;
    }
    let mut l_temp = rate_distance(brate, table, START_16K).clamp(-3, 3);
    let mut l_idx = l_add(l_temp, START_16K);
    l_temp = rate_distance(brate, table, l_idx).clamp(-2, 2);
    l_idx = l_add(l_temp, l_idx);
    l_temp = rate_distance(brate, table, l_idx).clamp(-1, 1);
    l_idx = l_add(l_temp, l_idx);
    l_idx as i16
}

/// `BIT_ALLOC_IDX_fx`: the row of the 12.8 kHz ACELP bit-allocation tables for a bit rate, coder
/// type, subframe (`sfrm`, -1 for the frame-level entry) and TC subframe (`tc`, -1 if none).
#[must_use]
pub fn bit_alloc_idx(brate: i32, mut ctype: i16, sfrm: i16, tc: i16) -> i32 {
    if ctype == INACTIVE {
        ctype = GENERIC;
    }
    let mut l_temp = l_mac0(-256, 256, ctype);
    let temp = brate2idx(brate);
    l_temp = l_mac0(l_temp, 4 * 256, temp);
    if tc >= 0 {
        l_temp = l_mac0(l_temp, (10 - 4) * 256, temp);
    }
    // So either 'temp' x 4 when 'tc < 0', 'temp' x 10 otherwise
    l_temp = l_mac0(l_temp, 256, tc.max(0));
    l_temp = l_mac0(l_temp, sfrm.max(0), 1);
    if sfrm < 0 {
        l_temp = l_shr(l_temp, 2);
    }
    l_shr(l_temp, 6)
}

/// `BIT_ALLOC_IDX_16KHZ_fx`: [`bit_alloc_idx`] for the 16 kHz core's tables.
#[must_use]
pub fn bit_alloc_idx_16khz(brate: i32, ctype: i16, sfrm: i16, tc: i16) -> i32 {
    // 'ctype' = TRANSITION => 2, GENERIC => 1, all other => 0
    let mut l_temp = i32::from(shr(0x0240, shl(ctype, 1))) & 3;
    let temp = brate2idx16k(brate);
    l_temp = l_mac0(l_temp, 3, temp);
    if tc >= 0 {
        l_temp = l_mac0(l_temp, 7 - 3, temp);
    }
    l_temp = l_mac0(l_temp, 1, tc.max(0));
    if sfrm >= 0 {
        // Mult by 5
        l_temp = l_add(l_temp, crate::itu::basic_ops::l_shl(l_temp, 2));
        l_temp = l_mac0(l_temp, shr(sfrm, 6), 1);
    }
    l_temp
}

/// `read_indices_fx` for one G.192 frame: [`read_indices`] with the frame's bits.
///
/// # Errors
/// As [`read_indices`].
pub fn read_indices_frame(st: &mut DecoderState, frame: &G192Frame<'_>) -> Result<(), CodecError> {
    let mut bits = [0u8; MAX_BITS_PER_FRAME as usize];
    let count = frame.unpack_bits(&mut bits)?;
    read_indices(st, frame.good, &bits[..count])
}

/// `read_indices_fx`: take one received frame into the decoder: the bad-frame indicator from the
/// G.192 sync word (`good`), the G.192 RX DTX handler (SID_FIRST / SID_BAD / SPEECH_LOST /
/// NO_DATA against the CNG state), the codec selection, the frame's bits plus the 16 zero bits the
/// arithmetic coder flushes into, and the MDCT switching read-ahead. `bits` holds one bit (0/1) per
/// element; its length is the G.192 frame length.
///
/// Differences from the file reader, both at the I/O boundary only: the reference's `rew_flag` path
/// (read until the first good frame and rewind the file, used by the encoder's I/O to print the
/// configuration) is not ported; and the reference tests an EVS SID's first G.192 *word* against
/// `G192_BIN0` where this reads the unpacked bit, which differs only for a non-canonical G.192 word
/// that is neither `G192_BIN0` nor `G192_BIN1`.
///
/// # Errors
/// [`CodecError::Malformed`] for a frame longer than `MAX_BITS_PER_FRAME` or of a size no EVS or
/// AMR-WB IO mode has, where the reference exits. The state is left untouched then.
pub fn read_indices(st: &mut DecoderState, good: bool, bits: &[u8]) -> Result<(), CodecError> {
    let num_bits = bits.len();
    if num_bits > MAX_BITS_PER_FRAME as usize {
        return Err(CodecError::Malformed("too large G.192 frame"));
    }
    // fits: num_bits <= 2560
    let mut total_brate = num_bits as i32 * 50;
    if rate2evs_mode(total_brate) < 0 {
        return Err(CodecError::Malformed("illegal bit rate in the G.192 frame"));
    }

    st.bfi = 0;
    st.ber_detect = 0;
    st.mdct_sw_enable = 0;
    st.mdct_sw = 0;
    reset_indices_dec(st);

    // set the BFI indicator according the value of Sync Header
    st.bfi = i16::from(!good);

    read_indices_rx_dtx_handler(st, &mut total_brate, bits);

    // get total bit-rate
    if st.bfi == 0 {
        // select MODE1 or MODE2
        decoder_select_codec(st, total_brate, bits.first().copied().unwrap_or(0) == 0);
    }

    st.total_num_bits = brate_to_bits(total_brate);

    // GOOD frame
    if st.bfi == 0 {
        // GOOD frame - convert ITU-T G.192 words to short values
        for (slot, &bit) in st.bit_stream.iter_mut().zip(bits) {
            *slot = u16::from(bit != 0);
        }
        // add two zero bytes for arithmetic coder flush
        for slot in st.bit_stream.iter_mut().skip(num_bits).take(2 * 8) {
            *slot = 0;
        }
        // a change of the total bitrate should not be known to the decoder, if the received frame
        // was lost
        st.total_brate = total_brate;
        mdct_switching_dec(st);
    }
    Ok(())
}

/// The G.192 RX DTX handler of `read_indices_fx`: handle SID_FIRST, SID_BAD, SPEECH_LOST and
/// NO_DATA as properly as possible for the G.192 format, updating `bfi`, the CNG state and the
/// frame's effective bit rate.
fn read_indices_rx_dtx_handler(st: &mut DecoderState, total_brate: &mut i32, bits: &[u8]) {
    let sid_2k40 = i32::from(SID_2K40);
    let sid_1k75 = i32::from(SID_1K75);
    let mut curr_ft_good_sp = false;
    let mut curr_ft_bad_sp = false;
    if *total_brate > sid_2k40 {
        if st.bfi == 0 {
            curr_ft_good_sp = true;
        } else {
            curr_ft_bad_sp = true;
        }
    }
    let mut sid_update = false;
    let mut sid_upd_bad = false;
    if *total_brate == sid_1k75 || *total_brate == sid_2k40 {
        if st.bfi == 0 {
            sid_update = true;
        } else {
            // may happen in CS, corrupt but detected sid frame
            sid_upd_bad = true;
        }
    }

    // all zero indices/bits iSP AMRWB SID_update results in a valid LP filter with extremely high
    // LP-filter-gain; all zero bits may be a result of CS bit errors and/or erroneously injected
    // by gateways or by a bad dejitter handler
    if *total_brate == sid_1k75 && sid_update && bits.iter().all(|&bit| bit == 0) {
        // initial signal as corrupt (BER likely)
        sid_upd_bad = true;
    }

    // The AMR-WB 26.173 G.192 reader does not declare/use SID_BAD; inhibit use of the SID length
    // info and treat SID_BAD as a stolen signalling frame --> SPEECH LOST.
    if sid_upd_bad {
        sid_upd_bad = false;
        *total_brate = i32::from(FRAME_NO_DATA);
    }

    // SID_FIRST detected for previous AMRWB/AMRWBIO active frames only
    let g192_sid_first = st.core == AMR_WB_CORE
        && st.prev_ft_speech != 0
        && *total_brate == i32::from(FRAME_NO_DATA)
        && st.bfi == 0;

    // CS-type of CRC failure frame: initial assumption, CNG_state decides what to do
    let speech_bad = *total_brate > sid_2k40 && st.bfi != 0;
    // unsent NO_DATA or stolen NO_DATA/signalling frame: initial assumption, CNG_state decides
    let speech_lost = *total_brate == 0 && st.bfi != 0;

    // Do not allow decoder to enter CNG-synthesis for any instantly received GOOD+LENGTH==0 frame
    if st.cng != 0 {
        // We were in CNG synthesis: only a good speech frame makes you leave it
        if curr_ft_good_sp {
            st.cng = 0;
        }
    } else if g192_sid_first || sid_update || sid_upd_bad {
        // We were in SPEECH synthesis: only a received SID frame can make the decoder enter CNG
        st.cng = 1;
    }

    // handle the g.192 _simulated_ untransmitted frame, setting for decoder SPEECH synthesis
    if st.cng == 0 && *total_brate == 0 && st.bfi == 0 {
        // SPEECH PLC code will now become active as in a real system
        st.bfi = 1;
    }

    // handle bad speech frame (and bad sid frame) in the decoder's CNG synthesis settings pair
    // (SP_BAD or SPEECH_LOST --> stay in CNG; SID_UPD_BAD --> start CNG)
    if (st.cng != 0 && (speech_bad || speech_lost)) || sid_upd_bad {
        st.bfi = 0;
        *total_brate = 0;
    }
    // update for next frame's G.192 file format's SID_FIRST detection (primarily for AMRWBIO)
    st.prev_ft_speech = i16::from(curr_ft_good_sp || curr_ft_bad_sp);
}

/// `berCheck`: in a channel-aware frame, a bandwidth or coder type the RF mode never sends means a
/// bit error: drop the partial copy and conceal.
fn ber_check(st: &mut DecoderState, coder_type: &mut i16) {
    // In case of RF flag = 1, and valid RF packet with primary and partial copy
    if st.bwidth == NB || st.bwidth == FB || *coder_type >= TRANSITION {
        if st.use_partial_copy == 1 {
            st.use_partial_copy = 0;
        }
        st.bfi = 1;
        st.bwidth = st.last_bwidth;
        st.ber_detect = 1;
        *coder_type = GENERIC;
    }
}

/// `getPartialCopyInfo`: whether the frame is a channel-aware frame carrying a partial copy; reads
/// its RF frame type, FEC offset and (for an RF frame) coder type, bandwidth and sharpening flag.
pub fn get_partial_copy_info(st: &mut DecoderState, coder_type: &mut i16, sharp_flag: &mut i16) {
    // check the rf flag in the packet
    let (rf_flag, n_bits, ind) = get_rf_flag(st);
    st.rf_flag = rf_flag;
    // get rf frame type info
    st.rf_frame_type = get_rf_frame_type(st);
    // Get the FEC offset info
    st.rf_fec_offset = get_rf_fec_offset(st);
    // reset number of target bits in case of rate switching
    st.rf_target_bits = 0;

    // Get the number of bits used for RF
    if st.rf_flag == 1 {
        *coder_type = ind & 0x7;
        st.bwidth = shr(ind, 3) & 0x7;
        *sharp_flag = shr(ind, 6) & 0x1;
        st.codec_mode = MODE2;
        if let Some(bits) = get_rf_target_bits(st.rf_frame_type) {
            st.rf_target_bits = bits;
        }
        if st.bfi == FRAMEMODE_FUTURE {
            st.use_partial_copy = 1;
            // now set the frame mode to normal mode
            if st.rf_frame_type >= RF_TCXFD && st.rf_frame_type <= RF_TCXTD2 {
                st.bfi = 1;
                st.core = 1;
            } else {
                st.bfi = FRAMEMODE_NORMAL;
                st.core = 0;
            }
        }
        // check for bit errors
        ber_check(st, coder_type);
        get_next_indice_tmp(st, n_bits);
    }
}

/// `get_rfFlag`: the RF flag of a 13.2 kbit/s frame, with the signalling's bit count and index
/// (`(rf_flag, nBits, ind)`; the last two are 0 when the reference leaves them unwritten).
pub fn get_rf_flag(st: &mut DecoderState) -> (i16, i16, i16) {
    if st.total_brate == i32::from(ACELP_13K20)
        && (st.bfi == FRAMEMODE_NORMAL || st.bfi == FRAMEMODE_FUTURE)
    {
        // find the section in the ACELP signalling table corresponding to bitrate (13.2 kbit/s
        // always has one)
        let Some(mut start_idx) = acelp_sig_section(st.total_brate) else {
            return (0, 0, 0);
        };
        // retrieve the number of bits
        let n_bits_tmp = acelp_sig_entry(start_idx) as i16;
        start_idx += 1;
        // retrieve the signalling indice
        let ind_tmp =
            acelp_sig_entry(start_idx + usize::from(get_indice(st, 0, n_bits_tmp))) as i16;
        // convert signalling indice into RF flag
        (shr(ind_tmp, 7) & 0x1, n_bits_tmp, ind_tmp)
    } else {
        (0, 0, 0)
    }
}

/// Bits in the frame for the RF readers: 264 at 13.2 kbit/s, `total_brate / 50` otherwise.
fn rf_frame_bits(st: &DecoderState) -> i16 {
    if st.total_brate == i32::from(ACELP_13K20) {
        264
    } else {
        brate_to_bits(st.total_brate)
    }
}

/// `get_rfFrameType`: the RF frame type, the last three bits of an RF frame (0 otherwise).
pub fn get_rf_frame_type(st: &mut DecoderState) -> i16 {
    if st.rf_flag == 1 {
        let num_bits = rf_frame_bits(st);
        get_indice(st, num_bits.wrapping_sub(3), 3) as i16
    } else {
        0
    }
}

/// `get_rf_fec_offset`: the FEC offset of an RF frame (the two bits before the frame type), 0
/// otherwise.
pub fn get_rf_fec_offset(st: &mut DecoderState) -> i16 {
    if st.rf_flag == 1 {
        let num_bits = rf_frame_bits(st);
        let tmp = get_indice(st, num_bits.wrapping_sub(5), 2) as i16;
        if tmp == 0 {
            2
        } else {
            add(shl(tmp, 1), 1)
        }
    } else {
        0
    }
}

/// `get_rfTargetBits`: the RF bit budget of an RF frame type, or `None` for a type the reference's
/// switch has no case for (it leaves the output unwritten then).
#[must_use]
pub fn get_rf_target_bits(rf_frame_type: i16) -> Option<i16> {
    match rf_frame_type {
        RF_NO_DATA => Some(5),
        RF_TCXFD => Some(27),
        RF_TCXTD1 | RF_TCXTD2 => Some(16),
        // Es_pred bits 3 bits, LTF: 1, pitch: 8,5,5,5, FCB: 0, gain: 7,0,7,0, Diff GFr: 4
        RF_ALLPRED => Some(63),
        // Es_pred bits 3 bits, LTF: 0, pitch: 0, FCB: 7,7,7,7, gain: 6,0,6,0, Diff GFr: 2
        RF_NOPRED => Some(66),
        // Es_pred bits 3 bits, LTF: 1, pitch: 8,0,8,0, FCB: 6,7,5,5, gain: 5,0,5,0, Diff GFr: 0
        RF_GENPRED => Some(70),
        // gain: 19, Diff GFr: 5
        RF_NELP => Some(45),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evs_and_amr_wb_io_rates_map_to_their_modes() {
        assert_eq!(rate2evs_mode(0), 15);
        assert_eq!(rate2evs_mode(7200), 1);
        assert_eq!(rate2evs_mode(1750), 9);
        assert_eq!(rate2evs_mode(23850), 8);
        assert_eq!(rate2evs_mode(5000), -1);
    }

    #[test]
    fn reading_past_the_frame_flags_a_bit_error() {
        let mut st = Box::new(DecoderState::zeroed());
        st.total_num_bits = 4;
        st.codec_mode = MODE1;
        st.bit_stream[..4].copy_from_slice(&[1, 0, 1, 1]);
        assert_eq!(get_next_indice(&mut st, 3), 0b101);
        assert_eq!(get_next_indice_1(&mut st), 1);
        assert_eq!(st.ber_detect, 0);
        assert_eq!(get_next_indice(&mut st, 1), 0);
        assert_eq!(st.ber_detect, 1);
        assert_eq!(st.next_bit_pos, 4);
    }

    #[test]
    fn an_illegal_frame_size_is_refused_without_touching_the_state() {
        let mut st = Box::new(DecoderState::zeroed());
        st.bfi = 7;
        assert!(read_indices(&mut st, true, &[0; 100]).is_err());
        assert!(read_indices(&mut st, true, &[0; 2561]).is_err());
        assert_eq!(st.bfi, 7);
    }
}

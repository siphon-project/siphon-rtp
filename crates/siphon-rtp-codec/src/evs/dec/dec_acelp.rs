//! Algebraic codebook index decoding of the MODE2 / 4-track ACELP (TS 26.442
//! `lib_dec/dec_acelp.c`; TS 26.445 §6.1.1.2.2).
//!
//! The C views its index words both as `UWord16[8]` and, for `longshr`, as `UWord32[4]` over the
//! same memory (little-endian on every platform the reference vectors were made on); the port
//! keeps the 16-bit words and converts for the shift.

use crate::evs::cnst::{L_SUBFR, NB_TRACK_FCB_4T};
use crate::evs::com::basop_util::imult1616;
use crate::evs::com::longarith::longshr;
use crate::evs::com::tools::{idiv_and_mod_32, set16};
use crate::evs::dec::dec4t64::d_acelp_decode_43bit;
use crate::evs::rom::types::PulseConfig;
use crate::evs::rom::{INDEX_LEN, INDEX_MASK_ACELP, INDX_FACT, LOW_LEN, LOW_MASK, PULSESTOSTATES};
use crate::itu::basic_ops::{add, l_add, l_sub, shr, sub};
use crate::itu::stl2009::{l_lshl, l_lshr};

/// `enum TRACKPOS` (`lib_com/cnst_fx.h`): how the extra pulses are spread over the tracks.
const TRACKPOS_FIXED_FIRST: i8 = 0;
const TRACKPOS_FIXED_EVEN: i8 = 1;
const TRACKPOS_FIXED_TWO: i8 = 3;
const TRACKPOS_FREE_ONE: i8 = 4;
const TRACKPOS_FREE_THREE: i8 = 5;

/// `pulsestostates[row][column]` read as the reference's flat `Word32[17][9]`, so a column of -1
/// reads the end of the previous row exactly as the C pointer arithmetic does; `None` outside the
/// whole table.
fn pulsestostates(row: i16, column: i16) -> Option<i32> {
    let flat = i32::from(row) * 9 + i32::from(column);
    let flat = usize::try_from(flat).ok()?;
    PULSESTOSTATES.get(flat / 9).map(|r| r[flat % 9])
}

/// The 16-bit index words as the `UWord32[4]` the C shifts with `longshr`, and back.
fn longshr_words(idxs: &mut [u16; 8], bits: i16, wordcnt32: i16) {
    let mut words = [0u32; 4];
    for (k, word) in words.iter_mut().enumerate() {
        *word = u32::from(idxs[2 * k]) | (u32::from(idxs[2 * k + 1]) << 16);
    }
    longshr(&mut words, bits, wordcnt32);
    for (k, word) in words.iter().enumerate() {
        idxs[2 * k] = *word as u16;
        idxs[2 * k + 1] = (*word >> 16) as u16;
    }
}

/// `D_ACELP_indexing`: decode the algebraic codebook index words `index` (one 16-bit word per
/// entry, least significant first) of a `config` codebook with `num_tracks` (4) tracks into
/// `code[0..L_SUBFR]` (Q9). An index outside the codebook clears `code` and sets `ber_detect`.
pub fn d_acelp_indexing(
    code: &mut [i16],
    config: PulseConfig,
    _num_tracks: i16,
    index: &[i16],
    ber_detect: &mut i16,
) {
    const TRACKS: usize = NB_TRACK_FCB_4T as usize;
    let mut pulsestrack = [0i16; TRACKS];
    let mut index_n = [0u32; TRACKS];
    let mut idxs = [0u16; 8];
    // the reference asserts num_tracks == NB_TRACK_FCB_4T
    let num_tracks = NB_TRACK_FCB_4T;

    // ceil(bits/16); the codebook configurations stay within the reference's 8 words
    let wordcnt = shr(add(config.bits, 15), 4).clamp(0, 7);
    // check if some tracks have more pulses
    let nb_pulse = i16::from(config.nb_pulse);
    let restpulses = nb_pulse & sub(num_tracks, 1);

    for k in 0..wordcnt as usize {
        idxs[k] = index[k] as u16;
    }
    idxs[wordcnt as usize] = 0;
    // init 32bits wordcnt
    let wordcnt32 = shr(add(wordcnt, 1), 1);

    if restpulses != 0 {
        match config.codetrackpos {
            TRACKPOS_FREE_THREE => {
                // Find track with less pulses
                let trackpos = (idxs[0] & 3) as usize;
                longshr_words(&mut idxs, 2, wordcnt32);
                set16(&mut pulsestrack, add(shr(nb_pulse, 2), 1), 4);
                pulsestrack[trackpos] = sub(pulsestrack[trackpos], 1); // this one has less pulses
            }
            TRACKPOS_FREE_ONE => {
                // Find track with more pulses
                let trackpos = (idxs[0] & 3) as usize;
                longshr_words(&mut idxs, 2, wordcnt32);
                set16(&mut pulsestrack, shr(nb_pulse, 2), 4);
                pulsestrack[trackpos] = add(pulsestrack[trackpos], 1);
            }
            TRACKPOS_FIXED_EVEN => {
                // Pulses on even tracks
                pulsestrack[0] = shr(add(nb_pulse, 1), 1);
                pulsestrack[1] = 0;
                pulsestrack[2] = shr(nb_pulse, 1);
                pulsestrack[3] = 0;
            }
            TRACKPOS_FIXED_FIRST => {
                set16(&mut pulsestrack, shr(nb_pulse, 2), 4);
                for count in pulsestrack.iter_mut().take(restpulses.max(0) as usize) {
                    *count = add(*count, 1);
                }
            }
            TRACKPOS_FIXED_TWO => {
                // 1100, 0110, 0011, 1001: find track with less pulses
                let mut trackpos = (idxs[0] & 3) as i16;
                longshr_words(&mut idxs, 2, wordcnt32);
                set16(&mut pulsestrack, shr(nb_pulse, 2), 4);
                pulsestrack[trackpos as usize] = add(pulsestrack[trackpos as usize], 1);
                trackpos = add(trackpos, 1) & 3;
                pulsestrack[trackpos as usize] = add(pulsestrack[trackpos as usize], 1);
            }
            _ => {
                // The reference asserts here; no codebook configuration uses another mode. Keep
                // the even distribution so the decode stays bounded.
                set16(&mut pulsestrack, shr(nb_pulse, 2), 4);
            }
        }
    } else {
        // set number of pulses per track
        set16(&mut pulsestrack, shr(nb_pulse, 2), 4);
    }

    if sub(config.bits, 43) == 0 {
        d_acelp_decode_43bit(&idxs, code, &pulsestrack);
        return;
    }

    fcb_pulse_track_joint_decode(&idxs, wordcnt, &mut index_n, &pulsestrack, num_tracks);
    for track in (1..TRACKS).rev() {
        let pulses = pulsestrack[track];
        if pulses != 0 {
            // decode state to actual pulse positions on track
            let s = index_n[track] as i32;
            d_acelp_decode_arithtrack(&mut code[track..], s, pulses, num_tracks, 16);
        } else {
            // track is empty
            for k in (track..16 * TRACKS).step_by(TRACKS) {
                code[k] = 0;
            }
        }
    }

    let s = l_add(index_n[0] as i32, 0);
    let pulses = pulsestrack[0];
    // safety check in case of bit errors
    let limit = pulsestostates(16, sub(pulses, 1)).unwrap_or(0);
    if l_sub(s, limit) >= 0 {
        set16(code, 0, L_SUBFR);
        *ber_detect = 1;
        return;
    }
    if pulses != 0 {
        d_acelp_decode_arithtrack(code, s, pulses, num_tracks, 16);
    } else {
        for k in (0..16 * TRACKS).step_by(TRACKS) {
            code[k] = 0;
        }
    }
}

/// `_1_CODE`: one pulse of the codebook excitation, Q9.
const ONE_CODE: i16 = 0x200;

/// `D_ACELP_decode_arithtrack`: decode the state `s` of one track into `p` signed pulses at
/// positions `v[k·trackstep]`, `k` in `0..tracklen` (`v` starts at the track's first position).
///
/// The reference asserts `s >= 0`; a negative state (only a corrupt frame) leaves the track empty.
pub fn d_acelp_decode_arithtrack(v: &mut [i16], s: i32, p: i16, trackstep: i16, tracklen: i16) {
    let mut s = s;
    let mut p = p;
    for k in (0..tracklen.max(0)).rev() {
        let idx = imult1616(k, trackstep) as usize;
        v[idx] = 0; // default: there is no pulse here
        if s < 0 {
            continue;
        }
        while p != 0 {
            // pulsestostates covers every track length and pulse count the codebook defines
            let Some(&states) = PULSESTOSTATES
                .get(k as usize)
                .and_then(|row| row.get(sub(p, 1) as usize))
            else {
                break;
            };
            if l_sub(s, states) < 0 {
                break;
            }
            s = l_sub(s, states);
            if v[idx] != 0 {
                // there is a pulse here already = sign is known
                if v[idx] > 0 {
                    v[idx] = add(v[idx], ONE_CODE);
                }
                if v[idx] <= 0 {
                    v[idx] = sub(v[idx], ONE_CODE);
                }
            } else {
                // this is the first pulse here -> determine sign
                v[idx] = ONE_CODE;
                if s & 0x1 != 0 {
                    v[idx] = -ONE_CODE;
                }
                s = l_lshr(s, 1);
            }
            p -= 1;
        }
    }
}

/// `fcb_pulse_track_joint_decode`: split the joint index words `idxs[0..wordcnt]` into one state
/// per track (`index_n`) for tracks carrying `pulse_num[t]` pulses.
pub fn fcb_pulse_track_joint_decode(
    idxs: &[u16],
    wordcnt: i16,
    index_n: &mut [u32],
    pulse_num: &[i16],
    track_num: i16,
) {
    let mut hi_to_low: [i16; 10] = [0, 0, 0, 3, 9, 5, 3, 1, 8, 8];
    let tracks = track_num.max(0) as usize;
    let word = |k: i16| i32::from(idxs[k.max(0) as usize]);
    // per-pulse-count tables have 10 entries; a track never carries more than 9 pulses
    let pulses = |track: usize| (pulse_num[track].clamp(0, 9)) as usize;

    let mut indx_flag: i16 = 0;
    let mut indx_flag_1: i16 = 0;
    let mut indx_flag_2: i16 = 0;
    for &count in &pulse_num[..tracks] {
        indx_flag = add(indx_flag, shr(count, 2));
        indx_flag_1 = add(indx_flag_1, shr(count, 1));
        indx_flag_2 = add(indx_flag_2, shr(count, 3));
    }

    hi_to_low[4] = 1;
    if sub(indx_flag, track_num) >= 0 {
        hi_to_low[4] = 9;
    }
    hi_to_low[7] = 1;
    if sub(indx_flag_2, 1) >= 0 {
        hi_to_low[7] = 9;
    }

    if sub(indx_flag_1, track_num) >= 0 {
        let mut index: i32;
        if sub(indx_flag, track_num) >= 0 {
            index = 0;
            if sub(indx_flag_2, 1) >= 0 {
                let mut track = sub(wordcnt, 1);
                while track >= 6 {
                    index = l_add(l_lshl(index, 16), word(track));
                    track -= 1;
                }
                index_n[3] = l_add(l_lshl(word(5), 8), l_lshr(word(4), 8) & 0xFF) as u32;
                index_n[2] = (l_add(l_lshl(word(4), 16), word(3)) & 0xFF_FFFF) as u32;
                index_n[1] = l_add(l_lshl(word(2), 8), l_lshr(word(1), 8) & 0xFF) as u32;
                index_n[0] = (l_add(l_lshl(word(1), 16), word(0)) & 0xFF_FFFF) as u32;
            } else {
                let mut track = wordcnt - 1;
                while track >= track_num {
                    index = l_add(l_lshl(index, 16), word(track));
                    track -= 1;
                }
                for track in 0..tracks {
                    index_n[track] = u32::from(idxs[track]);
                }
            }
        } else {
            index = 0;
            let mut track = wordcnt - 1;
            while track >= 2 {
                index = l_add(l_lshl(index, 16), word(track));
                track -= 1;
            }
            index_n[3] = (word(1) & 0xFF) as u32;
            index_n[2] = l_lshr(word(1), 8) as u32;
            index_n[1] = (word(0) & 0xFF) as u32;
            index_n[0] = l_lshr(word(0), 8) as u32;
        }

        let mut track_num1 = sub(track_num, 1) as usize;
        let mut pulse_num1 = pulses(track_num1);
        index = l_add(
            l_lshl(index, hi_to_low[pulse_num1]),
            l_lshr(index_n[track_num1] as i32, LOW_LEN[pulse_num1]),
        );
        for track in (1..tracks).rev() {
            track_num1 = track - 1;
            let pulse_num0 = pulses(track_num1);
            pulse_num1 = pulses(track);
            index = l_add(
                l_lshl(index, hi_to_low[pulse_num0]),
                l_lshr(index_n[track_num1] as i32, LOW_LEN[pulse_num0]),
            );
            let (mut div_tmp, mut indx_tmp) = (0, 0);
            idiv_and_mod_32(index, INDX_FACT[pulse_num1], &mut div_tmp, &mut indx_tmp, 0);
            index_n[track] = l_add(
                index_n[track] as i32 & LOW_MASK[pulse_num1],
                l_lshl(indx_tmp, LOW_LEN[pulse_num1]),
            ) as u32;
            index = l_add(div_tmp, 0);
        }
        pulse_num1 = pulses(0);
        index_n[0] = l_add(
            index_n[0] as i32 & LOW_MASK[pulse_num1],
            l_lshl(index, LOW_LEN[pulse_num1]),
        ) as u32;
    } else {
        let mut index: i32 = 0;
        let mut track = wordcnt - 1;
        while track >= 0 {
            index = l_add(l_lshl(index, 16), word(track));
            track -= 1;
        }
        for track in (1..4).rev() {
            // this branch has at most one pulse pair per track; the tables cover 0..=2 pulses
            let pulse_num1 = pulses(track);
            let mask = INDEX_MASK_ACELP.get(pulse_num1).copied().unwrap_or(0);
            index_n[track] = (index as u32) & mask;
            index = l_lshr(index, INDEX_LEN.get(pulse_num1).copied().unwrap_or(0));
        }
        index_n[0] = index as u32;
    }
}

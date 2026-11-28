//! Decoding of the HQ envelope (norm) indices (TS 26.442 `lib_dec/hq_env_dec_fx.c`; TS 26.445
//! §6.2.2.3).

use crate::evs::cnst::{
    BITS_DE_FCOMP, BITS_DE_HMODE, LOW_RATE_HQ_CORE, LOW_RATE_HQ_CORE_TRAN, NB_SFM, NORM0_BITS,
    NORMI_BITS,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::recovernorm::recovernorm;
use crate::evs::dec::hdecnrm::{hdecnrm, hdecnrm_context, hdecnrm_resize, hdecnrm_tran};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{DICNLG2, HUFFSIZN, HUFFSIZN_TRAN, RESIZE_HUFFSIZN};
use crate::itu::basic_ops::{add, sub};

/// `table[index]`; the Huffman decoders only produce indices inside their 32-entry size tables,
/// so the 0 fallback is unreachable and only keeps an inconsistent call from panicking.
fn at(table: &[i16], index: i16) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or(0)
}

/// `decode_envelope_indices_fx`: read the coding mode and the differential norm indices of bands
/// `start_norm..start_norm + num_sfm` into `difidx`; returns the number of bits the indices took.
pub fn decode_envelope_indices(
    st: &mut DecoderState,
    start_norm: i16,
    num_sfm: i16,
    numnrmibits: i16,
    difidx: &mut [i16],
    flag_hq2: i16,
    is_transient: i16,
) -> i16 {
    let start = start_norm as usize;
    let lc_mode: i16;
    if sub(flag_hq2, LOW_RATE_HQ_CORE) == 0 || sub(flag_hq2, LOW_RATE_HQ_CORE_TRAN) == 0 {
        lc_mode = get_next_indice(st, BITS_DE_HMODE) as i16;
        difidx[start] = get_next_indice(st, BITS_DE_FCOMP) as i16;
    } else {
        lc_mode = get_next_indice(st, 2) as i16;
        difidx[start] = get_next_indice(st, NORM0_BITS) as i16;
    }

    let mut hcode_l: i16 = 0;
    if is_transient != 0 && sub(flag_hq2, LOW_RATE_HQ_CORE_TRAN) == 0 {
        if sub(lc_mode, 1) == 0 {
            hdecnrm_tran(st, num_sfm, &mut difidx[start + 1..]);
            let j = add(start_norm, num_sfm);
            for i in start_norm + 1..j {
                hcode_l = add(hcode_l, at(&HUFFSIZN_TRAN, difidx[i as usize]));
            }
        } else {
            hdecnrm_context(st, num_sfm, &mut difidx[start..], &mut hcode_l);
        }
    } else if lc_mode == 0 {
        hdecnrm_context(st, num_sfm, &mut difidx[start..], &mut hcode_l);
    } else if lc_mode == 1 {
        let start1 = start + 1;
        hdecnrm_resize(st, num_sfm, &mut difidx[start1..]);

        let num_sfm_minus1 = sub(num_sfm, 1);
        for i in 0..num_sfm_minus1.max(0) as usize {
            hcode_l = add(hcode_l, at(&RESIZE_HUFFSIZN, difidx[start1 + i]));
        }

        let num_sfm_minus2 = sub(num_sfm, 2);
        for i in 0..num_sfm_minus2.max(0) as usize {
            let previous = difidx[start1 + i];
            if previous > 17 {
                let offset = sub(previous, 17).min(3);
                difidx[start1 + i + 1] = sub(difidx[start1 + i + 1], offset);
            } else if previous < 13 {
                let offset = sub(previous, 13).max(-3);
                difidx[start1 + i + 1] = sub(difidx[start1 + i + 1], offset);
            }
        }
    } else if lc_mode == 2 {
        let start1 = start + 1;
        hdecnrm(st, num_sfm, &mut difidx[start1..]);
        let num_sfm_minus1 = sub(num_sfm, 1);
        for i in 0..num_sfm_minus1.max(0) as usize {
            hcode_l = add(hcode_l, at(&HUFFSIZN, difidx[start1 + i]));
        }
    } else {
        let start1 = start + 1;
        let num_sfm_minus1 = sub(num_sfm, 1);
        for i in 0..num_sfm_minus1.max(0) as usize {
            difidx[start1 + i] = get_next_indice(st, NORMI_BITS) as i16;
        }
        hcode_l = numnrmibits;
    }

    hcode_l
}

/// `dequantize_norms_fx`: turn the differential norm indices `ynrm[start_norm..start_norm +
/// num_sfm]` into absolute ones (in place) and their log2 norms `normqlg2`. A transient frame's
/// indices are in the reordered layout and are put back in band order by `recovernorm_fx`.
///
/// An index outside 0..=39 after accumulation is a bit error: it is set to 39 and `BER_detect`
/// raised, as in the reference. The first index (`NORM0_BITS` or `BITS_DE_FCOMP` wide) always lies
/// in the 40-entry dictionary.
pub fn dequantize_norms(
    st: &mut DecoderState,
    start_norm: i16,
    num_sfm: i16,
    is_transient: i16,
    ynrm: &mut [i16],
    normqlg2: &mut [i16],
) {
    let mut idxbuf = [0i16; NB_SFM as usize];
    let start = start_norm as usize;

    // First sub-frame
    let i = ynrm[start];
    normqlg2[start] = at(&DICNLG2, i);

    // Other sub-frames
    if is_transient != 0 {
        // Recover quantization indices and quantized norms
        idxbuf[0] = ynrm[0];
        for i in 1..num_sfm.max(0) as usize {
            idxbuf[i] = sub(add(ynrm[i], idxbuf[i - 1]), 15);
            // safety check in case of bit errors
            if idxbuf[i] < 0 || sub(idxbuf[i], 39) > 0 {
                idxbuf[i] = 39;
                st.ber_detect = 1;
            }
        }

        recovernorm(&idxbuf, ynrm, normqlg2, num_sfm);
    } else {
        for i in 1..num_sfm.max(0) as usize {
            let j = sub(ynrm[start + i - 1], 15);
            let current = &mut ynrm[start + i];
            *current = add(*current, j);
            // safety check in case of bit errors
            if *current < 0 || sub(*current, 39) > 0 {
                *current = 39;
                st.ber_detect = 1;
            }
            normqlg2[start + i] = at(&DICNLG2, *current);
        }
    }
}

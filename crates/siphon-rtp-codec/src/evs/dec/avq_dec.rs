//! Algebraic vector quantiser demultiplexing and decoding (TS 26.442 `lib_dec/avq_dec_fx.c`;
//! TS 26.445 §6.1.4.2.1). Only `AVQ_demuxdec_fx` is ported; `AVQ_dec_lpc` is MODE2's LPC path.

use crate::evs::com::bitstream::{get_next_indice, get_next_indice_1};
use crate::evs::dec::re8_dec::re8_dec;
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{add, extract_l, shl, shr, sub};
use crate::itu::stl2009::l_mac0;

/// The reference's `I[]` / `nq[]` scratch length, an upper bound on `Nsv`.
const NSV_MAX: usize = 34;

/// `AVQ_demuxdec_fx`: read `nsv` sub-vectors of 8 from the bitstream within the budget
/// `nb_bits` (which receives the bits left) and decode them into `xriq` (`8·nsv` values);
/// `nq_out` receives each sub-vector's codebook number. A codebook number past 32 is a corrupt
/// frame: it sets `BER_detect` and zeroes the output.
pub fn avq_demuxdec(
    st: &mut DecoderState,
    xriq: &mut [i16],
    nb_bits: &mut i16,
    nsv: i16,
    nq_out: &mut [i16],
) {
    let mut big_i = [0_u16; NSV_MAX];
    let mut nq = [0_i16; NSV_MAX];
    let mut code = [0_i16; 8];
    let nsv_count = (nsv.max(0) as usize).min(NSV_MAX);

    // `kv` is `xriq` itself: the Voronoi indices are read into the block each sub-vector's
    // decoded point is later written over.
    let mut bits = *nb_bits;

    // read the codebook indices (unary code) and the base / Voronoi indices
    for i in 0..nsv_count {
        nq[i] = 0;
        if sub(bits, 8) > 0 {
            // read the unary code including the stop bit for nq[i]
            nq[i] = -1;
            let mut tmp16: i16;
            loop {
                nq[i] = add(nq[i], 1);
                // check if the codebook number is the last one to be read
                tmp16 = extract_l(l_mac0(4, nq[i], 5));
                tmp16 = sub(tmp16, bits);
                if tmp16 == 0 {
                    break;
                }
                if get_next_indice_1(st) == 0 {
                    break;
                }
            }
            if tmp16 == 0 {
                bits = add(bits, 1); // the stop bit was not written
            }
            if sub(nq[i], 32) > 0 {
                // A codebook this large is a corrupt frame.
                st.ber_detect = 1;
                let n8 = (shl(nsv, 3).max(0) as usize).min(xriq.len());
                xriq[..n8].fill(0);
                nq_out[..nsv_count].fill(0);
                *nb_bits = 0;
                return;
            }
            bits = sub(bits, nq[i]);
            bits = sub(bits, 1); // count the stop bit

            if nq[i] > 0 {
                nq[i] = add(nq[i], 1);
            }

            // read the base codebook index and, beyond Q4, the Voronoi index
            if nq[i] != 0 {
                let order_v;
                if sub(nq[i], 5) < 0 {
                    tmp16 = shl(nq[i], 2);
                    order_v = 0;
                } else {
                    let mut j: i16 = 1;
                    if nq[i] & 1 == 0 {
                        j = add(j, 1);
                    }
                    order_v = sub(shr(nq[i], 1), j); // Voronoi extension order
                    tmp16 = shl(add(j, 2), 2);
                }
                big_i[i] = get_next_indice(st, tmp16);
                bits = sub(bits, tmp16);

                if order_v > 0 {
                    let base = i * 8;
                    for j in 0..8 {
                        xriq[base + j] = get_next_indice(st, order_v) as i16;
                    }
                    bits = sub(bits, shl(order_v, 3));
                }
            }
        }
    }

    // decode all the sub-vectors
    for i in 0..nsv_count {
        let base = i * 8;
        let mut kv = [0_i16; 8];
        kv.copy_from_slice(&xriq[base..base + 8]);
        re8_dec(nq[i], big_i[i], &kv, &mut code);
        xriq[base..base + 8].copy_from_slice(&code);
    }

    // write the remaining bits and the codebook numbers
    *nb_bits = bits;
    nq_out[..nsv_count].copy_from_slice(&nq[..nsv_count]);
}

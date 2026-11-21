//! The low-rate HQ core's TCQ / USQ spectrum decoder (TS 26.442 `lib_dec/tcq_core_dec_fx.c`;
//! TS 26.445 §6.2.3.2.2).
//!
//! `Overflow`: the reference clears it on entry ("before entering TCQ functions without any
//! message") and nothing in this function or the arithmetic decoders it calls reads it, so the
//! clear is unobservable and not reproduced.

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{L_FRAME16K, L_FRAME32K, L_FRAME48K, L_FRAME8K, NB_SFM, TCQ_AMP};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::hq2_core_com::bit_allocation_second;
use crate::evs::com::tcq_position_arith::{
    ar_decoder_done, ar_decoder_start, ar_div, decode_magnitude_usq, decode_mangitude_tcq,
    decode_position_ari, decode_signs, get_scale, load_tcq_data, restore_tcq_dec, srt_vec_ind,
    tcq_lsb_dec, ArCodec,
};
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{add, l_add, l_deposit_l, l_shl, l_sub, shl, shr, sub};

/// Which magnitude quantiser a band uses: TCQ for ordinary bands, USQ for the high-importance
/// ones (more than 0.75 bits per coefficient).
const USQ: i16 = 1;

/// The per-call working state: the arithmetic decoder, the pulse positions and the surplus.
struct TcqWork {
    ardec: ArCodec,
    positions: [i16; L_FRAME48K as usize],
    surplus: i32,
}

impl TcqWork {
    /// Decode one band's positions, magnitudes (TCQ updating the surplus, or USQ) and signs.
    fn decode_band(
        &mut self,
        inp_vector: &mut [i16],
        start: usize,
        width: i16,
        pulses: i16,
        usq: bool,
    ) {
        let mut nz: i16 = 0;
        decode_position_ari(
            &mut self.ardec,
            width,
            pulses,
            &mut nz,
            &mut self.positions[start..],
        );
        if usq {
            // decode usq magnitude and don't need to update surplus bits
            decode_magnitude_usq(
                &mut self.ardec,
                width,
                pulses,
                nz,
                &self.positions[start..],
                &mut inp_vector[start..],
            );
        } else {
            // decode tcq magnitude and update the surplus bits
            decode_mangitude_tcq(
                &mut self.ardec,
                width,
                pulses,
                nz,
                &self.positions[start..],
                &mut inp_vector[start..],
                &mut self.surplus,
            );
        }
        decode_signs(&mut self.ardec, width, &mut inp_vector[start..]);
    }
}

/// `inp_vector[start..start + width] = 0`: a band that carries no pulses.
fn zero_band(inp_vector: &mut [i16], start: usize, width: i16) {
    inp_vector[start..start + width.max(0) as usize].fill(0);
}

/// `tcq_core_LR_dec_fx`: decode the low-rate HQ spectrum `inp_vector` (x5) of `bands` bands from
/// `bit_budget` bits of the stream, with the bit allocation `rk_fx` (Q16, updated), returning the
/// pulse counts per band in `npulses` and the band order in `k_sort`. At WB / NB without the
/// allocation adjustment and outside transients, two bands get a second-pass allocation
/// (`bit_allocation_second`) and the TCQ LSB path is not sent.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
pub fn tcq_core_lr_dec(
    st: &mut DecoderState,
    inp_vector_fx: &mut [i16],
    bit_budget: i16,
    bands: i16,
    band_start: &[i16],
    band_width: &[i16],
    rk_fx: &mut [i32],
    npulses: &mut [i16],
    k_sort: &mut [i16],
    p2a_flags: &[i16],
    p2a_bands: i16,
    last_bitalloc: &[i16],
    input_frame: i16,
    adjust_flag: i16,
    is_transient: i16,
) {
    let bands_us = (bands.max(0) as usize).min(NB_SFM as usize);
    let mut rk_sort_fx = [0i32; NB_SFM as usize];
    let mut usq_tcq = [0i16; NB_SFM as usize]; // TCQ is selected by default
    let mut k_num = [0i16; 2];
    let mut dpath = [0i16; 280];
    let mut mbuffer_fx = [0i16; 560];
    let mut bcount: i16 = 0;
    let mut nzb: i16 = 0;
    let mut nzbands: i16 = 0;
    let mut lsbtcq_bits = TCQ_AMP;
    let mut tcq_arbits: i16 = 2;
    let mut flag_wbnb = false;

    let mut work = TcqWork {
        ardec: ArCodec::new(),
        positions: [0; L_FRAME48K as usize],
        surplus: 0,
    };
    work.positions[..L_FRAME32K as usize].fill(0);

    if sub(input_frame, L_FRAME16K) <= 0 && adjust_flag == 0 && is_transient == 0 {
        flag_wbnb = true;
        lsbtcq_bits = 0;
        tcq_arbits = 0;
    }

    work.ardec.bs_inst.cur_pos = 7;
    work.ardec.bs_inst.numbits = l_deposit_l(0);
    work.ardec.bs_inst.num_byte = l_deposit_l(0);

    // Bits distribution analysis
    for i in 0..bands_us {
        // USQ used for high importance bands, TCQ for usual bands
        usq_tcq[i] = if l_sub(ar_div(rk_fx[i], i32::from(band_width[i])), 49152) >= 0 {
            USQ
        } else {
            0
        };
        if rk_fx[i] > 0 {
            nzbands = add(nzbands, 1);
        }
    }

    for &rk in rk_fx.iter().take(bands_us) {
        if rk > 0 {
            nzb = add(nzb, 1);
        }
    }

    let mut bsub_fx = l_shl(l_add(i32::from(tcq_arbits), i32::from(lsbtcq_bits)), 16);
    if bsub_fx > 0 {
        bsub_fx = l_add(bsub_fx, 2048);
    }
    for j in (0..bands_us).rev() {
        if rk_fx[j] > 0 {
            rk_fx[j] = l_sub(rk_fx[j], ar_div(bsub_fx, i32::from(nzb)));
            if rk_fx[j] < 0 {
                bsub_fx = l_sub(bsub_fx, l_add(ar_div(bsub_fx, i32::from(nzb)), rk_fx[j]));
                rk_fx[j] = l_deposit_l(0);
            } else {
                bsub_fx = l_sub(bsub_fx, ar_div(bsub_fx, i32::from(nzb)));
            }
            nzb = sub(nzb, 1);
        }
    }

    srt_vec_ind(rk_fx, &mut rk_sort_fx, k_sort, bands);

    // read the bits
    tcq_core_lr_dec_read_bits(st, &mut work.ardec, bit_budget);

    ar_decoder_start(&mut work.ardec);

    if flag_wbnb {
        work.surplus = -131_072; // -2 in Q16
        bit_allocation_second(
            rk_fx,
            &rk_sort_fx,
            bands,
            band_width,
            k_sort,
            &mut k_num,
            p2a_flags,
            p2a_bands,
            last_bitalloc,
            input_frame,
        );
        tcq_core_lr_dec_wbnb(
            &mut work,
            inp_vector_fx,
            bands_us,
            band_start,
            band_width,
            rk_fx,
            npulses,
            k_sort,
            &usq_tcq,
            &k_num,
            input_frame,
        );
    } else {
        let mut delta_fx: i32 = 0;
        for k in 0..bands_us {
            let ks = k_sort[k] as usize;
            let start = band_start[ks] as usize;
            let pulsesnum = if rk_fx[ks] > 0 {
                let pulses = get_scale(
                    band_width[ks],
                    rk_fx[ks].wrapping_add(delta_fx),
                    Some(&mut work.surplus),
                );
                // decode usq magnitude and don't need to update surplus bits
                work.decode_band(inp_vector_fx, start, band_width[ks], pulses, true);
                nzbands = sub(nzbands, 1);
                pulses
            } else {
                zero_band(inp_vector_fx, start, band_width[ks]);
                0
            };

            npulses[ks] = pulsesnum;

            // surplus distribution
            if work.surplus > 0 && nzbands > 0 {
                delta_fx = ar_div(work.surplus, i32::from(nzbands));
                work.surplus = l_sub(work.surplus, delta_fx);
            }
        }
    }

    // Load TCQ path from bitstream
    load_tcq_data(&mut work.ardec, &mut dpath, lsbtcq_bits);

    tcq_lsb_dec(&dpath, &mut mbuffer_fx, 2 * lsbtcq_bits);

    ar_decoder_done(&mut work.ardec);

    // Restore TCQ
    let k_num0 = i32::from(k_num[0]);
    let k_num1 = i32::from(k_num[1]);
    let mut restore = |k: usize, inp_vector_fx: &mut [i16]| {
        let ks = k_sort[k] as usize;
        restore_tcq_dec(
            &mut inp_vector_fx[band_start[ks] as usize..],
            band_width[ks],
            &mut bcount,
            &mut mbuffer_fx,
        );
    };
    if !flag_wbnb {
        for k in 0..bands_us {
            if rk_fx[k_sort[k] as usize] > 0 {
                restore(k, inp_vector_fx);
            }
        }
    } else {
        for k in 0..bands_us {
            let second = k as i32 == k_num0 || k as i32 == k_num1;
            if rk_fx[k_sort[k] as usize] > 0 && !second {
                restore(k, inp_vector_fx);
            }
        }
        for k in 0..bands_us {
            let second = k as i32 == k_num0 || k as i32 == k_num1;
            if rk_fx[k_sort[k] as usize] > 0 && second {
                restore(k, inp_vector_fx);
            }
        }
    }
}

/// Read `bit_budget` bits into the arithmetic decoder's byte buffer, the last partial byte
/// left-aligned, then two zero bytes to flush the decoder ("this avoids reading of uninitialized
/// memory"). A budget beyond the buffer (never sent) is cut at the buffer.
fn tcq_core_lr_dec_read_bits(st: &mut DecoderState, ardec: &mut ArCodec, bit_budget: i16) {
    let buf = &mut ardec.bs_inst.buf;
    let mut nb_bytes = shr(bit_budget, 3);
    let k = sub(bit_budget, shl(nb_bytes, 3));
    let mut i: i16 = 0;
    while i < nb_bytes {
        let byte = get_next_indice(st, 8) as u8;
        if let Some(slot) = buf.get_mut(i as usize) {
            *slot = byte;
        }
        i += 1;
    }

    if k > 0 {
        let tmp = i16::from(get_next_indice(st, k) as u8);
        if let Some(slot) = buf.get_mut(nb_bytes.max(0) as usize) {
            *slot = shl(tmp, sub(8, k)) as u8;
        }
        i = add(i, 1);
        nb_bytes = add(nb_bytes, 1);
    }
    // set two more bytes, which are used to flush the arithmetic coder, to 0
    nb_bytes = add(nb_bytes, 2).min(buf.len() as i16);
    while i < nb_bytes {
        if let Some(slot) = buf.get_mut(i.max(0) as usize) {
            *slot = 0;
        }
        i += 1;
    }

    ardec.bs_inst.max_bytes = i32::from(nb_bytes);
}

/// The WB / NB first pass of [`tcq_core_lr_dec`]: every band except the two second-pass ones
/// (`k_num`, sorted indices), each band's shortfall of bits spread over the remaining bands once
/// the surplus turns negative; then the two second-pass bands with the surplus split between
/// them.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
fn tcq_core_lr_dec_wbnb(
    work: &mut TcqWork,
    inp_vector_fx: &mut [i16],
    bands_us: usize,
    band_start: &[i16],
    band_width: &[i16],
    rk_fx: &mut [i32],
    npulses: &mut [i16],
    k_sort: &[i16],
    usq_tcq: &[i16],
    k_num: &[i16; 2],
    input_frame: i16,
) {
    let mut leftbits: i32 = 0;
    let mut sepbits: i32 = 0;
    let mut delta_fx: i32 = 0;
    let mut nzbands: i16 = 0;
    for j in 0..bands_us {
        let ks = k_sort[j] as usize;
        if j as i32 == i32::from(k_num[0]) || j as i32 == i32::from(k_num[1]) {
            sepbits = l_add(sepbits, rk_fx[ks]);
        } else {
            leftbits = l_add(leftbits, rk_fx[ks]);
            if rk_fx[ks] > 0 {
                nzbands = add(nzbands, 1);
            }
        }
    }

    for k in 0..bands_us {
        if k as i32 == i32::from(k_num[0]) || k as i32 == i32::from(k_num[1]) {
            continue;
        }
        let ks = k_sort[k] as usize;
        let start = band_start[ks] as usize;
        let width = band_width[ks];
        let pulsesnum = if rk_fx[ks] > 0 {
            // When the number of bits per band is less than the arithmetic bits overhead, this
            // band is not encoded. It may happen when the actual number of bits per band is near
            // the estimated number of bits, for most bands (very unprobable but possible)
            let pulses = if l_add(rk_fx[ks], delta_fx) < 0 {
                zero_band(inp_vector_fx, start, width);
                if work.surplus != 0 {
                    work.surplus = l_add(rk_fx[ks], work.surplus);
                    work.surplus = l_add(delta_fx, work.surplus);
                }
                0
            } else {
                // get number of pulses
                let pulses = get_scale(width, l_add(rk_fx[ks], delta_fx), Some(&mut work.surplus));
                leftbits = l_sub(leftbits, l_add(rk_fx[ks], delta_fx));
                work.decode_band(inp_vector_fx, start, width, pulses, usq_tcq[ks] == USQ);
                pulses
            };
            // the C's two branches (TCQ: usq_tcq 0, USQ: 1) differ only in the magnitude decoder;
            // a band with any other flag is never > 0 here, so both decrement
            nzbands = nzbands.wrapping_sub(1);
            pulses
        } else {
            zero_band(inp_vector_fx, start, width);
            0
        };

        npulses[ks] = pulsesnum;

        delta_fx = l_deposit_l(0);
        if rk_fx[ks] > 0 && work.surplus < 0 {
            let divider: i32 = if nzbands <= 1 { 0 } else { 2 };

            if l_add(l_add(work.surplus, sepbits), ar_div(leftbits, divider)) < 0 {
                // Overflow possible => start to distribute negative surplus
                delta_fx = ar_div(work.surplus.wrapping_add(sepbits), i32::from(nzbands));
            } else {
                delta_fx = 0;
            }
            work.surplus = l_sub(work.surplus, delta_fx);
        }
    }

    let mut bit_surplus_fx = [0i32; 2];
    if (l_sub(work.surplus, 524_288) > 0 && sub(input_frame, L_FRAME8K) == 0)
        || (l_sub(work.surplus, 786_432) > 0 && sub(input_frame, L_FRAME16K) == 0)
    {
        bit_surplus_fx[0] = mult_32_16(work.surplus, 24576); // Q16
        bit_surplus_fx[1] = mult_32_16(work.surplus, 8192); // Q16
    } else {
        bit_surplus_fx[0] = work.surplus;
        bit_surplus_fx[1] = l_deposit_l(0);
    }

    for k in 0..bands_us {
        for (j, &surplus) in bit_surplus_fx.iter().enumerate() {
            if k as i32 != i32::from(k_num[j]) {
                continue;
            }
            let ks = k_sort[k] as usize;
            let start = band_start[ks] as usize;
            let width = band_width[ks];
            rk_fx[ks] = l_add(rk_fx[ks], surplus);

            let pulsesnum = if rk_fx[ks] > 0 && (usq_tcq[ks] == 0 || usq_tcq[ks] == USQ) {
                // get number of pulses
                let pulses = get_scale(width, rk_fx[ks], Some(&mut work.surplus));
                work.decode_band(inp_vector_fx, start, width, pulses, usq_tcq[ks] == USQ);
                pulses
            } else {
                zero_band(inp_vector_fx, start, width);
                0
            };

            npulses[ks] = pulsesnum;
        }
    }
}

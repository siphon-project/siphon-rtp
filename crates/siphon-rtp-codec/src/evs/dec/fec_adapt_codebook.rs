//! Adaptive-codebook repair after a frame loss: the artificial onset of a lost onset frame and the
//! pulse resynchronisation of the adaptive codebook of the first good frame (TS 26.442
//! `lib_dec/FEC_adapt_codebook_fx.c`; TS 26.445 §6.8.3.2 and §6.8.3.3).

use crate::evs::cnst::{
    DEC, L_EXC_MEM, L_FRAME, L_FRAME16K, L_SUBFR, L_SUBFR16K, M, MODE1_L_FIR_FER, PIT16K_MAX,
    PIT_MAX, PIT_MIN_DOUBLEEXTEND,
};
use crate::evs::com::findpulse::findpulse;
use crate::evs::com::math_op::{dot_product12, isqrt_lc};
use crate::evs::com::syn_filt::e_util_synthesis_in_place;
use crate::evs::rom::{H_LOW, INV_SQI, SQI};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_mac, l_msu, l_mult, l_shl,
    l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{i_mult, l_mac0};

/// `FEC_SinOnset_fx`: builds an artificial onset when the onset frame is lost. A train of low-pass
/// filtered pulses (the pulse prototype `H_low` scaled by the transmitted energy `enr_q` over
/// the energy of the LP filter `aq`'s impulse response) is placed `puls_pos` samples before the
/// end of the frame (a negative `puls_pos` is a negative pulse), and the last `L_EXC_MEM`
/// samples of the result are written to `exc`. `qold` is the excitation's Q; the returned Q is
/// lowered when the pulse would otherwise overflow.
pub fn fec_sin_onset(
    exc: &mut [i16],
    puls_pos: i16,
    t0: i16,
    enr_q: i32,
    aq: &[i16],
    l_frame: i16,
    qold: i16,
) -> i16 {
    let mut sign: i16 = 0;
    let mut q_exc = qold;
    let mut l_subfr = L_SUBFR;
    if sub(l_frame, L_FRAME16K) == 0 {
        l_subfr = L_SUBFR16K;
    }

    let l_subfr2 = shl(l_subfr, 1);
    let onset_len = t0.max(l_subfr2);

    let mut p0 = puls_pos;
    if p0 < 0 {
        sign = 1;
        p0 = negate(p0);
    }

    if sub(p0, PIT_MAX) > 0 && sub(l_frame, L_FRAME) == 0 {
        p0 = PIT_MAX; // should never be the case, however...
    } else if sub(p0, PIT16K_MAX) > 0 && sub(l_frame, L_FRAME16K) == 0 {
        p0 = PIT16K_MAX; // should never be the case, however...
    }
    let mut exc_tmp = [0i16; L_FRAME16K as usize + MODE1_L_FIR_FER as usize];

    // Find the LP filter impulse response energy and generate the scaled pulse prototype
    let mut h1 = [0i16; L_SUBFR16K as usize];
    let mut mem = [0i16; M as usize];
    h1[0] = 1024;
    e_util_synthesis_in_place(1, aq, &mut h1, l_subfr, &mut mem, 0, M);

    let mut exp_gain: i16 = 0;
    let mut enr_lp = extract_h(dot_product12(&h1, &h1, l_subfr, &mut exp_gain));
    exp_gain = sub(exp_gain, 10 + 10); // h1 in Q10

    // divide by the LP filter energy, scaled by the transmitted energy:
    // gain = sqrt(enr_q / enr_LP)
    let enr_q = enr_q.max(1);

    let mut exp2 = norm_l(enr_q);
    let mut tmp = extract_h(l_shl(enr_q, exp2));
    tmp = mult(tmp, 24576); // multiply by 1.5

    if sub(tmp, 16384) < 0 {
        exp2 = add(exp2, 1);
        tmp = shl(tmp, 1);
    }
    exp2 = sub(30, exp2); // in Q15

    if sub(enr_lp, tmp) > 0 {
        enr_lp = shr(enr_lp, 1);
        exp_gain = add(exp_gain, 1);
    }

    tmp = div_s(enr_lp, tmp);
    exp2 = sub(exp_gain, exp2);

    let l_tmp = l_deposit_h(tmp);
    let l_tmp = isqrt_lc(l_tmp, &mut exp2);
    let mut gain = round_word(l_tmp);

    gain = mult_r(gain, 31457); // multiply by .96 like the floating-point reference
    exp2 = add(sub(exp2, 15), q_exc); // from Q15 to Q_exc

    // Find if rescaling is needed
    tmp = extract_h(l_mult(H_LOW[2], gain));
    exp_gain = norm_s(tmp);
    tmp = sub(exp_gain, exp2); // difference

    if tmp < 0 {
        // need to correct the scaling
        q_exc = add(q_exc, tmp);
        exp2 = add(exp2, tmp);
    }
    // Scale the pulse prototype energy: generate the scaled pulse
    let mut h_low_s = [0i16; MODE1_L_FIR_FER as usize];
    for i in 0..MODE1_L_FIR_FER as usize {
        let l_tmp = l_mult(gain, H_LOW[i]); // Q_exc * Q15 -> Q_exc
        h_low_s[i] = round_word(l_shl(l_tmp, exp2));
    }

    // Construct the harmonic part as a train of low-pass filtered pulses
    let pt_exc = i32::from(sub(l_frame, add(add(1, MODE1_L_FIR_FER / 2), p0))); // 1st pulse
    let pt_end = i32::from(onset_len);
    let len = ((pt_exc - pt_end) as i16).min(MODE1_L_FIR_FER);
    for (i, &pulse) in h_low_s.iter().enumerate().take(len.max(0) as usize) {
        // the filter response would have E=1 in full band
        let at = pt_exc as usize + i;
        exc_tmp[at] = if sign == 0 {
            add(exc_tmp[at], pulse)
        } else {
            sub(exc_tmp[at], pulse)
        };
    }
    // Copy(&exc_tmp[L_frame - L_EXC_MEM], exc, L_EXC_MEM): at L_frame = L_FRAME the reference starts
    // 64 samples before exc_tmp and copies whatever its stack holds there. Those are the oldest
    // samples of the window, further back than any later subframe reads (PIT_MAX + L_INTERPOL), so
    // they are zero here.
    let from = i32::from(l_frame) - i32::from(L_EXC_MEM);
    for (index, slot) in exc[..L_EXC_MEM as usize].iter_mut().enumerate() {
        let source = from + index as i32;
        *slot = if source < 0 {
            0
        } else {
            exc_tmp[source as usize]
        };
    }
    q_exc
}

/// `FEC_enhACB_fx`: after a lost frame, resynchronises the glottal pulse of the adaptive-codebook
/// memory `exc_io` (`L_EXC_MEM` samples) with the pulse position `puls_pos` the encoder sent
/// (negative for a negative pulse), when the pitch decoded for the first subframe `new_pit`
/// agrees with the concealment pitch `bfi_pitch` (Q6) closely enough. Returns the `do_WI` flag:
/// 1 when the codebook was resynchronised and the previous frame was 16 kHz-based.
pub fn fec_enh_acb(
    l_frame: i16,
    last_l_frame: i16,
    exc_io: &mut [i16],
    new_pit: i16,
    puls_pos: i16,
    bfi_pitch: i16,
) -> i16 {
    let mut exc = [0i16; L_FRAME16K as usize + L_SUBFR as usize];
    let mut sign: i16 = 0;

    let mem = L_EXC_MEM as usize;
    let frame16 = L_FRAME16K as usize;
    exc[frame16 - mem..frame16].copy_from_slice(&exc_io[..mem]);

    let tc = shr(bfi_pitch, 6);
    // the pitch is a lag inside the memory; a hostile value would index before the buffer
    if !(0..=L_FRAME16K).contains(&tc) || tc > l_frame {
        return 0;
    }
    let tc_at = frame16 - tc as usize;
    let mut head = [0i16; L_SUBFR as usize];
    head.copy_from_slice(&exc[tc_at..tc_at + L_SUBFR as usize]);
    exc[frame16..frame16 + L_SUBFR as usize].copy_from_slice(&head);

    // Decode the phase information transmitted in the bitstream (the position of the absolute
    // maximum glottal pulse from the end of the frame and its sign)
    let mut p0 = puls_pos;
    if p0 < 0 {
        sign = 1;
        p0 = negate(p0);
    }

    if sub(l_frame, L_FRAME) == 0 {
        p0 = p0.min(PIT_MAX);
    } else {
        p0 = p0.min(PIT16K_MAX); // L_frame == L_FRAME16k
    }

    // Find the position of the first maximum (minimum) low-pass filtered pulse
    let pit_search = tc;
    let search_at = (l_frame - pit_search) as usize;

    let mut tlist = [0i16; 2];
    tlist[0] = findpulse(l_frame, &exc[search_at..], pit_search, DEC, &mut sign);

    let mut terr = abs_s(sub(pit_search, add(tlist[0], p0)));
    let mut dist_plast = sub(tc, tlist[0]);

    tlist[1] = findpulse(
        l_frame,
        &exc[search_at..],
        add(pit_search, L_SUBFR),
        DEC,
        &mut sign,
    );

    if sub(terr, abs_s(add(sub(tlist[1], tc), p0))) > 0 {
        dist_plast = sub(tc, tlist[1]);
        terr = abs_s(add(sub(tlist[1], tc), p0));
    }

    let diff_pit = abs_s(sub(new_pit, tc));
    let tmp2 = mult_r(div_s(16, tc), shr(l_frame, 4));
    let mut do_wi;
    if sub(terr, i_mult(tmp2, diff_pit)) <= 0
        && terr != 0 // if Terr = 0, no resynchronisation is required
        && sub(terr, L_SUBFR) < 0
    // prevent a catastrophic search
    {
        // perform the excitation resynchronisation here
        do_wi = fec_synchro_exc(l_frame, &mut exc, p0, dist_plast, tc);
        exc_io[..mem].copy_from_slice(&exc[frame16 - mem..frame16]);
    } else {
        do_wi = 0;
    }

    if sub(last_l_frame, L_FRAME16K) != 0 {
        do_wi = 0;
    }
    do_wi
}

/// `Copy` with the destination and source clipped to the buffers: the reference's lengths stay
/// inside them on every frame the codec produces; a hostile value copies what fits.
fn copy_clipped(src: &[i16], src_at: usize, dst: &mut [i16], dst_at: usize, length: i16) {
    let length = (length.max(0) as usize)
        .min(src.len().saturating_sub(src_at))
        .min(dst.len().saturating_sub(dst_at));
    dst[dst_at..dst_at + length].copy_from_slice(&src[src_at..src_at + length]);
}

/// `FEC_synchro_exc_fx`: adds or removes `true_puls_pos - desire_puls_pos` samples in the
/// minimum-energy regions of the `l_frame` samples of `exc` (one region per pitch cycle, `old_pitch`
/// apart), so the last pulse lands on `desire_puls_pos`. Returns the `do_WI` flag: 1 when the
/// excitation was modified, 0 when the search was unsafe.
pub fn fec_synchro_exc(
    l_frame: i16,
    exc: &mut [i16],
    desire_puls_pos: i16,
    true_puls_pos: i16,
    old_pitch: i16,
) -> i16 {
    const CAPACITY: usize = (L_FRAME16K / PIT_MIN_DOUBLEEXTEND) as usize;
    let mut exc_tmp = [0i16; L_FRAME16K as usize + L_SUBFR as usize];
    let mut min_pos = [10000i16; CAPACITY];
    let mut points_by_pos = [0i16; CAPACITY];
    let mut point_to_add: i16 = -1;

    // number of points to remove (negative: add points) and of minimum-energy regions
    let point_to_remove = sub(true_puls_pos, desire_puls_pos);
    let pos = sub(l_frame, true_puls_pos);
    if pos < 0 || pos as usize > exc.len() {
        return 0; // outside the excitation: the reference would read out of bounds
    }

    // nb_min = (L_FRAME - true_puls_pos) / Old_pitch
    let mut tmp16 = shl(old_pitch, 5);
    tmp16 = div_s(pos, tmp16);
    let mut nb_min = shr(tmp16, 10);
    // if Old_pitch < 128, there must be at least 2 minima
    if sub(old_pitch, 128) <= 0 {
        nb_min = nb_min.max(2);
    }
    // there must be at least 1 minimum
    nb_min = nb_min.max(1);

    let pos_at = pos as usize;

    // Find the starting point for the minimum energy search
    let mut start_search = mult_r(old_pitch, -24576);
    if sub(old_pitch & 3, 1) == 0 {
        // only be aligned with the integer operation -3*Old_pitch/4
        start_search = add(start_search, 1);
    }
    if add(start_search, pos) < 0 {
        start_search = negate(pos);
        if sub(abs_s(start_search), shr(old_pitch, 3)) < 0 {
            // it's not safe to remove/add points inside 1/8 of the pulse position
            return 0;
        }
    }
    if i32::from(pos) + i32::from(start_search) + 5 > exc.len() as i32 {
        return 0; // the energy window would end outside the excitation
    }
    let at = |offset: i16| -> usize { (pos_at as i32 + i32::from(offset)) as usize };

    // Find the minimum energy in the first pitch section. The minimum energy regions are
    // determined by computing the energy with a sliding 5-sample window; the minimum energy
    // position is the middle of the window at which the energy is minimal.
    let mut l_min_energy = l_add(i32::MAX, 0);
    let mut l_tmp = l_mult(exc[at(start_search)], exc[at(start_search)]);
    for k in 1..5 {
        let sample = exc[at(start_search + k)];
        l_tmp = l_mac(l_tmp, sample, sample);
    }

    if l_sub(l_tmp, l_min_energy) < 0 {
        l_min_energy = l_add(l_tmp, 0);
        min_pos[0] = add(add(pos, start_search), 2);
    }

    let mut i = start_search;
    while i < -5 {
        let old = exc[at(i)];
        let new = exc[at(i + 5)];
        l_tmp = l_msu(l_tmp, old, old);
        l_tmp = l_mac(l_tmp, new, new);

        if l_sub(l_tmp, l_min_energy) < 0 {
            l_min_energy = l_add(0, l_tmp); // sets to 'L_tmp' in 1 clock
            min_pos[0] = add(add(pos, i), 2);
        }
        i += 1;
    }

    // (min_pos has room for 18 regions; more is rejected below, the reference would write past it)
    let mut j: i16 = 1;
    while j < nb_min && (j as usize) < CAPACITY {
        min_pos[j as usize] = sub(min_pos[j as usize - 1], old_pitch);
        // if the first minimum is in the past, forget this minimum
        if min_pos[j as usize] < 0 {
            min_pos[j as usize] = -10000;
            nb_min = sub(nb_min, 1);
        }
        j += 1;
    }

    // safety measure against a not properly initialised min_pos[]
    if l_sub(l_min_energy, i32::MAX) >= 0 {
        return 0;
    }

    if sub(nb_min, 16) > 0 {
        // inv_sqi & sqi are built for a maximum of nb_min-2 = 14 values
        return 0;
    }

    // Determine the number of samples to be added or removed at each pitch cycle, whereby fewer
    // samples are added/removed at the beginning and more towards the end of the frame
    if sub(nb_min, 1) == 0 || sub(abs_s(point_to_remove), 1) == 0 {
        nb_min = 1;
        points_by_pos[0] = abs_s(point_to_remove);
    } else {
        // first position: fact = |point_to_remove| / sqi[nb_min-2]  (nb_min * nb_min)
        let fact = mult_r(shl(abs_s(point_to_remove), 7), INV_SQI[nb_min as usize - 2]); // Q7
        points_by_pos[0] = mult_r(fact, 256); // Q7
        let mut total_point = points_by_pos[0];

        for i in 2..=nb_min as usize {
            // points_by_pos[i-1] = (Word16)(fact*(sqi[i-2]) - total_point + 0.5)
            points_by_pos[i - 1] =
                sub(shr(extract_l(l_mac0(64, fact, SQI[i - 2])), 7), total_point);
            total_point = add(total_point, points_by_pos[i - 1]);

            // ensure a constant increase
            if sub(points_by_pos[i - 1], points_by_pos[i - 2]) < 0 {
                points_by_pos.swap(i - 1, i - 2);
            }
        }
    }

    // Sample deletion or insertion is performed in the minimum energy regions. At the end of this
    // section the last maximum pulse in the concealed excitation is forced to align to the actual
    // maximum pulse position at the end of the frame, which is transmitted in the future frame.
    if point_to_remove > 0 {
        point_to_add = point_to_remove;
    }

    let mut pt_exc = 0usize;
    let mut pt_exc1 = 0usize;
    let nb = nb_min as usize;
    let mut remaining_len = l_frame;
    for i in 0..nb {
        // pt_pos walks the minima from the last one back
        let pt_pos = nb - 1 - i;
        // Compute the length to copy
        let mut tmp_len = min_pos[pt_pos];
        if i != 0 {
            tmp_len = sub(
                sub(min_pos[pt_pos], min_pos[pt_pos + 1]),
                points_by_pos[i - 1],
            );
        }
        // Copy the section
        copy_clipped(exc, pt_exc1, &mut exc_tmp, pt_exc, tmp_len);
        remaining_len = sub(remaining_len, tmp_len);
        pt_exc1 = (pt_exc1 as i32 + i32::from(tmp_len)).max(0) as usize;
        pt_exc = (pt_exc as i32 + i32::from(tmp_len)).max(0) as usize;

        if point_to_add > 0 {
            // Samples insertion: find the point to add and add the points
            let mut tmp16 = mult_r(exc.get(pt_exc1).copied().unwrap_or(0), -1638);
            for _ in 0..points_by_pos[i] {
                if let Some(slot) = exc_tmp.get_mut(pt_exc) {
                    *slot = tmp16; // repeat the last point
                }
                pt_exc += 1;
                tmp16 = negate(tmp16);
            }
            remaining_len = sub(remaining_len, points_by_pos[i]);
        } else {
            // Samples deletion: remove the points
            pt_exc1 += points_by_pos[i].max(0) as usize;
        }
    }
    // Copy the remaining data
    remaining_len = remaining_len.max(0);
    copy_clipped(exc, pt_exc1, &mut exc_tmp, pt_exc, remaining_len);
    // Update the true excitation vector
    let frame = l_frame.max(0) as usize;
    exc[..frame].copy_from_slice(&exc_tmp[..frame]);
    1
}

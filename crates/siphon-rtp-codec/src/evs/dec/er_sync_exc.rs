//! Resynchronisation of the glottal pulses of a concealed voiced excitation (TS 26.442
//! `lib_dec/er_sync_exc.c`; TS 26.447 §5.4.2.3): the last pitch cycle, repeated at the old pitch,
//! is stretched or compressed to the extrapolated pitch by adding or removing a few samples at
//! the energy minima between the pulses.
//!
//! The reference passes the source and destination excitation as two pointers with
//! `src_exc < dst_exc`; both live in one buffer here (`exc`, with the offsets `src_at` and
//! `dst_at`), so a read that strays from the source region sees what the reference would. Reads
//! and writes the reference would make outside the buffer read 0 / are dropped instead.

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{MAXVAL_WORD32, NB_PULSES_MAX};
use crate::evs::com::basop_util::{
    basop_util_add_mant32_exp, basop_util_divide3216_scale, basop_util_divide_mant_exp, imult1616,
    inv16,
};
use crate::itu::basic_ops::{
    abs_s, add, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_msu, l_mult,
    l_negate, l_shl, l_shr, l_sub, mult, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_lshl, lshr};

/// `NB_PULSES_MAX + 1`, the size of the per-pulse arrays.
const PULSES: usize = NB_PULSES_MAX as usize + 1;

/// `exc[at]`, 0 outside the buffer.
fn read(exc: &[i16], at: isize) -> i16 {
    usize::try_from(at)
        .ok()
        .and_then(|at| exc.get(at))
        .copied()
        .unwrap_or(0)
}

/// `exc[at] = value`, dropped outside the buffer.
fn write(exc: &mut [i16], at: isize, value: i16) {
    if let Some(slot) = usize::try_from(at).ok().and_then(|at| exc.get_mut(at)) {
        *slot = value;
    }
}

/// `GetMinimumPosition`: the centre of the `filter_length`-sample window over
/// `exc[x_at..x_at + length]` with the least energy (relative to the first window).
fn get_minimum_position(exc: &[i16], x_at: isize, length: i16, filter_length: i16) -> i16 {
    let filter_length = filter_length.min(length);
    let mut center = shr(filter_length, 1);
    let mut i_min_energy_pos = center;

    if filter_length > 0 {
        center = add(center, 1);
        let mut energy_old = l_deposit_l(0);

        let cnt = sub(length, filter_length);

        let mut tmp_e: i16 = 0;
        let fl = filter_length as isize;
        for i in 0..cnt.max(0) {
            let at = x_at + i as isize;
            let mut tmp16 = shr(read(exc, at), tmp_e);
            let mut energy = l_msu(energy_old, tmp16, tmp16);
            tmp16 = shr(read(exc, at + fl), tmp_e);
            energy = l_mac(energy, tmp16, tmp16); // Saturation will be handled

            // if (energy == MAXVAL_WORD32); saturates if energy < 0
            let tmptest = l_sub(energy, MAXVAL_WORD32);
            if tmptest == 0 {
                tmp_e = add(tmp_e, 1);
                energy = l_shr(energy_old, 2);
                tmp16 = shr(read(exc, at), tmp_e);
                energy = l_msu(energy, tmp16, tmp16);
                tmp16 = shr(read(exc, at + fl), tmp_e);
                energy = l_mac(energy, tmp16, tmp16);
            }

            if energy < 0 {
                i_min_energy_pos = add(i, center);
                tmp_e = 0;
                energy = 0;
            }
            energy_old = l_add(energy, 0);
        }
    }
    i_min_energy_pos
}

/// `FindMaxPeak`: the index of the largest magnitude in `exc[x_at..x_at + length]` (the first one
/// on a tie).
fn find_max_peak(exc: &[i16], x_at: isize, length: i16) -> i16 {
    let mut i_max: i16 = 0;
    for i in 1..length.max(1) {
        if sub(
            abs_s(read(exc, x_at + i as isize)),
            abs_s(read(exc, x_at + i_max as isize)),
        ) > 0
        {
            i_max = i;
        }
    }
    i_max
}

/// `AddSamples`: copy the source to the destination, inserting `points_by_pos[i]` small
/// alternating samples at each `min_pos[i]`.
fn add_samples(
    exc: &mut [i16],
    src_at: isize,
    dst_at: isize,
    l_frame: i16,
    n_samples_to_add: i16,
    min_pos: &[i16; PULSES],
    points_by_pos: &[i16; PULSES],
    nb_min: i16,
) {
    let mut pt_dest = dst_at;
    let mut pt_src = src_at;
    let mut last_min_pos: i16 = 0;

    for i in 0..nb_min.max(0) as usize {
        // Copy section
        let mut j = (i32::from(min_pos[i]) - i32::from(last_min_pos)) as i16;
        while j > 0 {
            write(exc, pt_dest, read(exc, pt_src));
            pt_dest += 1;
            pt_src += 1;
            j -= 1;
        }
        // Add some samples
        let mut ftmp = negate(mult(read(exc, pt_src), 1638)); // .05f Q15

        for _ in 0..points_by_pos[i].max(0) {
            write(exc, pt_dest, ftmp);
            pt_dest += 1;
            ftmp = negate(ftmp);
        }
        // Prepare for the next loop iteration
        last_min_pos = min_pos[i];
    }
    // Copy remaining length
    let mut j = sub(l_frame, add(n_samples_to_add, last_min_pos));
    while j > 0 {
        write(exc, pt_dest, read(exc, pt_src));
        pt_dest += 1;
        pt_src += 1;
        j -= 1;
    }
}

/// `RemoveSamples`: copy the source to the destination backwards, dropping `points_by_pos[i]`
/// samples at each `min_pos[i]`.
fn remove_samples(
    exc: &mut [i16],
    src_at: isize,
    dst_at: isize,
    l_frame: i16,
    n_samples_to_add: i16,
    min_pos: &[i16; PULSES],
    points_by_pos: &[i16; PULSES],
    nb_min: i16,
) {
    let mut pt_dest = dst_at + l_frame as isize;
    let mut last_min_pos = sub(l_frame, n_samples_to_add);

    for i in (0..nb_min.max(0) as usize).rev() {
        // Copy section, removing some samples
        let mut pt_src = src_at + last_min_pos as isize;

        let mut j = sub(last_min_pos, add(min_pos[i], points_by_pos[i]));
        while j > 0 {
            pt_dest -= 1;
            pt_src -= 1;
            write(exc, pt_dest, read(exc, pt_src));
            j -= 1;
        }
        // Prepare for the next loop iteration
        last_min_pos = min_pos[i];
    }
    // Copy remaining length
    let mut pt_src = src_at + last_min_pos as isize;
    let mut j = last_min_pos;
    while j > 0 {
        pt_dest -= 1;
        pt_src -= 1;
        write(exc, pt_dest, read(exc, pt_src));
        j -= 1;
    }
}

/// `PulseResynchronization`: resynchronise the glottal pulses of the harmonic excitation at
/// `exc[src_at..]`, built by repeating the last pitch cycle (`pitch_start`, Q16), to a pitch
/// moving linearly to `pitch_end` (Q16) over `n_subframes`, writing `n_frame_length` samples to
/// `exc[dst_at..]`. The source must lie before the destination (`src_at < dst_at`); otherwise,
/// or for any other out-of-range parameter, the source is copied unchanged (the reference's
/// error recovery).
pub fn pulse_resynchronization(
    exc: &mut [i16],
    src_at: usize,
    dst_at: usize,
    n_frame_length: i16,
    n_subframes: i16,
    pitch_start: i32,
    pitch_end: i32,
) {
    if l_sub(l_deposit_h(n_frame_length), pitch_start) < 0
        || pitch_start <= 0
        || pitch_end <= 0
        || sub(n_subframes, 1) < 0
        || sub(n_subframes, 5) > 0
        || l_sub(
            mpy_32_16_1(pitch_end, add(n_subframes, 1)),
            mpy_32_16_1(pitch_start, sub(n_subframes, 1)),
        ) <= 0
        || src_at >= dst_at
    {
        // This is error handling and recovery that should never occur.
        if src_at != dst_at && sub(n_frame_length, 1200) <= 0 {
            let n = n_frame_length.max(0) as usize;
            if src_at + n <= exc.len() && dst_at + n <= exc.len() {
                exc.copy_within(src_at..src_at + n, dst_at);
            }
        }
        return;
    }
    let src = src_at as isize;
    let dst = dst_at as isize;

    let rounded_pitch_start = round_word(pitch_start); // Q0

    // freqStart = 1.0f/roundedPitchStart;
    let mut freq_start_e: i16 = 15;
    let freq_start = inv16(rounded_pitch_start, &mut freq_start_e); // Q15,freqStart_e

    let (samples_delta, samples_delta_e) = pulse_resynchronization_samples_delta(
        n_frame_length,
        n_subframes,
        pitch_start,
        pitch_end,
        rounded_pitch_start,
        freq_start,
        freq_start_e,
    );

    // To have enough samples in the buffer of length nFrameLength*(nSubframes+1)/nSubframes,
    // pitchEnd/pitchEnd must be bigger than (nSubframes-1)/(nSubframes+1)=1-2/(nSubframes+1).
    // Thus nSubframes must be bigger than 1
    let n_samples_delta = round_word(l_shl(samples_delta, sub(samples_delta_e, 31 - 16))); // Q0
    let n_samples_delta_remain = abs_s(n_samples_delta);
    // Find the location of the glottal pulse
    let t0 = find_max_peak(exc, src, rounded_pitch_start); // Q0
                                                           // Get the index of the last pulse in the resynchronized frame
                                                           // k = (int)ceil((nFrameLength-nSamplesDelta-T0)*freqStart - 1);
    let mut tmp_e: i16 = 0;
    let mut tmp32 = basop_util_add_mant32_exp(
        l_mult(sub(n_frame_length, add(n_samples_delta, t0)), freq_start), // Q16
        add(freq_start_e, 31 - 16),
        i32::MIN, // -1.f Q31
        0,
        &mut tmp_e,
    );
    tmp32 = l_shl(tmp32, sub(tmp_e, 31 - 16)); // Q16
    tmp32 = l_add(tmp32, 65536); // 1.f Q16
    let k = extract_h(tmp32);
    if k >= 0 && sub(add(k, 1), NB_PULSES_MAX) <= 0 {
        let mut i_delta_samples = [0i16; PULSES];
        let abs_pitch_diff = l_abs(l_sub(l_deposit_h(rounded_pitch_start), pitch_end)); // Q16

        let max_delta_samples = pulse_resynchronization_delta_samples(
            &mut i_delta_samples,
            k,
            t0,
            n_frame_length,
            rounded_pitch_start,
            freq_start,
            freq_start_e,
            samples_delta,
            samples_delta_e,
            abs_pitch_diff,
            n_samples_delta_remain,
        );

        // Find the location of the minimum energy between the first two pulses
        // iMinPos1 = T0+GetMinimumPosition(src_exc+T0, min(roundedPitchStart,
        //            (nSubframes+1)*nFrameLength/nSubframes-T0), maxDeltaSamples);
        let mut tmp16: i16 = 0;
        let mut tmp_e: i16 = 0;
        basop_util_divide_mant_exp(
            add(n_subframes, 1),
            15,
            n_subframes,
            15,
            &mut tmp16,
            &mut tmp_e,
        );
        let tmp32 = l_mult(n_frame_length, tmp16); // Q16,tmp_e
        tmp16 = round_word(l_shl(tmp32, tmp_e));
        tmp16 = sub(tmp16, t0);
        tmp16 = rounded_pitch_start.min(tmp16);

        let mut i_min_pos1 = get_minimum_position(exc, src + t0 as isize, tmp16, max_delta_samples);
        i_min_pos1 = add(i_min_pos1, t0);

        let geometry = PulseGeometry {
            src,
            dst,
            n_frame_length,
            n_samples_delta,
            rounded_pitch_start,
            t0,
            k,
        };
        if n_samples_delta < 0 {
            pulse_resynchronization_remove(exc, &geometry, i_min_pos1, &mut i_delta_samples);
        } else {
            pulse_resynchronization_add(exc, &geometry, i_min_pos1, &mut i_delta_samples);
        }
    }
}

/// The number of samples to remove (negative) or add over the frame,
/// `0.5·pitchDelta·nFrameLength·(nSubframes+1)·freqStart - nFrameLength·(1 - pitchStart·freqStart)`,
/// as a Q31 mantissa and its exponent.
fn pulse_resynchronization_samples_delta(
    n_frame_length: i16,
    n_subframes: i16,
    pitch_start: i32,
    pitch_end: i32,
    rounded_pitch_start: i16,
    freq_start: i16,
    freq_start_e: i16,
) -> (i32, i16) {
    // pitchDelta*freqStart = ((pitchEnd - pitchStart)/roundedPitchStart)/nSubframes
    let mut tmp16 = shl(rounded_pitch_start, 2); // Q0
    if sub(n_subframes, 5) == 0 {
        tmp16 = add(tmp16, rounded_pitch_start); // tmp16=roundedPitchStart*nSubframes
    }
    let mut tmp_e = norm_s(tmp16);
    tmp16 = shl(tmp16, tmp_e); // Q0,-tmp_e
    tmp_e = sub(15, tmp_e);
    tmp16 = inv16(tmp16, &mut tmp_e); // Q15,tmp_e; tmp16=1.0/(roundedPitchStart*nSubframes)
    let mut tmp32 = l_sub(pitch_end, pitch_start);
    let mut tmp2_e = norm_l(tmp32);
    tmp32 = l_shl(tmp32, tmp2_e); // Q16,-tmp2_e
    tmp32 = mpy_32_16_1(tmp32, tmp16); // Q16,tmp_e-tmp2_e; tmp32=pitchDelta*freqStart
    tmp_e = sub(tmp_e, tmp2_e); // sum up all the scalings for tmp32

    tmp16 = imult1616(n_frame_length, add(n_subframes, 1)); // tmp16=nFrameLength*(nSubframes+1)
    tmp2_e = norm_s(tmp16);
    tmp16 = shl(tmp16, tmp2_e);

    // Q1 scaling (tmp_e-tmp2_e-1), -1 because of 0.5f
    tmp32 = mpy_32_16_1(tmp32, tmp16);
    tmp_e = sub(sub(tmp_e, tmp2_e), 1); // sum up all the scalings for tmp32
    tmp_e = add(tmp_e, 31 - 1); // tmp32 is now regarded as Q31 with scaling tmp_e

    // samplesDelta -= nFrameLength*(1.0f-pitchStart*freqStart);
    tmp2_e = norm_l(pitch_start);
    let mut tmp32_a = l_shl(pitch_start, tmp2_e);
    // Q16, scaling (freqStart_e-tmp2_e); tmp32_a=pitchStart*freqStart
    tmp32_a = mpy_32_16_1(tmp32_a, freq_start);
    let tmp16 = norm_l(tmp32_a);
    tmp32_a = l_shl(tmp32_a, tmp16);
    tmp2_e = sub(sub(freq_start_e, tmp16), tmp2_e); // sum up all scalings for tmp32_a
    tmp2_e = add(tmp2_e, 31 - 16); // tmp32_a is now regarded as Q31 with scaling tmp2_e

    let tmp3_e = tmp2_e;
    tmp32_a = l_negate(tmp32_a);
    tmp32_a = l_add(l_shl(1, sub(31, tmp3_e)), tmp32_a); // Q31,tmp3_e; 1.0f-pitchStart*freqStart
    tmp2_e = norm_s(n_frame_length);
    let tmp16_a = shl(n_frame_length, tmp2_e);
    // Q16,tmp3_e-tmp2_e; tmp32_a= nFrameLength*(1.0f-pitchStart*freqStart)
    tmp32_a = mpy_32_16_1(tmp32_a, tmp16_a);
    tmp2_e = add(sub(tmp3_e, tmp2_e), 15);
    let mut samples_delta_e: i16 = 0;
    let samples_delta = basop_util_add_mant32_exp(
        tmp32,
        tmp_e,
        l_negate(tmp32_a),
        tmp2_e,
        &mut samples_delta_e,
    );
    (samples_delta, samples_delta_e)
}

/// The integer number of samples to add or remove in each of the `k + 2` pitch cycles into
/// `i_delta_samples`; returns the larger of the last two.
fn pulse_resynchronization_delta_samples(
    i_delta_samples: &mut [i16; PULSES],
    k: i16,
    t0: i16,
    n_frame_length: i16,
    rounded_pitch_start: i16,
    freq_start: i16,
    freq_start_e: i16,
    samples_delta: i32,
    samples_delta_e: i16,
    abs_pitch_diff: i32,
    mut n_samples_delta_remain: i16,
) -> i16 {
    // Calculate the delta of the samples to be added/removed between consecutive cycles
    // perCycleDeltaDelta = (absPitchDiff*(nFrameLength-samplesDelta)
    //                       - (float)fabs(samplesDelta)*roundedPitchStart)
    //                      / ((k+1)*(T0+0.5f*k*roundedPitchStart));
    let mut tmp32 = l_sub(
        l_deposit_h(n_frame_length),
        l_shl(samples_delta, sub(samples_delta_e, 31 - 16)),
    ); // Q16
    let mut tmp_e: i16 = 15; // tmp32 = Q31,tmp_e
    let mut tmp2_e = norm_l(tmp32);
    tmp32 = l_shl(tmp32, tmp2_e);
    tmp_e = sub(tmp_e, tmp2_e); // tmp32 = Q31,tmp_e
    tmp2_e = norm_l(abs_pitch_diff);
    let tmp32_b = l_shl(abs_pitch_diff, tmp2_e);
    tmp_e = sub(tmp_e, tmp2_e);
    // Q16,tmp_e; tmp32 = absPitchDiff*(nFrameLength-samplesDelta)
    tmp32 = mpy_32_16_1(tmp32_b, round_word(tmp32));
    // Q16,samplesDelta_e; tmp32_a=fabs(samplesDelta)*roundedPitchStart
    let tmp32_a = mpy_32_16_1(l_abs(samples_delta), rounded_pitch_start);
    // Q31,tmp_e; tmp32=absPitchDiff*(nFrameLength-samplesDelta)
    //                  -fabs(samplesDelta)*roundedPitchStart
    let mut sum_e: i16 = 0;
    tmp32 = basop_util_add_mant32_exp(
        tmp32,
        add(tmp_e, 31 - 16),
        l_negate(tmp32_a),
        add(samples_delta_e, 31 - 16),
        &mut sum_e,
    );
    tmp_e = sum_e;
    // Q0,-1; tmp16=(k+1)*(T0+0.5f*k*roundedPitchStart)
    let tmp16 = imult1616(
        add(k, 1),
        add(shl(t0, 1), imult1616(k, rounded_pitch_start)),
    );
    let mut per_cycle_delta_delta_e: i16 = 0;
    let mut per_cycle_delta_delta =
        basop_util_divide3216_scale(tmp32, tmp16, &mut per_cycle_delta_delta_e); // Q15
    per_cycle_delta_delta_e = add(per_cycle_delta_delta_e, sub(tmp_e, -1 + 15));
    tmp_e = norm_s(per_cycle_delta_delta);
    per_cycle_delta_delta_e = sub(per_cycle_delta_delta_e, tmp_e);
    per_cycle_delta_delta = shl(per_cycle_delta_delta, tmp_e); // Q15,perCycleDeltaDelta_e

    // Calculate the integer number of samples to be added/removed in each pitch cycle
    // cycleDelta = max(0, (absPitchDiff-(k+1)*perCycleDeltaDelta)*T0*freqStart);
    tmp_e = norm_s(add(k, 1));
    // Q0+16, perCycleDeltaDelta_e-tmp_e
    tmp32 = l_mult(per_cycle_delta_delta, shl(add(k, 1), tmp_e));
    let mut sum_e: i16 = 0;
    tmp32 = basop_util_add_mant32_exp(
        abs_pitch_diff,
        31 - 16,
        l_negate(tmp32),
        add(sub(per_cycle_delta_delta_e, tmp_e), 31 - 16),
        &mut sum_e,
    ); // Q31,tmp_e
    tmp_e = sum_e;
    tmp32 = mpy_32_16_1(tmp32, t0); // Q16,tmp_e
    tmp32 = mpy_32_16_1(tmp32, freq_start); // Q16, tmp_e+(freqStart_e)
    tmp32 = tmp32.max(0);
    let mut cycle_delta_e = add(tmp_e, freq_start_e);
    let tmp32_a = l_shl(tmp32, cycle_delta_e);
    let mut rounded_cycle_delta = extract_h(l_abs(tmp32_a));
    if tmp32 < 0 {
        rounded_cycle_delta = negate(rounded_cycle_delta);
    }
    let mut fractional_left = lshr(extract_l(tmp32_a), 1); // Q15
                                                           // cycleDelta in Q15, cycleDelta_e: the reference computes it here and never reads it again
    tmp_e = sub(15, norm_l(tmp32));
    cycle_delta_e = add(cycle_delta_e, tmp_e);
    tmp32 = l_shr(tmp32, sub(tmp_e, 15)); // Q31 frac, cycleDelta_e
    let _cycle_delta = round_word(tmp32);
    let _ = cycle_delta_e;

    i_delta_samples[0] = rounded_cycle_delta; // Q0
    n_samples_delta_remain = sub(n_samples_delta_remain, rounded_cycle_delta); // Q0

    tmp_e = 2i16.max(k);
    tmp_e = norm_s(tmp_e); // maximum norming factor for following loop

    for i in 1..=k {
        let iu = i as usize;
        // cycleDelta = (absPitchDiff-(k+1-i)*perCycleDeltaDelta) + fractionalLeft;
        // Q0+16, perCycleDeltaDelta_e-tmp_e; calcultion of base for first iteration
        let mut tmp32 = l_mult(per_cycle_delta_delta, shl(sub(add(k, 1), i), tmp_e));
        tmp32 = l_shl(tmp32, sub(per_cycle_delta_delta_e, tmp_e)); // Q16
        let tmp32_a = l_sub(abs_pitch_diff, tmp32);
        let tmp32_b = l_lshl(l_deposit_l(fractional_left), 1); // Q16
        let mut cycle_delta32 = l_add(tmp32_a, tmp32_b); // Q16
        cycle_delta32 = cycle_delta32.max(0);

        // Make sure that the number of samples increases
        if l_sub(l_deposit_h(rounded_cycle_delta), cycle_delta32) > 0 {
            i_delta_samples[iu] = rounded_cycle_delta;
            rounded_cycle_delta = extract_h(cycle_delta32);
            i_delta_samples[iu - 1] = rounded_cycle_delta;
        } else {
            rounded_cycle_delta = extract_h(cycle_delta32);
            i_delta_samples[iu] = rounded_cycle_delta;
        }
        // fractionalLeft = cycleDelta-roundedCycleDelta = cycleDelta-(int)cycleDelta;
        fractional_left = lshr(extract_l(cycle_delta32), 1); // Q15
        n_samples_delta_remain = sub(n_samples_delta_remain, rounded_cycle_delta);
    }
    let ku = k as usize;
    i_delta_samples[ku + 1] = n_samples_delta_remain.max(0);
    i_delta_samples[ku].max(i_delta_samples[ku + 1]) // Q0
}

/// What the placement of the minima needs to know about the frame.
struct PulseGeometry {
    src: isize,
    dst: isize,
    n_frame_length: i16,
    n_samples_delta: i16,
    rounded_pitch_start: i16,
    t0: i16,
    k: i16,
}

/// Place the minima and remove `-n_samples_delta` samples there.
fn pulse_resynchronization_remove(
    exc: &mut [i16],
    g: &PulseGeometry,
    i_min_pos1: i16,
    i_delta_samples: &mut [i16; PULSES],
) {
    let (k, rp, t0) = (g.k, g.rounded_pitch_start, g.t0);
    let ku = k as usize;
    let mut i_min_pos = [0i16; PULSES];
    let end = sub(g.n_frame_length, g.n_samples_delta);

    // Find the location of the minimum energy before the first pulse
    if sub(i_min_pos1, add(rp, shr(i_delta_samples[0], 1))) > 0 {
        i_min_pos[0] = sub(i_min_pos1, sub(rp, shr(i_delta_samples[0], 1)));
    } else {
        i_min_pos[0] = sub(
            get_minimum_position(exc, g.src, t0, i_delta_samples[0]),
            shr(i_delta_samples[0], 1),
        );
    }

    // Find the location of the minimum energy between the pulses
    for i in 1..=k {
        let iu = i as usize;
        i_min_pos[iu] = add(
            i_min_pos1,
            sub(imult1616(sub(i, 1), rp), shr(i_delta_samples[iu], 1)),
        );
    }
    // Find the location of the minimum energy after the last pulse
    if sub(
        add(
            i_min_pos1,
            add(
                imult1616(k, rp),
                sub(i_delta_samples[ku + 1], shr(i_delta_samples[ku + 1], 1)),
            ),
        ),
        end,
    ) < 0
    {
        i_min_pos[ku + 1] = add(
            i_min_pos1,
            sub(imult1616(k, rp), shr(i_delta_samples[ku + 1], 1)),
        );
    } else {
        // iMinPos[k+1] = T0+k*roundedPitchStart + GetMinimumPosition(src_exc+T0+k*roundedPitchStart,
        //   nFrameLength-nSamplesDelta-(T0+k*roundedPitchStart), iDeltaSamples[k+1])
        //   - iDeltaSamples[k+1]/2;
        let mut tmp16 = get_minimum_position(
            exc,
            g.src + t0 as isize + k as isize * rp as isize,
            sub(
                g.n_frame_length,
                add(g.n_samples_delta, add(t0, imult1616(k, rp))),
            ),
            i_delta_samples[ku + 1],
        );
        tmp16 = add(add(t0, imult1616(k, rp)), tmp16);
        tmp16 = sub(tmp16, shr(i_delta_samples[ku + 1], 1));
        i_min_pos[ku + 1] = tmp16;
    }

    if sub(add(i_min_pos[ku + 1], i_delta_samples[ku + 1]), end) > 0 {
        // the reference's `+=`: an int addition stored back into the Word16
        i_delta_samples[ku] = (i32::from(i_delta_samples[ku])
            + i32::from(add(i_min_pos[ku + 1], sub(i_delta_samples[ku + 1], end))))
            as i16;
        i_delta_samples[ku + 1] = sub(g.n_frame_length, add(g.n_samples_delta, i_min_pos[ku + 1]));
    }

    // Remove samples at the given positions
    remove_samples(
        exc,
        g.src,
        g.dst,
        g.n_frame_length,
        g.n_samples_delta,
        &i_min_pos,
        i_delta_samples,
        k + 2,
    );
}

/// Place the minima and add `n_samples_delta` samples there.
fn pulse_resynchronization_add(
    exc: &mut [i16],
    g: &PulseGeometry,
    mut i_min_pos1: i16,
    i_delta_samples: &mut [i16; PULSES],
) {
    let (k, rp, t0) = (g.k, g.rounded_pitch_start, g.t0);
    let ku = k as usize;
    let mut i_min_pos = [0i16; PULSES];
    let end = sub(g.n_frame_length, g.n_samples_delta);

    // Find the location of the minimum energy before the first pulse
    if sub(i_min_pos1, rp) > 0 {
        i_min_pos[0] = sub(i_min_pos1, rp);
    } else {
        i_min_pos[0] = get_minimum_position(exc, g.src, t0, i_delta_samples[0]);
    }
    // Find the location of the minimum energy between the pulses
    for position in &mut i_min_pos[1..=ku] {
        *position = i_min_pos1;
        i_min_pos1 = add(i_min_pos1, rp);
    }

    // Find the location of the minimum energy after the last pulse
    if sub(i_min_pos1, end) < 0 {
        i_min_pos[ku + 1] = i_min_pos1;
    } else {
        let mut tmp16 = get_minimum_position(
            exc,
            g.src + t0 as isize + k as isize * rp as isize,
            sub(
                g.n_frame_length,
                add(g.n_samples_delta, add(t0, imult1616(k, rp))),
            ),
            i_delta_samples[ku + 1],
        );
        tmp16 = add(add(tmp16, t0), imult1616(k, rp));
        i_min_pos[ku + 1] = tmp16;
    }

    if sub(add(i_min_pos[ku + 1], i_delta_samples[ku + 1]), end) > 0 {
        i_delta_samples[ku] = add(
            i_delta_samples[ku],
            add(i_min_pos[ku + 1], sub(i_delta_samples[ku + 1], end)),
        );
        i_delta_samples[ku + 1] = sub(end, i_min_pos[ku + 1]);
    }
    // Add samples at the given positions
    add_samples(
        exc,
        g.src,
        g.dst,
        g.n_frame_length,
        g.n_samples_delta,
        &i_min_pos,
        i_delta_samples,
        k + 2,
    );
}

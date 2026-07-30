//! CELT time-frequency resolution decode (RFC 6716 §4.3.1; libopus `tf_decode`, `celt_decoder.c`).
//!
//! **Phase 3b/3d.** Per-band, CELT can trade time resolution for frequency resolution (longer vs
//! shorter effective transform). `tf_decode` reads the per-band change bits (a differential code) and
//! an optional `tf_select` bit from the range coder, then maps them through [`TF_SELECT_TABLE`] to
//! the signed per-band TF adjustment used later by the band decode / inverse MDCT.

use crate::opus::celt::tables::TF_SELECT_TABLE;
use crate::opus::range_coder::{RangeDecoder, RangeEncoder};

/// Encode the per-band time-frequency adjustments and map `tf_res[start..end]` through the
/// selection table in place (libopus `tf_encode`, `celt_encoder.c:756`).
///
/// libopus keeps this separate from `tf_decode` rather than sharing one body, because the two are
/// not mirror images: the encoder differentially codes `tf_res[i] ^ curr` and *overwrites*
/// `tf_res[i]` with `curr` when the budget runs out, whereas the decoder accumulates `curr` from the
/// bits it read. Both then apply the same [`TF_SELECT_TABLE`] mapping. Kept in the same shape here,
/// with the shared mapping tail spelled identically.
pub fn tf_encode(
    start: usize,
    end: usize,
    is_transient: bool,
    tf_res: &mut [i32],
    lm: usize,
    mut tf_select: usize,
    enc: &mut RangeEncoder,
) {
    let it = usize::from(is_transient);
    let mut budget = enc.storage_bits();
    let mut tell = enc.tell() as u32;
    let mut logp: u32 = if is_transient { 2 } else { 4 };
    // Reserve space to code the tf_select decision (`tell+logp+1 <= budget`, spelled without the
    // `+1` so clippy's int_plus_one is satisfied — identical for these unsigned operands).
    let tf_select_rsv = u32::from(lm > 0 && tell + logp < budget);
    budget -= tf_select_rsv;
    let mut curr = 0i32;
    let mut tf_changed = 0i32;
    for slot in tf_res.iter_mut().take(end).skip(start) {
        if tell + logp <= budget {
            enc.enc_bit_logp(*slot ^ curr != 0, logp);
            tell = enc.tell() as u32;
            curr = *slot;
            tf_changed |= curr;
        } else {
            *slot = curr;
        }
        logp = if is_transient { 4 } else { 5 };
    }
    // Only code tf_select if it would actually make a difference.
    if tf_select_rsv != 0
        && TF_SELECT_TABLE[lm][4 * it + tf_changed as usize]
            != TF_SELECT_TABLE[lm][4 * it + 2 + tf_changed as usize]
    {
        enc.enc_bit_logp(tf_select != 0, 1);
    } else {
        tf_select = 0;
    }
    for slot in tf_res.iter_mut().take(end).skip(start) {
        *slot = i32::from(TF_SELECT_TABLE[lm][4 * it + 2 * tf_select + *slot as usize]);
    }
}

/// Decode the per-band time-frequency adjustments into `tf_res[start..end]` (libopus `tf_decode`).
pub fn tf_decode(
    start: usize,
    end: usize,
    is_transient: bool,
    tf_res: &mut [i32],
    lm: usize,
    dec: &mut RangeDecoder,
) {
    let it = usize::from(is_transient);
    let mut budget = dec.storage_bits();
    let mut tell = dec.tell() as u32;
    let mut logp: u32 = if is_transient { 2 } else { 4 };
    let tf_select_rsv: u32 = u32::from(lm > 0 && tell + logp < budget);
    budget -= tf_select_rsv;

    let mut curr: i32 = 0;
    let mut tf_changed: i32 = 0;
    for slot in tf_res.iter_mut().take(end).skip(start) {
        if tell + logp <= budget {
            curr ^= i32::from(dec.dec_bit_logp(logp));
            tell = dec.tell() as u32;
            tf_changed |= curr;
        }
        *slot = curr;
        logp = if is_transient { 4 } else { 5 };
    }

    let mut tf_select = 0usize;
    if tf_select_rsv != 0
        && TF_SELECT_TABLE[lm][4 * it + tf_changed as usize]
            != TF_SELECT_TABLE[lm][4 * it + 2 + tf_changed as usize]
    {
        tf_select = usize::from(dec.dec_bit_logp(1));
    }
    for slot in tf_res.iter_mut().take(end).skip(start) {
        *slot = i32::from(TF_SELECT_TABLE[lm][4 * it + 2 * tf_select + *slot as usize]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::celt::tables::NB_BANDS;
    use crate::opus::range_coder::RangeEncoder;

    /// Mirror of `tf_decode`'s bit stream on the encoder side (with a non-binding budget), returning
    /// the per-band TF result the decoder should produce.
    fn tf_encode(
        start: usize,
        end: usize,
        is_transient: bool,
        changes: &[i32],
        tf_select_bit: bool,
        lm: usize,
        enc: &mut RangeEncoder,
    ) -> Vec<i32> {
        let it = usize::from(is_transient);
        let mut logp: u32 = if is_transient { 2 } else { 4 };
        let mut curr = 0i32;
        let mut tf_changed = 0i32;
        let mut tf_res = vec![0i32; end];
        for i in start..end {
            enc.enc_bit_logp(changes[i] != 0, logp);
            curr ^= changes[i];
            tf_changed |= curr;
            tf_res[i] = curr;
            logp = if is_transient { 4 } else { 5 };
        }
        let tf_select_rsv = lm > 0; // non-binding budget in the test
        let mut tf_select = 0usize;
        if tf_select_rsv
            && TF_SELECT_TABLE[lm][4 * it + tf_changed as usize]
                != TF_SELECT_TABLE[lm][4 * it + 2 + tf_changed as usize]
        {
            enc.enc_bit_logp(tf_select_bit, 1);
            tf_select = usize::from(tf_select_bit);
        }
        for slot in tf_res.iter_mut().take(end).skip(start) {
            *slot = i32::from(TF_SELECT_TABLE[lm][4 * it + 2 * tf_select + *slot as usize]);
        }
        tf_res
    }

    #[test]
    fn tf_decode_matches_mirrored_encoder() {
        for lm in 0..4usize {
            for &is_transient in &[false, true] {
                // A change pattern that flips `curr` (so tf_changed becomes 1 and the tf_select bit
                // path is exercised where the table makes it relevant).
                let changes: Vec<i32> = (0..NB_BANDS)
                    .map(|i| i32::from((i * 5 + 1) % 4 == 0))
                    .collect();
                for &tf_select_bit in &[false, true] {
                    let mut buf = vec![0u8; 1024];
                    let expected = {
                        let mut enc = RangeEncoder::new(&mut buf);
                        let exp = tf_encode(
                            0,
                            NB_BANDS,
                            is_transient,
                            &changes,
                            tf_select_bit,
                            lm,
                            &mut enc,
                        );
                        enc.done();
                        assert!(!enc.error());
                        exp
                    };
                    let mut tf_res = vec![0i32; NB_BANDS];
                    let mut dec = RangeDecoder::new(&buf);
                    tf_decode(0, NB_BANDS, is_transient, &mut tf_res, lm, &mut dec);
                    assert_eq!(
                        tf_res, expected,
                        "lm={lm} transient={is_transient} sel={tf_select_bit}"
                    );
                }
            }
        }
    }
}

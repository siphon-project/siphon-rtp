//! First-stage LPC dequantiser of the variable-rate LPC quantiser (TS 26.442
//! `lib_dec/vlpc_1st_dec.c`).

use crate::evs::cnst::M;
use crate::evs::rom::DICO_LSF_ABS_8B;
use crate::itu::basic_ops::add;

/// `vlpc_1st_dec`: add the first-stage codebook vector `index` (0..256, 8 bits) to `lsfq`
/// (the prediction in, the quantised LSFs out; 14Q1, ×1.28).
pub fn vlpc_1st_dec(index: i16, lsfq: &mut [i16]) {
    // the reference asserts index < 256; a larger one (a corrupted frame) reads zeros
    let base = usize::try_from(index).unwrap_or(0) * M as usize;
    for (i, value) in lsfq.iter_mut().enumerate().take(M as usize) {
        let entry = DICO_LSF_ABS_8B.get(base + i).copied().unwrap_or(0);
        *value = add(*value, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_the_codebook_row_to_the_prediction() {
        let mut lsfq = [100i16; 16];
        vlpc_1st_dec(2, &mut lsfq);
        for i in 0..16 {
            assert_eq!(lsfq[i], 100 + DICO_LSF_ABS_8B[2 * 16 + i]);
        }
    }
}

// Development oracle check: run the Rust LP analysis + perceptual weighting over the same input the
// reference encoder saw, and compare the per-frame factors, normalised LSFs and reflections.
use siphon_rtp_codec::g729::analysis::{
    autocorrelation, lag_window, lp_to_lsp, Levinson, PreProcessor, ORDER, WINDOW,
};
use siphon_rtp_codec::g729::lpcfunc::interpolate_subframe_filters;
use siphon_rtp_codec::g729::weighting::{lsp_to_normalised_lsf, PerceptualWeighting};
fn main() {
    let mut args = std::env::args().skip(1);
    let raw = std::fs::read(args.next().unwrap()).unwrap();
    let want = std::fs::read_to_string(args.next().unwrap()).unwrap();
    let mut pcm = Vec::with_capacity(raw.len() / 2);
    let mut at = 0;
    while at + 1 < raw.len() {
        pcm.push(i16::from_le_bytes([raw[at], raw[at + 1]]));
        at += 2;
    }

    let mut pre = PreProcessor::new();
    let mut buffer = vec![0_i16; WINDOW];
    let mut levinson = Levinson::new();
    let mut weighting = PerceptualWeighting::new();
    let mut previous_lsp: [i16; ORDER] = [
        30000, 26000, 21000, 15000, 8000, 0, -8000, -15000, -21000, -26000,
    ];

    let (mut frames, mut bad_gamma, mut bad_lsf, mut bad_rc) = (0_u32, 0_u32, 0_u32, 0_u32);
    let mut offset = 0;
    for line in want.lines() {
        if offset + 80 > pcm.len() {
            break;
        }
        let w: Vec<i16> = line
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();

        let mut frame: Vec<i16> = pcm[offset..offset + 80].to_vec();
        pre.process(&mut frame);
        buffer[160..240].copy_from_slice(&frame);

        let mut correlations = autocorrelation(&buffer);
        lag_window(&mut correlations);
        let (a, rc) = levinson.solve(&correlations);
        let lsp = lp_to_lsp(&a, &previous_lsp);

        // Int_lpc: the unquantised interpolation, whose midpoint LSPs give the first subframe's LSF.
        let mut midpoint = [0_i16; ORDER];
        for i in 0..ORDER {
            midpoint[i] = (lsp[i] >> 1) + (previous_lsp[i] >> 1);
        }
        let _ = interpolate_subframe_filters(&previous_lsp, &lsp);
        let lsf_int = lsp_to_normalised_lsf(&midpoint);
        let lsf_new = lsp_to_normalised_lsf(&lsp);
        previous_lsp = lsp;

        // The reference dumps these *after* perc_var, which doubles both vectors in place, so the
        // comparison is against the doubled values — `factors` does that doubling internally.
        let doubled_int: Vec<i16> = lsf_int.iter().map(|&v| v.saturating_mul(2)).collect();
        let doubled_new: Vec<i16> = lsf_new.iter().map(|&v| v.saturating_mul(2)).collect();
        if doubled_int != w[4..14] || doubled_new != w[14..24] {
            bad_lsf += 1;
            if bad_lsf <= 2 {
                println!(
                    "frame {frames} lsf_int\n  got  {doubled_int:?}\n  want {:?}",
                    &w[4..14]
                );
            }
        }
        if rc[0] != w[24] || rc[1] != w[25] {
            bad_rc += 1;
            if bad_rc <= 2 {
                println!(
                    "frame {frames} rc: got ({},{}) want ({},{})",
                    rc[0], rc[1], w[24], w[25]
                );
            }
        }

        let factors = weighting.factors(&lsf_int, &lsf_new, &[rc[0], rc[1]]);
        let got = [factors[0].0, factors[0].1, factors[1].0, factors[1].1];
        if got.to_vec() != w[0..4] {
            bad_gamma += 1;
            if bad_gamma <= 2 {
                println!(
                    "frame {frames} gamma\n  got  {got:?}\n  want {:?}",
                    &w[0..4]
                );
            }
        }
        frames += 1;
        offset += 80;
        buffer.copy_within(80.., 0);
    }
    println!("frames {frames}: gamma {bad_gamma}, lsf {bad_lsf}, rc {bad_rc}");
}

// Development oracle check: run the Rust LP analysis over the same input the reference encoder saw
// and compare its per-frame LSPs and A(z) against what the reference produced.
use siphon_rtp_codec::g729::analysis::{
    autocorrelation, lag_window, lp_to_lsp, Levinson, PreProcessor, ORDER, WINDOW,
};
use siphon_rtp_codec::g729::qualsp::LspQuantiser;
fn main() {
    let mut args = std::env::args().skip(1);
    let pcm_bytes = std::fs::read(args.next().unwrap()).unwrap();
    let want = std::fs::read_to_string(args.next().unwrap()).unwrap();
    let mut pcm = Vec::with_capacity(pcm_bytes.len() / 2);
    let mut at = 0;
    while at + 1 < pcm_bytes.len() {
        pcm.push(i16::from_le_bytes([pcm_bytes[at], pcm_bytes[at + 1]]));
        at += 2;
    }

    // The reference pre-processes 40 samples of lookahead before the first frame, then a frame at a
    // time; the analysis window spans the whole 240-sample buffer.
    let mut pre = PreProcessor::new();
    let mut buffer = vec![0_i16; WINDOW];
    let mut levinson = Levinson::new();
    let mut previous_lsp: [i16; ORDER] = [
        30000, 26000, 21000, 15000, 8000, 0, -8000, -15000, -21000, -26000,
    ];

    // Each frame's 80 new samples land at 160..240 and the buffer shifts left by 80 afterwards, so
    // the analysis window trails 160 samples of history. The reference's separate 40-sample
    // lookahead read is behind #ifdef SYNC and was disabled when the vectors were generated.

    let (mut frames, mut bad_lsp, mut bad_a) = (0_u32, 0_u32, 0_u32);
    let mut quantiser = LspQuantiser::new();
    let mut bad_q = 0_u32;
    let quant_want = std::env::var("QLSP")
        .ok()
        .map(|p| std::fs::read_to_string(p).unwrap());
    let mut quant_lines = quant_want.as_deref().map(|t| t.lines());
    let mut lines = want.lines();
    let mut offset = 0;
    while offset + 80 <= pcm.len() {
        let Some(line) = lines.next() else { break };
        let expected: Vec<i16> = line
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();

        let mut frame: Vec<i16> = pcm[offset..offset + 80].to_vec();
        pre.process(&mut frame);
        buffer[160..240].copy_from_slice(&frame);

        if std::env::var("DUMP_WINDOW").is_ok() && frames < 3 {
            println!("frame {frames} window: {:?}", &buffer[..8]);
            println!("frame {frames} window tail: {:?}", &buffer[232..]);
        }
        let mut correlations = autocorrelation(&buffer);
        lag_window(&mut correlations);
        let (a, _rc) = levinson.solve(&correlations);
        let lsp = lp_to_lsp(&a, &previous_lsp);
        previous_lsp = lsp;

        if lsp.to_vec() != expected[..ORDER] {
            bad_lsp += 1;
            if bad_lsp <= 2 {
                println!(
                    "frame {frames} lsp\n  got  {lsp:?}\n  want {:?}",
                    &expected[..ORDER]
                );
            }
        }
        if a.to_vec() != expected[ORDER..ORDER + 11] {
            bad_a += 1;
            if bad_a <= 2 {
                println!(
                    "frame {frames} A(z)\n  got  {a:?}\n  want {:?}",
                    &expected[ORDER..ORDER + 11]
                );
            }
        }
        buffer.copy_within(80.., 0);
        if let Some(lines) = quant_lines.as_mut() {
            if let Some(line) = lines.next() {
                let w: Vec<i32> = line
                    .split_whitespace()
                    .map(|x| x.parse().unwrap())
                    .collect();
                let (s1, s2, q) = quantiser.quantise(&lsp);
                let got: Vec<i32> = std::iter::once(i32::from(s1))
                    .chain(std::iter::once(i32::from(s2)))
                    .chain(q.iter().map(|&v| i32::from(v)))
                    .collect();
                if got != w {
                    bad_q += 1;
                    if bad_q <= 2 {
                        println!("frame {frames} qlsp\n  got  {got:?}\n  want {w:?}");
                    }
                }
            }
        }
        frames += 1;
        offset += 80;
    }
    println!("frames {frames}: lsp mismatches {bad_lsp}, A(z) mismatches {bad_a}, quantiser mismatches {bad_q}");
}

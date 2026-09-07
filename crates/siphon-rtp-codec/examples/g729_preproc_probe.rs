// Isolate pre-processing: feed the raw input through the Rust PreProcessor in the reference's own
// chunking (40 samples of lookahead, then frames of 80) and diff against the reference's output.
use siphon_rtp_codec::g729::analysis::PreProcessor;
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
    // The reference's 40-sample lookahead read sits behind #ifdef SYNC, which its own comment says
    // was disabled when the vectors were generated: it reads frames of 80 from the very start.
    let mut pre = PreProcessor::new();
    let mut offset = 0;
    let (mut frames, mut bad) = (0_u32, 0_u32);
    for line in want.lines() {
        if offset + 80 > pcm.len() {
            break;
        }
        let expected: Vec<i16> = line
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();
        let mut frame: Vec<i16> = pcm[offset..offset + 80].to_vec();
        pre.process(&mut frame);
        if frame != expected {
            bad += 1;
            if bad == 1 {
                let at = frame
                    .iter()
                    .zip(&expected)
                    .position(|(a, b)| a != b)
                    .unwrap();
                println!(
                    "frame {frames} sample {at}: got {} want {}",
                    frame[at], expected[at]
                );
                println!(
                    "  raw in  {:?}",
                    &pcm[offset + at.saturating_sub(2)..offset + at + 3]
                );
                println!("  got     {:?}", &frame[at.saturating_sub(2)..at + 3]);
                println!("  want    {:?}", &expected[at.saturating_sub(2)..at + 3]);
            }
        }
        frames += 1;
        offset += 80;
    }
    println!("frames {frames}, mismatched {bad}");
}

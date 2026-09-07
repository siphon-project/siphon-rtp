// Development oracle check: replay the reference decoder's per-frame parameters through the Rust
// LSP decoder and compare against the LSPs the reference produced for the same frames.
use siphon_rtp_codec::g729::lspdec::LspDecoder;
fn main() {
    let mut args = std::env::args().skip(1);
    let parm = std::fs::read_to_string(args.next().unwrap()).unwrap();
    let lsp = std::fs::read_to_string(args.next().unwrap()).unwrap();
    let mut decoder = LspDecoder::new();
    let (mut frames, mut bad) = (0_u32, 0_u32);
    for (line, want_line) in parm.lines().zip(lsp.lines()) {
        let p: Vec<i32> = line
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();
        let want: Vec<i16> = want_line
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();
        let got = decoder.decode(p[1] as u16, p[2] as u16, p[0] != 0);
        if got.to_vec() != want {
            bad += 1;
            if bad <= 3 {
                println!("frame {frames}\n  got  {got:?}\n  want {want:?}");
            }
        }
        frames += 1;
    }
    println!("frames {frames}, mismatches {bad}");
}

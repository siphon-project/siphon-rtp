// Development oracle check: run the Rust LSP decode + LPC interpolation over the reference's own
// per-frame parameters and compare the resulting A(z) against what the reference computed.
use siphon_rtp_codec::g729::{lpcfunc::interpolate_subframe_filters, lspdec::LspDecoder};
fn main() {
    let mut args = std::env::args().skip(1);
    let parm = std::fs::read_to_string(args.next().unwrap()).unwrap();
    let az = std::fs::read_to_string(args.next().unwrap()).unwrap();
    let mut decoder = LspDecoder::new();
    let mut previous = [30000_i16, 26000, 21000, 15000, 8000, 0, -8000, -15000, -21000, -26000];
    let (mut frames, mut bad) = (0_u32, 0_u32);
    for (line, want_line) in parm.lines().zip(az.lines()) {
        let p: Vec<i32> = line.split_whitespace().map(|x| x.parse().unwrap()).collect();
        let want: Vec<i16> = want_line.split_whitespace().map(|x| x.parse().unwrap()).collect();
        let lsp = decoder.decode(p[1] as u16, p[2] as u16, p[0] != 0);
        let filters = interpolate_subframe_filters(&previous, &lsp);
        previous = lsp;
        let got: Vec<i16> = filters[0].iter().chain(filters[1].iter()).copied().collect();
        if got != want {
            bad += 1;
            if bad <= 2 { println!("frame {frames}\n  got  {got:?}\n  want {want:?}"); }
        }
        frames += 1;
    }
    println!("frames {frames}, mismatches {bad}");
}

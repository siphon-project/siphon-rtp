// Development oracle check: decode a whole ITU serial bitstream with the Rust frame loop and
// compare the pre-postfilter synthesis against the reference's own, frame by frame.
use siphon_rtp_codec::g729::{bitstream::unpack, decoder::Decoder};
fn main() {
    let mut args = std::env::args().skip(1);
    let bits = std::fs::read(args.next().unwrap()).unwrap();
    let want = std::fs::read_to_string(args.next().unwrap()).unwrap();
    let mut decoder = Decoder::new();
    let (mut frames, mut bad, mut first_bad) = (0_u32, 0_u32, None);
    for (index, want_line) in want.lines().enumerate() {
        let chunk = &bits[index * 164..(index + 1) * 164];
        let mut words = Vec::with_capacity(82);
        let mut at = 0;
        while at + 1 < chunk.len() {
            words.push(i16::from_le_bytes([chunk[at], chunk[at + 1]]));
            at += 2;
        }
        // The file format flags an erased frame by zeroing its bit words.
        let erased = words[2..].contains(&0);
        let mut packed = [0u8; 10];
        for (i, &w) in words[2..].iter().enumerate() {
            if w == 0x0081 {
                packed[i / 8] |= 1 << (7 - i % 8);
            }
        }
        let parameters = unpack(&packed).unwrap();
        let (got, _, _) = decoder.decode_frame(if erased { None } else { Some(&parameters) }, 60);
        let expected: Vec<i16> = want_line
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();
        if got.to_vec() != expected {
            bad += 1;
            if first_bad.is_none() {
                let at = got.iter().zip(&expected).position(|(a, b)| a != b).unwrap();
                first_bad = Some((frames, at, got[at], expected[at]));
            }
        }
        frames += 1;
    }
    if let Some((f, at, g, w)) = first_bad {
        println!("first divergence: frame {f} sample {at}: got {g} want {w}");
    }
    println!("frames {frames}, mismatched frames {bad}");
}

// Development oracle check: replay the reference's per-frame parameters through the Rust lag
// decode, fixed codebook and gain decode, comparing against the reference's own per-subframe dump.
use siphon_rtp_codec::g729::excitation::{
    clamp_sharpening, decode_first_lag, decode_second_lag, fixed_codebook, sharpen, GainDecoder,
    PitchLag, PITCH_MAX, SHARP_MIN,
};
fn main() {
    let mut args = std::env::args().skip(1);
    let parm = std::fs::read_to_string(args.next().unwrap()).unwrap();
    let sub = std::fs::read_to_string(args.next().unwrap()).unwrap();
    let mut subs = sub.lines();
    let mut gains = GainDecoder::new();
    let (mut n, mut bad_lag, mut bad_code, mut bad_gain) = (0_u32, 0_u32, 0_u32, 0_u32);
    let (mut old_t0, mut prev_pitch, mut prev_code) = (60_i16, 0_i16, 0_i16);
    let mut sharp = SHARP_MIN;
    for line in parm.lines() {
        let p: Vec<i32> = line
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();
        let (bfi, parity) = (p[0] != 0, p[4] != 0);
        let mut first = PitchLag {
            integer: 0,
            fraction: 0,
        };
        for s in 0..2 {
            let want: Vec<i32> = subs
                .next()
                .unwrap()
                .split_whitespace()
                .map(|x| x.parse().unwrap())
                .collect();
            let (lag_index, pos, sign, gain_index) = if s == 0 {
                (p[3], p[5], p[6], p[7])
            } else {
                (p[8], p[9], p[10], p[11])
            };
            let lag = if (s == 0 && (bfi || parity)) || (s == 1 && bfi) {
                let l = PitchLag {
                    integer: old_t0,
                    fraction: 0,
                };
                old_t0 = (old_t0 + 1).min(PITCH_MAX);
                l
            } else {
                let l = if s == 0 {
                    decode_first_lag(lag_index as u16)
                } else {
                    decode_second_lag(lag_index as u16, first)
                };
                old_t0 = l.integer;
                l
            };
            if s == 0 {
                first = lag;
            }
            if i32::from(lag.integer) != want[0] || i32::from(lag.fraction) != want[1] {
                bad_lag += 1;
                if bad_lag <= 3 {
                    println!("sub {n}: lag {lag:?} want ({},{})", want[0], want[1]);
                }
            }
            if !bfi {
                let mut code = fixed_codebook(sign as u16, pos as u16);
                sharpen(&mut code, lag.integer, sharp);
                let want_code: Vec<i32> = want[4..].to_vec();
                if code.iter().map(|&c| i32::from(c)).collect::<Vec<_>>() != want_code {
                    bad_code += 1;
                    if bad_code <= 2 {
                        println!("sub {n}: code mismatch");
                    }
                }
                let (gp, gc) = gains.decode(gain_index as u16, &code);
                if i32::from(gp) != want[2] || i32::from(gc) != want[3] {
                    bad_gain += 1;
                    if bad_gain <= 3 {
                        println!("sub {n}: gains ({gp},{gc}) want ({},{})", want[2], want[3]);
                    }
                }
                sharp = clamp_sharpening(gp);
                prev_pitch = gp;
                prev_code = gc;
            } else {
                let (gp, gc) = gains.decode_erased(prev_pitch, prev_code);
                if i32::from(gp) != want[2] || i32::from(gc) != want[3] {
                    bad_gain += 1;
                    if bad_gain <= 3 {
                        println!(
                            "sub {n} (erased): gains ({gp},{gc}) want ({},{})",
                            want[2], want[3]
                        );
                    }
                }
                prev_pitch = gp;
                prev_code = gc;
            }
            n += 1;
        }
    }
    println!("subframes {n}: lag mismatches {bad_lag}, code {bad_code}, gain {bad_gain}");
}

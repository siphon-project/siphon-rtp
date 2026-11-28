//! Behaviour the Rust port adds on top of the reference (a guard where the reference would spin or
//! overrun its arrays) and defaults the oracles overwrite before they look at them. No reference
//! output exists for these inputs, so each is asserted directly.

use std::sync::mpsc;
use std::time::Duration;

use siphon_rtp_codec::evs::cnst::{MAXLAG_WI, PIT_MAX};
use siphon_rtp_codec::evs::com::bitallocsum::bitallocsum;
use siphon_rtp_codec::evs::com::modif_fs::modify_fs_intcub3m_sup;
use siphon_rtp_codec::evs::com::wi::{dtfs_new, dtfs_to_fs, dtfs_zero_padd, get_sin_cos_tab};

/// `bitallocsum_fx` spins forever when bits are left over (`v > sum`) and no band has any; the port
/// returns with the sums untouched. A hang is reported as a failure instead of stalling the run.
#[test]
fn bitallocsum_returns_when_bits_are_left_over_and_no_band_has_any() {
    for bits_left in [1i16, 2, 7] {
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let allocation = [0i16; 20];
            let sfmsize = [8i16; 20];
            let mut sum = -7;
            let mut rsubband = [-7i16; 20];
            bitallocsum(
                &allocation,
                20,
                &mut sum,
                &mut rsubband,
                bits_left,
                320,
                &sfmsize,
            );
            let _ = sender.send((sum, rsubband));
        });
        let (sum, rsubband) = receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("bitallocsum did not return with {bits_left} bits left"));
        assert_eq!(sum, 0);
        assert_eq!(rsubband, [0i16; 20]);
    }
}

/// `modify_Fs_intcub3m_sup_fx` recognises its two decimating pairs (12.8 -> 8 kHz, 16 -> 12.8 kHz)
/// and returns `lg * fout / fin` samples. Asserted directly: the reference reads past the `lg + 2`
/// samples it copies to a fresh allocation on these pairs (heap over-read in
/// `lib_com/modif_fs_fx.c`), so an oracle comparison there would pass or fail by heap luck. No caller
/// in the decoder uses these pairs.
#[test]
fn modify_fs_intcub3m_sup_produces_lg_fout_over_fin_samples_on_the_decimating_pairs() {
    for (fin, fout) in [(12800i32, 8000i32), (16000, 12800)] {
        for lg in [40i16, 80, 200] {
            let input: Vec<i16> = (0..2 + lg + 64).map(|n| (n * 97) % 2001 - 1000).collect();
            let mut out = vec![0i16; 4 * 200 + 16];
            let mut delay = -99;
            let lg_out = modify_fs_intcub3m_sup(&input, 2, lg, fin, &mut out, fout, &mut delay);
            assert_eq!(
                i32::from(lg_out),
                i32::from(lg) * fout / fin,
                "{fin} -> {fout}, lg {lg}"
            );
        }
    }
}

/// `DTFS_new_fx` starts a prototype with every field zero except the two cut-offs; `Q` is read
/// before it is first written when a lost frame follows a reset.
#[test]
fn dtfs_new_starts_with_a_zero_q_and_the_default_cut_offs() {
    let dtfs = dtfs_new();
    assert_eq!(dtfs.q, 0);
    assert_eq!(dtfs.lag, 0);
    assert_eq!(dtfs.nh, 0);
    assert_eq!(dtfs.nh_4khz, 0);
    assert_eq!(dtfs.fs, 0);
    assert_eq!(dtfs.upper_cut_off_freq_of_interest, 3300);
    assert_eq!(dtfs.upper_cut_off_freq, 4000);
    assert!(dtfs.a.iter().chain(dtfs.b.iter()).all(|&value| value == 0));
}

/// The prototype arrays hold `MAXLAG_WI` harmonics; a lag of 204 or more (a doubled pitch lag up to
/// `PIT_MAX - 1`) has more, which the reference overruns and the port leaves out.
#[test]
fn dtfs_zero_padd_stays_inside_the_harmonic_arrays_for_long_lags() {
    for target in [204i16, 210, PIT_MAX - 1] {
        let mut dtfs = dtfs_new();
        dtfs.lag = 100;
        dtfs.a.fill(1000);
        dtfs.b.fill(-1000);
        dtfs_zero_padd(target, &mut dtfs);
        assert_eq!(dtfs.lag, target);
        assert!(dtfs.a[..=50].iter().all(|&value| value == 1000));
        assert!(dtfs.a[51..].iter().all(|&value| value == 0));
        assert!(dtfs.b[51..].iter().all(|&value| value == 0));
    }
}

/// An even period of 204 samples or more has its harmonic at pi beyond the arrays; it is skipped.
#[test]
fn dtfs_to_fs_stays_inside_the_harmonic_arrays_for_long_even_periods() {
    let table_len = PIT_MAX as usize * 4 + 1;
    for period in [204i16, 210, PIT_MAX - 1 - ((PIT_MAX - 1) & 1)] {
        let mut sine = vec![0i16; table_len];
        let mut cosine = vec![0i16; table_len];
        get_sin_cos_tab(period, &mut sine, &mut cosine);
        let waveform: Vec<i16> = (0..period).map(|n| ((n * 37) % 2001) - 1000).collect();
        let mut dtfs = dtfs_new();
        dtfs_to_fs(&waveform, period, &mut dtfs, 16000, 0, &sine, &cosine);
        assert_eq!(dtfs.lag, period);
        // the harmonics the arrays hold are filled, the one at pi is not stored
        assert!(dtfs.a[1..MAXLAG_WI as usize]
            .iter()
            .any(|&value| value != 0));
    }
}

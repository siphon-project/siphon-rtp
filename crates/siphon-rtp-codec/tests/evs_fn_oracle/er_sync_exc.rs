//! `lib_dec/er_sync_exc.c` (`PulseResynchronization`, and through it `GetMinimumPosition`,
//! `FindMaxPeak`, `AddSamples`, `RemoveSamples`) against `fn_er_sync_exc`.

use siphon_rtp_codec::evs::dec::er_sync_exc::pulse_resynchronization;

use crate::common::{corpus_sized, mismatch};

#[test]
fn pulse_resynchronization_matches_the_reference() {
    // the tail adjustment of the removal branch (more samples left to remove after the last
    // pulse than there are samples there) is reached by about one case in 1100, so the corpus is
    // large enough to hit it a dozen times
    let Some(cases) = corpus_sized("er_sync_exc", "pulse_resynchronization", 20000) else {
        return;
    };
    let mut changed = 0;
    for case in &cases {
        let mut buf = case.i16s("buf");
        let dst_at = case.i16("dst_at") as usize;
        let l_frame = case.i16("l_frame") as usize;
        let before = buf[dst_at..dst_at + l_frame].to_vec();
        pulse_resynchronization(
            &mut buf,
            case.i16("src_at") as usize,
            dst_at,
            case.i16("l_frame"),
            case.i16("nb_subfr"),
            case.i32("pitch_start"),
            case.i32("pitch_end"),
        );
        if let Some(message) = mismatch(case, "buf", &buf, &case.out_i16s("buf")) {
            panic!("{message}");
        }
        changed += usize::from(buf[dst_at..dst_at + l_frame] != before[..]);
    }
    assert!(changed > cases.len() / 2, "only {changed} resynchronised");
}

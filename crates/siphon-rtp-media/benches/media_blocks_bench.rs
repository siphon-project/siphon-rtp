//! Criterion perf gates for the PlayMedia / PlayDtmf / Subscribe building blocks.
//! `cargo bench -p siphon-rtp-media`.
//!
//! Three per-frame hot paths, each reported as µs/frame (ns where finer):
//!   - player frame pull ([`PcmPlayer::next_frame`]) — the per-tick announcement/MoH cost,
//!   - DTMF payload generation ([`DtmfGenerator::next_payload`]) — per telephone-event packet,
//!   - fork encode + send ([`RtpForkSink`] via [`MediaSink`]) — re-encode one PCM frame → RTP →
//!     bounded channel, the per-frame cost a SIPREC subscriber adds to one decode.
//!
//! No per-frame heap allocation on the player/DTMF paths (caller-owned buffers); the fork copies
//! the finished packet into a `Bytes` for the channel, which is the unavoidable handoff cost.

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_codec::g711::G711;
use siphon_rtp_media::dtmf::{DtmfGenerator, DEFAULT_DTMF_VOLUME_DBM0};
use siphon_rtp_media::fanout::MediaSink;
use siphon_rtp_media::fork::RtpForkSink;
use siphon_rtp_media::player::{PcmPlayer, WavSource};
use siphon_rtp_media::wav::WavRecorder;

/// A 1-second 8 kHz mono WAV source for the player bench.
fn one_second_source() -> WavSource {
    let mut recorder = WavRecorder::new(8000, 1);
    let body: Vec<i16> = (0..8000)
        .map(|index| (index as i16).wrapping_mul(7))
        .collect();
    recorder.write_pcm(&body);
    WavSource::parse(&recorder.into_wav()).expect("parse")
}

fn bench_player_frame_pull(criterion: &mut Criterion) {
    let source = one_second_source();
    let mut frame = [0i16; 160]; // 20 ms @ 8 kHz, caller-owned

    criterion.bench_function("player_next_frame_160", |bencher| {
        // Loop forever so every iteration pulls a real frame (no exhaustion mid-bench).
        let mut player = PcmPlayer::new(&source, u32::MAX, 0);
        bencher.iter(|| {
            let produced = player.next_frame(black_box(&mut frame));
            black_box(produced)
        });
    });
}

fn bench_dtmf_payload_gen(criterion: &mut Criterion) {
    criterion.bench_function("dtmf_next_payload", |bencher| {
        bencher.iter(|| {
            // One full digit burst (5 updates + 3 End) per iteration, '5' for 100 ms @ 8 kHz.
            let mut generator = DtmfGenerator::new('5', 100, DEFAULT_DTMF_VOLUME_DBM0, 8000, 20)
                .expect("generator");
            let mut count = 0usize;
            while let Some(payload) = generator.next_payload() {
                black_box(payload.bytes);
                count += 1;
            }
            black_box(count)
        });
    });
}

fn bench_fork_encode_send(criterion: &mut Criterion) {
    let pcm = [1234i16; 160];

    criterion.bench_function("fork_encode_send_160", |bencher| {
        // A large bounded channel drained each iteration so the send path always succeeds (we are
        // measuring encode + packetize + handoff, not the drop branch).
        let (sender, receiver) = flume::bounded::<Bytes>(1024);
        let mut fork = RtpForkSink::new(Box::new(G711::ulaw()), sender, 0xFEED_BEEF, 0);
        bencher.iter(|| {
            fork.write_pcm(black_box(&pcm));
            // Drain to keep the channel from filling across iterations.
            let _ = receiver.try_recv();
        });
    });
}

criterion_group!(
    benches,
    bench_player_frame_pull,
    bench_dtmf_payload_gen,
    bench_fork_encode_send
);
criterion_main!(benches);

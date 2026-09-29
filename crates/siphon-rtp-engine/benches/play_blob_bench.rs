//! The cost of reading a `play_media` blob off a control frame: once per play command, never per
//! packet. The two rows are the two wire forms the engine accepts for the same 256 KB of audio.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_proto::PlayMediaSource;

fn play_blob_benches(criterion: &mut Criterion) {
    let audio: Vec<u8> = (0..256 * 1024).map(|index| (index % 251) as u8).collect();
    let base64 = serde_json::to_string(&PlayMediaSource::Blob {
        data: audio.clone(),
    })
    .expect("json");
    let array = serde_json::json!({ "source": "blob", "data": audio }).to_string();

    let mut group = criterion.benchmark_group("play_blob_decode_256k");
    group.bench_function("base64", |bencher| {
        bencher
            .iter(|| black_box(serde_json::from_str::<PlayMediaSource>(&base64).expect("parse")));
    });
    group.bench_function("decimal_array", |bencher| {
        bencher.iter(|| black_box(serde_json::from_str::<PlayMediaSource>(&array).expect("parse")));
    });
    group.finish();
}

criterion_group!(benches, play_blob_benches);
criterion_main!(benches);

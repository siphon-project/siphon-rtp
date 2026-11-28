//! Sub-millisecond launch spacing without Tokio timer-wheel quantization.
use super::Error;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

fn deadline(epoch: Instant, index: u64, cps: u32) -> Instant {
    epoch + Duration::from_nanos((u128::from(index) * 1_000_000_000 / u128::from(cps)) as u64)
}
pub struct Pacer {
    pub receiver: mpsc::Receiver<u64>,
    stopped: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}
impl Pacer {
    pub fn new(count: u64, cps: u32) -> Result<Self, Error> {
        let (sender, receiver) = mpsc::channel(1);
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let handle = thread::Builder::new()
            .name("sipload-pace".into())
            .spawn(move || {
                let epoch = Instant::now();
                let spacing = Duration::from_secs_f64(1.0 / f64::from(cps));
                let mut earliest = epoch;
                for index in 0..count {
                    let next = deadline(epoch, index, cps).max(earliest);
                    while Instant::now() < next && !stop.load(Ordering::Relaxed) {
                        thread::park_timeout(next.saturating_duration_since(Instant::now()));
                    }
                    if stop.load(Ordering::Relaxed) || sender.blocking_send(index).is_err() {
                        return;
                    }
                    // A delayed scheduler must not repay accumulated debt as a launch burst.
                    earliest = Instant::now() + spacing / 2;
                }
                // Keep the thread visible to cpu.rs until the final sample has been collected.
                while !stop.load(Ordering::Relaxed) {
                    thread::park();
                }
            })?;
        Ok(Self {
            receiver,
            stopped,
            handle: Some(handle),
        })
    }
}
impl Drop for Pacer {
    fn drop(&mut self) {
        self.receiver.close();
        self.stopped.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deadlines_are_evenly_spaced_without_integer_millisecond_rounding() {
        let epoch = Instant::now();
        assert_eq!(
            deadline(epoch, 1, 1200) - epoch,
            Duration::from_nanos(833_333)
        );
        assert_eq!(deadline(epoch, 1200, 1200) - epoch, Duration::from_secs(1));
    }
    #[tokio::test]
    async fn pacer_emits_every_index_and_shuts_down_on_drop() {
        let mut pacer = Pacer::new(3, 1000).unwrap();
        for index in 0..3 {
            assert_eq!(pacer.receiver.recv().await, Some(index));
        }
        drop(pacer);
    }
}

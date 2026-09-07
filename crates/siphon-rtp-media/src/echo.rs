//! Reporting what the echo canceller's bulk-delay estimator concluded.
//!
//! The echo canceller's failure mode is that it does not have one. GCC-PHAT commits the tallest lag
//! inside its search window whatever that lag is, so an echo that returns from further away than the
//! window reaches does not produce an error, a missing canceller, or an absent estimate — it
//! produces a *lock on noise*, after which the adaptive filter converges against a reference that is
//! not the echo. The canceller keeps running, keeps allocating nothing, and keeps passing audio
//! through, so from the outside "the estimator never located the echo" and "there is no echo on this
//! leg" are the same observation. On a voice-AI bridge the only visible symptom is several layers
//! away and in a different component: an agent that hears itself and barges in on its own voice.
//!
//! [`EchoCanceller::take_delay_report`](siphon_rtp_dsp::EchoCanceller::take_delay_report) is the
//! estimator's own account of what it decided; this module turns one into a log line. It lives here
//! rather than in either caller because both the transcode pipeline (in the engine) and the
//! WebSocket takeover bridge (in this crate) cancel with the same canceller and must say the same
//! thing about it — and `siphon-rtp-dsp` deliberately carries no logging dependency, so a shared
//! home has to be a crate above it that both can see.
//!
//! Edge-triggered at the source: the report is `None` on every frame that did not commit anything,
//! so calling this per frame from the media path costs an `Option` check.

use siphon_rtp_dsp::{DelayLock, DelayReport, WEAK_DELAY_LOCK_CONFIDENCE};

/// Log one [`DelayReport`] against the call and leg it belongs to.
///
/// `leg` names the audio path the canceller sits on, in whatever terms the caller already has — the
/// party (`"a"` / `"b"`) on a transcoded call, the WebSocket `streamId` on a takeover bridge.
///
/// Levels are chosen so that a healthy fleet is silent and an unhealthy one is not:
///
/// * `debug` for a normal lock. The two numbers that matter are the delay *and* the window it was
///   found in — either alone is unactionable, because the question is always whether the window has
///   room left.
/// * `warn` for a lock too flat to be an echo ([`DelayLock::is_weak`]). This is the one that would
///   have turned a day of eliminating the VAD, the prompt, the model and the codec into a first
///   look at the right component, so it names the remedy.
/// * `warn` for an estimator that never committed anything at all, distinguishing a far end that
///   never spoke from one whose audio was never usable.
///
/// A re-align that stays confident is `debug` like any other lock; a path that genuinely moves
/// (a re-INVITE onto a different carrier route) is normal operation, not a fault.
pub fn log_delay_report(report: &DelayReport, call_id: &str, leg: &str) {
    match report {
        DelayReport::Locked(lock) if lock.is_weak() => log_weak_lock(lock, call_id, leg),
        DelayReport::Locked(lock) => {
            tracing::debug!(
                target: "siphon_rtp::media",
                %call_id,
                leg,
                delay_ms = lock.delay_millis(),
                delay_samples = lock.delay_samples,
                search_range_ms = lock.search_range_millis(),
                confidence = lock.confidence,
                first_lock = lock.first_lock,
                at_search_edge = lock.at_search_edge(),
                "echo canceller located the echo path"
            );
            if lock.at_search_edge() {
                // Not a fault: a genuine path can be this long. It is a warning about the *margin* —
                // the estimator found a real echo in the last eighth of the window it was given, so
                // one more carrier hop on this route puts the echo outside it and the canceller
                // silently stops working. Cheaper to say now than to diagnose then.
                tracing::warn!(
                    target: "siphon_rtp::media",
                    %call_id,
                    leg,
                    delay_ms = lock.delay_millis(),
                    search_range_ms = lock.search_range_millis(),
                    "echo delay is near the edge of the search window; a slightly longer path on \
                     this route would fall outside it and go uncancelled — consider raising \
                     echo_delay_search_ms for these legs"
                );
            }
        }
        DelayReport::NeverLocked {
            frames_observed,
            blocks_dropped,
            sample_rate_hz,
        } => {
            // 20 ms frames: the canceller's frame is the media tick by construction.
            let observed_ms = (*frames_observed as u64) * 20;
            tracing::warn!(
                target: "siphon_rtp::media",
                %call_id,
                leg,
                observed_ms,
                frames_observed,
                blocks_dropped,
                sample_rate_hz,
                "echo canceller never located a delay: it has been fed audio this long without \
                 committing an estimate, so nothing on this leg is being cancelled. blocks_dropped \
                 near zero means the far end never played enough to correlate against (no echo to \
                 cancel); a large count means it did and none of it was usable — a permanently \
                 double-talking leg, or a reference that is not what the party actually hears"
            );
        }
    }
}

/// The weak-lock warning — split out only because it is the one line in this module an operator is
/// most likely to read, and it earns its own explanation.
fn log_weak_lock(lock: &DelayLock, call_id: &str, leg: &str) {
    tracing::warn!(
        target: "siphon_rtp::media",
        %call_id,
        leg,
        delay_ms = lock.delay_millis(),
        delay_samples = lock.delay_samples,
        search_range_ms = lock.search_range_millis(),
        confidence = lock.confidence,
        threshold = WEAK_DELAY_LOCK_CONFIDENCE,
        first_lock = lock.first_lock,
        "echo canceller locked on a weak peak: the correlation is too flat to be an echo, so this \
         leg is almost certainly being cancelled against the wrong alignment and the echo is \
         passing through. The usual cause is an echo path longer than the search window — a party \
         behind a carrier or a mobile network puts the whole media path in the loop twice — so \
         raise echo_delay_search_ms on these legs. The alternative reading is that there is genuinely \
         no echo on this leg, in which case the canceller has nothing to do and this is harmless"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lock is classified by its confidence, and only by that — the delay itself carries no
    /// information about whether it is real. Pins the two sides of the threshold, since the whole
    /// reporting surface is worthless if it cannot tell them apart.
    #[test]
    fn a_flat_peak_is_weak_and_a_sharp_one_is_not() {
        let sharp = DelayLock {
            delay_samples: 2_400,
            search_range_samples: 4_096,
            sample_rate_hz: 8_000,
            confidence: 100.0,
            first_lock: true,
        };
        let flat = DelayLock {
            confidence: 4.0,
            ..sharp
        };
        assert!(!sharp.is_weak());
        assert!(flat.is_weak());
        // Same delay, opposite verdicts: confidence is doing all the work.
        assert_eq!(sharp.delay_samples, flat.delay_samples);
    }

    /// The logging entry point must accept every variant without panicking, including with no
    /// subscriber installed (which is how it runs under the zero-allocation gates).
    #[test]
    fn every_report_variant_logs_without_a_subscriber() {
        let lock = DelayLock {
            delay_samples: 800,
            search_range_samples: 4_096,
            sample_rate_hz: 8_000,
            confidence: 60.0,
            first_lock: true,
        };
        log_delay_report(&DelayReport::Locked(lock), "call-1", "a");
        log_delay_report(
            &DelayReport::Locked(DelayLock {
                confidence: 2.0,
                ..lock
            }),
            "call-1",
            "a",
        );
        // In the last eighth of the window: the margin warning, not the weak one.
        log_delay_report(
            &DelayReport::Locked(DelayLock {
                delay_samples: 4_000,
                ..lock
            }),
            "call-1",
            "b",
        );
        log_delay_report(
            &DelayReport::NeverLocked {
                frames_observed: 500,
                blocks_dropped: 12,
                sample_rate_hz: 8_000,
            },
            "call-1",
            "ws-stream-1",
        );
    }
}

//! Reporting what the echo canceller's bulk-delay estimator concluded.
//!
//! The echo canceller only cancels against a delay it has located: GCC-PHAT commits a peak only when
//! it stands clear of the correlation floor, and until one does the leg passes through uncancelled.
//! From the outside that makes "there is no echo on this leg" and "the echo returns from beyond the
//! search window" the same observation, so the estimator's own account of what it found is the only
//! way to tell a leg that is being cancelled from one that is not. On a voice-AI bridge the visible
//! symptom of a window that is too short is several layers away and in a different component: an
//! agent that hears itself and barges in on its own voice.
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

use siphon_rtp_dsp::{DelayReport, WEAK_DELAY_LOCK_CONFIDENCE};

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
/// * `debug` for a search that found no echo ([`DelayReport::NoEchoFound`]). That is the healthy
///   outcome on a line that returns none, so it must not warn on every such call; it still names
///   the window, which is the remedy when the leg does audibly carry echo.
/// * `warn` for an estimator that never had enough usable audio to judge anything, distinguishing
///   a far end that never spoke from one whose audio was never usable.
///
/// A re-align that stays confident is `debug` like any other lock; a path that genuinely moves
/// (a re-INVITE onto a different carrier route) is normal operation, not a fault.
pub fn log_delay_report(report: &DelayReport, call_id: &str, leg: &str) {
    match report {
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
        DelayReport::NoEchoFound {
            best_delay_samples,
            confidence,
            search_range_samples,
            sample_rate_hz,
        } => {
            let rate = u64::from((*sample_rate_hz).max(1));
            tracing::debug!(
                target: "siphon_rtp::media",
                %call_id,
                leg,
                search_range_ms = *search_range_samples as u64 * 1000 / rate,
                best_delay_ms = *best_delay_samples as u64 * 1000 / rate,
                confidence,
                threshold = WEAK_DELAY_LOCK_CONFIDENCE,
                "echo canceller found no echo within its search window, so this leg passes through \
                 uncancelled. Expected on a line that returns no echo; if this leg audibly does carry \
                 echo, its path is longer than the window and echo_delay_search_ms needs raising"
            );
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

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_dsp::DelayLock;

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
            &DelayReport::NoEchoFound {
                best_delay_samples: 3_721,
                confidence: 4.5,
                search_range_samples: 4_096,
                sample_rate_hz: 16_000,
            },
            "call-1",
            "a",
        );
        // A zero rate must not divide by zero while rendering the durations.
        log_delay_report(
            &DelayReport::NoEchoFound {
                best_delay_samples: 1,
                confidence: 1.0,
                search_range_samples: 1,
                sample_rate_hz: 0,
            },
            "call-1",
            "a",
        );
        // In the last eighth of the window: the margin warning.
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

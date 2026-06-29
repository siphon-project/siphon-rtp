//! Graceful-shutdown plumbing for the engine daemon.
//!
//! A single [`Shutdown`] flag is threaded into the control accept loop's `select!` so it stops
//! accepting new connections the moment a termination signal arrives, while in-flight calls are
//! left to drain. [`wait_for_signal`] resolves on the first SIGTERM or SIGINT (Ctrl-C).

use tokio::sync::watch;

/// A cloneable shutdown flag built on a `tokio::watch` channel: the daemon holds the [`Sender`]
/// half and trips it on a signal; the accept loop holds a [`Receiver`] and `select!`s on
/// [`Shutdown::cancelled`] alongside `listener.accept()`.
///
/// [`Sender`]: watch::Sender
/// [`Receiver`]: watch::Receiver
#[derive(Debug, Clone)]
pub struct Shutdown {
    receiver: watch::Receiver<bool>,
}

/// The trigger half of a [`Shutdown`] flag, held by the daemon's main task.
#[derive(Debug)]
pub struct ShutdownTrigger {
    sender: watch::Sender<bool>,
}

/// Create a fresh, un-tripped shutdown flag and its trigger.
#[must_use]
pub fn channel() -> (ShutdownTrigger, Shutdown) {
    let (sender, receiver) = watch::channel(false);
    (ShutdownTrigger { sender }, Shutdown { receiver })
}

impl ShutdownTrigger {
    /// Trip the flag — every [`Shutdown::cancelled`] future then resolves at once.
    pub fn trigger(&self) {
        // A send failure means every receiver was dropped (nothing left to notify) — ignore it.
        let _ = self.sender.send(true);
    }
}

impl Shutdown {
    /// Whether shutdown has already been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Resolve once shutdown is requested. Cancellation-safe: it can be dropped and re-created in a
    /// `select!` arm without losing the signal (the flag is sticky once set).
    pub async fn cancelled(&self) {
        // Already tripped? Return immediately.
        if *self.receiver.borrow() {
            return;
        }
        let mut receiver = self.receiver.clone();
        // Wait for any change; loop until the flag is actually `true` (defensive against spurious
        // wakeups). `changed()` errors only if the sender dropped — treat that as "shutting down".
        while receiver.changed().await.is_ok() {
            if *receiver.borrow() {
                return;
            }
        }
    }
}

/// Resolve on the first termination signal: SIGTERM (`kill`, container stop) or SIGINT (Ctrl-C).
///
/// On non-Unix targets only Ctrl-C is wired (SIGTERM has no portable equivalent), which is enough
/// for local runs; the engine's production target is Linux.
pub async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        // If we cannot install the SIGTERM handler, fall back to Ctrl-C alone rather than aborting.
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = sigterm.recv() => tracing::info!("received SIGTERM"),
                    result = tokio::signal::ctrl_c() => {
                        if result.is_ok() {
                            tracing::info!("received SIGINT (Ctrl-C)");
                        }
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, "could not install SIGTERM handler; waiting on Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("received Ctrl-C");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_resolves_after_trigger() {
        let (trigger, shutdown) = channel();
        assert!(!shutdown.is_cancelled());
        trigger.trigger();
        assert!(shutdown.is_cancelled());
        // Already-tripped: resolves immediately.
        shutdown.cancelled().await;
    }

    #[tokio::test]
    async fn cancelled_wakes_a_waiter() {
        let (trigger, shutdown) = channel();
        let waiter = tokio::spawn(async move { shutdown.cancelled().await });
        // Give the waiter a chance to park, then trip the flag.
        tokio::task::yield_now().await;
        trigger.trigger();
        waiter.await.expect("waiter task joins");
    }

    #[tokio::test]
    async fn clones_share_the_same_flag() {
        let (trigger, shutdown) = channel();
        let clone = shutdown.clone();
        trigger.trigger();
        assert!(shutdown.is_cancelled());
        assert!(clone.is_cancelled());
    }
}

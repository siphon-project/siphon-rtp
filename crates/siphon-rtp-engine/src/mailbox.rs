//! Request/reply with an actor without letting the requester wait forever.
//!
//! The engine reaches a call's media actor and a room's conference actor through a bounded `flume`
//! mailbox, and asks for an answer by putting a `oneshot` sender in the message. Two things can
//! leave that answer pending for good:
//!
//! - **The actor ends while it is still registered.** A room ends itself when its last participant
//!   leaves, and any actor can panic, which tokio turns into a finished task. A flume queue lives as
//!   long as any sender does, and the registry (and the routing table) still holds one, so a
//!   request queued for the dead actor is never dropped and its reply never resolves.
//!   [`ActorInbox`] closes that: it empties the queue when the actor ends, by returning or by
//!   unwinding, which drops every pending reply sender and so answers each requester with "gone".
//! - **The actor is alive but does not get to the request** (stuck in a long step). The requester is
//!   a control command, served on a connection every call shares, so it must not wait on that:
//!   [`actor_reply`] bounds the wait.

use std::time::Duration;

/// How long a control command waits for an actor's answer. An actor serves its mailbox between
/// 20 ms media steps, so a healthy one answers in well under a millisecond; this only ever fires on
/// an actor that is not serving its mailbox at all.
pub(crate) const ACTOR_REPLY_TIMEOUT: Duration = Duration::from_secs(2);

/// An actor's mailbox receiver that empties the mailbox when it is dropped.
///
/// Held by the actor task for its whole life, so the drop runs on every way out of it: a `Stop`, a
/// self-ending room, a closed mailbox, an abort, and a panic unwinding the task. A message sent
/// after the drop fails at the sender (no receiver is left), which callers already treat as "the
/// actor is gone".
pub(crate) struct ActorInbox<T>(flume::Receiver<T>);

impl<T> ActorInbox<T> {
    pub(crate) fn new(receiver: flume::Receiver<T>) -> Self {
        Self(receiver)
    }
}

impl<T> std::ops::Deref for ActorInbox<T> {
    type Target = flume::Receiver<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Drop for ActorInbox<T> {
    fn drop(&mut self) {
        for message in self.0.drain() {
            drop(message);
        }
    }
}

/// Why an actor's answer did not arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ActorReplyError {
    /// The actor ended (or dropped the request) without answering.
    #[error("actor ended without answering")]
    Gone,
    /// The actor did not answer within [`ACTOR_REPLY_TIMEOUT`].
    #[error("actor did not answer within {} ms", ACTOR_REPLY_TIMEOUT.as_millis())]
    TimedOut,
}

/// Wait for an actor's answer, but not past [`ACTOR_REPLY_TIMEOUT`].
pub(crate) async fn actor_reply<T>(
    receiver: tokio::sync::oneshot::Receiver<T>,
) -> Result<T, ActorReplyError> {
    match tokio::time::timeout(ACTOR_REPLY_TIMEOUT, receiver).await {
        Ok(Ok(answer)) => Ok(answer),
        Ok(Err(_)) => Err(ActorReplyError::Gone),
        Err(_) => {
            tracing::warn!(
                target: "siphon_rtp::media",
                timeout_ms = ACTOR_REPLY_TIMEOUT.as_millis() as u64,
                "an actor did not answer a control request in time; the command fails instead of waiting"
            );
            Err(ActorReplyError::TimedOut)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    #[tokio::test]
    async fn a_request_queued_for_an_actor_that_returns_is_answered_gone() {
        let (mailbox, inbox) = flume::bounded::<oneshot::Sender<u8>>(4);
        let (reply, answer) = oneshot::channel();
        mailbox.send(reply).expect("queued");
        let actor = tokio::spawn(async move {
            let _inbox = ActorInbox::new(inbox);
            // Ends without reading, as a room does when its last participant leaves.
        });
        actor.await.expect("actor");
        let outcome = timeout(Duration::from_secs(1), answer)
            .await
            .expect("the reply resolves although the mailbox sender is still held");
        assert!(outcome.is_err(), "answered as gone");
        assert!(
            mailbox.send(oneshot::channel().0).is_err(),
            "a later request fails at once"
        );
    }

    #[tokio::test]
    async fn a_request_queued_for_an_actor_that_panics_is_answered_gone() {
        let (mailbox, inbox) = flume::bounded::<oneshot::Sender<u8>>(4);
        let (reply, answer) = oneshot::channel();
        mailbox.send(reply).expect("queued");
        let actor = tokio::spawn(async move {
            let _inbox = ActorInbox::new(inbox);
            panic!("an actor step panicked");
        });
        assert!(actor.await.is_err(), "the task ended in a panic");
        let outcome = timeout(Duration::from_secs(1), answer)
            .await
            .expect("the reply resolves on the unwind");
        assert!(outcome.is_err());
        drop(mailbox);
    }

    #[tokio::test]
    async fn an_inbox_still_reads_like_the_receiver_it_wraps() {
        let (mailbox, inbox) = flume::bounded::<u8>(4);
        let inbox = ActorInbox::new(inbox);
        mailbox.send(7).expect("queued");
        assert_eq!(inbox.recv_async().await.expect("message"), 7);
    }

    #[tokio::test]
    async fn an_actor_that_never_answers_is_waited_for_only_up_to_the_bound() {
        let (_held, answer) = oneshot::channel::<u8>();
        assert_eq!(actor_reply(answer).await, Err(ActorReplyError::TimedOut));
    }

    #[tokio::test]
    async fn an_answer_and_a_dropped_request_come_back_as_such() {
        let (reply, answer) = oneshot::channel();
        reply.send(3u8).expect("answer");
        assert_eq!(actor_reply(answer).await, Ok(3));
        let (reply, answer) = oneshot::channel::<u8>();
        drop(reply);
        assert_eq!(actor_reply(answer).await, Err(ActorReplyError::Gone));
    }

    #[test]
    fn the_errors_say_what_happened() {
        assert_eq!(
            ActorReplyError::Gone.to_string(),
            "actor ended without answering"
        );
        assert_eq!(
            ActorReplyError::TimedOut.to_string(),
            "actor did not answer within 2000 ms"
        );
    }
}

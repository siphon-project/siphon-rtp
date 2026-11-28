//! UDP retransmission schedules using Tokio's replaceable clock.

use std::time::Duration;
use tokio::time::{sleep_until, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Invite,
    NonInvite,
    Server,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Retransmit,
    Timeout,
}

/// A/B, E/F and 2xx retransmissions (§17.1, §13.3.1.4); completion cancels both clocks.
pub struct Timer {
    kind: Kind,
    interval: Duration,
    next: Instant,
    deadline: Instant,
    retry: bool,
    finished: bool,
}
impl Timer {
    pub fn new(kind: Kind) -> Self {
        let now = Instant::now();
        Self {
            kind,
            interval: Duration::from_millis(500),
            next: now + Duration::from_millis(500),
            deadline: now + Duration::from_secs(32),
            retry: true,
            finished: false,
        }
    }
    pub fn provisional(&mut self) {
        if self.kind == Kind::Invite {
            self.retry = false;
        } else {
            self.interval = Duration::from_secs(4);
            self.next = Instant::now() + self.interval;
        }
    }
    pub fn finish(&mut self) {
        self.finished = true;
    }
    pub async fn wait(&mut self) -> Event {
        if self.finished {
            return std::future::pending().await;
        }
        let wake = if self.retry {
            self.next.min(self.deadline)
        } else {
            self.deadline
        };
        sleep_until(wake).await;
        if Instant::now() >= self.deadline {
            self.finished = true;
            return Event::Timeout;
        }
        self.interval *= 2;
        if self.kind != Kind::Invite {
            self.interval = self.interval.min(Duration::from_secs(4));
        }
        self.next = Instant::now() + self.interval;
        Event::Retransmit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn non_invite_timer_e_caps_at_four_seconds_and_f_expires() {
        let start = Instant::now();
        let mut timer = Timer::new(Kind::NonInvite);
        for milliseconds in [500, 1000, 2000, 4000, 4000, 4000, 4000, 4000, 4000, 4000] {
            let before = Instant::now();
            assert_eq!(timer.wait().await, Event::Retransmit);
            assert_eq!(Instant::now() - before, Duration::from_millis(milliseconds));
        }
        assert_eq!(timer.wait().await, Event::Timeout);
        assert_eq!(Instant::now() - start, Duration::from_secs(32));
    }
    #[tokio::test(start_paused = true)]
    async fn invite_doubles_and_times_out_at_32_seconds() {
        let start = Instant::now();
        let mut timer = Timer::new(Kind::Invite);
        for milliseconds in [500, 1000, 2000, 4000, 8000, 16000] {
            let before = Instant::now();
            assert_eq!(timer.wait().await, Event::Retransmit);
            assert_eq!(Instant::now() - before, Duration::from_millis(milliseconds));
        }
        assert_eq!(timer.wait().await, Event::Timeout);
        assert_eq!(Instant::now() - start, Duration::from_secs(32));
    }
    #[tokio::test(start_paused = true)]
    async fn server_timer_caps_at_t2_and_ack_stops_retransmission() {
        let mut timer = Timer::new(Kind::Server);
        for milliseconds in [500, 1000, 2000, 4000, 4000] {
            let before = Instant::now();
            assert_eq!(timer.wait().await, Event::Retransmit);
            assert_eq!(Instant::now() - before, Duration::from_millis(milliseconds));
        }
        timer.finish();
        assert!(tokio::time::timeout(Duration::from_secs(40), timer.wait())
            .await
            .is_err());
    }
    #[tokio::test(start_paused = true)]
    async fn provisional_stops_invite_retries_but_preserves_deadline() {
        let mut timer = Timer::new(Kind::Invite);
        timer.provisional();
        assert_eq!(timer.wait().await, Event::Timeout);
        let mut timer = Timer::new(Kind::NonInvite);
        timer.provisional();
        let start = Instant::now();
        assert_eq!(timer.wait().await, Event::Retransmit);
        assert_eq!(Instant::now() - start, Duration::from_secs(4));
    }
}

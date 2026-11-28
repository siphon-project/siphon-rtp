//! SIP call and instrumented RTP load generation.
mod call;
mod endpoint;
pub mod media;
mod pacing;
mod registration;
pub mod report;
pub mod runner;
mod wheel;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid run plan: {0}")]
    Plan(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sip(#[from] crate::sip::message::Error),
    #[error("timeout")]
    Timeout,
    #[error("SIP status {0}")]
    Status(u16),
    #[error("media worker stopped unexpectedly")]
    Worker,
    #[error("registration failed for {0}: {1}")]
    Registration(String, String),
    #[error("task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}
#[derive(Debug, Clone)]
pub struct RunPlan {
    pub target: SocketAddrV4,
    pub local: Ipv4Addr,
    pub domain: String,
    pub cps: u32,
    pub duration: Duration,
    pub hold: Duration,
    pub users: usize,
    pub password: String,
    pub uas_base_port: u16,
    pub uac_sockets: usize,
    pub media_sockets: usize,
    pub media_threads: usize,
    pub sip_threads: usize,
    pub media_base_port: u16,
    pub ptime: Duration,
    /// Only for direct UAC → UAS tests; normal runs always register first.
    pub skip_registration: bool,
}
impl RunPlan {
    pub fn validate(&self) -> Result<(), Error> {
        if self.cps == 0
            || self.duration.is_zero()
            || self.users == 0
            || self.uac_sockets == 0
            || self.media_sockets == 0
            || self.media_threads == 0
            || self.sip_threads == 0
            || self.ptime < Duration::from_millis(1)
            || !self.ptime.subsec_nanos().is_multiple_of(1_000_000)
        {
            return Err(Error::Plan("counts and intervals must be positive"));
        }
        if self.users > u16::MAX as usize
            || self.uas_base_port as usize + self.users > u16::MAX as usize
            || self.media_sockets > 32767
            || self.media_base_port as usize + self.media_sockets * 2 > 65536
        {
            return Err(Error::Plan("port range overflow"));
        }
        if self.domain.is_empty() || self.domain.contains(['\r', '\n', ' ', '\t']) {
            return Err(Error::Plan("invalid domain"));
        }
        if self.calls() > u32::MAX as u64 / 2 {
            return Err(Error::Plan("stream identifier space exhausted"));
        }
        Ok(())
    }
    pub fn calls(&self) -> u64 {
        (self.duration.as_secs_f64() * f64::from(self.cps)).floor() as u64
    }
}

pub fn default_media_threads() -> usize {
    (std::thread::available_parallelism().map_or(1, usize::from) / 2).max(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    pub fn plan() -> RunPlan {
        RunPlan {
            target: "127.0.0.1:5101".parse().unwrap(),
            local: Ipv4Addr::LOCALHOST,
            domain: "127.0.0.1".into(),
            cps: 25,
            duration: Duration::from_secs(2),
            hold: Duration::from_secs(1),
            users: 1,
            password: "secret".into(),
            uas_base_port: 5100,
            uac_sockets: 2,
            media_sockets: 2,
            media_threads: 2,
            sip_threads: 4,
            media_base_port: 0,
            ptime: Duration::from_millis(20),
            skip_registration: true,
        }
    }
    #[test]
    fn thread_counts_must_be_positive() {
        let mut plan = plan();
        plan.media_threads = 0;
        assert!(plan.validate().is_err());
        plan.media_threads = 3;
        plan.sip_threads = 0;
        assert!(plan.validate().is_err());
        plan.sip_threads = 2;
        assert!(plan.validate().is_ok());
        assert!(default_media_threads() >= 2);
    }
    #[test]
    fn plan_rejects_zero_and_overflow() {
        let mut plan = plan();
        assert!(plan.validate().is_ok());
        assert_eq!(plan.calls(), 50);
        plan.cps = 0;
        assert!(plan.validate().is_err());
        plan.cps = 1;
        plan.media_base_port = 65535;
        assert!(plan.validate().is_err());
    }
}

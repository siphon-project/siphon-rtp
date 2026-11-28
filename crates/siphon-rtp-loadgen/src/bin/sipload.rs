//! SIP and bidirectional RTP load generator.
#![forbid(unsafe_code)]
use clap::Parser;
use siphon_rtp_loadgen::sipload::{runner, RunPlan};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "siphon-rtp-sipload",
    about = "SIP/UDP calls with instrumented bidirectional RTP"
)]
struct Arguments {
    #[arg(long)]
    target: SocketAddrV4,
    #[arg(long)]
    local: Ipv4Addr,
    #[arg(long)]
    cps: u32,
    #[arg(long)]
    duration: u64,
    #[arg(long)]
    hold: u64,
    #[arg(long)]
    users: usize,
    #[arg(long)]
    password: String,
    #[arg(long)]
    domain: Option<String>,
    #[arg(long, default_value_t = 5100)]
    uas_base_port: u16,
    #[arg(long, default_value_t = 8)]
    uac_sockets: usize,
    #[arg(long, default_value_t = 64)]
    media_sockets: usize,
    #[arg(long, default_value_t = siphon_rtp_loadgen::sipload::default_media_threads())]
    media_threads: usize,
    #[arg(long, default_value_t = 4)]
    sip_threads: usize,
    #[arg(long, default_value_t = 40000)]
    media_base_port: u16,
    #[arg(long, default_value_t = 20)]
    ptime: u64,
    #[arg(long)]
    json: Option<PathBuf>,
    /// Dial the target without registering the callees first. With the target set to a
    /// callee's own port (`--uas-base-port` + 1 for one user), the generator calls itself,
    /// which measures its own cost with no SUT in the path.
    #[arg(long)]
    no_register: bool,
}
impl Arguments {
    fn plan(&self) -> RunPlan {
        RunPlan {
            target: self.target,
            local: self.local,
            domain: self
                .domain
                .clone()
                .unwrap_or_else(|| self.target.ip().to_string()),
            cps: self.cps,
            duration: Duration::from_secs(self.duration),
            hold: Duration::from_secs(self.hold),
            users: self.users,
            password: self.password.clone(),
            uas_base_port: self.uas_base_port,
            uac_sockets: self.uac_sockets,
            media_sockets: self.media_sockets,
            media_threads: self.media_threads,
            sip_threads: self.sip_threads,
            media_base_port: self.media_base_port,
            ptime: Duration::from_millis(self.ptime),
            skip_registration: self.no_register,
        }
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    let result = runner::run(arguments.plan())?;
    print!("{}", result.to_text());
    if let Some(path) = arguments.json {
        std::fs::write(path, serde_json::to_vec_pretty(&result)?)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_defaults_match_the_documented_plan() {
        let command = [
            "sipload",
            "--target",
            "192.0.2.10:5070",
            "--local",
            "192.0.2.20",
            "--cps",
            "300",
            "--duration",
            "30",
            "--hold",
            "10",
            "--users",
            "32",
            "--password",
            "secret",
        ];
        let plan = Arguments::try_parse_from(command).unwrap().plan();
        assert!(plan.validate().is_ok());
        assert_eq!(plan.domain, "192.0.2.10");
        assert_eq!(plan.calls(), 9000);
        assert_eq!(plan.media_sockets, 64);
        assert_eq!(plan.uac_sockets, 8);
        assert_eq!(plan.sip_threads, 4);
        assert_eq!(
            plan.media_threads,
            siphon_rtp_loadgen::sipload::default_media_threads()
        );
        assert!(!plan.skip_registration);
        let overrides = command.into_iter().chain([
            "--media-threads",
            "3",
            "--sip-threads",
            "2",
            "--no-register",
        ]);
        let plan = Arguments::try_parse_from(overrides).unwrap().plan();
        assert_eq!(plan.media_threads, 3);
        assert_eq!(plan.sip_threads, 2);
        assert!(plan.skip_registration);
    }
}

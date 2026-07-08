//! siphon-rtp-engine binary: the default, **UDP-only** media engine daemon.
//!
//! This binary always runs the always-available UDP-loopback datapath — it never depends on the
//! excluded XDP/AF_XDP crate (that lives in the separate `crates/siphon-rtp-xdp` workspace and ships
//! its own `siphon-rtp-xdp-daemon` binary). Everything after datapath construction is the shared,
//! generic runner [`siphon_rtp_engine::run_with_datapath`], so the control server, built-in TURN
//! server, redirect dispatcher, sweeper, and metrics/HEP/NG front-ends are identical across both
//! binaries — only the datapath a binary hands the runner differs.

use clap::{CommandFactory, FromArgMatches, Parser};
use siphon_rtp_engine::config::FileConfig;
use siphon_rtp_engine::daemon::{
    build_udp_datapath, init_tracing, resolve_port_range, run_with_datapath,
};
use siphon_rtp_engine::{EngineArgs, RunConfig};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// siphon-rtp media engine daemon (UDP datapath).
#[derive(Parser, Debug)]
#[command(name = "siphon-rtp-engine", version, about)]
struct Cli {
    #[command(flatten)]
    engine: EngineArgs,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse the CLI via `ArgMatches` (not just the typed struct) so the precedence merge can tell an
    // explicit flag from a defaulted one (`ValueSource::CommandLine`). `matches`/`from_arg_matches`
    // here handle `--help`/`--version`/parse errors exactly as `Cli::parse()` would.
    let matches = Cli::command().get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(error) => error.exit(),
    };

    // Load the optional `--config` TOML file. A missing/malformed file is fatal: fail loudly before
    // the subscriber exists (no tracing yet) rather than starting with a half-applied config.
    let file = match &cli.engine.config {
        Some(path) => match FileConfig::load(path) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("siphon-rtp-engine: {error}");
                std::process::exit(1);
            }
        },
        None => FileConfig::default(),
    };

    // Merge CLI over file over default, once, up front. Everything below reads `config`, not `cli`.
    let config = RunConfig::resolve(cli.engine, &matches, file);
    init_tracing(&config);

    // Optional deterministic media-port range (`--port-min`/`--port-max`). Both-or-neither and
    // min <= max; a half-set or inverted range is a fatal config error (fail loudly, before serving).
    let port_range = match resolve_port_range(config.port_min, config.port_max) {
        Ok(range) => range,
        Err(error) => {
            tracing::error!("{error}");
            std::process::exit(1);
        }
    };

    // The always-available NIC-free backend. Endpoints bind loopback by default; `--relay-bind-ip`
    // binds a routable IP so the relay reaches real peers (docs/security-and-nat.md §11.1). A
    // configured port range draws media ports from a bounded, firewallable window (and enables
    // same-port HA takeover) instead of OS-ephemeral ports.
    let datapath = build_udp_datapath(&config, port_range);
    run_with_datapath(datapath, config).await
}

//! siphon-rtp-engine binary: start the control server over the capability-selected datapath.
//!
//! M1 binds the UDP-loopback backend unconditionally; XDP/AF_XDP selection by capability
//! detection (NET_ADMIN/BPF probe → graceful fallback) lands with the XDP backend.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_engine::{server, Engine};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// siphon-rtp media engine daemon.
#[derive(Parser, Debug)]
#[command(name = "siphon-rtp-engine", version, about)]
struct Args {
    /// JSON-over-TCP control listen address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    control: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();

    // M1: the always-available NIC-free backend. XDP backend slots in behind the same trait.
    let datapath = UdpLoopbackDatapath::new();
    let engine = Arc::new(Engine::new(datapath));

    let listener = TcpListener::bind(args.control).await?;
    tracing::info!(control = %args.control, "siphon-rtp-engine control server listening");

    server::serve(engine, listener).await?;
    Ok(())
}

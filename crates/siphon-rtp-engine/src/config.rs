//! Optional TOML config-file support for the daemon (`--config <PATH>`).
//!
//! rtpengine ships `/etc/rtpengine/rtpengine.conf`; operators expect to configure siphon-rtp
//! declaratively too, instead of assembling a long CLI-arg line in a unit file. This module defines
//! the file schema ([`FileConfig`]) and the precedence rule that merges it with the CLI.
//!
//! # Precedence (highest wins)
//!
//! 1. an **explicit CLI argument** (something the operator actually typed on the command line),
//! 2. the **config file** value (when `--config` was given and the key is set),
//! 3. the built-in **default**.
//!
//! In other words: the file overrides the built-in defaults, and any CLI flag the operator passes
//! overrides the file. "Explicit on the CLI" is detected in `main.rs` via clap's
//! [`clap::parser::ValueSource::CommandLine`], so a flag left at its clap default does *not* mask a
//! file value. Every field in [`FileConfig`] is `Option<_>`, so a config file only needs to set the
//! keys it wants to override; everything else falls through to the default.
//!
//! The two precedence primitives ([`resolve_defaulted`] and [`resolve_optional`]) are pure and
//! unit-tested; the field-by-field wiring lives in `main.rs` next to the `Args` struct.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

/// Failure loading or parsing the `--config` TOML file. Surfaced to the operator as a clear message
/// (never a panic): a missing/unreadable file and a malformed TOML body are distinct variants so the
/// error text points at the real problem.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The config file could not be read (missing, wrong permissions, not a file, …).
    #[error("cannot read config file {path}: {source}")]
    Read {
        /// The path that failed to read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The file was read but its contents are not valid TOML / do not match the schema.
    #[error("invalid config file {path}: {source}")]
    Parse {
        /// The path that failed to parse.
        path: PathBuf,
        /// The underlying TOML deserialization error.
        source: toml::de::Error,
    },
}

/// The on-disk TOML schema for the daemon. Every field is optional: a config file only sets the keys
/// it overrides, and the rest fall through to the CLI default. Field names mirror the CLI long flags
/// (`--relay-bind-ip` → `relay_bind_ip`, …). Unknown keys are rejected so a typo'd key is a loud
/// parse error, not a silently ignored line.
///
/// See `config.example.toml` (next to the crate) for a fully-documented sample.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// JSON-over-TCP control listen address (`--control`).
    pub control: Option<SocketAddr>,
    /// rtpengine NG/bencode control listen address, UDP (`--ng`).
    pub ng: Option<SocketAddr>,
    /// Bind relay/media sockets to this IP instead of loopback (`--relay-bind-ip`).
    pub relay_bind_ip: Option<IpAddr>,
    /// Lowest media port the datapath may bind (`--port-min`). Set together with `port_max` to draw
    /// media ports from a bounded, firewallable range instead of OS-ephemeral ports.
    pub port_min: Option<u16>,
    /// Highest media port the datapath may bind (`--port-max`). Set together with `port_min`.
    pub port_max: Option<u16>,
    /// Prometheus metrics + health HTTP listen address (`--metrics-addr`).
    pub metrics_addr: Option<SocketAddr>,
    /// Per-connection control request cap, requests/second; 0 disables (`--max-control-rps`).
    pub max_control_rps: Option<u64>,
    /// Reap a call after this many seconds with no accepted media (`--media-timeout-secs`).
    pub media_timeout_secs: Option<u64>,
    /// Bounded SIGTERM/SIGINT drain grace period, seconds (`--shutdown-grace-secs`).
    pub shutdown_grace_secs: Option<u64>,
    /// TURN UDP listen address (`--turn-udp`).
    pub turn_udp: Option<SocketAddr>,
    /// TURN TCP listen address (`--turn-tcp`).
    pub turn_tcp: Option<SocketAddr>,
    /// TURN TLS listen address (`--turn-tls`).
    pub turn_tls: Option<SocketAddr>,
    /// PEM certificate-chain file for the `turns:` listener (`--turn-tls-cert`).
    pub turn_tls_cert: Option<PathBuf>,
    /// PEM private-key file for the `turns:` listener (`--turn-tls-key`).
    pub turn_tls_key: Option<PathBuf>,
    /// Public IP to advertise in XOR-RELAYED-ADDRESS (`--turn-relay-ip`).
    pub turn_relay_ip: Option<IpAddr>,
    /// `tracing` env-filter directive used when the process environment does not set one
    /// (`RUST_LOG` / the default-env filter always win over this).
    pub log_filter: Option<String>,
    /// Stable cluster node identifier advertised by the `load` / `node_info` control commands
    /// (`--node-id`). Defaults to the host's `HOSTNAME` (else `siphon-rtp`) when unset.
    pub node_id: Option<String>,
    /// Advertised maximum concurrent sessions for cluster load reporting; `0` = unlimited
    /// (`--max-sessions`). Drives the normalized load score a dispatcher ranks nodes by.
    pub max_sessions: Option<u64>,
    /// NIC to attach the XDP/AF_XDP kernel datapath to (`--xdp-interface`). Acted on **only** by the
    /// separate `siphon-rtp-xdp-daemon` binary (the excluded XDP workspace); the default UDP-only
    /// `siphon-rtp` engine ignores it. Kept here so both binaries share one TOML schema + parser.
    pub xdp_interface: Option<String>,
    /// NIC queue the XDP/AF_XDP socket binds (`--xdp-queue`), default 0. Read **only** by the
    /// `siphon-rtp-xdp-daemon` binary; the default UDP engine ignores it (shared schema, see above).
    pub xdp_queue: Option<u32>,
}

impl FileConfig {
    /// Load and parse the TOML config file at `path`.
    ///
    /// Returns [`ConfigError::Read`] if the file can't be read and [`ConfigError::Parse`] if its
    /// contents are not valid TOML or contain an unknown/mistyped key — never panics.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Parse a TOML string into a [`FileConfig`] (the I/O-free core of [`Self::load`], so tests can
    /// exercise the schema without touching the filesystem).
    pub fn parse_str(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}

/// Resolve one value for a CLI flag that has a built-in default (clap `default_value`/
/// `default_value_t`), applying the module precedence: explicit CLI > file > default.
///
/// * `cli_value` — the value clap produced (may be the default or the operator's).
/// * `cli_explicit` — `true` iff the operator actually passed the flag on the command line
///   (`ValueSource::CommandLine`), so a defaulted value never masks the file.
/// * `file_value` — the config-file value, if any.
/// * `default` — the built-in default to fall back to when neither CLI nor file set the value.
pub fn resolve_defaulted<T>(
    cli_value: T,
    cli_explicit: bool,
    file_value: Option<T>,
    default: T,
) -> T {
    if cli_explicit {
        cli_value
    } else {
        file_value.unwrap_or(default)
    }
}

/// Resolve one value for an optional CLI flag (no built-in default; `None` means "feature off"),
/// applying the module precedence: explicit CLI > file. A flag the operator passed always wins; a
/// flag left unset falls through to the file value (which may itself be `None`).
pub fn resolve_optional<T>(cli_value: Option<T>, file_value: Option<T>) -> Option<T> {
    cli_value.or(file_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// A representative, fully-populated config file deserializes into the expected struct — proves
    /// the field names, types, and address parsing all line up with the CLI.
    #[test]
    fn deserializes_representative_toml_sample() {
        let toml = concat!(
            "control = \"0.0.0.0:8080\"\n",
            "ng = \"0.0.0.0:22222\"\n",
            "relay_bind_ip = \"203.0.113.7\"\n",
            "port_min = 30000\n",
            "port_max = 40000\n",
            "metrics_addr = \"127.0.0.1:9090\"\n",
            "max_control_rps = 500\n",
            "media_timeout_secs = 45\n",
            "shutdown_grace_secs = 30\n",
            "turn_udp = \"0.0.0.0:3478\"\n",
            "turn_tcp = \"0.0.0.0:3478\"\n",
            "turn_tls = \"0.0.0.0:5349\"\n",
            "turn_tls_cert = \"/etc/siphon-rtp/turn.pem\"\n",
            "turn_tls_key = \"/etc/siphon-rtp/turn.key\"\n",
            "turn_relay_ip = \"203.0.113.7\"\n",
            "log_filter = \"info,siphon_rtp_engine=debug\"\n",
            "node_id = \"rtp-ams-3\"\n",
            "max_sessions = 4000\n",
            "xdp_interface = \"eth0\"\n",
            "xdp_queue = 2\n",
        );

        let config = FileConfig::parse_str(toml).expect("valid TOML deserializes");

        assert_eq!(
            config.control,
            Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)))
        );
        assert_eq!(
            config.ng,
            Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 22222)))
        );
        assert_eq!(
            config.relay_bind_ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
        );
        assert_eq!(config.port_min, Some(30000));
        assert_eq!(config.port_max, Some(40000));
        assert_eq!(
            config.metrics_addr,
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9090)))
        );
        assert_eq!(config.max_control_rps, Some(500));
        assert_eq!(config.media_timeout_secs, Some(45));
        assert_eq!(config.shutdown_grace_secs, Some(30));
        assert_eq!(
            config.turn_tls_cert.as_deref(),
            Some(Path::new("/etc/siphon-rtp/turn.pem"))
        );
        assert_eq!(
            config.turn_relay_ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
        );
        assert_eq!(
            config.log_filter.as_deref(),
            Some("info,siphon_rtp_engine=debug")
        );
        assert_eq!(config.node_id.as_deref(), Some("rtp-ams-3"));
        assert_eq!(config.max_sessions, Some(4000));
        assert_eq!(config.xdp_interface.as_deref(), Some("eth0"));
        assert_eq!(config.xdp_queue, Some(2));
    }

    /// An empty file is valid and yields all-`None` (every key falls through to the CLI default).
    #[test]
    fn empty_file_is_all_none() {
        let config = FileConfig::parse_str("").expect("empty TOML is valid");
        assert_eq!(config, FileConfig::default());
    }

    /// A partial file only sets the keys it lists; the rest stay `None`.
    #[test]
    fn partial_file_leaves_unset_keys_none() {
        let config = FileConfig::parse_str("max_control_rps = 1000\n").expect("valid");
        assert_eq!(config.max_control_rps, Some(1000));
        assert_eq!(config.control, None);
        assert_eq!(config.metrics_addr, None);
    }

    /// Precedence for a defaulted flag: explicit CLI beats the file, the file beats the default, and
    /// a defaulted (non-explicit) CLI value never masks the file.
    #[test]
    fn defaulted_precedence_cli_over_file_over_default() {
        // Operator typed `--max-control-rps 900`: CLI wins over the file's 500.
        assert_eq!(resolve_defaulted(900u64, true, Some(500), 300), 900);
        // Operator did not pass the flag: the file's 500 wins over the default 300.
        assert_eq!(resolve_defaulted(300u64, false, Some(500), 300), 500);
        // Neither CLI nor file set it: fall through to the default.
        assert_eq!(resolve_defaulted(300u64, false, None, 300), 300);
    }

    /// Precedence for an optional flag: the CLI value wins; otherwise the file value; else `None`.
    #[test]
    fn optional_precedence_cli_over_file() {
        let cli = Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 1)));
        let file = Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 2)));
        assert_eq!(resolve_optional(cli, file), cli);
        assert_eq!(resolve_optional(None, file), file);
        assert_eq!(resolve_optional::<SocketAddr>(None, None), None);
    }

    /// Malformed TOML is a clean `Err`, never a panic (syntactically broken body).
    #[test]
    fn malformed_toml_is_a_clean_error() {
        let result = FileConfig::parse_str("control = \"not a socket addr\"\n");
        assert!(result.is_err(), "bad socket address must error, not panic");

        let syntax = FileConfig::parse_str("this is not = = toml\n");
        assert!(syntax.is_err(), "broken TOML syntax must error, not panic");
    }

    /// An unknown/mistyped key is rejected (`deny_unknown_fields`) so a config typo is loud.
    #[test]
    fn unknown_key_is_rejected() {
        let result = FileConfig::parse_str("relay_bind_up = \"127.0.0.1\"\n");
        assert!(result.is_err(), "typo'd key must error, not be ignored");
    }

    /// The shipped `config.example.toml` parses against the live schema — guards the example and the
    /// [`FileConfig`] struct from drifting apart (a documented key that no longer exists, or a bad
    /// value, fails here). With every non-`control` key commented out, only `control` is set.
    #[test]
    fn shipped_example_config_parses() {
        let example = include_str!("../config.example.toml");
        let config = FileConfig::parse_str(example).expect("config.example.toml must parse");
        assert_eq!(
            config.control,
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)))
        );
    }

    /// A real on-disk file is read and parsed by [`FileConfig::load`] (the filesystem path, not just
    /// the string core).
    #[test]
    fn loads_from_a_real_file() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(file, "control = \"127.0.0.1:9000\"\nmax_control_rps = 42").expect("write temp");
        let config = FileConfig::load(file.path()).expect("on-disk file loads");
        assert_eq!(
            config.control,
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9000)))
        );
        assert_eq!(config.max_control_rps, Some(42));
    }

    /// A real on-disk file with malformed TOML is a clean [`ConfigError::Parse`], not a panic.
    #[test]
    fn malformed_on_disk_file_yields_parse_error() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(file, "control = = broken").expect("write temp");
        let error = FileConfig::load(file.path()).expect_err("broken file must error");
        assert!(matches!(error, ConfigError::Parse { .. }));
    }

    /// `ConfigError::Read` is produced (not a panic) when the file does not exist, and its `Display`
    /// names the path.
    #[test]
    fn missing_file_yields_read_error() {
        let path = Path::new("/nonexistent/siphon-rtp/does-not-exist.toml");
        let error = FileConfig::load(path).expect_err("missing file must error");
        assert!(matches!(error, ConfigError::Read { .. }));
        assert!(error.to_string().contains("does-not-exist.toml"));
    }
}

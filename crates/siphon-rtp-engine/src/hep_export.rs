//! Where the HEP collector is, as the deployment named it, and how the engine reaches it.
//!
//! The collector is configured as `host:port` in [`COLLECTOR_ENV`]. The host may be a name: a
//! container deployment addresses its collector by service name and has no stable IP to write
//! down. The value is checked at startup and a malformed one is **refused** — a typo that turned
//! export off with one `warn` line left a node running for weeks with nothing reaching the
//! collector and nothing saying so.
//!
//! Resolving the name is a different matter. Telemetry must never decide whether media starts, so
//! a collector that does not resolve *yet* (it starts after the engine, or its DNS record lags)
//! does not stop the engine: the connect is retried until it succeeds, and says so while it waits.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use siphon_rtp_hep::exporter::HepExporter;

/// `host:port` of the HEP collector. Unset or empty leaves export off.
pub const COLLECTOR_ENV: &str = "SIPHON_RTP_HEP_COLLECTOR";
/// The HEP capture-agent id stamped on every capture. Unset means `0`.
pub const AGENT_ID_ENV: &str = "SIPHON_RTP_HEP_AGENT_ID";

/// How long to wait before trying an unreachable collector again.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// The HEP export a deployment asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HepSettings {
    /// The collector's host: a DNS name, or an IP literal (an IPv6 one without its brackets).
    pub host: String,
    pub port: u16,
    pub capture_agent_id: u32,
}

impl HepSettings {
    /// Read the settings from the process environment. `Ok(None)` when no collector is named.
    pub fn from_env() -> Result<Option<Self>, String> {
        Self::parse(
            std::env::var(COLLECTOR_ENV).ok().as_deref(),
            std::env::var(AGENT_ID_ENV).ok().as_deref(),
        )
    }

    /// Check a collector and agent id as written. An unset or empty collector is "export off" (a
    /// compose file that passes the variable through unset hands the process an empty string);
    /// anything else has to be a usable `host:port`, and a set agent id has to be a number.
    pub fn parse(collector: Option<&str>, agent_id: Option<&str>) -> Result<Option<Self>, String> {
        let Some(collector) = collector.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        let (host, port) = split_host_port(collector).ok_or_else(|| {
            format!(
                "{COLLECTOR_ENV}={collector:?} is not a collector address; expected host:port, \
                 e.g. collector.example.net:9060, 192.0.2.10:9060 or [2001:db8::10]:9060"
            )
        })?;
        let capture_agent_id = match agent_id.map(str::trim).filter(|value| !value.is_empty()) {
            None => 0,
            Some(value) => value.parse().map_err(|_| {
                format!(
                    "{AGENT_ID_ENV}={value:?} is not a capture-agent id; expected 0 to 4294967295"
                )
            })?,
        };
        Ok(Some(Self {
            host,
            port,
            capture_agent_id,
        }))
    }
}

/// Split `host:port`, accepting an IP literal (IPv6 in brackets) or a host name. `None` for
/// anything that could not name a collector: no port, port 0, or a host that is not a name.
fn split_host_port(value: &str) -> Option<(String, u16)> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return (address.port() != 0).then(|| (address.ip().to_string(), address.port()));
    }
    let (host, port) = value.rsplit_once(':')?;
    let port: u16 = port.parse().ok().filter(|port| *port != 0)?;
    is_host_name(host).then(|| (host.to_string(), port))
}

/// Whether `host` is a host name in the RFC 1123 §2.1 sense: dot-separated labels of letters,
/// digits and hyphens, none starting or ending with a hyphen, 63 octets a label and 253 in all.
fn is_host_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// Resolve `host:port` through the system resolver, without blocking the runtime.
pub async fn resolve(host: String, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok(tokio::net::lookup_host((host.as_str(), port))
        .await?
        .collect())
}

/// Connect an exporter to the collector, retrying every `retry` until it is reachable.
///
/// The first failure is logged at `error`: a node that was told to export and is not exporting
/// is a fault, and the operator should hear about it once, with the name that failed. Later
/// attempts stay quiet until one succeeds.
pub async fn connect_when_reachable<R, F>(
    settings: &HepSettings,
    resolve: R,
    retry: Duration,
) -> (HepExporter, SocketAddr)
where
    R: Fn(String, u16) -> F,
    F: Future<Output = std::io::Result<Vec<SocketAddr>>>,
{
    let mut reported = false;
    loop {
        let attempt = async {
            let address = resolve(settings.host.clone(), settings.port)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| std::io::Error::other("the name resolved to no address"))?;
            Ok::<_, std::io::Error>((HepExporter::connect(address).await?, address))
        };
        match attempt.await {
            Ok(connected) => return connected,
            Err(error) if !reported => {
                reported = true;
                tracing::error!(
                    %error,
                    host = %settings.host,
                    port = settings.port,
                    retry_seconds = retry.as_secs(),
                    "HEP collector is not reachable; nothing is exported until it is, retrying"
                );
            }
            Err(error) => tracing::debug!(%error, "HEP collector still not reachable"),
        }
        tokio::time::sleep(retry).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn settings(host: &str, port: u16) -> HepSettings {
        HepSettings {
            host: host.to_string(),
            port,
            capture_agent_id: 0,
        }
    }

    #[test]
    fn an_unset_or_empty_collector_leaves_export_off() {
        assert_eq!(HepSettings::parse(None, None), Ok(None));
        assert_eq!(HepSettings::parse(Some(""), Some("2001")), Ok(None));
        assert_eq!(HepSettings::parse(Some("   "), None), Ok(None));
    }

    #[test]
    fn a_collector_is_accepted_by_name() {
        assert_eq!(
            HepSettings::parse(Some("collector.example.net:9060"), None),
            Ok(Some(settings("collector.example.net", 9060)))
        );
        // A single-label service name, as a container network resolves it.
        assert_eq!(
            HepSettings::parse(Some("homer:9060"), None),
            Ok(Some(settings("homer", 9060)))
        );
    }

    #[test]
    fn a_collector_is_accepted_by_address_in_either_family() {
        assert_eq!(
            HepSettings::parse(Some("192.0.2.10:9060"), None),
            Ok(Some(settings("192.0.2.10", 9060)))
        );
        assert_eq!(
            HepSettings::parse(Some("[2001:db8::10]:9060"), None),
            Ok(Some(settings("2001:db8::10", 9060)))
        );
    }

    #[test]
    fn surrounding_whitespace_is_not_part_of_the_value() {
        assert_eq!(
            HepSettings::parse(Some(" homer:9060\n"), Some(" 2001 ")),
            Ok(Some(HepSettings {
                host: "homer".to_string(),
                port: 9060,
                capture_agent_id: 2001,
            }))
        );
    }

    #[test]
    fn a_malformed_collector_is_refused_and_named() {
        for bad in [
            "homer",             // no port
            "homer:",            // empty port
            ":9060",             // no host
            "homer:0",           // port 0 is not a destination
            "192.0.2.10:0",      //
            "homer:65536",       // out of range
            "homer:hep",         // not a number
            "2001:db8::10:9060", // IPv6 without brackets is ambiguous
            "udp://homer:9060",  // a URL, not host:port
            "homer.example.net/:9060",
            "-homer:9060",
            "homer-:9060",
            "ho mer:9060",
            "a..b:9060",
        ] {
            let error =
                HepSettings::parse(Some(bad), None).expect_err(&format!("{bad:?} must be refused"));
            assert!(
                error.contains(COLLECTOR_ENV) && error.contains(bad),
                "the refusal names the variable and the value: {error}"
            );
        }
    }

    #[test]
    fn an_over_long_name_or_label_is_refused() {
        let label = "a".repeat(64);
        assert!(HepSettings::parse(Some(&format!("{label}:9060")), None).is_err());
        let name = ["a".repeat(63).as_str(); 4].join(".");
        assert_eq!(name.len(), 255);
        assert!(HepSettings::parse(Some(&format!("{name}:9060")), None).is_err());
    }

    #[test]
    fn a_bad_agent_id_is_refused_rather_than_read_as_zero() {
        for bad in ["two", "-1", "4294967296", "0x10"] {
            let error = HepSettings::parse(Some("homer:9060"), Some(bad))
                .expect_err(&format!("{bad:?} must be refused"));
            assert!(
                error.contains(AGENT_ID_ENV) && error.contains(bad),
                "the refusal names the variable and the value: {error}"
            );
        }
        assert_eq!(
            HepSettings::parse(Some("homer:9060"), Some("4294967295"))
                .expect("the largest id")
                .expect("export on")
                .capture_agent_id,
            u32::MAX
        );
    }

    #[tokio::test]
    async fn an_address_literal_resolves_to_itself() {
        let resolved = resolve("192.0.2.10".to_string(), 9060)
            .await
            .expect("a literal needs no lookup");
        assert_eq!(resolved, vec![SocketAddr::from(([192, 0, 2, 10], 9060))]);
    }

    #[tokio::test]
    async fn the_exporter_reaches_a_collector_named_by_host() {
        // The collector listens on loopback; the engine is told its name, not its address.
        let collector = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind collector");
        let address = collector.local_addr().expect("collector address");
        let named = settings("collector.example.net", address.port());
        let (exporter, connected) = connect_when_reachable(
            &named,
            |host, port| async move {
                assert_eq!(host, "collector.example.net");
                Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
            },
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(connected, address);
        let capture = siphon_rtp_hep::Capture {
            src: "192.0.2.1:5004".parse().expect("src"),
            dst: "192.0.2.2:5004".parse().expect("dst"),
            timestamp_secs: 0,
            timestamp_micros: 0,
            protocol_type: siphon_rtp_hep::protocol_type::RTCP,
            capture_agent_id: 7,
            correlation_id: Some("call-1".to_string()),
            payload: vec![0x80, 201, 0x00, 0x01, 0, 0, 0, 1],
        };
        let sent = exporter.export(&capture).await.expect("export");
        let mut buffer = [0u8; 2048];
        let (received, _) =
            tokio::time::timeout(Duration::from_secs(1), collector.recv_from(&mut buffer))
                .await
                .expect("the collector receives the capture")
                .expect("recv");
        assert_eq!(received, sent);
        assert_eq!(&buffer[..4], b"HEP3");
    }

    #[tokio::test]
    async fn a_collector_that_does_not_resolve_yet_is_retried_until_it_does() {
        // The collector comes up after the engine. Export must start once the name resolves,
        // without the engine having been restarted.
        let attempts = AtomicUsize::new(0);
        let (_exporter, connected) = connect_when_reachable(
            &settings("homer", 9060),
            |_, port| {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    match attempt {
                        0 => Err(std::io::Error::other("name not known")),
                        1 => Ok(Vec::new()),
                        _ => Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))]),
                    }
                }
            },
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(connected, SocketAddr::from(([127, 0, 0, 1], 9060)));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }
}

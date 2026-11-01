//! The engine's TURN client configuration, credential minting and allocation release.
//!
//! Gathering and the per-tick drive live in `gather.rs` and `sweep.rs`; this module owns what is
//! shared by both: which servers to try, how a username/password is produced for each new
//! allocation, and the one place an allocation is closed.

use std::net::SocketAddr;

use siphon_rtp_datapath::{Datapath, EndpointId};
use siphon_rtp_stun::turn::base64_encode;
use siphon_rtp_stun::turn_client::{TurnAction, TurnCredentials};

use super::Engine;

/// Where relayed ICE candidates are allocated from (RFC 8656), raced, and how the
/// long-term credentials for each allocation are produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnClientConfig {
    /// Candidate servers, raced for every endpoint. The first to grant an allocation wins; the
    /// others are deleted.
    pub servers: Vec<SocketAddr>,
    /// How the credentials are produced.
    pub credentials: TurnCredentialSource,
}

/// Source of the long-term credentials (RFC 8656 §9.2) an allocation authenticates with.
#[derive(Clone, PartialEq, Eq)]
pub enum TurnCredentialSource {
    /// One fixed username and password for every allocation.
    Static {
        /// Long-term-credential username.
        username: String,
        /// Long-term-credential password.
        password: String,
    },
    /// The coturn `use-auth-secret` (TURN REST) profile: every allocation mints a fresh
    /// `<unix expiry>:<identity>` username and the password `base64(HMAC-SHA1(secret, username))`.
    Rest {
        /// The server's `static-auth-secret`.
        secret: String,
        /// Suffix of the username, so the server's logs can tell nodes apart.
        identity: String,
        /// How long past the allocation a username stays valid, in seconds. The username cannot
        /// change during an allocation (RFC 8656 §7.2, 441 Wrong Credentials), so this has to
        /// outlive the longest call; each new allocation mints its own, so it need not outlive
        /// the process.
        ttl_secs: u64,
    },
}

impl std::fmt::Debug for TurnCredentialSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Secrets never reach a log line.
        match self {
            Self::Static { username, .. } => formatter
                .debug_struct("Static")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            Self::Rest {
                identity, ttl_secs, ..
            } => formatter
                .debug_struct("Rest")
                .field("secret", &"<redacted>")
                .field("identity", identity)
                .field("ttl_secs", ttl_secs)
                .finish(),
        }
    }
}

impl TurnCredentialSource {
    /// The credentials for one new allocation made at `unix_now_secs`.
    #[must_use]
    pub fn credentials_at(&self, unix_now_secs: u64) -> TurnCredentials {
        match self {
            Self::Static { username, password } => {
                TurnCredentials::new(username.clone(), password.clone())
            }
            Self::Rest {
                secret,
                identity,
                ttl_secs,
            } => {
                let username = format!("{}:{identity}", unix_now_secs.saturating_add(*ttl_secs));
                let password = base64_encode(&siphon_rtp_stun::hmac_sha1(
                    secret.as_bytes(),
                    username.as_bytes(),
                ));
                TurnCredentials::new(username, password)
            }
        }
    }

    /// The credentials for an allocation made now.
    pub(super) fn credentials_now(&self) -> TurnCredentials {
        let unix_now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        self.credentials_at(unix_now_secs)
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Delete `endpoint`'s TURN allocation, if it has one (RFC 8656 §7.1: a Refresh with
    /// `LIFETIME` 0), so the server frees the relay port now instead of when the lifetime lapses.
    ///
    /// The delete is one datagram sent on the leg's own socket just before it goes away, so it is
    /// not retransmitted: if it is lost the server reclaims the allocation when its lifetime lapses.
    /// A request still in flight does not hold it back, because `close` abandons that request.
    pub(super) async fn release_turn_allocation(&self, endpoint: EndpointId) {
        if let Some(agents) = &self.ice_agents {
            agents.set_turn_server(endpoint, None);
        }
        let Some((_, mut allocation)) = self.ice_relays.remove(&endpoint) else {
            return;
        };
        let server = allocation.client.server();
        allocation.client.close();
        let released = match allocation.client.poll(allocation.last_driven_ms) {
            TurnAction::Send { datagram } => {
                match self.datapath.send(endpoint, server, &datagram).await {
                    Ok(_) => true,
                    Err(error) => {
                        tracing::debug!(
                            target: "siphon_rtp::media",
                            ?endpoint, %server, %error,
                            "failed to transmit a TURN allocation delete"
                        );
                        false
                    }
                }
            }
            TurnAction::Idle => false,
        };
        tracing::debug!(
            target: "siphon_rtp::media",
            ?endpoint, %server, released,
            "TURN allocation released with its endpoint"
        );
    }

    /// Free one media endpoint: its TURN allocation first (the delete needs the socket), then the
    /// endpoint itself. The single funnel every endpoint release goes through, so no teardown path
    /// can leave an allocation refreshing for a leg that no longer exists.
    pub(super) async fn release_endpoint(&self, endpoint: EndpointId) {
        self.release_turn_allocation(endpoint).await;
        self.datapath.remove_endpoint(endpoint).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rest_credentials_follow_the_coturn_derivation() {
        let source = TurnCredentialSource::Rest {
            secret: "static-auth-secret".to_string(),
            identity: "node-a".to_string(),
            ttl_secs: 86_400,
        };
        let credentials = source.credentials_at(1_700_000_000);
        assert_eq!(credentials.username, "1700086400:node-a");
        let expected = base64_encode(&siphon_rtp_stun::hmac_sha1(
            b"static-auth-secret",
            b"1700086400:node-a",
        ));
        assert_eq!(credentials.password, expected);
    }

    #[test]
    fn rest_username_is_fresh_for_every_allocation() {
        let source = TurnCredentialSource::Rest {
            secret: "s".to_string(),
            identity: "n".to_string(),
            ttl_secs: 60,
        };
        assert_ne!(
            source.credentials_at(1_000).username,
            source.credentials_at(1_001).username
        );
    }

    #[test]
    fn static_credentials_are_passed_through() {
        let source = TurnCredentialSource::Static {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        let credentials = source.credentials_at(5);
        assert_eq!(credentials.username, "user");
        assert_eq!(credentials.password, "pass");
    }

    #[test]
    fn debug_output_never_shows_a_secret() {
        let rest = TurnCredentialSource::Rest {
            secret: "hunter2".to_string(),
            identity: "n".to_string(),
            ttl_secs: 1,
        };
        let fixed = TurnCredentialSource::Static {
            username: "u".to_string(),
            password: "hunter3".to_string(),
        };
        assert!(!format!("{rest:?}").contains("hunter2"));
        assert!(!format!("{fixed:?}").contains("hunter3"));
    }
}

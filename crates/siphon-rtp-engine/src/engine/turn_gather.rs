//! Gathering a relayed ICE candidate (RFC 8445 §5.1.1.2, RFC 8656): race the configured TURN
//! servers, UDP and stream alike, and keep the allocation of the first to answer.

use std::io;

use siphon_rtp_datapath::{Datapath, EndpointId, TurnCarrier, TurnRelay};
use siphon_rtp_stun::turn_client::{TurnAction, TurnClient};
use tokio::task::JoinHandle;

use super::gather::{TurnAllocation, GATHER_POLL_INTERVAL_MS};
use super::turn_relay::{TurnServer, TurnTransport};
use super::turn_stream::TurnStream;
use super::Engine;

/// How long a UDP TURN allocation may take before gathering gives up on it, in milliseconds.
/// Matches the STUN gathering deadline's intent: a dead relay costs one bounded delay, never a
/// hung offer.
const TURN_GATHER_DEADLINE_MS: u64 = 1_500;

/// How long a TCP or TLS allocation may take. It has a connect and a TLS handshake in front of the
/// Allocate exchange, which on a path that needs a stream relay at all (a middlebox that blocks UDP)
/// is slower than one datagram round trip.
const TURN_GATHER_STREAM_DEADLINE_MS: u64 = 5_000;

const _: () = assert!(TURN_GATHER_STREAM_DEADLINE_MS > TURN_GATHER_DEADLINE_MS);

/// Local preference of a relayed candidate obtained over TCP (RFC 8445 §5.1.2.2: the preference
/// reflects the protocol used to reach the TURN server, and UDP is the better one, so a pair over a
/// UDP-allocated relay outranks an otherwise equal pair over a stream-allocated one).
const TCP_RELAY_LOCAL_PREFERENCE: u16 = 40_000;

/// Local preference of a relayed candidate obtained over TLS: below TCP, since it is the
/// transport an operator picks when plain TCP is not enough.
const TLS_RELAY_LOCAL_PREFERENCE: u16 = 30_000;

/// A spawned connect that is aborted if it is dropped before it is collected.
struct Connecting(Option<JoinHandle<io::Result<TurnStream>>>);

impl Connecting {
    /// The result, once the connect task has finished.
    async fn poll(&mut self) -> Option<io::Result<TurnStream>> {
        if !self.0.as_ref().is_some_and(JoinHandle::is_finished) {
            return None;
        }
        let handle = self.0.take()?;
        Some(match handle.await {
            Ok(result) => result,
            Err(error) => Err(io::Error::other(error)),
        })
    }
}

impl Drop for Connecting {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// How a contender's requests reach its server.
enum Link {
    /// Datagrams on the endpoint's own socket; replies come back through the gathering queue.
    Datagram,
    /// A stream still being connected.
    Connecting(Connecting),
    /// A live stream.
    Stream(TurnStream),
    /// The stream could not be established.
    Failed,
}

/// One server in the race.
struct Contender {
    server: TurnServer,
    client: TurnClient,
    link: Link,
    /// Millisecond (from the start of the race) after which this contender is given up on.
    deadline_ms: u64,
}

impl Contender {
    fn expired(&self, elapsed_ms: u64) -> bool {
        elapsed_ms >= self.deadline_ms
    }

    /// Still worth driving: not finished, not allocated, not out of time.
    fn is_racing(&self, elapsed_ms: u64) -> bool {
        !self.client.is_terminal() && !self.client.is_allocated() && !self.expired(elapsed_ms)
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Allocate a TURN relay on `endpoint` and turn it into a relayed ICE candidate, or return an
    /// empty list when there is no TURN server configured, the backend cannot relay, or no
    /// configured server grants an allocation inside its gathering deadline.
    ///
    /// Every configured server is raced inside one window, so a dead server costs the offer
    /// nothing; the first to allocate wins and the others are deleted.
    ///
    /// The allocation is **kept** on success (in `ice_relays`): it needs refreshing for the life of
    /// the leg, and each remote candidate needs a permission before it can reach us.
    pub(super) async fn gather_relayed_candidate(
        &self,
        endpoint: EndpointId,
        component: u16,
        events_rx: &flume::Receiver<siphon_rtp_datapath::IceDatapathEvent>,
    ) -> Vec<siphon_rtp_ice::Candidate> {
        let Some(turn) = self.turn_client.clone() else {
            return Vec::new();
        };
        // Never advertise a path this datapath cannot actually carry.
        if !self.datapath.supports_turn_relay() {
            tracing::warn!(
                target: "siphon_rtp::control",
                ?endpoint,
                "a TURN server is configured but this datapath backend cannot relay through an \
                 allocation — not advertising a relayed candidate"
            );
            return Vec::new();
        }
        self.allocate_from_any(endpoint, component, events_rx, &turn)
            .await
            .into_iter()
            .collect()
    }

    /// Send one request from `contender` to its server.
    async fn transmit_request(&self, endpoint: EndpointId, contender: &Contender, datagram: &[u8]) {
        let server = contender.server.address;
        match &contender.link {
            Link::Datagram => {
                if let Err(error) = self.datapath.send(endpoint, server, datagram).await {
                    tracing::debug!(
                        target: "siphon_rtp::control",
                        ?endpoint, %server, %error,
                        "failed to transmit a TURN allocation request"
                    );
                }
            }
            Link::Stream(stream) => {
                if !stream.handle().send(datagram) {
                    tracing::debug!(
                        target: "siphon_rtp::control",
                        ?endpoint, %server,
                        "TURN stream is not accepting the allocation request"
                    );
                }
            }
            Link::Connecting(_) | Link::Failed => {}
        }
    }

    /// Race one [`TurnClient`] per configured server for `endpoint`.
    ///
    /// Datagram replies are demultiplexed from the shared `events_rx` by their source address;
    /// a stream's replies arrive on the stream's own queue. The first client to reach `Allocated`
    /// (in configuration order when several land in one pass) wins. A loser that never answered its
    /// unauthenticated probe is dropped at once: the server only allocates for the authenticated
    /// Allocate, which is sent after the `401` challenge (RFC 8656 §7.2), so it cannot hold
    /// anything. A loser that did answer is driven inside the same window, and if it allocates
    /// anyway it is deleted with a `Refresh` of lifetime 0 (RFC 8656 §7.1) so the server frees the
    /// relay port now.
    async fn allocate_from_any(
        &self,
        endpoint: EndpointId,
        component: u16,
        events_rx: &flume::Receiver<siphon_rtp_datapath::IceDatapathEvent>,
        turn: &super::TurnClientConfig,
    ) -> Option<siphon_rtp_ice::Candidate> {
        let started = tokio::time::Instant::now();
        let elapsed_ms = |start: tokio::time::Instant| start.elapsed().as_millis() as u64;
        let tls = turn
            .tls
            .clone()
            .unwrap_or_else(|| self.ws_tls_client_config());
        // A fresh username per allocation: it cannot change during one (RFC 8656 §7.2), so the
        // credential lifetime only has to cover this allocation.
        let mut contenders: Vec<Contender> = turn
            .servers
            .iter()
            .map(|server| {
                let credentials = turn.credentials.credentials_now();
                if server.transport.is_stream() {
                    let connect = tokio::spawn(TurnStream::connect(
                        server.clone(),
                        tls.clone(),
                        self.datapath.clone(),
                        endpoint,
                    ));
                    Contender {
                        server: server.clone(),
                        client: TurnClient::new_reliable(server.address, credentials),
                        link: Link::Connecting(Connecting(Some(connect))),
                        deadline_ms: TURN_GATHER_STREAM_DEADLINE_MS,
                    }
                } else {
                    Contender {
                        server: server.clone(),
                        client: TurnClient::new(
                            server.address,
                            credentials,
                            siphon_rtp_ice::gather::DEFAULT_RTO_MS,
                        ),
                        link: Link::Datagram,
                        deadline_ms: TURN_GATHER_DEADLINE_MS,
                    }
                }
            })
            .collect();
        // Bounded exactly like STUN gathering: dead TURN servers cost their deadline in total and a
        // host-only candidate list, never a hung offer.
        let winner = loop {
            let now = elapsed_ms(started);
            // Streams that finished connecting become live, or fail.
            for contender in &mut contenders {
                let Link::Connecting(connecting) = &mut contender.link else {
                    continue;
                };
                match connecting.poll().await {
                    None => {}
                    Some(Ok(stream)) => contender.link = Link::Stream(stream),
                    Some(Err(error)) => {
                        tracing::debug!(
                            target: "siphon_rtp::control",
                            ?endpoint, server = %contender.server.address, %error,
                            "TURN stream could not be established"
                        );
                        contender.client.on_transport_closed();
                        contender.link = Link::Failed;
                    }
                }
            }
            // Replies and closes from the streams.
            for contender in &mut contenders {
                if let Link::Stream(stream) = &contender.link {
                    for message in stream.handle().drain_responses() {
                        contender.client.on_datagram(&message, now);
                    }
                    if stream.handle().is_closed() {
                        contender.client.on_transport_closed();
                    }
                }
            }
            let winner = contenders.iter().position(|c| c.client.is_allocated());
            // Once a winner exists, only losers that already answered still need to be resolved.
            let pending = contenders.iter().enumerate().any(|(index, contender)| {
                contender.is_racing(now)
                    && Some(index) != winner
                    && (winner.is_none() || contender.client.is_challenged())
            });
            if !pending {
                break winner;
            }
            for contender in &mut contenders {
                // A stream still connecting has nothing to send yet.
                if !contender.is_racing(now) || matches!(contender.link, Link::Connecting(_)) {
                    continue;
                }
                if let TurnAction::Send { datagram } = contender.client.poll(now) {
                    self.transmit_request(endpoint, contender, &datagram).await;
                }
            }
            match tokio::time::timeout(
                std::time::Duration::from_millis(GATHER_POLL_INTERVAL_MS),
                events_rx.recv_async(),
            )
            .await
            {
                Ok(Ok(event)) => {
                    // Only a datagram server's own packets are an allocation's; a peer's early
                    // check on this endpoint is not, and feeding it in would be uncorrelated noise.
                    if let Some(contender) = contenders.iter_mut().find(|contender| {
                        matches!(contender.link, Link::Datagram)
                            && contender.server.address == event.source
                    }) {
                        contender
                            .client
                            .on_datagram(&event.datagram, elapsed_ms(started));
                    }
                }
                Ok(Err(_)) => {
                    tokio::time::sleep(std::time::Duration::from_millis(GATHER_POLL_INTERVAL_MS))
                        .await;
                }
                Err(_) => {}
            }
        };
        let elapsed = elapsed_ms(started);
        let mut winning = None;
        for (index, mut contender) in contenders.into_iter().enumerate() {
            if Some(index) == winner {
                winning = Some(contender);
                continue;
            }
            let server = contender.server.address;
            // A challenged loser may hold an allocation: either it is up, or its authenticated
            // Allocate is still in flight and the server may yet grant it after we stop listening.
            if contender.client.is_allocated()
                || (contender.client.is_challenged() && !contender.client.is_terminal())
            {
                // RFC 8656 §7.1: free the loser's relay port now rather than at lifetime expiry.
                contender.client.close();
                if let TurnAction::Send { datagram } = contender.client.poll(elapsed) {
                    self.transmit_request(endpoint, &contender, &datagram).await;
                }
                tracing::debug!(
                    target: "siphon_rtp::control",
                    ?endpoint, %server,
                    "TURN allocation raced and lost — deleted"
                );
                // Closed gracefully so the delete above is written before the stream ends.
                if let Link::Stream(stream) = std::mem::replace(&mut contender.link, Link::Failed) {
                    stream.close().await;
                }
            } else if winner.is_none() {
                // Say why, rather than silently shipping a smaller candidate list.
                tracing::warn!(
                    target: "siphon_rtp::control",
                    ?endpoint,
                    %server,
                    state = ?contender.client.state(),
                    elapsed_ms = elapsed,
                    "TURN allocation did not come up — advertising without a relayed candidate from this server"
                );
            }
            // Any other loser holds nothing: its stream and any connect still in flight are
            // aborted by the drop.
        }
        let contender = winning?;
        let Contender {
            server,
            client,
            link,
            ..
        } = contender;
        let relayed_addr = client.relayed_address()?;
        // RFC 8839 §5.1: a relayed candidate carries the mapped address as its related address.
        let mapped = client.mapped_address();
        let stream = match link {
            Link::Stream(stream) => Some(stream),
            _ => None,
        };
        // The allocation is live: install it on the datapath (no channels yet — they arrive as
        // remote candidates are learned) and keep the client for refreshing.
        self.datapath.set_turn_relay(
            endpoint,
            Some(TurnRelay {
                carrier: stream
                    .as_ref()
                    .map_or(TurnCarrier::Udp, |stream| stream.handle().carrier()),
                server: server.address,
                channels: Vec::new(),
                permitted: Vec::new(),
            }),
        );
        if let Some(stream) = &stream {
            // Now that the relay is installed, the server's ChannelData has channels to resolve against.
            stream.handle().activate_relay();
        } else if let Some(agents) = &self.ice_agents {
            // Recorded for the agent whenever it registers: the agent is armed after gathering on
            // every path, so the allocation's responses must be routable without a registered
            // entry. A stream's responses never reach the datapath, so it needs no such route.
            agents.set_turn_server(endpoint, Some(server.address));
        }
        self.ice_relays.insert(
            endpoint,
            TurnAllocation {
                client,
                stream,
                published: Vec::new(),
                published_permitted: Vec::new(),
                last_driven_ms: 0,
            },
        );
        tracing::info!(
            target: "siphon_rtp::control",
            ?endpoint,
            server = %server.address,
            transport = ?server.transport,
            relayed = %relayed_addr,
            "TURN allocation established — advertising a relayed ICE candidate"
        );
        let (local_preference, server_transport) = relay_preference(&server);
        let candidate = siphon_rtp_ice::Candidate {
            foundation: siphon_rtp_ice::Candidate::compute_foundation(
                siphon_rtp_ice::CandidateKind::Relayed,
                relayed_addr.ip(),
                &server_transport,
                Some(server.address),
            ),
            ..siphon_rtp_ice::Candidate::new(
                String::new(),
                component,
                relayed_addr,
                siphon_rtp_ice::CandidateKind::Relayed,
                local_preference,
            )
        };
        Some(match mapped {
            Some(mapped) => candidate.with_related(mapped),
            None => candidate,
        })
    }
}

/// The local preference of a relayed candidate and the transport token its foundation is computed
/// from. RFC 8445 §5.1.1.3 makes the foundation depend on the protocol used to reach the TURN
/// server, so two relays from one server over different transports are different foundations
/// (the candidate itself is a UDP candidate in every case: the relay leg is UDP).
fn relay_preference(server: &TurnServer) -> (u16, siphon_rtp_ice::Transport) {
    match server.transport {
        TurnTransport::Udp => (
            siphon_rtp_ice::gather::DEFAULT_LOCAL_PREFERENCE,
            siphon_rtp_ice::Transport::Udp,
        ),
        TurnTransport::Tcp => (
            TCP_RELAY_LOCAL_PREFERENCE,
            siphon_rtp_ice::Transport::Other("TCP".to_string()),
        ),
        TurnTransport::Tls { .. } => (
            TLS_RELAY_LOCAL_PREFERENCE,
            siphon_rtp_ice::Transport::Other("TLS".to_string()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> std::net::SocketAddr {
        "192.0.2.1:3478".parse().expect("address")
    }

    #[test]
    fn a_stream_relay_ranks_below_a_udp_relay_and_gets_its_own_foundation() {
        let (udp_preference, udp_transport) = relay_preference(&TurnServer::from(address()));
        let (tcp_preference, tcp_transport) = relay_preference(&TurnServer::tcp(address()));
        let (tls_preference, tls_transport) =
            relay_preference(&TurnServer::tls(address(), "turn.example.com"));
        assert!(udp_preference > tcp_preference);
        assert!(tcp_preference > tls_preference);
        let foundation = |transport: &siphon_rtp_ice::Transport| {
            siphon_rtp_ice::Candidate::compute_foundation(
                siphon_rtp_ice::CandidateKind::Relayed,
                address().ip(),
                transport,
                Some(address()),
            )
        };
        let foundations = [
            foundation(&udp_transport),
            foundation(&tcp_transport),
            foundation(&tls_transport),
        ];
        assert_ne!(foundations[0], foundations[1]);
        assert_ne!(foundations[1], foundations[2]);
        assert_ne!(foundations[0], foundations[2]);
    }
}

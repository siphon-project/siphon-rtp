//! One DTLS-SRTP association, driven by the caller.
//!
//! [`DtlsSession`] wraps a sans-I/O [`Endpoint`]: it owns no socket, reads no clock and spawns no
//! task. The caller feeds inbound datagrams to [`DtlsSession::handle_datagram`], drains
//! [`DtlsSession::poll_transmit`] to the peer, and arms a timer from [`DtlsSession::poll_timeout`],
//! calling [`DtlsSession::handle_timeout`] when it fires. After **every** one of those three calls the
//! caller drains `poll_transmit` again and recomputes the deadline: the state machine queues records
//! rather than sending them.
//!
//! # One association, one fixed key
//!
//! An [`Endpoint`] indexes associations by remote address and, as a server, spawns a fresh one for
//! every unseen address. A session therefore addresses its association by a **fixed synthetic key**
//! and passes that key for every operation, whatever address the datagram actually came from. Two
//! consequences, both deliberate:
//!
//! - An ICE re-point (RFC 8445 §12.1.1 moves where we *send*) cannot start a second handshake, and
//!   the association survives the move. Where bytes go is the caller's business, not the session's.
//! - The session can no longer tell sources apart, so **the caller must gate the source and demux
//!   before calling in** (see the crate-level caller contract). The fingerprint check still stops an
//!   impersonator from completing a handshake, but not from making us do the work.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use rtc_dtls::config::{ClientAuthType, ConfigBuilder, HandshakeConfig};
use rtc_dtls::endpoint::{Endpoint, EndpointEvent};
use rtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use rtc_shared::TransportProtocol;
use siphon_rtp_srtp::leg::SecureLeg;

use crate::handshake::{derive_keying, verify_peer, DtlsRole, SrtpKeying};
use crate::{DtlsCertificate, DtlsError, Fingerprint};

/// The association's fixed identity. RFC 5737 documentation addresses, never routed and never
/// compared against anything real — the caller owns addressing. The port is non-zero because
/// `Endpoint::connect` rejects port 0.
const ASSOCIATION_LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 1);
const ASSOCIATION_REMOTE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 1);

/// What a session reports to its caller.
#[non_exhaustive]
#[derive(Debug)]
pub enum DtlsEvent {
    /// The handshake completed, the peer's certificate matched the signalled fingerprint (RFC 5763
    /// §5) and the SRTP keying material has been derived. Read it with [`DtlsSession::keying`] or
    /// [`DtlsSession::into_secure_leg`] — the event carries no secret.
    Keyed,
    /// Decrypted DTLS application data. A DTLS-SRTP leg carries none (media rides SRTP beside the
    /// association, RFC 5764), so the engine logs and drops it.
    ApplicationData(Bytes),
}

/// One DTLS-SRTP association.
pub struct DtlsSession {
    endpoint: Endpoint,
    role: DtlsRole,
    expected_peer_fingerprint: Fingerprint,
    config: Arc<HandshakeConfig>,
    keying: Option<SrtpKeying>,
    started: bool,
    failed: bool,
}

impl DtlsSession {
    /// Build a session for `role`, authenticating the peer against `expected_peer_fingerprint`.
    ///
    /// `retransmit_interval` is the initial RFC 6347 §4.2.4 retransmission timeout the state machine
    /// arms; the caller drives it through [`Self::poll_timeout`].
    pub fn new(
        certificate: &DtlsCertificate,
        role: DtlsRole,
        expected_peer_fingerprint: Fingerprint,
        retransmit_interval: Duration,
    ) -> Result<Self, DtlsError> {
        let config = build_handshake_config(certificate, role, retransmit_interval)?;
        // A server needs its config up front (it answers an inbound ClientHello); a client passes
        // the config to `connect` instead.
        let server_config = (role == DtlsRole::Server).then(|| config.clone());
        Ok(Self {
            endpoint: Endpoint::new(ASSOCIATION_LOCAL, TransportProtocol::UDP, server_config),
            role,
            expected_peer_fingerprint,
            config,
            keying: None,
            started: false,
            failed: false,
        })
    }

    /// As DTLS **client**, emit the first flight; drain [`Self::poll_transmit`] afterwards. A server
    /// session is driven entirely by [`Self::handle_datagram`], so this is a no-op for it.
    /// Idempotent: calling it again never starts a second handshake.
    pub fn start(&mut self, now: Instant) -> Result<(), DtlsError> {
        if self.failed {
            return Err(DtlsError::Closed);
        }
        if self.started || self.role == DtlsRole::Server {
            return Ok(());
        }
        self.started = true;
        self.endpoint
            .connect(now, ASSOCIATION_REMOTE, self.config.clone(), None)
            .map_err(|error| self.fail(&error.to_string()))
    }

    /// Feed one inbound DTLS datagram. The caller must have gated its source and confirmed it is a
    /// DTLS record (RFC 7983 §7) first.
    pub fn handle_datagram(
        &mut self,
        now: Instant,
        datagram: &[u8],
    ) -> Result<Vec<DtlsEvent>, DtlsError> {
        if self.failed {
            return Err(DtlsError::Closed);
        }
        self.started = true;
        let raw = self
            .endpoint
            .read(now, ASSOCIATION_REMOTE, None, BytesMut::from(datagram))
            .map_err(|error| self.fail(&error.to_string()))?;

        let mut events = Vec::with_capacity(raw.len());
        for event in raw {
            match event {
                EndpointEvent::HandshakeComplete => {
                    if let Some(keyed) = self.on_handshake_complete()? {
                        events.push(keyed);
                    }
                }
                EndpointEvent::ApplicationData(data) => {
                    events.push(DtlsEvent::ApplicationData(data.freeze()));
                }
                _ => {}
            }
        }
        Ok(events)
    }

    /// The next datagram to send to the peer, if any. Drain to `None` after every call that advances
    /// the session.
    pub fn poll_transmit(&mut self) -> Option<Bytes> {
        self.endpoint
            .poll_transmit()
            .map(|transmit| transmit.message.freeze())
    }

    /// When the association next needs [`Self::handle_timeout`], or `None` when no timer is pending.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.endpoint.poll_timeout(&ASSOCIATION_REMOTE)
    }

    /// Fire the retransmission timer. Drain [`Self::poll_transmit`] afterwards.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsError> {
        if self.failed {
            return Err(DtlsError::Closed);
        }
        self.endpoint
            .handle_timeout(ASSOCIATION_REMOTE, now)
            .map_err(|error| self.fail(&error.to_string()))
    }

    /// The derived SRTP keying material, once the handshake has completed and the peer verified.
    #[must_use]
    pub fn keying(&self) -> Option<&SrtpKeying> {
        self.keying.as_ref()
    }

    /// Whether this session has keyed.
    #[must_use]
    pub fn is_keyed(&self) -> bool {
        self.keying.is_some()
    }

    /// Consume the session for its keyed [`SecureLeg`].
    #[must_use]
    pub fn into_secure_leg(self) -> Option<SecureLeg> {
        self.keying.map(SrtpKeying::into_secure_leg)
    }

    /// Verify the peer and derive keying on completion. Returns `None` when the session has already
    /// keyed: a *second* completion is possible once we answer a retransmitted last flight
    /// (RFC 6347 §4.2.4), and re-keying would reset the SRTP contexts and their rollover counters
    /// mid-call (RFC 3711 §3.3.1).
    fn on_handshake_complete(&mut self) -> Result<Option<DtlsEvent>, DtlsError> {
        if self.keying.is_some() {
            return Ok(None);
        }
        let state = self
            .endpoint
            .get_connection_state(ASSOCIATION_REMOTE)
            .ok_or_else(|| DtlsError::Handshake("association vanished on completion".to_owned()))?;
        verify_peer(state, &self.expected_peer_fingerprint)?;
        let keying = derive_keying(state, self.role)?;
        self.keying = Some(keying);
        Ok(Some(DtlsEvent::Keyed))
    }

    /// Mark the session dead so later calls report [`DtlsError::Closed`] rather than re-entering a
    /// state machine that has already errored, and return the error to report for *this* call.
    fn fail(&mut self, reason: &str) -> DtlsError {
        self.failed = true;
        DtlsError::Handshake(reason.to_owned())
    }
}

/// Build the handshake config for `role`. DTLS-SRTP's trust anchor is the SDP fingerprint, so chain
/// verification is skipped here and the fingerprint is checked on completion (RFC 5763 §5).
fn build_handshake_config(
    certificate: &DtlsCertificate,
    role: DtlsRole,
    retransmit_interval: Duration,
) -> Result<Arc<HandshakeConfig>, DtlsError> {
    let is_client = role == DtlsRole::Client;
    let mut builder = ConfigBuilder::default()
        // The same provider that imported this certificate's private key, or the key it signs with
        // and the one it was parsed by disagree.
        .with_crypto_provider(certificate.provider())
        .with_certificates(vec![certificate.inner()])
        .with_srtp_protection_profiles(vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80])
        .with_insecure_skip_verify(true)
        // Otherwise the builder derives a server name from the remote address, which would put the
        // synthetic association key into the ClientHello SNI.
        .with_server_name("siphon-rtp".to_owned())
        .with_flight_interval(retransmit_interval);
    if !is_client {
        // As the DTLS server we MUST request the peer's certificate or there is nothing to check the
        // fingerprint against (the default is `NoClientCert`). It is not chain-verified — the
        // fingerprint is the authenticator — so `RequireAnyClientCert`, which also stays below the
        // threshold at which the builder demands a rustls verifier.
        builder = builder.with_client_auth(ClientAuthType::RequireAnyClientCert);
    }
    builder
        .build(is_client, None)
        .map(Arc::new)
        .map_err(|error| DtlsError::Certificate(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 6347 §4.2.4 initial retransmission timeout these tests arm. Short and explicit so a
    /// test can step past it with an offset rather than sleeping.
    const RETRANSMIT: Duration = Duration::from_millis(100);

    /// A client/server pair that trust each other's fingerprints.
    fn pair() -> (DtlsSession, DtlsSession) {
        let client_certificate = DtlsCertificate::generate().expect("client certificate");
        let server_certificate = DtlsCertificate::generate().expect("server certificate");
        let client = DtlsSession::new(
            &client_certificate,
            DtlsRole::Client,
            server_certificate.fingerprint(),
            RETRANSMIT,
        )
        .expect("client session");
        let server = DtlsSession::new(
            &server_certificate,
            DtlsRole::Server,
            client_certificate.fingerprint(),
            RETRANSMIT,
        )
        .expect("server session");
        (client, server)
    }

    /// Move every queued datagram from `source` to `destination`, returning what it reported.
    fn transfer(
        now: Instant,
        source: &mut DtlsSession,
        destination: &mut DtlsSession,
    ) -> Vec<DtlsEvent> {
        let mut events = Vec::new();
        while let Some(record) = source.poll_transmit() {
            events.extend(
                destination
                    .handle_datagram(now, &record)
                    .expect("peer accepts the record"),
            );
        }
        events
    }

    /// Drive both sides to completion, or panic. Returns nothing: the sessions carry the keying.
    fn complete(now: Instant, client: &mut DtlsSession, server: &mut DtlsSession) {
        client.start(now).expect("client first flight");
        for _ in 0..32 {
            transfer(now, client, server);
            transfer(now, server, client);
            if client.is_keyed() && server.is_keyed() {
                return;
            }
        }
        panic!("the handshake did not complete");
    }

    #[test]
    fn a_loopback_handshake_keys_both_sides_interoperably() {
        let now = Instant::now();
        let (mut client, mut server) = pair();
        complete(now, &mut client, &mut server);

        // Each side encrypts with its own write key and decrypts with the peer's, so a packet
        // protected by one unprotects on the other (RFC 5764 §4.2).
        let mut client_leg = client.into_secure_leg().expect("client keyed");
        let mut server_leg = server.into_secure_leg().expect("server keyed");
        let packet = rtp(7, 0x0A0A_0A0A);

        let mut sealed = Vec::new();
        client_leg
            .protect(&packet, &mut sealed)
            .expect("client protects");
        let mut opened = Vec::new();
        server_leg
            .unprotect(&sealed, &mut opened)
            .expect("server unprotects what the client sealed");
        assert_eq!(opened, packet);

        let mut sealed = Vec::new();
        server_leg
            .protect(&packet, &mut sealed)
            .expect("server protects");
        let mut opened = Vec::new();
        client_leg
            .unprotect(&sealed, &mut opened)
            .expect("client unprotects what the server sealed");
        assert_eq!(opened, packet);
    }

    #[test]
    fn a_wrong_peer_fingerprint_aborts_the_handshake() {
        // RFC 5763 §5: the fingerprint is the trust anchor, so a peer whose certificate does not
        // hash to the signalled value is rejected even though the DTLS handshake itself succeeds.
        let now = Instant::now();
        let client_certificate = DtlsCertificate::generate().expect("client certificate");
        let server_certificate = DtlsCertificate::generate().expect("server certificate");
        let impostor = DtlsCertificate::generate().expect("impostor certificate");

        let mut client = DtlsSession::new(
            &client_certificate,
            DtlsRole::Client,
            // The client is told to expect somebody else's certificate.
            impostor.fingerprint(),
            RETRANSMIT,
        )
        .expect("client session");
        let mut server = DtlsSession::new(
            &server_certificate,
            DtlsRole::Server,
            client_certificate.fingerprint(),
            RETRANSMIT,
        )
        .expect("server session");

        client.start(now).expect("client first flight");
        let mut rejected = false;
        for _ in 0..32 {
            while let Some(record) = client.poll_transmit() {
                let _ = server.handle_datagram(now, &record);
            }
            while let Some(record) = server.poll_transmit() {
                match client.handle_datagram(now, &record) {
                    Err(DtlsError::FingerprintMismatch) => rejected = true,
                    Err(other) => panic!("unexpected error: {other}"),
                    Ok(_) => {}
                }
            }
            if rejected {
                break;
            }
        }
        assert!(
            rejected,
            "the client rejects a certificate it did not expect"
        );
        assert!(!client.is_keyed(), "and derives no keys from it");
    }

    #[test]
    fn a_completed_server_retransmits_its_last_flight_when_the_client_repeats_its_own() {
        // RFC 6347 §4.2.4: the last-flight sender cannot know its flight arrived, so when the peer
        // repeats its own final flight, ours must be sent again. Losing flight 6 without this leaves
        // the peer retransmitting until it gives up while we believe the leg is keyed — a call that
        // is up and silent. Passes only against the patched rtc-dtls (webrtc-rs/rtc#243).
        let now = Instant::now();
        let (mut client, mut server) = pair();
        client.start(now).expect("client first flight");

        // Drive until the server keys; its last flight is queued at that point, not yet taken.
        let mut server_keyed = false;
        for _ in 0..32 {
            for event in transfer(now, &mut client, &mut server) {
                server_keyed |= matches!(event, DtlsEvent::Keyed);
            }
            if server_keyed {
                break;
            }
            transfer(now, &mut server, &mut client);
        }
        assert!(server_keyed, "the server never keyed");

        // Lose it: drain the server's queued flight and deliver none of it.
        let mut lost = 0usize;
        while server.poll_transmit().is_some() {
            lost += 1;
        }
        assert!(lost > 0, "the server had a last flight to lose");
        assert!(!client.is_keyed(), "so the client cannot have completed");

        // The client is waiting for that flight with its retransmit timer armed.
        let deadline = client
            .poll_timeout()
            .expect("a client waiting for the last flight arms a retransmit timer");
        client.handle_timeout(deadline).expect("client retransmits");

        // Its repeated flight reaches the server, which owes it a fresh last flight.
        let mut retransmitted = 0usize;
        while let Some(record) = client.poll_transmit() {
            retransmitted += 1;
            server
                .handle_datagram(deadline, &record)
                .expect("server accepts the repeat");
        }
        assert!(retransmitted > 0, "the client repeated its own flight");

        // Capture the whole flight rather than testing for one record and dropping it: flight 6 is
        // ChangeCipherSpec *and* Finished, so consuming the first to prove it exists would hand the
        // client half a flight and it could never complete.
        let mut resent = Vec::new();
        while let Some(record) = server.poll_transmit() {
            resent.push(record);
        }
        assert!(
            !resent.is_empty(),
            "a completed server must retransmit its last flight when the peer repeats its own"
        );

        // And delivering it recovers the call: the client completes.
        for record in resent {
            client
                .handle_datagram(deadline, &record)
                .expect("client accepts the retransmitted flight");
        }
        assert!(
            client.is_keyed(),
            "the client completes on the retransmission"
        );
    }

    #[test]
    fn a_second_completion_never_re_keys() {
        // Answering a retransmitted last flight can report completion twice. Re-deriving would reset
        // the SRTP contexts and their rollover counters mid-call (RFC 3711 §3.3.1), so the session
        // keys exactly once.
        let now = Instant::now();
        let (mut client, mut server) = pair();
        complete(now, &mut client, &mut server);

        assert!(server.is_keyed(), "the server keyed once");
        // Replay the client's whole flight at the completed server. The keying material itself is
        // deliberately neither cloneable nor comparable — it is a secret, not a test fixture — so the
        // observable guarantee is that no second `Keyed` is reported and the session stays keyed.
        client.handle_timeout(now).ok();
        while let Some(record) = client.poll_transmit() {
            let events = server
                .handle_datagram(now, &record)
                .expect("server accepts the repeat");
            assert!(
                !events.iter().any(|event| matches!(event, DtlsEvent::Keyed)),
                "a completed session never reports a second Keyed"
            );
        }
        assert!(server.is_keyed(), "and stays keyed");
    }

    /// A minimal G.711 RTP packet (V2, PT0, given seq/ssrc, 16-byte payload).
    fn rtp(sequence: u16, ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0xFF; 16]);
        packet
    }
}

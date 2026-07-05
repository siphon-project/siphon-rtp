//! Drive a DTLS-SRTP handshake to completion and turn its exported keying material into a keyed
//! [`SecureLeg`] — the same secure leg the SDES path yields, so all downstream media handling (relay,
//! HA, conference) is shared.

use std::sync::Arc;

use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
use webrtc_dtls::config::{ClientAuthType, Config};
use webrtc_dtls::conn::DTLSConn;
use webrtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use webrtc_util::{Conn, KeyingMaterialExporter};

use crate::identity::{DtlsCertificate, Fingerprint};
use crate::DtlsError;

/// The RFC 5764 §4.2 exporter label for DTLS-SRTP keying material.
const DTLS_SRTP_LABEL: &str = "EXTRACTOR-dtls_srtp";
/// `AES_CM_128_HMAC_SHA1_80` master key length (RFC 3711).
const SRTP_KEY_LEN: usize = 16;
/// `AES_CM_128_HMAC_SHA1_80` master salt length (RFC 3711).
const SRTP_SALT_LEN: usize = 14;
/// The keying block is a write key + write salt for *each* direction (RFC 5764 §4.2): 2·(16+14) = 60.
const KEYING_LEN: usize = 2 * (SRTP_KEY_LEN + SRTP_SALT_LEN);

/// Which side of the DTLS handshake this leg plays, chosen from the SDP `a=setup` (RFC 5763 §5). The
/// engine is normally [`DtlsRole::Server`] — it answered `a=setup:passive`, so the remote (a browser)
/// is the DTLS client and initiates the handshake into the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsRole {
    /// This side initiates the handshake (`a=setup:active`).
    Client,
    /// This side waits for the handshake (`a=setup:passive`).
    Server,
}

/// Run a DTLS-SRTP handshake over `transport` to completion, verify the peer's certificate against
/// `expected_peer_fingerprint` (RFC 5763 §5), and return a [`SecureLeg`] keyed for both directions.
///
/// `transport` is driven by the caller (the engine feeds inbound DTLS datagrams and sends the outbound
/// ones); in tests it is an in-memory pipe. The handshake completes when `DTLSConn::new` returns.
pub async fn handshake(
    transport: Arc<dyn Conn + Send + Sync>,
    certificate: &DtlsCertificate,
    role: DtlsRole,
    expected_peer_fingerprint: &Fingerprint,
) -> Result<SecureLeg, DtlsError> {
    let is_client = role == DtlsRole::Client;

    let mut config = Config {
        certificates: vec![certificate.webrtc()],
        srtp_protection_profiles: vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80],
        // DTLS-SRTP's trust anchor is the SDP fingerprint, not a CA chain — skip chain verification
        // and check the fingerprint ourselves below (RFC 5763 §5).
        insecure_skip_verify: true,
        ..Default::default()
    };
    if !is_client {
        // As the DTLS server we MUST request the client's certificate, or we cannot verify the peer's
        // fingerprint (the default is `NoClientCert`). We do not chain-verify it — the fingerprint is
        // the authenticator — so `RequireAnyClientCert`, not `RequireAndVerifyClientCert`.
        config.client_auth = ClientAuthType::RequireAnyClientCert;
    }

    let connection = DTLSConn::new(transport, config, is_client, None)
        .await
        .map_err(|error| DtlsError::Handshake(error.to_string()))?;

    // RFC 5764 §4.1.2: the negotiated profile must be one SecureLeg implements (AES-CM-128/HMAC-SHA1-80).
    if connection.selected_srtpprotection_profile()
        != SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80
    {
        return Err(DtlsError::UnsupportedProfile);
    }

    let state = connection.connection_state().await;

    // RFC 5763 §5: authenticate the peer by matching its certificate to the fingerprint it signalled.
    // A mismatch means the media is not from the party we negotiated with — abort before deriving keys.
    let peer_certificate = state
        .peer_certificates
        .first()
        .ok_or(DtlsError::MissingPeerCertificate)?;
    if !expected_peer_fingerprint.verify(peer_certificate) {
        return Err(DtlsError::FingerprintMismatch);
    }

    let keying = state
        .export_keying_material(DTLS_SRTP_LABEL, &[], KEYING_LEN)
        .await
        .map_err(|error| DtlsError::KeyExport(error.to_string()))?;

    let (local, remote) = split_keying(&keying, role)?;
    Ok(SecureLeg::new(&local, &remote))
}

/// Split the RFC 5764 §4.2 keying block into this leg's `(local, remote)` SRTP key material.
///
/// The block is laid out `client_write_key | server_write_key | client_write_salt | server_write_salt`
/// (RFC 5764 §4.2). `SecureLeg` encrypts outbound with `local` and decrypts inbound with `remote`, so
/// `local` is *our* write key and `remote` is the *peer's* write key — which of the two client/server
/// halves that is depends on our DTLS role.
fn split_keying(
    keying: &[u8],
    role: DtlsRole,
) -> Result<(SrtpKeyMaterial, SrtpKeyMaterial), DtlsError> {
    if keying.len() != KEYING_LEN {
        return Err(DtlsError::KeyExport(format!(
            "expected {KEYING_LEN} keying bytes, got {}",
            keying.len()
        )));
    }
    let client_key = &keying[0..SRTP_KEY_LEN];
    let server_key = &keying[SRTP_KEY_LEN..2 * SRTP_KEY_LEN];
    let salts = &keying[2 * SRTP_KEY_LEN..];
    let client_salt = &salts[0..SRTP_SALT_LEN];
    let server_salt = &salts[SRTP_SALT_LEN..2 * SRTP_SALT_LEN];

    let material = |key: &[u8], salt: &[u8]| -> Result<SrtpKeyMaterial, DtlsError> {
        let mut inline = [0u8; SRTP_KEY_LEN + SRTP_SALT_LEN];
        inline[..SRTP_KEY_LEN].copy_from_slice(key);
        inline[SRTP_KEY_LEN..].copy_from_slice(salt);
        SrtpKeyMaterial::from_inline_bytes(&inline)
            .map_err(|error| DtlsError::KeyExport(error.to_string()))
    };

    // local = our write key; remote = the peer's write key.
    match role {
        DtlsRole::Server => Ok((
            material(server_key, server_salt)?,
            material(client_key, client_salt)?,
        )),
        DtlsRole::Client => Ok((
            material(client_key, client_salt)?,
            material(server_key, server_salt)?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrtc_util::conn::conn_pipe::pipe;

    /// A minimal G.711 RTP packet (V2, PT0, given seq/ssrc, 16-byte payload).
    fn rtp(seq: u16, ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0x2A; 16]);
        packet
    }

    #[tokio::test]
    async fn loopback_handshake_yields_interoperable_secure_legs() {
        let server_cert = DtlsCertificate::generate().expect("server cert");
        let client_cert = DtlsCertificate::generate().expect("client cert");
        let server_fingerprint = server_cert.fingerprint();
        let client_fingerprint = client_cert.fingerprint();
        let (server_transport, client_transport) = pipe();

        // Server (passive) runs on a task; client (active) drives on this one.
        let server = {
            let server_cert = server_cert.clone();
            let client_fingerprint = client_fingerprint.clone();
            tokio::spawn(async move {
                handshake(
                    Arc::new(server_transport),
                    &server_cert,
                    DtlsRole::Server,
                    &client_fingerprint,
                )
                .await
            })
        };
        let mut client_leg = handshake(
            Arc::new(client_transport),
            &client_cert,
            DtlsRole::Client,
            &server_fingerprint,
        )
        .await
        .expect("client handshake");
        let mut server_leg = server.await.expect("server task").expect("server handshake");

        // The role→key mapping is correct: what the server encrypts, the client decrypts, and back.
        let packet = rtp(1000, 0xDEAD_BEEF);
        let mut sealed = Vec::new();
        let mut recovered = Vec::new();

        server_leg.protect(&packet, &mut sealed).expect("server protect");
        client_leg
            .unprotect(&sealed, &mut recovered)
            .expect("client unprotect");
        assert_eq!(recovered, packet, "server→client media decrypts");

        client_leg.protect(&packet, &mut sealed).expect("client protect");
        server_leg
            .unprotect(&sealed, &mut recovered)
            .expect("server unprotect");
        assert_eq!(recovered, packet, "client→server media decrypts");
    }

    #[tokio::test]
    async fn a_wrong_peer_fingerprint_aborts_the_handshake() {
        let server_cert = DtlsCertificate::generate().expect("server cert");
        let client_cert = DtlsCertificate::generate().expect("client cert");
        let client_fingerprint = client_cert.fingerprint();
        let (server_transport, client_transport) = pipe();

        // The server expects the real client fingerprint (so it completes); the client is told a bogus
        // server fingerprint, so its side must reject after the DTLS handshake (RFC 5763 §5).
        let server = {
            let server_cert = server_cert.clone();
            tokio::spawn(async move {
                handshake(
                    Arc::new(server_transport),
                    &server_cert,
                    DtlsRole::Server,
                    &client_fingerprint,
                )
                .await
            })
        };
        let bogus = Fingerprint::sha256_of(b"not the server certificate");
        // Map the Ok payload away — `SecureLeg` is not `Debug`, and we only care about the error.
        let result = handshake(
            Arc::new(client_transport),
            &client_cert,
            DtlsRole::Client,
            &bogus,
        )
        .await
        .map(|_| ());
        assert!(
            matches!(result, Err(DtlsError::FingerprintMismatch)),
            "expected FingerprintMismatch, got {result:?}"
        );
        let _ = server.await; // the server side completes (it had the right fingerprint)
    }

    #[test]
    fn split_keying_maps_role_to_write_keys() {
        // A distinctive block so each 16/14 slice is identifiable.
        let mut block = Vec::new();
        block.extend_from_slice(&[0x11; SRTP_KEY_LEN]); // client write key
        block.extend_from_slice(&[0x22; SRTP_KEY_LEN]); // server write key
        block.extend_from_slice(&[0x33; SRTP_SALT_LEN]); // client write salt
        block.extend_from_slice(&[0x44; SRTP_SALT_LEN]); // server write salt

        // As server: local = server-write (0x22/0x44), remote = client-write (0x11/0x33).
        let (local, remote) = split_keying(&block, DtlsRole::Server).expect("split");
        assert_eq!(local.master_key, [0x22; SRTP_KEY_LEN]);
        assert_eq!(local.master_salt, [0x44; SRTP_SALT_LEN]);
        assert_eq!(remote.master_key, [0x11; SRTP_KEY_LEN]);
        assert_eq!(remote.master_salt, [0x33; SRTP_SALT_LEN]);

        // As client the mapping is mirrored.
        let (local, remote) = split_keying(&block, DtlsRole::Client).expect("split");
        assert_eq!(local.master_key, [0x11; SRTP_KEY_LEN]);
        assert_eq!(remote.master_key, [0x22; SRTP_KEY_LEN]);
    }

    #[test]
    fn split_keying_rejects_a_short_block() {
        assert!(matches!(
            split_keying(&[0u8; 10], DtlsRole::Server),
            Err(DtlsError::KeyExport(_))
        ));
    }
}

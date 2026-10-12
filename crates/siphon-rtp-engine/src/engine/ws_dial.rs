//! Dialling a WebSocket media server on a controller's word, inside a bound.
//!
//! `attach_ws_tee`, `attach_ws_bridge` and the `ws_uri` / `ws_tee` profile fields all make the
//! engine a WebSocket *client* of an address the controller names. That address is another
//! process, and another process can accept a TCP connection and then do nothing: a listen backlog
//! with nobody on `accept`, a server stuck behind a lock, a TLS terminator with no backend. Left
//! unbounded, such a dial never returns, and whatever waits for it waits with it.
//!
//! Every dial therefore goes through [`Engine::dial_ws`], which bounds the whole of it (name
//! resolution, the TCP connect, the TLS handshake and the RFC 6455 upgrade) by one timeout,
//! closes the connection when the bound is hit, counts the failure by its class and logs it. The
//! control connection in turn runs the commands that dial off its own loop
//! ([`Engine::command_dials`]), so the bound limits how long *that command* takes and nothing else.

use std::time::{Duration, Instant};

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::Command;
use tokio_tungstenite::tungstenite;

use super::Engine;
use crate::metrics::WsDialFailure;

/// The default bound on a WebSocket dial: three seconds from the TCP connect to the end of the
/// upgrade. Long enough for a server on another continent behind TLS, short enough that a
/// controller waiting four or five seconds for its answer still gets one.
pub const DEFAULT_WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// A dialled WebSocket client connection to a media server.
pub(super) type WsClientSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The class of a failure the WebSocket client reported.
fn failure_class(error: &tungstenite::Error) -> WsDialFailure {
    match error {
        // The rustls connector reports a failed handshake as an I/O error carrying its own.
        tungstenite::Error::Io(io)
            if io
                .get_ref()
                .is_some_and(|inner| inner.is::<rustls::Error>()) =>
        {
            WsDialFailure::Tls
        }
        tungstenite::Error::Io(_) => WsDialFailure::Connect,
        tungstenite::Error::Tls(_) => WsDialFailure::Tls,
        _ => WsDialFailure::Handshake,
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Dial a WebSocket media server as a client, inside the engine's connect timeout.
    ///
    /// A `wss://` URI completes the RFC 8446 handshake on the ring/rustls connector before the
    /// RFC 6455 upgrade; a `ws://` URI ignores the connector. Nothing of the call is touched until
    /// this returns `Ok`, so a failure leaves its media exactly as it was. On the bound running
    /// out the half-made connection is dropped, which closes it.
    pub(super) async fn dial_ws(
        &self,
        call_id: &str,
        ws_uri: &str,
    ) -> Result<WsClientSocket, String> {
        let connector = tokio_tungstenite::Connector::Rustls(self.ws_tls_client_config());
        let bound = self.ws_connect_timeout;
        let started = Instant::now();
        let dial =
            tokio_tungstenite::connect_async_tls_with_config(ws_uri, None, false, Some(connector));
        let (class, reason) = match tokio::time::timeout(bound, dial).await {
            Ok(Ok((socket, _response))) => return Ok(socket),
            Ok(Err(error)) => (failure_class(&error), format!("dial {ws_uri}: {error}")),
            Err(_) => (
                WsDialFailure::TimedOut,
                format!(
                    "dial {ws_uri}: timed out after {} ms without completing the WebSocket upgrade",
                    bound.as_millis()
                ),
            ),
        };
        self.metrics.record_ws_dial_failure(class);
        tracing::warn!(
            target: "siphon_rtp::media",
            call_id,
            ws_uri,
            class = class.as_str(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            %reason,
            "websocket dial failed; the command is refused and the call's media is untouched"
        );
        Err(reason)
    }

    /// Whether serving `command` may dial a WebSocket server, and so take as long as the connect
    /// timeout. The control connection runs such a command off its own loop.
    #[must_use]
    pub fn command_dials(command: &Command) -> bool {
        match command {
            Command::AttachWsTee { .. } | Command::AttachWsBridge { .. } => true,
            Command::Offer { profile, .. }
            | Command::Reoffer { profile, .. }
            | Command::Answer { profile, .. }
            | Command::AnswerLocal { profile, .. } => {
                profile.ws_uri.is_some() || profile.ws_tee.is_some()
            }
            _ => false,
        }
    }

    /// The call or conference `command` addresses, `None` for the verbs that address none (health,
    /// census, cluster). Commands that share one are served in the order they arrived.
    #[must_use]
    pub fn command_lane(command: &Command) -> Option<&str> {
        super::dispatch::command_call_id(command)
    }
}

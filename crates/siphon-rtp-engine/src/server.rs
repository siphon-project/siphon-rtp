//! The JSON-over-TCP control server.
//!
//! Each accepted connection is a persistent stream of length-prefixed JSON frames
//! ([`siphon_rtp_proto::frame`]). Requests are processed in order per connection and answered with
//! a correlated [`Response`]; connections are handled concurrently. This is SIPhon's native
//! front-end — the rtpengine NG/bencode compat listener is a separate front-end added later.

use std::sync::Arc;

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{frame, CmdResult, Command, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::engine::{ClientId, Engine};

/// Accept loop with no control-plane authentication — suitable only for a trusted, private control
/// network. Use [`serve_with_auth`] to require a shared secret.
pub async fn serve<D>(engine: Arc<Engine<D>>, listener: TcpListener) -> std::io::Result<()>
where
    D: Datapath + Clone + Send + 'static,
{
    serve_with_auth(engine, listener, None).await
}

/// Accept loop: serve control connections against `engine` until the listener errors. When `secret`
/// is `Some`, a connection must first send [`Command::Authenticate`] with the matching token before
/// any other command is honoured (docs/security-and-nat.md §5).
pub async fn serve_with_auth<D>(
    engine: Arc<Engine<D>>,
    listener: TcpListener,
    secret: Option<String>,
) -> std::io::Result<()>
where
    D: Datapath + Clone + Send + 'static,
{
    let secret = secret.map(Arc::new);
    // Each accepted connection gets a distinct identity; a call is private to the connection that
    // created it (docs/security-and-nat.md §5).
    let next_client_id = std::sync::atomic::AtomicU64::new(0);
    loop {
        let (stream, peer) = listener.accept().await?;
        let client = ClientId(next_client_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        tracing::debug!(%peer, ?client, "control connection accepted");
        let engine = engine.clone();
        let secret = secret.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(engine, client, secret, stream).await {
                tracing::warn!(%peer, %error, "control connection closed with error");
            }
        });
    }
}

/// Deregisters a client's event sink when its connection ends, on every exit path (clean close,
/// error, or task drop).
struct ClientGuard<D: Datapath + Clone + Send + 'static> {
    engine: Arc<Engine<D>>,
    client: ClientId,
}

impl<D: Datapath + Clone + Send + 'static> Drop for ClientGuard<D> {
    fn drop(&mut self) {
        self.engine.deregister_client(self.client);
    }
}

/// Drive one connection: decode request frames and dispatch them, write back responses, and push
/// the engine's asynchronous events (e.g. `MediaTimeout`) out the same socket.
async fn handle_connection<D>(
    engine: Arc<Engine<D>>,
    client: ClientId,
    secret: Option<Arc<String>>,
    stream: TcpStream,
) -> std::io::Result<()>
where
    D: Datapath + Clone + Send + 'static,
{
    let events = engine.register_client(client);
    let _guard = ClientGuard {
        engine: engine.clone(),
        client,
    };
    // Split so the inbound-read future and the event/response writes borrow disjoint halves.
    let (mut read_half, mut write_half) = stream.into_split();

    // With no configured secret the connection starts authenticated; otherwise it must authenticate
    // before any other command is honoured.
    let mut authenticated = secret.is_none();
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        // Drain every complete request frame currently buffered, writing each response.
        loop {
            match frame::decode::<Request>(&buffer) {
                Ok(Some((request, consumed))) => {
                    buffer.drain(..consumed);
                    let result = match request.command {
                        Command::Authenticate { token } => match secret.as_deref() {
                            None => auth_ok(),
                            Some(secret) if tokens_match(token.as_bytes(), secret.as_bytes()) => {
                                authenticated = true;
                                auth_ok()
                            }
                            Some(_) => CmdResult::Error {
                                reason: "authentication failed".to_string(),
                            },
                        },
                        command if !authenticated => {
                            let _ = command;
                            CmdResult::Error {
                                reason: "authentication required".to_string(),
                            }
                        }
                        command => engine.handle(client, command).await,
                    };
                    let response = Response {
                        id: request.id,
                        result,
                    };
                    match frame::encode(&response) {
                        Ok(bytes) => write_half.write_all(&bytes).await?,
                        Err(error) => {
                            tracing::error!(%error, "failed to encode control response");
                        }
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::warn!(%error, "malformed control frame; closing connection");
                    return Ok(());
                }
            }
        }

        // Wait for more inbound data or an event to push. Both arms are cancellation-safe: a read
        // that loses the race drops without consuming, and an unreceived event stays queued.
        tokio::select! {
            read = read_half.read(&mut chunk) => {
                let read = read?;
                if read == 0 {
                    return Ok(()); // peer closed
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            event = events.recv_async() => {
                if let Ok(event) = event {
                    match frame::encode(&event) {
                        Ok(bytes) => write_half.write_all(&bytes).await?,
                        Err(error) => tracing::error!(%error, "failed to encode control event"),
                    }
                }
            }
        }
    }
}

/// Length-checked, branch-free token comparison — no early exit on the first differing byte.
fn tokens_match(provided: &[u8], expected: &[u8]) -> bool {
    if provided.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in provided.iter().zip(expected) {
        diff |= a ^ b;
    }
    diff == 0
}

/// The success result for an accepted control verb that carries no payload (e.g. `Authenticate`).
fn auth_ok() -> CmdResult {
    CmdResult::Ok {
        sdp: None,
        duration_ms: None,
        to_tag: None,
        stats: None,
    }
}

//! The JSON-over-TCP control server.
//!
//! Each accepted connection is a persistent stream of length-prefixed JSON frames
//! ([`siphon_rtp_proto::frame`]). Requests are processed in order per connection and answered with
//! a correlated [`Response`]; connections are handled concurrently. This is SIPhon's native
//! front-end — the rtpengine NG/bencode compat listener is a separate front-end added later.

use std::sync::Arc;

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{frame, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::engine::Engine;

/// Accept loop: serve control connections against `engine` until the listener errors.
pub async fn serve<D>(engine: Arc<Engine<D>>, listener: TcpListener) -> std::io::Result<()>
where
    D: Datapath + 'static,
{
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::debug!(%peer, "control connection accepted");
        let engine = engine.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(engine, stream).await {
                tracing::warn!(%peer, %error, "control connection closed with error");
            }
        });
    }
}

/// Drive one connection: decode frames, dispatch to the engine, write back responses.
async fn handle_connection<D>(
    engine: Arc<Engine<D>>,
    mut stream: TcpStream,
) -> std::io::Result<()>
where
    D: Datapath,
{
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        // Drain every complete frame currently buffered before reading more.
        loop {
            match frame::decode::<Request>(&buffer) {
                Ok(Some((request, consumed))) => {
                    buffer.drain(..consumed);
                    let response = Response {
                        id: request.id,
                        result: engine.handle(request.command).await,
                    };
                    match frame::encode(&response) {
                        Ok(bytes) => stream.write_all(&bytes).await?,
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

        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(()); // peer closed
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

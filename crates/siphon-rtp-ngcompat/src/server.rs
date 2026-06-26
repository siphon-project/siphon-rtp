//! The rtpengine NG UDP listener.
//!
//! Binds a UDP control socket (the rtpengine default is port 22222), and for each datagram:
//! split the cookie, decode + map the bencode dict to a [`Command`], run it through the supplied
//! handler, and reply `<cookie> <result-dict>` to the source. The handler is a closure the daemon
//! supplies (it calls the session engine), so this crate never depends on the engine and tests
//! NIC-free with a stub. A datagram with no cookie can't be correlated, so it is dropped; a
//! malformed/unknown command still gets a `{result:error}` reply (so the client fails fast rather
//! than hitting its ~1 s timeout).

use std::future::Future;

use siphon_rtp_proto::{CmdResult, Command};
use tokio::net::UdpSocket;

use crate::bencode;
use crate::ng;

/// rtpengine's default NG control port.
pub const DEFAULT_NG_PORT: u16 = 22222;

/// Serve NG control on `socket` until a socket error, dispatching each command through `handler`.
pub async fn serve<Handler, Fut>(socket: UdpSocket, handler: Handler) -> std::io::Result<()>
where
    Handler: Fn(Command) -> Fut,
    Fut: Future<Output = CmdResult>,
{
    // SDP/blobs keep responses well under one datagram; 64 KiB matches the rtpengine client buffer.
    let mut buffer = vec![0u8; 65_535];
    loop {
        let (len, peer) = socket.recv_from(&mut buffer).await?;
        if let Some(response) = respond(&buffer[..len], &handler).await {
            if let Err(error) = socket.send_to(&response, peer).await {
                tracing::warn!(%peer, %error, "NG response send failed");
            }
        }
    }
}

/// Map one datagram to its response bytes, or `None` if it cannot be correlated (no cookie).
async fn respond<Handler, Fut>(datagram: &[u8], handler: &Handler) -> Option<Vec<u8>>
where
    Handler: Fn(Command) -> Fut,
    Fut: Future<Output = CmdResult>,
{
    let (cookie, body) = match ng::split_cookie(datagram) {
        Ok(parts) => parts,
        Err(_) => {
            tracing::debug!("NG datagram without a cookie separator; dropping");
            return None;
        }
    };

    let parsed = bencode::decode(body)
        .map_err(ng::NgError::from)
        .and_then(|request| ng::parse_command(&request));
    let result = match parsed {
        Ok(command) => handler(command).await,
        Err(error) => CmdResult::Error {
            reason: error.to_string(),
        },
    };
    Some(ng::serialize_response(cookie, &result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bencode::Value;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use tokio::time::timeout;

    /// A stub handler: pong for ping, an Ok-with-SDP for offer, error otherwise.
    fn stub(command: Command) -> std::future::Ready<CmdResult> {
        let result = match command {
            Command::Ping => CmdResult::Pong,
            Command::Offer { sdp, .. } => CmdResult::Ok {
                sdp: Some(sdp.replace("RTP/SAVP", "RTP/AVP")),
                duration_ms: None,
                to_tag: None,
                stats: None,
            },
            _ => CmdResult::Error {
                reason: "stub".into(),
            },
        };
        std::future::ready(result)
    }

    async fn start_server() -> SocketAddr {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind");
        let addr = socket.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = serve(socket, stub).await;
        });
        addr
    }

    fn ng_datagram(cookie: &str, entries: &[(&str, Value)]) -> Vec<u8> {
        let mut dict = std::collections::BTreeMap::new();
        for (key, value) in entries {
            dict.insert(key.as_bytes().to_vec(), value.clone());
        }
        let mut out = cookie.as_bytes().to_vec();
        out.push(b' ');
        out.extend_from_slice(&bencode::encode(&Value::Dict(dict)));
        out
    }

    async fn exchange(client: &UdpSocket, server: SocketAddr, request: &[u8]) -> Vec<u8> {
        client.send_to(request, server).await.expect("send");
        let mut buffer = [0u8; 65_535];
        let (len, _) = timeout(Duration::from_secs(1), client.recv_from(&mut buffer))
            .await
            .expect("no timeout")
            .expect("recv");
        buffer[..len].to_vec()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ping_pong_over_udp_echoes_cookie() {
        let server = start_server().await;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("client");

        let response = exchange(&client, server, &ng_datagram("cafe1234", &[("command", Value::string("ping"))])).await;
        let (cookie, body) = ng::split_cookie(&response).expect("split");
        assert_eq!(cookie, b"cafe1234", "cookie echoed verbatim");
        assert_eq!(bencode::decode(body).unwrap().get("result").and_then(Value::as_str), Some("pong"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offer_returns_rewritten_sdp() {
        let server = start_server().await;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("client");

        let request = ng_datagram(
            "deadbeef",
            &[
                ("command", Value::string("offer")),
                ("call-id", Value::string("c")),
                ("from-tag", Value::string("f")),
                ("sdp", Value::string("v=0\r\nm=audio 8000 RTP/SAVP 96\r\n")),
                ("transport-protocol", Value::string("RTP/AVP")),
            ],
        );
        let response = exchange(&client, server, &request).await;
        let (_, body) = ng::split_cookie(&response).expect("split");
        let dict = bencode::decode(body).expect("decode");
        assert_eq!(dict.get("result").and_then(Value::as_str), Some("ok"));
        assert!(dict.get("sdp").and_then(Value::as_str).unwrap().contains("RTP/AVP"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unknown_command_returns_error_not_silence() {
        let server = start_server().await;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("client");

        let response = exchange(&client, server, &ng_datagram("k", &[("command", Value::string("frobnicate"))])).await;
        let (_, body) = ng::split_cookie(&response).expect("split");
        let dict = bencode::decode(body).expect("decode");
        assert_eq!(dict.get("result").and_then(Value::as_str), Some("error"));
        assert!(dict.get("error-reason").and_then(Value::as_str).unwrap().contains("frobnicate"));
    }
}

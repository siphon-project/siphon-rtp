//! The single PCMU audio description used by sipload.
use super::message::Error;
use std::net::{Ipv4Addr, SocketAddrV4};

pub fn offer(address: SocketAddrV4, session: u64) -> String {
    format!(
        concat!(
            "v=0\r\n",
            "o=sipload {session} 1 IN IP4 {}\r\n",
            "s=sipload\r\n",
            "c=IN IP4 {}\r\n",
            "t=0 0\r\n",
            "m=audio {} RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=sendrecv\r\n",
            "",
        ),
        address.ip(),
        address.ip(),
        address.port(),
        session = session
    )
}
pub fn parse(body: &str) -> Result<SocketAddrV4, Error> {
    let mut session_connection = None;
    let mut media_connection = None;
    let mut in_media = false;
    let mut in_audio = false;
    let mut port = None;
    for line in body.lines().map(str::trim) {
        if let Some(media) = line.strip_prefix("m=") {
            if in_audio {
                break;
            }
            in_media = true;
            let fields: Vec<_> = media.split_whitespace().collect();
            if fields.first() == Some(&"audio") && port.is_none() {
                if fields.len() < 4 || fields[2] != "RTP/AVP" || !fields[3..].contains(&"0") {
                    return Err(Error("unsupported audio"));
                }
                port = Some(
                    fields[1]
                        .parse::<u16>()
                        .map_err(|_| Error("bad media port"))?,
                );
                in_audio = true;
            }
        } else if let Some(connection) = line.strip_prefix("c=IN IP4 ") {
            let address = connection
                .parse::<Ipv4Addr>()
                .map_err(|_| Error("bad SDP address"))?;
            if in_audio {
                media_connection = Some(address);
            } else if !in_media {
                session_connection = Some(address);
            }
        }
    }
    let port = port
        .filter(|port| *port != 0)
        .ok_or(Error("missing audio port"))?;
    Ok(SocketAddrV4::new(
        media_connection
            .or(session_connection)
            .ok_or(Error("missing connection"))?,
        port,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_connection_and_media_override() {
        let address = "127.0.0.1:9000".parse().unwrap();
        assert_eq!(parse(&offer(address, 1)).unwrap(), address);
        assert_eq!(
            parse(concat!(
                "v=0\r\n",
                "c=IN IP4 192.0.2.1\r\n",
                "m=video 10 RTP/AVP 96\r\n",
                "c=IN IP4 192.0.2.2\r\n",
                "m=audio 20 RTP/AVP 0\r\n",
                "c=IN IP4 192.0.2.3\r\n",
                "m=audio 30 RTP/AVP 0\r\n",
                "c=IN IP4 192.0.2.4\r\n",
                "",
            ))
            .unwrap(),
            "192.0.2.3:20".parse::<SocketAddrV4>().unwrap()
        );
    }
    #[test]
    fn malformed_sdp_returns_errors() {
        for value in [
            "",
            "m=audio bad RTP/AVP 0",
            "c=IN IP4 bad\r\nm=audio 2 RTP/AVP 0",
            "c=IN IP4 127.0.0.1\r\nm=audio 0 RTP/AVP 0",
        ] {
            assert!(parse(value).is_err());
        }
    }
}

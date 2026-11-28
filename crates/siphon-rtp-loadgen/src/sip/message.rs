//! SIP framing and the fields needed by the generator (RFC 3261 §7).

use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
#[error("malformed SIP: {0}")]
pub struct Error(pub &'static str);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Start {
    Request { method: String, uri: String },
    Response { status: u16, reason: String },
}
#[derive(Debug, Clone)]
pub struct Message {
    pub start: Start,
    pub headers: Vec<(String, String)>,
    pub body: String,
}
fn canonical(name: &str) -> String {
    match name.trim().to_ascii_lowercase().as_str() {
        "v" => "via",
        "f" => "from",
        "t" => "to",
        "i" => "call-id",
        "m" => "contact",
        "l" => "content-length",
        "c" => "content-type",
        other => return other.to_string(),
    }
    .into()
}
/// Split lists without breaking quoted commas or name-address URIs (§7.3.1).
pub fn split_list(input: &str) -> Result<Vec<&str>, Error> {
    let mut quoted = false;
    let mut escaped = false;
    let mut angle = false;
    let mut start = 0;
    let mut parts = Vec::new();
    for (index, character) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '<' if !quoted => angle = true,
            '>' if !quoted => angle = false,
            ',' if !quoted && !angle => {
                parts.push(input[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    if quoted || angle || escaped {
        return Err(Error("unterminated quoted value"));
    }
    parts.push(input[start..].trim());
    Ok(parts)
}
pub fn uri(value: &str) -> Result<String, Error> {
    let value = value.trim();
    let result = if let Some((_, rest)) = value.split_once('<') {
        rest.split_once('>').ok_or(Error("missing >"))?.0
    } else {
        value.split_whitespace().next().ok_or(Error("empty URI"))?
    };
    if !result.starts_with("sip:") || result.len() <= 4 || result.contains(['\r', '\n', ' ']) {
        return Err(Error("unsupported URI"));
    }
    Ok(result.into())
}
pub fn parameter(value: &str, name: &str) -> Option<String> {
    value.split(';').skip(1).find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().trim_matches('"').to_string())
    })
}
pub fn parameters(value: &str) -> Result<BTreeMap<String, String>, Error> {
    let (scheme, rest) = value
        .split_once(' ')
        .ok_or(Error("missing authentication scheme"))?;
    if !scheme.eq_ignore_ascii_case("Digest") {
        return Err(Error("unsupported authentication"));
    }
    split_list(rest)?
        .into_iter()
        .map(|part| {
            let (name, value) = part.split_once('=').ok_or(Error("bad digest parameter"))?;
            Ok((
                name.trim().to_ascii_lowercase(),
                value
                    .trim()
                    .trim_matches('"')
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\"),
            ))
        })
        .collect()
}
impl Message {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(bytes).map_err(|_| Error("non UTF-8 message"))?;
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or(Error("missing header terminator"))?;
        let mut lines = head.split("\r\n");
        let first = lines.next().ok_or(Error("missing start line"))?;
        let start = if let Some(rest) = first.strip_prefix("SIP/2.0 ") {
            let (status, reason) = rest.split_once(' ').ok_or(Error("bad status line"))?;
            let status = status.parse::<u16>().map_err(|_| Error("bad status"))?;
            if !(100..=699).contains(&status) {
                return Err(Error("bad status"));
            }
            Start::Response {
                status,
                reason: reason.into(),
            }
        } else {
            let fields: Vec<_> = first.split_whitespace().collect();
            if fields.len() != 3 || fields[2] != "SIP/2.0" {
                return Err(Error("bad request line"));
            }
            Start::Request {
                method: fields[0].into(),
                uri: uri(fields[1])?,
            }
        };
        let mut headers: Vec<(String, String)> = Vec::new();
        for line in lines {
            if line.contains(['\r', '\n']) {
                return Err(Error("bad line ending"));
            }
            if line.starts_with([' ', '\t']) {
                let (_, value) = headers.last_mut().ok_or(Error("orphan folded line"))?;
                value.push(' ');
                value.push_str(line.trim());
            } else {
                let (name, value) = line.split_once(':').ok_or(Error("bad header"))?;
                if name.trim().is_empty() {
                    return Err(Error("empty header name"));
                }
                headers.push((canonical(name), value.trim().into()));
            }
        }
        let mut message = Self {
            start,
            headers,
            body: String::new(),
        };
        for name in ["call-id", "from", "to", "cseq"] {
            if message.header(name).is_none_or(str::is_empty) || message.values(name).count() != 1 {
                return Err(Error("missing or duplicate required header"));
            }
        }
        // RFC 3261 §17.2.3 distinguishes parsing from transaction matching, including
        // legacy Vias without a branch. The dispatcher rejects unsupported matching keys.
        if message.header("via").is_none_or(str::is_empty) {
            return Err(Error("missing Via"));
        }
        let (_, method) = message.cseq()?;
        if let Start::Request {
            method: request_method,
            ..
        } = &message.start
        {
            if method != request_method {
                return Err(Error("CSeq method mismatch"));
            }
        }
        if message.values("content-length").count() > 1 {
            return Err(Error("duplicate content length"));
        }
        let length = message
            .header("content-length")
            .map(|value| value.parse::<usize>())
            .transpose()
            .map_err(|_| Error("bad content length"))?
            .unwrap_or(body.len());
        message.body = body.get(..length).ok_or(Error("truncated body"))?.into();
        Ok(message)
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.values(name).next()
    }
    pub fn values<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a str> {
        let name = canonical(name);
        self.headers
            .iter()
            .filter(move |(key, _)| canonical(key) == name)
            .map(|(_, value)| value.as_str())
    }
    pub fn set(&mut self, name: &str, value: &str) {
        let key = canonical(name);
        self.headers
            .retain(|(existing, _)| canonical(existing) != key);
        self.headers.push((name.into(), value.into()));
    }
    pub fn call_id(&self) -> &str {
        self.header("call-id").unwrap_or("")
    }
    pub fn branch(&self) -> Result<String, Error> {
        let top = split_list(self.header("via").ok_or(Error("missing Via"))?)?;
        parameter(top.first().copied().ok_or(Error("empty Via"))?, "branch")
            .ok_or(Error("missing branch"))
    }
    pub fn from_tag(&self) -> Option<String> {
        parameter(self.header("from")?, "tag")
    }
    pub fn to_tag(&self) -> Option<String> {
        parameter(self.header("to")?, "tag")
    }
    pub fn cseq(&self) -> Result<(u32, &str), Error> {
        let mut parts = self
            .header("cseq")
            .ok_or(Error("missing CSeq"))?
            .split_whitespace();
        let number = parts
            .next()
            .ok_or(Error("empty CSeq"))?
            .parse()
            .map_err(|_| Error("bad CSeq number"))?;
        let method = parts.next().ok_or(Error("missing CSeq method"))?;
        if parts.next().is_some() {
            return Err(Error("extra CSeq fields"));
        }
        Ok((number, method))
    }
    pub fn contact(&self) -> Result<String, Error> {
        uri(self.header("contact").ok_or(Error("missing Contact"))?)
    }
    pub fn record_routes(&self) -> Result<Vec<String>, Error> {
        let mut routes = Vec::new();
        for value in self.values("record-route") {
            for part in split_list(value)? {
                routes.push(uri(part)?);
            }
        }
        Ok(routes)
    }
    pub fn status(&self) -> Option<u16> {
        match self.start {
            Start::Response { status, .. } => Some(status),
            _ => None,
        }
    }
    pub fn method(&self) -> Option<&str> {
        match &self.start {
            Start::Request { method, .. } => Some(method),
            _ => None,
        }
    }
    pub fn request(
        method: &str,
        target: &str,
        local: &str,
        branch: &str,
        from: &str,
        to: &str,
        call_id: &str,
        sequence: u32,
        contact: &str,
        body: &str,
    ) -> Self {
        let mut message = Self {
            start: Start::Request {
                method: method.into(),
                uri: target.into(),
            },
            headers: Vec::new(),
            body: body.into(),
        };
        for (name, value) in [
            ("Via", format!("SIP/2.0/UDP {local};branch={branch};rport")),
            ("Max-Forwards", "70".into()),
            ("From", from.into()),
            ("To", to.into()),
            ("Call-ID", call_id.into()),
            ("CSeq", format!("{sequence} {method}")),
            ("Contact", format!("<{contact}>")),
        ] {
            message.set(name, &value);
        }
        message
    }
    pub fn response(
        &self,
        status: u16,
        tag: &str,
        contact: Option<&str>,
        body: &str,
    ) -> Result<Self, Error> {
        let reason = match status {
            100 => "Trying",
            200 => "OK",
            400 => "Bad Request",
            481 => "Call/Transaction Does Not Exist",
            488 => "Not Acceptable Here",
            _ => "Failure",
        };
        let mut response = Self {
            start: Start::Response {
                status,
                reason: reason.into(),
            },
            headers: Vec::new(),
            body: body.into(),
        };
        for (name, value) in &self.headers {
            if ["via", "from", "to", "call-id", "cseq", "record-route"]
                .contains(&canonical(name).as_str())
            {
                response.headers.push((name.clone(), value.clone()));
            }
        }
        if status > 100 && response.to_tag().is_none() {
            response.set(
                "To",
                &format!(
                    "{};tag={tag}",
                    self.header("to").ok_or(Error("missing To"))?
                ),
            );
        }
        if let Some(contact) = contact {
            response.set("Contact", &format!("<{contact}>"));
        }
        Ok(response)
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let first = match &self.start {
            Start::Request { method, uri } => format!("{method} {uri} SIP/2.0"),
            Start::Response { status, reason } => format!("SIP/2.0 {status} {reason}"),
        };
        if first.contains(['\r', '\n']) {
            return Err(Error("start line injection"));
        }
        let mut text = format!("{first}\r\n");
        for (name, value) in &self.headers {
            if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
                return Err(Error("header injection"));
            }
            if canonical(name) != "content-length" && canonical(name) != "content-type" {
                text.push_str(&format!("{name}: {value}\r\n"));
            }
        }
        if !self.body.is_empty() {
            text.push_str("Content-Type: application/sdp\r\n");
        }
        text.push_str(&format!(
            "Content-Length: {}\r\n\r\n{}",
            self.body.len(),
            self.body
        ));
        Ok(text.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice(method: &str) -> String {
        format!(
            concat!(
                "{method} sip:bob@biloxi.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8\r\n",
                "Max-Forwards: 70\r\n",
                "To: Bob <sip:bob@biloxi.com>\r\n",
                "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
                "Call-ID: a84b4c76e66710\r\n",
                "CSeq: 314159 {method}\r\n",
                "Contact: <sip:alice@pc33.atlanta.com>\r\n",
                "Content-Type: application/sdp\r\n",
                "Content-Length: 142\r\n",
                "\r\n",
                "{}",
            ),
            " ".repeat(142),
            method = method
        )
    }
    #[test]
    fn missing_branch_can_be_parsed_but_has_no_transaction_key() {
        let wire = alice("INVITE").replace(";branch=z9hG4bKnashds8", "");
        let message = Message::parse(wire.as_bytes()).unwrap();
        assert_eq!(message.method(), Some("INVITE"));
        assert!(message.branch().is_err());
        assert!(Message::parse(
            wire.replace("Via: SIP/2.0/UDP pc33.atlanta.com\r\n", "",)
                .as_bytes()
        )
        .is_err());
    }
    #[test]
    fn rfc3261_section24_invite_fields() {
        // §24.2 F1 leaves the 142-byte SDP unprinted; retain the exact headers.
        let message = Message::parse(alice("INVITE").as_bytes()).unwrap();
        assert_eq!(
            message.start,
            Start::Request {
                method: "INVITE".into(),
                uri: "sip:bob@biloxi.com".into()
            }
        );
        assert_eq!(message.branch().unwrap(), "z9hG4bKnashds8");
        assert_eq!(message.from_tag(), Some("1928301774".into()));
        assert_eq!(message.to_tag(), None);
        assert_eq!(message.call_id(), "a84b4c76e66710");
        assert_eq!(message.cseq().unwrap(), (314159, "INVITE"));
        assert_eq!(message.contact().unwrap(), "sip:alice@pc33.atlanta.com");
        assert_eq!(message.body.len(), 142);
    }
    #[test]
    fn compact_folded_headers_and_quoted_lists() {
        let input = concat!(
            "SIP/2.0 180 Ringing\r\n",
            "v : SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK77\r\n",
            " ;received=192.0.2.1\r\n",
            "f: Alice <sip:alice@atlanta.com>;tag=alice\r\n",
            "t: Bob <sip:bob@biloxi.com>;tag=bob\r\n",
            "i: call\r\n",
            "CSeq: 1 INVITE\r\n",
            "m: <sip:bob@192.0.2.4>\r\n",
            "Record-Route: \"a,b\" <sip:one;lr>, <sip:two;lr>\r\n",
            "c: application/sdp\r\n",
            "l: 0\r\n",
            "\r\n",
            "",
        );
        let message = Message::parse(input.as_bytes()).unwrap();
        assert_eq!(message.status(), Some(180));
        assert_eq!(message.branch().unwrap(), "z9hG4bK77");
        assert_eq!(message.to_tag(), Some("bob".into()));
        assert_eq!(
            message.record_routes().unwrap(),
            ["sip:one;lr", "sip:two;lr"]
        );
        assert_eq!(message.contact().unwrap(), "sip:bob@192.0.2.4");
        assert_eq!(message.header("Content-Type"), Some("application/sdp"));
    }
    #[test]
    fn malformed_messages_return_errors() {
        for input in [
            alice("INVITE").replace("\r\n\r\n", "\n\n"),
            alice("INVITE").replace("142", "bad"),
            alice("INVITE").replace("Call-ID: a84b4c76e66710\r\n", ""),
            alice("INVITE").replace("142", "900"),
            alice("INVITE").replace("CSeq: 314159 INVITE", "CSeq: 1 BYE"),
        ] {
            assert!(Message::parse(input.as_bytes()).is_err());
        }
        for length in 0..alice("INVITE").len() {
            let _ = Message::parse(&alice("INVITE").as_bytes()[..length]);
        }
    }
    #[test]
    fn builders_round_trip_and_have_independent_wire_fields() {
        for method in ["INVITE", "ACK", "BYE", "REGISTER"] {
            let request = Message::request(
                method,
                "sip:bob@example.com",
                "127.0.0.1:5060",
                "z9hG4bKtest",
                "<sip:a@example.com>;tag=a",
                "<sip:b@example.com>",
                "unique",
                7,
                "sip:a@127.0.0.1:5060",
                "é",
            );
            let wire = request.encode().unwrap();
            let text = std::str::from_utf8(&wire).unwrap();
            assert!(text.starts_with(&format!("{method} sip:bob@example.com SIP/2.0\r\n")));
            assert!(text.contains("Content-Length: 2\r\n"));
            assert!(text.contains("Max-Forwards: 70\r\n"));
            assert!(text.contains("Content-Type: application/sdp\r\n"));
            assert_eq!(Message::parse(&wire).unwrap().cseq().unwrap(), (7, method));
            let response = request
                .response(200, "b", Some("sip:b@127.0.0.1:5061"), "body")
                .unwrap();
            let encoded = response.encode().unwrap();
            assert!(std::str::from_utf8(&encoded)
                .unwrap()
                .starts_with("SIP/2.0 200 OK\r\n"));
            let decoded = Message::parse(&encoded).unwrap();
            assert_eq!(decoded.to_tag(), Some("b".into()));
            assert_eq!(decoded.body, "body");
        }
    }
    #[test]
    fn digest_parameters_and_invalid_quoting() {
        let parsed =
            parameters("Digest realm=\"a,b\", nonce=\"abc\", qop=\"auth,auth-int\"").unwrap();
        assert_eq!(parsed["realm"], "a,b");
        assert_eq!(parsed["qop"], "auth,auth-int");
        assert!(parameters("Digest nonce=\"unfinished").is_err());
        assert!(uri("<broken").is_err());
        assert!(uri("https://example.com").is_err());
    }
    #[test]
    fn header_injection_is_rejected() {
        let mut message = Message::parse(alice("INVITE").as_bytes()).unwrap();
        message.set("Contact", "bad\r\nInjected: yes");
        assert!(message.encode().is_err());
    }
}

#[cfg(test)]
mod rfc_examples {
    use super::*;

    #[test]
    fn section24_f8_and_f11_preserve_all_consumed_fields() {
        let ringing = concat!(
            "SIP/2.0 180 Ringing\r\n",
            "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8\r\n",
            " ;received=192.0.2.1\r\n",
            "To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n",
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "Call-ID: a84b4c76e66710\r\n",
            "Contact: <sip:bob@192.0.2.4>\r\n",
            "CSeq: 314159 INVITE\r\n",
            "Content-Length: 0\r\n\r\n"
        );
        // The RFC prints the Content-Length but omits Bob's SDP, as it does Alice's.
        let accepted = concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8\r\n",
            " ;received=192.0.2.1\r\n",
            "To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n",
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "Call-ID: a84b4c76e66710\r\n",
            "CSeq: 314159 INVITE\r\n",
            "Contact: <sip:bob@192.0.2.4>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: 131\r\n\r\n"
        )
        .to_string()
            + &" ".repeat(131);
        for (wire, status, length) in [(ringing, 180, 0), (accepted.as_str(), 200, 131)] {
            let message = Message::parse(wire.as_bytes()).unwrap();
            assert_eq!(message.status(), Some(status));
            assert_eq!(message.branch().unwrap(), "z9hG4bKnashds8");
            assert_eq!(message.from_tag().as_deref(), Some("1928301774"));
            assert_eq!(message.to_tag().as_deref(), Some("a6c85cf"));
            assert_eq!(message.call_id(), "a84b4c76e66710");
            assert_eq!(message.cseq().unwrap(), (314159, "INVITE"));
            assert_eq!(message.contact().unwrap(), "sip:bob@192.0.2.4");
            assert!(message.record_routes().unwrap().is_empty());
            assert!(message.header("www-authenticate").is_none());
            assert_eq!(message.body.len(), length);
        }
    }
    #[test]
    fn section24_f12_ack_and_f13_bye_swap_tags_and_numbering_spaces() {
        let ack = concat!(
            "ACK sip:bob@192.0.2.4 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds9\r\n",
            "Max-Forwards: 70\r\n",
            "To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n",
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "Call-ID: a84b4c76e66710\r\n",
            "CSeq: 314159 ACK\r\n",
            "Content-Length: 0\r\n\r\n"
        );
        let bye = concat!(
            "BYE sip:alice@pc33.atlanta.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.4;branch=z9hG4bKnashds10\r\n",
            "Max-Forwards: 70\r\n",
            "From: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n",
            "To: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "Call-ID: a84b4c76e66710\r\n",
            "CSeq: 231 BYE\r\n",
            "Content-Length: 0\r\n\r\n"
        );
        for (wire, method, target, sequence, branch, from, to) in [
            (
                ack,
                "ACK",
                "sip:bob@192.0.2.4",
                314159,
                "z9hG4bKnashds9",
                "1928301774",
                "a6c85cf",
            ),
            (
                bye,
                "BYE",
                "sip:alice@pc33.atlanta.com",
                231,
                "z9hG4bKnashds10",
                "a6c85cf",
                "1928301774",
            ),
        ] {
            let message = Message::parse(wire.as_bytes()).unwrap();
            assert_eq!(
                message.start,
                Start::Request {
                    method: method.into(),
                    uri: target.into()
                }
            );
            assert_eq!(message.cseq().unwrap(), (sequence, method));
            assert_eq!(message.branch().unwrap(), branch);
            assert_eq!(message.from_tag().as_deref(), Some(from));
            assert_eq!(message.to_tag().as_deref(), Some(to));
            assert_eq!(message.call_id(), "a84b4c76e66710");
            assert!(message.header("contact").is_none());
            assert!(message.record_routes().unwrap().is_empty());
            assert!(message.body.is_empty());
        }
    }
}

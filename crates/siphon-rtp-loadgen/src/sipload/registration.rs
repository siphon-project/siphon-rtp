//! Registration and MD5 challenge handling.
use super::{
    endpoint::{branch, unique, Endpoint},
    Error, RunPlan,
};
use crate::sip::{
    digest,
    message::{parameters, Error as ParseError, Message},
};
use std::io::Read;

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
fn authorization(
    challenge: &str,
    username: &str,
    password: &str,
    target: &str,
    cnonce: &str,
) -> Result<String, Error> {
    let parameters = parameters(challenge)?;
    let realm = parameters.get("realm").ok_or(ParseError("missing realm"))?;
    let nonce = parameters.get("nonce").ok_or(ParseError("missing nonce"))?;
    if parameters
        .get("algorithm")
        .is_some_and(|algorithm| !algorithm.eq_ignore_ascii_case("MD5"))
    {
        return Err(ParseError("only MD5 authentication is supported").into());
    }
    let auth = if let Some(qop) = parameters.get("qop") {
        if !qop
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case("auth"))
        {
            return Err(ParseError("qop auth not offered").into());
        }
        Some(("00000001", cnonce))
    } else {
        None
    };
    let response = digest::response(username, realm, password, "REGISTER", target, nonce, auth);
    let mut value = format!(
        "Digest username={}, realm={}, nonce={}, uri={}, response={}, algorithm=MD5",
        quote(username),
        quote(realm),
        quote(nonce),
        quote(target),
        quote(&response)
    );
    if auth.is_some() {
        value.push_str(&format!(
            ", qop=auth, nc=00000001, cnonce={}",
            quote(cnonce)
        ));
    }
    if let Some(opaque) = parameters.get("opaque") {
        value.push_str(&format!(", opaque={}", quote(opaque)));
    }
    Ok(value)
}
fn cnonce() -> Result<String, Error> {
    let mut bytes = [0; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
pub async fn register(endpoint: &Endpoint, plan: &RunPlan, user: usize) -> Result<(), Error> {
    let username = format!("bob{user}");
    let target = format!("sip:{}", plan.domain);
    let identity = format!("<sip:{username}@{}>", plan.domain);
    let call_id = unique();
    let mut inbox = endpoint.inbox(&call_id)?;
    let mut request = Message::request(
        "REGISTER",
        &target,
        &endpoint.local.to_string(),
        &branch(),
        &format!("{identity};tag={}", unique()),
        &identity,
        &call_id,
        1,
        &format!("sip:{username}@{}", endpoint.local),
        "",
    );
    request.set("Expires", "3600");
    let mut response = endpoint
        .exchange(&mut inbox, &request, plan.target.into())
        .await?;
    if response.status() == Some(401) {
        let challenge = response
            .header("www-authenticate")
            .ok_or(ParseError("401 missing challenge"))?;
        request.set(
            "Authorization",
            &authorization(challenge, &username, &plan.password, &target, &cnonce()?)?,
        );
        request.set("CSeq", "2 REGISTER");
        request.set(
            "Via",
            &format!("SIP/2.0/UDP {};branch={};rport", endpoint.local, branch()),
        );
        response = endpoint
            .exchange(&mut inbox, &request, plan.target.into())
            .await?;
    }
    match response.status() {
        Some(200..=299) => Ok(()),
        status => Err(Error::Status(status.unwrap_or(0))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn registration_retries_401_with_incremented_cseq_and_correct_digest() {
        for qop in [true, false] {
            let registrar = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = registrar.local_addr().unwrap();
            let counters = std::sync::Arc::new(super::super::endpoint::Counters::default());
            let endpoint = Endpoint::bind("127.0.0.1:0".parse().unwrap(), counters.clone())
                .await
                .unwrap();
            let (stop_sender, stop_receiver) = tokio::sync::watch::channel(false);
            let dispatcher = tokio::spawn(endpoint.clone().dispatch(None, stop_receiver));
            let registrar_task = tokio::spawn(async move {
                let mut buffer = [0; 4096];
                let (length, source) = registrar.recv_from(&mut buffer).await.unwrap();
                let first = Message::parse(&buffer[..length]).unwrap();
                assert_eq!(first.method(), Some("REGISTER"));
                assert_eq!(first.header("expires"), Some("3600"));
                assert_eq!(first.cseq().unwrap(), (1, "REGISTER"));
                assert!(first.contact().unwrap().starts_with("sip:bob1@127.0.0.1:"));
                let mut challenge = first.response(401, "registrar", None, "").unwrap();
                challenge.set(
                    "WWW-Authenticate",
                    if qop {
                        "Digest realm=realm, nonce=nonce, qop=auth"
                    } else {
                        "Digest realm=realm, nonce=nonce"
                    },
                );
                registrar
                    .send_to(&challenge.encode().unwrap(), source)
                    .await
                    .unwrap();
                let (length, source) = registrar.recv_from(&mut buffer).await.unwrap();
                let second = Message::parse(&buffer[..length]).unwrap();
                assert_eq!(second.cseq().unwrap(), (2, "REGISTER"));
                assert_eq!(first.call_id(), second.call_id());
                assert_ne!(first.branch().unwrap(), second.branch().unwrap());
                let fields = parameters(second.header("authorization").unwrap()).unwrap();
                let auth = qop.then(|| (fields["nc"].as_str(), fields["cnonce"].as_str()));
                assert_eq!(
                    fields["response"],
                    digest::response(
                        "bob1",
                        "realm",
                        "secret",
                        "REGISTER",
                        &fields["uri"],
                        "nonce",
                        auth
                    )
                );
                registrar
                    .send_to(
                        &second
                            .response(200, "registrar", None, "")
                            .unwrap()
                            .encode()
                            .unwrap(),
                        source,
                    )
                    .await
                    .unwrap();
            });
            let mut plan = super::super::tests::plan();
            plan.target = match address {
                std::net::SocketAddr::V4(address) => address,
                _ => unreachable!(),
            };
            register(&endpoint, &plan, 1).await.unwrap();
            registrar_task.await.unwrap();
            stop_sender.send(true).unwrap();
            dispatcher.await.unwrap().unwrap();
            assert_eq!(
                counters
                    .pending_transactions
                    .load(std::sync::atomic::Ordering::Relaxed),
                0
            );
            assert!(endpoint.inbox("new-call").is_ok());
        }
    }
    #[test]
    fn client_nonces_have_128_random_bits_encoded_as_hex() {
        let first = cnonce().unwrap();
        let second = cnonce().unwrap();
        assert_eq!(first.len(), 32);
        assert_ne!(first, second);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    #[test]
    fn authorization_supports_qop_and_opaque_and_rejects_other_algorithms() {
        let challenge =
            "Digest realm=\"test\", nonce=\"nonce\", qop=\"auth-int,auth\", opaque=\"opaque\"";
        let value =
            authorization(challenge, "bob1", "secret", "sip:example.com", "random").unwrap();
        assert!(value.contains("qop=auth, nc=00000001, cnonce=\"random\""));
        assert!(value.contains("opaque=\"opaque\""));
        let value = authorization(
            "Digest realm=\"test\", nonce=\"nonce\"",
            "bob1",
            "secret",
            "sip:example.com",
            "random",
        )
        .unwrap();
        assert!(!value.contains("qop="));
        assert!(authorization(
            "Digest realm=x, nonce=y, algorithm=SHA-256",
            "bob",
            "secret",
            "sip:x",
            "r"
        )
        .is_err());
    }
    #[test]
    fn quoting_escapes_digest_values() {
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }
}

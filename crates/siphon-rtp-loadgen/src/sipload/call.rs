//! UAC and UAS dialog lifecycles.
use super::{
    endpoint::{branch, destination, unique, Endpoint, Inbox, Pending},
    media::Media,
    Error, RunPlan,
};
use crate::sip::{
    message::{Error as ParseError, Message},
    sdp,
    timers::{Event, Kind, Timer},
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

struct Dialog {
    target: String,
    routes: Vec<String>,
    from: String,
    to: String,
    call_id: String,
    contact: String,
}
impl Dialog {
    fn new(request: &Message, response: &Message) -> Result<Self, Error> {
        let mut routes = response.record_routes()?;
        routes.reverse();
        if response.to_tag().is_none() {
            return Err(ParseError("200 missing To tag").into());
        }
        Ok(Self {
            target: response.contact()?,
            routes,
            from: request
                .header("from")
                .ok_or(ParseError("missing From"))?
                .into(),
            to: response
                .header("to")
                .ok_or(ParseError("missing To"))?
                .into(),
            call_id: request.call_id().into(),
            contact: request.contact()?,
        })
    }
    fn request(
        &self,
        method: &str,
        sequence: u32,
        local: &str,
    ) -> Result<(Message, String), Error> {
        let mut routes = self.routes.clone();
        let next = routes
            .first()
            .cloned()
            .unwrap_or_else(|| self.target.clone());
        // RFC 3261 §12.2.1.1: strict routers take the Request-URI; remote target goes last.
        let target = if routes.first().is_some_and(|route| {
            !route
                .split(';')
                .skip(1)
                .any(|part| part.eq_ignore_ascii_case("lr"))
        }) {
            let strict = routes.remove(0);
            routes.push(self.target.clone());
            strict
        } else {
            self.target.clone()
        };
        let mut request = Message::request(
            method,
            &target,
            local,
            &branch(),
            &self.from,
            &self.to,
            &self.call_id,
            sequence,
            &self.contact,
            "",
        );
        for route in routes {
            request.headers.push(("Route".into(), format!("<{route}>")));
        }
        Ok((request, next))
    }
}
struct StreamGuard {
    media: Arc<Media>,
    id: u32,
}
impl Drop for StreamGuard {
    fn drop(&mut self) {
        let _ = self.media.stop(self.id);
    }
}
pub async fn originate(
    endpoint: Endpoint,
    plan: Arc<RunPlan>,
    media: Arc<Media>,
    index: u64,
) -> Result<(), Error> {
    let call_id = unique();
    let mut inbox = endpoint.inbox(&call_id)?;
    let target = format!("sip:bob{}@{}", index as usize % plan.users + 1, plan.domain);
    let contact = format!("sip:sipload@{}", endpoint.local);
    let request = Message::request(
        "INVITE",
        &target,
        &endpoint.local.to_string(),
        &branch(),
        &format!("<sip:sipload@{}>;tag={}", plan.domain, unique()),
        &format!("<{target}>"),
        &call_id,
        1,
        &contact,
        &sdp::offer(media.address(0, index as usize), index),
    );
    let start = Instant::now();
    let response = endpoint
        .exchange(&mut inbox, &request, plan.target.into())
        .await?;
    let setup_microseconds = start.elapsed().as_micros() as u64;
    let status = response
        .status()
        .ok_or(ParseError("expected INVITE response"))?;
    if !(200..300).contains(&status) {
        // Non-2xx ACK belongs to the INVITE transaction and reuses its branch (§17.1.1.3).
        let mut ack = request.clone();
        ack.start = crate::sip::message::Start::Request {
            method: "ACK".into(),
            uri: target,
        };
        ack.body.clear();
        ack.set("CSeq", "1 ACK");
        ack.set("To", response.header("to").ok_or(ParseError("missing To"))?);
        endpoint.send(&ack, plan.target.into()).await?;
        endpoint.remember(&response, &ack, plan.target.into())?;
        return Err(Error::Status(status));
    }
    endpoint
        .counters
        .setup
        .lock()
        .map_err(|_| Error::Worker)?
        .record(setup_microseconds);
    let dialog = Dialog::new(&request, &response)?;
    let (ack, next) = dialog.request("ACK", 1, &endpoint.local.to_string())?;
    let next = destination(&next).await?;
    endpoint.send(&ack, next).await?;
    endpoint.remember(&response, &ack, next)?;
    let media_target = sdp::parse(&response.body);
    let stream = match media_target {
        Ok(address) => Some(StreamGuard {
            id: media.start(0, index as usize, address)?,
            media: media.clone(),
        }),
        Err(_) => None,
    };
    let deadline = Instant::now()
        + if stream.is_some() {
            plan.hold
        } else {
            Duration::ZERO
        };
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            incoming = inbox.receiver.recv() => {
                let (incoming, source) = incoming.ok_or(Error::Worker)?;
                if let Some(method) = incoming.method() {
                    if method == "ACK" {
                        continue;
                    }
                    let known = incoming.to_tag() == request.from_tag()
                        && incoming.from_tag() == response.to_tag();
                    let answer = incoming.response(
                        if known { 200 } else { 481 }, "unused", None, "",
                    )?;
                    endpoint.send(&answer, source).await?;
                    endpoint.remember(&incoming, &answer, source)?;
                    if known && method == "BYE" {
                        return Ok(());
                    }
                }
            }
        }
    }
    drop(stream);
    let (bye, next) = dialog.request("BYE", 2, &endpoint.local.to_string())?;
    let next = destination(&next).await?;
    let start = Instant::now();
    let response = endpoint.exchange(&mut inbox, &bye, next).await?;
    let bye_microseconds = start.elapsed().as_micros() as u64;
    if !response
        .status()
        .is_some_and(|status| (200..300).contains(&status))
    {
        return Err(Error::Status(response.status().unwrap_or(0)));
    }
    endpoint
        .counters
        .bye
        .lock()
        .map_err(|_| Error::Worker)?
        .record(bye_microseconds);
    media_target?;
    Ok(())
}

pub async fn serve(
    endpoint: Endpoint,
    mut inbox: Inbox,
    invite: Message,
    source: SocketAddr,
    plan: Arc<RunPlan>,
    media: Arc<Media>,
) -> Result<(), Error> {
    let tag = unique();
    endpoint
        .send(&invite.response(100, &tag, None, "")?, source)
        .await?;
    let destination = match sdp::parse(&invite.body) {
        Ok(destination) => destination,
        Err(error) => {
            let response = invite.response(488, &tag, None, "")?;
            endpoint.send(&response, source).await?;
            endpoint.remember(&invite, &response, source)?;
            return Err(error.into());
        }
    };
    // Call IDs differ across a B2BUA; hashing them spreads B-leg offers independently of A legs.
    let index = invite.call_id().bytes().fold(0usize, |value, byte| {
        value.wrapping_mul(31).wrapping_add(usize::from(byte))
    });
    let response = invite.response(
        200,
        &tag,
        Some(&format!("sip:bob@{}", endpoint.local)),
        &sdp::offer(media.address(1, index), index as u64),
    )?;
    endpoint.send(&response, source).await?;
    endpoint.remember(&invite, &response, source)?;
    let mut timer = Timer::new(Kind::Server);
    let mut pending = Some(Pending::new(endpoint.counters.clone()));
    let mut stream: Option<StreamGuard> = None;
    let mut deadline = Instant::now() + Duration::from_secs(32);
    loop {
        tokio::select! {
            event = timer.wait() => match event {
                Event::Timeout => return Err(Error::Timeout),
                Event::Retransmit => endpoint.retransmit(&response, source).await?,
            },
            _ = tokio::time::sleep_until(deadline) => return Err(Error::Timeout),
            incoming = inbox.receiver.recv() => {
                let (incoming, address) = incoming.ok_or(Error::Worker)?;
                let Some(method) = incoming.method() else {
                    continue;
                };
                if method == "INVITE" && incoming.branch()? == invite.branch()?
                    && incoming.cseq()? == invite.cseq()?
                {
                    endpoint.retransmit(&response, address).await?;
                    continue;
                }
                let known = incoming.to_tag().as_deref() == Some(&tag)
                    && incoming.from_tag() == invite.from_tag();
                if method == "ACK" {
                    if known && incoming.cseq()?.0 == invite.cseq()?.0 && stream.is_none() {
                        timer.finish();
                        pending.take();
                        stream = Some(StreamGuard {
                            id: media.start(1, index, destination)?,
                            media: media.clone(),
                        });
                        deadline = Instant::now() + plan.hold + Duration::from_secs(32);
                    }
                    continue;
                }
                let answer = incoming.response(if known { 200 } else { 481 }, &tag, None, "")?;
                endpoint.send(&answer, address).await?;
                endpoint.remember(&incoming, &answer, address)?;
                if known && method == "BYE" {
                    endpoint.remember(&invite, &response, source)?;
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn route_sets_reverse_for_uac_and_support_strict_routing() {
        let request = Message::request(
            "INVITE",
            "sip:b@127.0.0.1",
            "127.0.0.1:5060",
            "z9hG4bKone",
            "<sip:a@local>;tag=a",
            "<sip:b@local>",
            "call",
            1,
            "sip:a@127.0.0.1:5060",
            "",
        );
        let mut response = request
            .response(200, "b", Some("sip:b@127.0.0.1:5061"), "")
            .unwrap();
        response.headers.push((
            "Record-Route".into(),
            "<sip:127.0.0.1:5070;lr>, <sip:127.0.0.1:5080;lr>".into(),
        ));
        let dialog = Dialog::new(&request, &response).unwrap();
        let (ack, next) = dialog.request("ACK", 1, "127.0.0.1:5060").unwrap();
        assert_eq!(next, "sip:127.0.0.1:5080;lr");
        assert_eq!(ack.header("route"), Some("<sip:127.0.0.1:5080;lr>"));
        assert_eq!(ack.to_tag(), Some("b".into()));
        assert!(ack
            .encode()
            .unwrap()
            .starts_with(b"ACK sip:b@127.0.0.1:5061 SIP/2.0"));
        response.set("Record-Route", "<sip:127.0.0.1:5070>");
        let dialog = Dialog::new(&request, &response).unwrap();
        let (bye, next) = dialog.request("BYE", 2, "127.0.0.1:5060").unwrap();
        assert_eq!(next, "sip:127.0.0.1:5070");
        assert_eq!(bye.header("route"), Some("<sip:b@127.0.0.1:5061>"));
        assert!(bye
            .encode()
            .unwrap()
            .starts_with(b"BYE sip:127.0.0.1:5070 SIP/2.0"));
    }
}

//! One receive dispatcher per SIP socket, routing dialogs without concurrent recv races.
use super::{call, media::Media, Error, RunPlan};
use crate::sip::{
    message::{Error as ParseError, Message},
    timers::{Event, Kind, Timer},
};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinSet, time::Instant};

static IDENTIFIER: AtomicU64 = AtomicU64::new(1);
pub fn unique() -> String {
    format!(
        "{:x}-{:x}-{:x}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        IDENTIFIER.fetch_add(1, Ordering::Relaxed)
    )
}
pub fn branch() -> String {
    format!("z9hG4bK{}", unique())
}
pub async fn destination(uri: &str) -> Result<SocketAddr, Error> {
    let address = uri
        .strip_prefix("sip:")
        .ok_or(ParseError("unsupported target URI"))?
        .split([';', '?'])
        .next()
        .ok_or(ParseError("empty URI"))?;
    let host = address
        .rsplit('@')
        .next()
        .ok_or(ParseError("empty URI host"))?;
    let address = if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:5060")
    };
    tokio::net::lookup_host(address)
        .await?
        .find(SocketAddr::is_ipv4)
        .ok_or(Error::Plan("no IPv4 target address"))
}
#[derive(Default)]
pub struct Counters {
    pub sip_messages_dropped: Failures,
    pub sip_send_errors: Failures,
    pub retransmitted_sent: AtomicU64,
    pub retransmitted_received: AtomicU64,
    pub active_server: AtomicUsize,
    pub server_failures: AtomicU64,
    pub pending_transactions: AtomicUsize,
    pub setup: Mutex<crate::stats::LatencyHistogram>,
    pub bye: Mutex<crate::stats::LatencyHistogram>,
    pub server_failed_by_reason: Mutex<std::collections::BTreeMap<String, u64>>,
}
/// Failure accounting must remain available even if an earlier writer panicked.
#[derive(Default)]
pub struct Failures(Mutex<BTreeMap<String, u64>>);
impl Failures {
    pub fn record(&self, reason: impl ToString) {
        let mut counts = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        *counts.entry(reason.to_string()).or_default() += 1;
    }
    pub fn snapshot(&self) -> BTreeMap<String, u64> {
        self.0
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }
}
fn message_lock<'a, T>(
    lock: &'a Mutex<T>,
    reason: &'static str,
) -> Result<std::sync::MutexGuard<'a, T>, Error> {
    match lock.lock() {
        Ok(guard) => Ok(guard),
        Err(poison) => {
            // Skip this message, but restore access so one panic cannot disable the socket.
            drop(poison.into_inner());
            lock.clear_poison();
            Err(Error::Plan(reason))
        }
    }
}
fn socket_fatal(error: &std::io::Error) -> bool {
    // On the supported Linux host only EBADF/ENOTSOCK invalidate this owned socket.
    matches!(error.raw_os_error(), Some(9 | 88))
}
struct Cached {
    expires: Instant,
    bytes: Vec<u8>,
    destination: SocketAddr,
}
type RouteMap = HashMap<String, mpsc::UnboundedSender<(Message, SocketAddr)>>;
#[derive(Clone)]
pub struct Endpoint {
    pub socket: Arc<UdpSocket>,
    pub local: SocketAddr,
    pub counters: Arc<Counters>,
    routes: Arc<Mutex<RouteMap>>,
    cache: Arc<Mutex<HashMap<String, Cached>>>,
}
/// Removing the route on every exit path prevents failed transactions retaining mailboxes.
pub struct Inbox {
    pub receiver: mpsc::UnboundedReceiver<(Message, SocketAddr)>,
    endpoint: Endpoint,
    call_id: String,
}
impl Drop for Inbox {
    fn drop(&mut self) {
        if let Ok(mut routes) = self.endpoint.routes.lock() {
            routes.remove(&self.call_id);
        }
    }
}
impl Endpoint {
    pub async fn bind(address: SocketAddr, counters: Arc<Counters>) -> Result<Self, Error> {
        let socket = Arc::new(UdpSocket::bind(address).await?);
        Ok(Self {
            local: socket.local_addr()?,
            socket,
            counters,
            routes: Arc::default(),
            cache: Arc::default(),
        })
    }
    pub fn inbox(&self, call_id: &str) -> Result<Inbox, Error> {
        let (sender, receiver) = mpsc::unbounded_channel();
        message_lock(&self.routes, "poisoned routes")?.insert(call_id.into(), sender);
        Ok(Inbox {
            receiver,
            endpoint: self.clone(),
            call_id: call_id.into(),
        })
    }
    pub async fn send(&self, message: &Message, target: SocketAddr) -> Result<(), Error> {
        self.send_bytes(&message.encode()?, target).await
    }
    async fn send_bytes(&self, bytes: &[u8], target: SocketAddr) -> Result<(), Error> {
        match self.socket.send_to(bytes, target).await {
            Ok(_) => Ok(()),
            Err(error) => {
                self.counters.sip_send_errors.record(error.to_string());
                Err(error.into())
            }
        }
    }
    fn dropped(&self, error: &Error) -> Result<(), Error> {
        self.counters.sip_messages_dropped.record(error.to_string());
        if let Error::Io(error) = error {
            if socket_fatal(error) {
                return Err(
                    std::io::Error::from_raw_os_error(error.raw_os_error().unwrap_or(9)).into(),
                );
            }
        }
        Ok(())
    }
    async fn handle_datagram(
        &self,
        bytes: &[u8],
        source: SocketAddr,
        server: &Option<(Arc<RunPlan>, Arc<Media>)>,
        servers: &mut JoinSet<Result<(), Error>>,
        seen: &mut HashMap<String, Instant>,
    ) -> Result<(), Error> {
        let message = Message::parse(bytes)?;
        let key = cache_key(&message)?;
        if seen
            .insert(key.clone(), Instant::now() + Duration::from_secs(32))
            .is_some()
        {
            self.received_again();
        }
        let cached = message_lock(&self.cache, "poisoned cache")?
            .get(&key)
            .filter(|entry| entry.expires > Instant::now())
            .map(|entry| (entry.bytes.clone(), entry.destination));
        if let Some((bytes, target)) = cached {
            self.send_bytes(&bytes, target).await?;
            self.counters
                .retransmitted_sent
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let route = message_lock(&self.routes, "poisoned routes")?
            .get(message.call_id())
            .cloned();
        if let Some(sender) = route {
            sender
                .send((message, source))
                .map_err(|_| Error::Plan("closed dialog inbox"))?;
            return Ok(());
        }
        if message.method() == Some("INVITE") && message.to_tag().is_none() {
            if let Some((plan, media)) = server {
                let inbox = self.inbox(message.call_id())?;
                self.counters.active_server.fetch_add(1, Ordering::Relaxed);
                servers.spawn(call::serve(
                    self.clone(),
                    inbox,
                    message,
                    source,
                    plan.clone(),
                    media.clone(),
                ));
                return Ok(());
            }
        }
        // ACK never has a response, including an unknown ACK (RFC 3261 §8.2.6).
        if message.method().is_some_and(|method| method != "ACK") {
            self.send(&message.response(481, &unique(), None, "")?, source)
                .await?;
        }
        Ok(())
    }
    fn server_finished(&self, result: Result<Result<(), Error>, tokio::task::JoinError>) {
        self.counters.active_server.fetch_sub(1, Ordering::Relaxed);
        let error = match result {
            Ok(Ok(())) => return,
            Ok(Err(error)) => error.to_string(),
            Err(error) => error.to_string(),
        };
        self.counters
            .server_failures
            .fetch_add(1, Ordering::Relaxed);
        let mut reasons = self
            .counters
            .server_failed_by_reason
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *reasons.entry(error).or_default() += 1;
    }
    pub async fn retransmit(&self, message: &Message, target: SocketAddr) -> Result<(), Error> {
        self.send(message, target).await?;
        self.counters
            .retransmitted_sent
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    pub fn received_again(&self) {
        self.counters
            .retransmitted_received
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn remember(
        &self,
        original: &Message,
        reply: &Message,
        target: SocketAddr,
    ) -> Result<(), Error> {
        let key = cache_key(original)?;
        message_lock(&self.cache, "poisoned cache")?.insert(
            key,
            Cached {
                expires: Instant::now() + Duration::from_secs(32),
                bytes: reply.encode()?,
                destination: target,
            },
        );
        Ok(())
    }
    pub async fn dispatch(
        self,
        server: Option<(Arc<RunPlan>, Arc<Media>)>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), Error> {
        let mut buffer = [0; 65535];
        let mut servers: JoinSet<Result<(), Error>> = JoinSet::new();
        let mut seen = HashMap::new();
        let mut cleanup = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        break;
                    }
                }
                _ = cleanup.tick() => {
                    match message_lock(&self.cache, "poisoned cache") {
                        Ok(mut cache) => cache.retain(|_, cached| cached.expires > Instant::now()),
                        Err(error) => self.counters.sip_messages_dropped.record(error),
                    }
                    seen.retain(|_, expires| *expires > Instant::now());
                }
                Some(result) = servers.join_next(), if !servers.is_empty() => {
                    self.server_finished(result);
                }
                packet = self.socket.recv_from(&mut buffer) => {
                    let result = match packet {
                        Ok((length, source)) => self.handle_datagram(
                            &buffer[..length], source, &server, &mut servers, &mut seen,
                        ).await,
                        Err(error) => Err(Error::Io(error)),
                    };
                    if let Err(error) = result {
                        self.dropped(&error)?;
                    }
                }
            }
        }
        servers.abort_all();
        while let Some(result) = servers.join_next().await {
            self.server_finished(result);
        }
        Ok(())
    }
    pub async fn exchange(
        &self,
        inbox: &mut Inbox,
        request: &Message,
        target: SocketAddr,
    ) -> Result<Message, Error> {
        let _pending = Pending::new(self.counters.clone());
        self.send(request, target).await?;
        let mut timer = Timer::new(if request.method() == Some("INVITE") {
            Kind::Invite
        } else {
            Kind::NonInvite
        });
        loop {
            tokio::select! {
                event = timer.wait() => match event {
                    Event::Timeout => return Err(Error::Timeout),
                    Event::Retransmit => self.retransmit(request, target).await?,
                },
                response = inbox.receiver.recv() => {
                    let (response, source) = response.ok_or(Error::Worker)?;
                    if response.method().is_some() {
                        if response.method() != Some("ACK") {
                            let known = response.to_tag().is_some()
                                && response.to_tag() == request.from_tag()
                                && response.from_tag() == request.to_tag();
                            let answer = response.response(
                                if known { 200 } else { 481 }, &unique(), None, "",
                            )?;
                            self.send(&answer, source).await?;
                        }
                        continue;
                    }
                    if response.cseq()? != request.cseq()?
                        || response.branch()? != request.branch()?
                    {
                        continue;
                    }
                    let status = response.status().ok_or(ParseError("expected response"))?;
                    if status < 200 {
                        timer.provisional();
                    } else {
                        return Ok(response);
                    }
                }
            }
        }
    }
}
fn cache_key(message: &Message) -> Result<String, Error> {
    let (sequence, method) = message.cseq()?;
    Ok(format!(
        "{}|{}|{sequence}|{method}|{}|{}",
        message.call_id(),
        message.branch()?,
        message.to_tag().unwrap_or_default(),
        message
            .status()
            .map(|status| status.to_string())
            .unwrap_or_else(|| "request".into())
    ))
}
pub struct Pending(Arc<Counters>);
impl Pending {
    pub fn new(counters: Arc<Counters>) -> Self {
        counters
            .pending_transactions
            .fetch_add(1, Ordering::Relaxed);
        Self(counters)
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.pending_transactions.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn dispatcher_counts_failed_cached_send_and_answers_the_next_request() {
        let counters = Arc::new(Counters::default());
        let endpoint = Endpoint::bind("127.0.0.1:0".parse().unwrap(), counters.clone())
            .await
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = Message::request(
            "OPTIONS",
            "sip:bob@localhost",
            &client.local_addr().unwrap().to_string(),
            "z9hG4bKtest",
            "<sip:a@localhost>;tag=a",
            "<sip:b@localhost>",
            "cached",
            1,
            "sip:a@localhost",
            "",
        );
        let response = request.response(200, "b", None, "").unwrap();
        endpoint
            .remember(&request, &response, "127.0.0.1:0".parse().unwrap())
            .unwrap();
        let target = endpoint.local;
        let (sender, receiver) = tokio::sync::watch::channel(false);
        let dispatcher = tokio::spawn(endpoint.dispatch(None, receiver));
        client
            .send_to(&request.encode().unwrap(), target)
            .await
            .unwrap();
        let mut next = request.clone();
        next.set("Call-ID", "uncached");
        client
            .send_to(&next.encode().unwrap(), target)
            .await
            .unwrap();
        let mut buffer = [0; 4096];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            Message::parse(&buffer[..length]).unwrap().status(),
            Some(481)
        );
        assert_eq!(counters.sip_send_errors.snapshot().values().sum::<u64>(), 1);
        assert_eq!(
            counters
                .sip_messages_dropped
                .snapshot()
                .values()
                .sum::<u64>(),
            1
        );
        sender.send(true).unwrap();
        dispatcher.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn dispatcher_survives_missing_branch_then_answers_invite() {
        let counters = Arc::new(Counters::default());
        let endpoint = Endpoint::bind("127.0.0.1:0".parse().unwrap(), counters.clone())
            .await
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let plan = Arc::new(super::super::tests::plan());
        let media = Arc::new(Media::new(plan.local, 0, 1, plan.ptime, 2).unwrap());
        let target = endpoint.local;
        let (sender, receiver) = tokio::sync::watch::channel(false);
        let dispatcher = tokio::spawn(endpoint.dispatch(Some((plan, media)), receiver));
        let mut request = Message::request(
            "INVITE",
            "sip:bob1@127.0.0.1",
            &client.local_addr().unwrap().to_string(),
            "z9hG4bKtest",
            "<sip:a@localhost>;tag=a",
            "<sip:b@localhost>",
            "call",
            1,
            "sip:a@127.0.0.1",
            &crate::sip::sdp::offer("127.0.0.1:9000".parse().unwrap(), 1),
        );
        let valid = request.encode().unwrap();
        request.set("Via", "SIP/2.0/UDP 127.0.0.1:5060");
        assert!(Message::parse(&request.encode().unwrap()).is_ok());
        client
            .send_to(&request.encode().unwrap(), target)
            .await
            .unwrap();
        client.send_to(&valid, target).await.unwrap();
        let mut buffer = [0; 4096];
        loop {
            let (length, _) =
                tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            if Message::parse(&buffer[..length]).unwrap().status() == Some(200) {
                break;
            }
        }
        assert_eq!(
            counters
                .sip_messages_dropped
                .snapshot()
                .values()
                .sum::<u64>(),
            1
        );
        sender.send(true).unwrap();
        dispatcher.await.unwrap().unwrap();
    }
    #[test]
    fn failure_counts_remain_available_after_lock_poisoning() {
        let failures = Failures::default();
        let _ = std::panic::catch_unwind(|| {
            let _guard = failures.0.lock().unwrap();
            panic!("poison fixture");
        });
        failures.record("ENOBUFS");
        failures.record("ENOBUFS");
        assert_eq!(failures.snapshot()["ENOBUFS"], 2);
    }
    #[test]
    fn poisoned_message_lock_recovers_for_the_next_message() {
        let lock = Mutex::new(5);
        let _ = std::panic::catch_unwind(|| {
            let _guard = lock.lock().unwrap();
            panic!("poison fixture");
        });
        assert!(message_lock(&lock, "poisoned test lock").is_err());
        assert_eq!(*message_lock(&lock, "poisoned test lock").unwrap(), 5);
    }
    #[test]
    fn only_invalid_socket_errors_are_fatal() {
        assert!(socket_fatal(&std::io::Error::from_raw_os_error(9)));
        for code in [1, 11, 105, 111] {
            assert!(!socket_fatal(&std::io::Error::from_raw_os_error(code)));
        }
    }
    #[test]
    fn pending_transaction_guard_releases_on_early_return() {
        let counters = Arc::new(Counters::default());
        {
            let _pending = Pending::new(counters.clone());
            assert_eq!(counters.pending_transactions.load(Ordering::Relaxed), 1);
        }
        assert_eq!(counters.pending_transactions.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn cache_keys_distinguish_provisional_final_and_forked_responses() {
        let request = Message::request(
            "INVITE",
            "sip:b@127.0.0.1",
            "127.0.0.1:5060",
            "z9hG4bKone",
            "<sip:a@local>;tag=a",
            "<sip:b@local>",
            "call",
            1,
            "sip:a@127.0.0.1",
            "",
        );
        let ringing = request.response(180, "b", None, "").unwrap();
        let accepted = request.response(200, "b", None, "").unwrap();
        let fork = request.response(200, "c", None, "").unwrap();
        assert_ne!(cache_key(&ringing).unwrap(), cache_key(&accepted).unwrap());
        assert_ne!(cache_key(&accepted).unwrap(), cache_key(&fork).unwrap());
    }
    #[test]
    fn identifiers_are_unique_and_cookie_prefixed() {
        let first = unique();
        assert_ne!(first, unique());
        assert!(branch().starts_with("z9hG4bK"));
    }
    #[tokio::test]
    async fn uri_resolution_defaults_to_5060() {
        assert_eq!(
            destination("sip:bob@127.0.0.1;lr").await.unwrap(),
            "127.0.0.1:5060".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            destination("sip:127.0.0.1:5090;lr").await.unwrap(),
            "127.0.0.1:5090".parse::<SocketAddr>().unwrap()
        );
        assert!(destination("sips:bad").await.is_err());
    }
}

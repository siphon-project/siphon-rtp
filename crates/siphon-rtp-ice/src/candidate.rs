//! ICE candidates: the RFC 8445 model (type, priority, foundation, component) and the RFC 8839 §5.1
//! SDP grammar that carries them on the wire.
//!
//! The engine has emitted a single hardcoded host candidate since ICE-lite landed, and has *parsed*
//! none at all — a peer's `a=candidate` lines were recognised only in order to be stripped. Candidate
//! pairing, and therefore every later ICE milestone, needs both directions of this grammar plus the
//! priority and foundation arithmetic, which is what this module provides.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use thiserror::Error;

/// The largest component ID ICE defines (RFC 8445 §5.1.2.1: the priority formula's `256 -
/// component ID` term). Component 1 is RTP and component 2 is RTCP (RFC 8445 §4.1.1.1); under
/// RFC 5761 `a=rtcp-mux` there is only component 1.
pub const MAX_COMPONENT_ID: u16 = 256;

/// The SDP attribute a peer sends to say its candidate list is complete (RFC 8838 §14 / RFC 8839
/// §5.1). Its presence ends trickling; its absence means more candidates may still arrive.
pub const END_OF_CANDIDATES_ATTRIBUTE: &str = "a=end-of-candidates";

/// RFC 8839 §5.1 `foundation = 1*32ice-char` — the wire cap on a foundation string.
const MAX_FOUNDATION_LEN: usize = 32;

/// RFC 8839 §5.1: `priority = 1*10DIGIT`, and the value is in `1..=(2^31 - 1)`.
const MAX_PRIORITY: u32 = i32::MAX as u32;

/// How a candidate was learned (RFC 8445 §5.1.1). The order of the variants is the order of their
/// recommended type preferences, most preferred first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CandidateKind {
    /// A local interface address (RFC 8445 §5.1.1.1). Directly on the host, no server involved.
    Host,
    /// Discovered by asking a STUN server what source address it saw (RFC 8445 §5.1.1.2) — the
    /// outside of our NAT.
    ServerReflexive,
    /// Learned from an incoming connectivity check that matched no known candidate (RFC 8445
    /// §7.3.1.3), or from a check response whose mapped address is not one of ours (§7.2.5.3.1).
    PeerReflexive,
    /// Allocated on a TURN server, which relays for us (RFC 8445 §5.1.1.2, RFC 8656 §7).
    Relayed,
}

impl CandidateKind {
    /// The RFC 8445 §5.1.2.2 **recommended** type preference: host 126, peer-reflexive 110,
    /// server-reflexive 100, relayed 0. Higher is more preferred, and the value must be in `0..=126`
    /// so it fits the priority formula's top octet.
    ///
    /// The relative order matters more than the absolute values: relayed last (it costs a server
    /// round trip and bandwidth), host first (direct), reflexive in between. RFC 8445 §5.1.2.2 also
    /// requires that a peer-reflexive candidate outrank the server-reflexive one it was discovered
    /// through, which 110 > 100 satisfies.
    #[must_use]
    pub fn type_preference(self) -> u8 {
        match self {
            CandidateKind::Host => 126,
            CandidateKind::PeerReflexive => 110,
            CandidateKind::ServerReflexive => 100,
            CandidateKind::Relayed => 0,
        }
    }

    /// The RFC 8839 §5.1 `cand-type` token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            CandidateKind::Host => "host",
            CandidateKind::ServerReflexive => "srflx",
            CandidateKind::PeerReflexive => "prflx",
            CandidateKind::Relayed => "relay",
        }
    }

    /// Whether this kind carries a related address (`raddr`/`rport`). RFC 8839 §5.1: the related
    /// address is the base for a reflexive candidate and the mapped address for a relayed one; a host
    /// candidate has none, because it *is* its own base.
    #[must_use]
    pub fn has_related_address(self) -> bool {
        !matches!(self, CandidateKind::Host)
    }
}

impl FromStr for CandidateKind {
    type Err = CandidateParseError;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        match token {
            "host" => Ok(CandidateKind::Host),
            "srflx" => Ok(CandidateKind::ServerReflexive),
            "prflx" => Ok(CandidateKind::PeerReflexive),
            "relay" => Ok(CandidateKind::Relayed),
            other => Err(CandidateParseError::UnknownCandidateType(other.to_string())),
        }
    }
}

impl fmt::Display for CandidateKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

/// The candidate's transport protocol. RFC 8839 §5.1 allows a `transport-extension` token, but this
/// agent is UDP-only by design (see the crate docs): a non-UDP candidate is parsed and preserved so
/// it round-trips, and is simply never paired.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Transport {
    /// `UDP` — the only transport this agent pairs and checks.
    Udp,
    /// Any other `transport-extension` token (e.g. `TCP` from an RFC 6544 peer), preserved verbatim.
    Other(String),
}

impl Transport {
    /// Whether this agent will form candidate pairs over this transport.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        matches!(self, Transport::Udp)
    }

    /// The wire token. RFC 8839 §5.1's ABNF spells the registered value `UDP`; the token is
    /// compared case-insensitively on parse (RFC 8839 §5.1 tokens are case-insensitive) but always
    /// written uppercase.
    #[must_use]
    pub fn token(&self) -> &str {
        match self {
            Transport::Udp => "UDP",
            Transport::Other(token) => token,
        }
    }
}

impl FromStr for Transport {
    type Err = CandidateParseError;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        if token.eq_ignore_ascii_case("udp") {
            return Ok(Transport::Udp);
        }
        if token.is_empty() || !token.bytes().all(is_token_byte) {
            return Err(CandidateParseError::MalformedTransport(token.to_string()));
        }
        Ok(Transport::Other(token.to_ascii_uppercase()))
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

/// Why an `a=candidate` line could not be parsed. Every variant names the offending token, so a log
/// line points at the actual problem rather than "bad SDP".
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CandidateParseError {
    /// The line did not start with `candidate:` / `a=candidate:`.
    #[error("not a candidate attribute")]
    NotACandidate,
    /// Fewer than the eight mandatory fields (RFC 8839 §5.1).
    #[error("candidate has too few fields (expected at least 8, got {0})")]
    TooFewFields(usize),
    /// The foundation was empty or longer than the 32 `ice-char`s RFC 8839 §5.1 allows.
    #[error("malformed foundation {0:?}")]
    MalformedFoundation(String),
    /// The component id was not a number, or fell outside `1..=256` (RFC 8445 §5.1.2.1).
    #[error("malformed component id {0:?} (expected 1..=256)")]
    MalformedComponent(String),
    /// The transport token was empty or not a token.
    #[error("malformed transport {0:?}")]
    MalformedTransport(String),
    /// The priority was not a number, was zero, or exceeded `2^31 - 1` (RFC 8839 §5.1).
    #[error("malformed priority {0:?} (expected 1..=2147483647)")]
    MalformedPriority(String),
    /// The connection address was not an IP literal. This is also what a browser's mDNS
    /// (`*.local`) candidate produces — see [`CandidateParseError::is_unresolved_hostname`].
    #[error("malformed connection address {0:?}")]
    MalformedAddress(String),
    /// The port was not a number in `0..=65535`.
    #[error("malformed port {0:?}")]
    MalformedPort(String),
    /// The `typ` keyword was missing where RFC 8839 §5.1 requires it.
    #[error("missing 'typ' keyword")]
    MissingTyp,
    /// The candidate type token is not one this agent knows.
    #[error("unknown candidate type {0:?}")]
    UnknownCandidateType(String),
    /// `raddr` was given without `rport`, or vice versa.
    #[error("incomplete related address (raddr and rport must appear together)")]
    IncompleteRelatedAddress,
}

impl CandidateParseError {
    /// Whether this failure is an unresolvable hostname rather than malformed syntax — in practice a
    /// browser's mDNS candidate (`<uuid>.local`, draft-ietf-mmusic-mdns-ice-candidates), which we do
    /// not resolve.
    ///
    /// Callers should **skip** such a candidate rather than reject the whole SDP: connectivity with
    /// those peers still succeeds, because their checks reach us and are discovered as peer-reflexive
    /// candidates (RFC 8445 §7.3.1.3).
    #[must_use]
    pub fn is_unresolved_hostname(&self) -> bool {
        matches!(self, CandidateParseError::MalformedAddress(address) if address.contains('.') && address.parse::<IpAddr>().is_err())
    }
}

/// One ICE candidate: a transport address this agent (or its peer) can be reached at, with the
/// metadata pairing needs (RFC 8445 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Identifies the group of candidates that share a type, base, protocol, and server — pairs with
    /// equal foundations are unfrozen together (RFC 8445 §5.1.1.3, §6.1.2.6). Build one with
    /// [`Candidate::compute_foundation`] rather than inventing a scheme per call site.
    pub foundation: String,
    /// Which component of the media stream this candidate is for: 1 = RTP, 2 = RTCP (RFC 8445
    /// §4.1.1.1). Always 1 under `a=rtcp-mux`.
    pub component: u16,
    /// The transport protocol.
    pub transport: Transport,
    /// The RFC 8445 §5.1.2.1 priority. Higher is preferred; pairing sorts on it.
    pub priority: u32,
    /// The transport address to send to.
    pub address: SocketAddr,
    /// How this candidate was learned.
    pub kind: CandidateKind,
    /// `raddr`/`rport` — the base (reflexive) or mapped (relayed) address. RFC 8839 §5.1 requires it
    /// for non-host candidates; it is informational for the peer and MUST NOT be used for pairing.
    pub related: Option<SocketAddr>,
    /// Unrecognised `cand-extension` name/value pairs, preserved in order so a candidate round-trips
    /// byte-for-byte rather than silently losing a peer's extensions.
    pub extensions: Vec<(String, String)>,
}

impl Candidate {
    /// Build a candidate, computing its RFC 8445 §5.1.2.1 priority from the kind's recommended type
    /// preference and the given local preference.
    #[must_use]
    pub fn new(
        foundation: impl Into<String>,
        component: u16,
        address: SocketAddr,
        kind: CandidateKind,
        local_preference: u16,
    ) -> Self {
        Self {
            foundation: foundation.into(),
            component,
            transport: Transport::Udp,
            priority: priority(kind.type_preference(), local_preference, component),
            address,
            kind,
            related: None,
            extensions: Vec::new(),
        }
    }

    /// Attach the related address (`raddr`/`rport`, RFC 8839 §5.1) — the base for a reflexive
    /// candidate, the mapped address for a relayed one.
    #[must_use]
    pub fn with_related(mut self, related: SocketAddr) -> Self {
        self.related = Some(related);
        self
    }

    /// The RFC 8445 §5.1.1.3 foundation for a candidate: *"an arbitrary string that is the same for
    /// two candidates that have the same type, base IP address, protocol, and STUN or TURN server. If
    /// any of these are different, the foundations will be different."*
    ///
    /// Implemented as a stable 64-bit FNV-1a over exactly those four inputs, rendered as decimal
    /// (all `ice-char`s, ≤ 20 characters, so always inside RFC 8839's 32-character cap). Stable
    /// rather than random because a reproducible foundation is testable and makes an ICE restart's
    /// candidate set diffable; the RFC only requires equality to track those four inputs, and this
    /// does so exactly.
    ///
    /// `server` is the STUN/TURN server the candidate was obtained from — `None` for a host
    /// candidate, which involves no server.
    #[must_use]
    pub fn compute_foundation(
        kind: CandidateKind,
        base: IpAddr,
        transport: &Transport,
        server: Option<SocketAddr>,
    ) -> String {
        // FNV-1a, 64-bit: tiny, dependency-free, and (unlike `DefaultHasher`) documented and stable
        // across processes and releases, which is what makes the foundation reproducible.
        const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x1000_0000_01b3;
        let mut hash = OFFSET_BASIS;
        let mut absorb = |bytes: &[u8]| {
            for byte in bytes {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(PRIME);
            }
            // A field separator, so ("a","bc") and ("ab","c") cannot collide.
            hash ^= 0xff;
            hash = hash.wrapping_mul(PRIME);
        };
        absorb(kind.token().as_bytes());
        absorb(base.to_string().as_bytes());
        absorb(transport.token().as_bytes());
        absorb(
            server
                .map(|server| server.to_string())
                .unwrap_or_default()
                .as_bytes(),
        );
        hash.to_string()
    }

    /// Render the RFC 8839 §5.1 attribute value (no `a=candidate:` prefix), e.g.
    /// `1 1 UDP 2130706431 203.0.113.7 30000 typ host`.
    #[must_use]
    pub fn to_attribute_value(&self) -> String {
        let mut line = format!(
            "{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.transport,
            self.priority,
            self.address.ip(),
            self.address.port(),
            self.kind
        );
        if let Some(related) = self.related {
            line.push_str(&format!(" raddr {} rport {}", related.ip(), related.port()));
        }
        for (name, value) in &self.extensions {
            line.push_str(&format!(" {name} {value}"));
        }
        line
    }

    /// Render the full SDP line, `a=candidate:…` (no trailing CRLF).
    #[must_use]
    pub fn to_attribute_line(&self) -> String {
        format!("a=candidate:{}", self.to_attribute_value())
    }

    /// Parse an RFC 8839 §5.1 candidate. Accepts the full SDP line (`a=candidate:…`), the attribute
    /// (`candidate:…`), or the bare value — whichever layer the caller has in hand.
    ///
    /// Never panics on hostile input: every field is validated and reported by name. A browser's
    /// mDNS candidate fails with an error for which
    /// [`is_unresolved_hostname`](CandidateParseError::is_unresolved_hostname) is true, so the caller
    /// can skip that one line instead of discarding the peer's whole candidate list.
    pub fn parse(line: &str) -> Result<Self, CandidateParseError> {
        let value = line
            .trim()
            .strip_prefix("a=")
            .unwrap_or_else(|| line.trim())
            .strip_prefix("candidate:")
            .ok_or(CandidateParseError::NotACandidate)?;

        let fields: Vec<&str> = value.split_whitespace().collect();
        // foundation, component, transport, priority, address, port, "typ", type — eight minimum.
        if fields.len() < 8 {
            return Err(CandidateParseError::TooFewFields(fields.len()));
        }

        let foundation = fields[0];
        if foundation.is_empty()
            || foundation.len() > MAX_FOUNDATION_LEN
            || !foundation.bytes().all(is_ice_char)
        {
            return Err(CandidateParseError::MalformedFoundation(
                foundation.to_string(),
            ));
        }

        let component: u16 = fields[1]
            .parse()
            .ok()
            .filter(|component| (1..=MAX_COMPONENT_ID).contains(component))
            .ok_or_else(|| CandidateParseError::MalformedComponent(fields[1].to_string()))?;

        let transport: Transport = fields[2].parse()?;

        let priority: u32 = fields[3]
            .parse()
            .ok()
            .filter(|priority| (1..=MAX_PRIORITY).contains(priority))
            .ok_or_else(|| CandidateParseError::MalformedPriority(fields[3].to_string()))?;

        let address = parse_socket_addr(fields[4], fields[5])?;

        if fields[6] != "typ" {
            return Err(CandidateParseError::MissingTyp);
        }
        let kind: CandidateKind = fields[7].parse()?;

        // The remainder is `[raddr <ip>] [rport <port>]` followed by extension name/value pairs.
        let mut related_ip: Option<&str> = None;
        let mut related_port: Option<&str> = None;
        let mut extensions = Vec::new();
        let mut rest = &fields[8..];
        while let [name, value, tail @ ..] = rest {
            match *name {
                "raddr" => related_ip = Some(value),
                "rport" => related_port = Some(value),
                _ => extensions.push(((*name).to_string(), (*value).to_string())),
            }
            rest = tail;
        }
        // A trailing name with no value is malformed; RFC 8839 §5.1 extensions are strict pairs.
        if !rest.is_empty() {
            return Err(CandidateParseError::TooFewFields(fields.len()));
        }
        let related = match (related_ip, related_port) {
            (Some(ip), Some(port)) => Some(parse_socket_addr(ip, port)?),
            (None, None) => None,
            _ => return Err(CandidateParseError::IncompleteRelatedAddress),
        };

        Ok(Self {
            foundation: foundation.to_string(),
            component,
            transport,
            priority,
            address,
            kind,
            related,
            extensions,
        })
    }
}

impl fmt::Display for Candidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_attribute_line())
    }
}

/// The RFC 8445 §5.1.2.1 priority formula:
///
/// ```text
/// priority = (2^24)*(type preference) + (2^8)*(local preference) + (256 - component ID)
/// ```
///
/// `type_preference` is clamped to the `0..=126` the formula allows and `component` to `1..=256`, so
/// a caller's bad input yields a well-formed (if suboptimal) priority instead of a wrapped one —
/// this runs on the offer/answer path, which must not panic.
#[must_use]
pub fn priority(type_preference: u8, local_preference: u16, component: u16) -> u32 {
    let type_preference = u32::from(type_preference.min(126));
    let component = component.clamp(1, MAX_COMPONENT_ID);
    (type_preference << 24) | (u32::from(local_preference) << 8) | (256 - u32::from(component))
}

/// Local preferences for a set of local addresses, **interleaved by address family** per RFC 8421
/// §4: a dual-stack host must not order all of one family above the other, or a peer that only has
/// the other family waits through a long run of doomed checks before reaching a usable pair.
///
/// Returns one preference per input address, in the input's order. IPv6 takes the first slot,
/// matching the RFC 6724 default policy's preference for IPv6, and the families then alternate;
/// whichever family runs out first, the remainder keeps descending.
#[must_use]
pub fn interleaved_local_preferences(addresses: &[IpAddr]) -> Vec<u16> {
    let (mut v6, mut v4): (Vec<usize>, Vec<usize>) = (Vec::new(), Vec::new());
    for (index, address) in addresses.iter().enumerate() {
        if address.is_ipv6() {
            v6.push(index);
        } else {
            v4.push(index);
        }
    }
    let mut preferences = vec![0u16; addresses.len()];
    let (mut v6, mut v4) = (v6.into_iter(), v4.into_iter());
    let mut rank = 0u16;
    loop {
        // One round takes the next address of each family, so the two interleave; when one family is
        // exhausted the other simply keeps descending.
        let round: Vec<usize> = [v6.next(), v4.next()].into_iter().flatten().collect();
        if round.is_empty() {
            return preferences;
        }
        for index in round {
            // Descend from the maximum so the first-ranked address is the most preferred.
            preferences[index] = u16::MAX - rank;
            rank = rank.saturating_add(1);
        }
    }
}

/// The `a=ice-options` token list (RFC 8839 §5.6) — how a peer advertises optional ICE behaviour,
/// most importantly `trickle` (RFC 8838).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IceOptions {
    /// The tokens as they appeared, lowercased.
    tokens: Vec<String>,
}

impl IceOptions {
    /// Parse an `a=ice-options:` line (or its bare value): space-separated tokens.
    #[must_use]
    pub fn parse(line: &str) -> Self {
        let value = line
            .trim()
            .strip_prefix("a=")
            .unwrap_or_else(|| line.trim())
            .strip_prefix("ice-options:")
            .unwrap_or("");
        Self {
            tokens: value
                .split_whitespace()
                .map(str::to_ascii_lowercase)
                .collect(),
        }
    }

    /// Whether `token` was advertised (case-insensitive).
    #[must_use]
    pub fn has(&self, token: &str) -> bool {
        self.tokens.iter().any(|have| have == token)
    }

    /// Whether the peer supports trickle ICE (RFC 8838 §4).
    #[must_use]
    pub fn supports_trickle(&self) -> bool {
        self.has("trickle")
    }

    /// The advertised tokens.
    #[must_use]
    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }

    /// Whether no options were advertised.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

/// Parse a `connection-address` + `port` pair (RFC 4566 §5.7 / RFC 8839 §5.1).
fn parse_socket_addr(address: &str, port: &str) -> Result<SocketAddr, CandidateParseError> {
    let ip: IpAddr = address
        .parse()
        .map_err(|_| CandidateParseError::MalformedAddress(address.to_string()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| CandidateParseError::MalformedPort(port.to_string()))?;
    Ok(SocketAddr::new(ip, port))
}

/// RFC 8445 §5.4 `ice-char = ALPHA / DIGIT / "+" / "/"`.
fn is_ice_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

/// RFC 4566 / RFC 8839 `token` characters — the permissive set an extension or transport may use.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-!#$%&'*+.^_`|~".contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host-candidate priority the engine has advertised since ICE-lite landed: type preference
    /// 126, local preference 65535, component 1. A known-answer check on the §5.1.2.1 formula.
    const HOST_COMPONENT_1: u32 = 2_130_706_431;

    #[test]
    fn priority_matches_the_rfc_8445_formula_for_known_values() {
        // (126 << 24) + (65535 << 8) + (256 - 1)
        assert_eq!(priority(126, 65535, 1), HOST_COMPONENT_1);
        // Component 2 (RTCP under non-mux) is exactly one less than component 1.
        assert_eq!(priority(126, 65535, 2), HOST_COMPONENT_1 - 1);
        // The lowest-priority candidate the formula can express: relayed, no local preference,
        // the last component.
        assert_eq!(priority(0, 0, MAX_COMPONENT_ID), 0);
        // Each kind's recommended type preference lands in the documented order.
        let of = |kind: CandidateKind| priority(kind.type_preference(), 65535, 1);
        assert!(of(CandidateKind::Host) > of(CandidateKind::PeerReflexive));
        assert!(of(CandidateKind::PeerReflexive) > of(CandidateKind::ServerReflexive));
        assert!(of(CandidateKind::ServerReflexive) > of(CandidateKind::Relayed));
        // Every priority stays inside RFC 8839 §5.1's 1..=2^31-1 wire range.
        assert!(of(CandidateKind::Host) <= MAX_PRIORITY);
    }

    #[test]
    fn priority_clamps_out_of_range_input_instead_of_wrapping() {
        // 255 is not a legal type preference; clamping to 126 keeps the value well-formed.
        assert_eq!(priority(255, 65535, 1), HOST_COMPONENT_1);
        // Component 0 does not exist (RFC 8445 §4.1.1.1 numbers from 1).
        assert_eq!(priority(126, 65535, 0), HOST_COMPONENT_1);
        // Beyond the last component, clamped rather than underflowing the `256 - component` term.
        assert_eq!(priority(126, 65535, 9999), priority(126, 65535, 256));
    }

    #[test]
    fn foundation_tracks_exactly_the_rfc_8445_inputs() {
        let base: IpAddr = "192.0.2.1".parse().expect("ip");
        let other_base: IpAddr = "192.0.2.2".parse().expect("ip");
        let server: SocketAddr = "198.51.100.1:3478".parse().expect("addr");
        let other_server: SocketAddr = "198.51.100.2:3478".parse().expect("addr");
        let base_foundation =
            Candidate::compute_foundation(CandidateKind::Host, base, &Transport::Udp, None);

        // Same type + base + protocol + server ⇒ same foundation.
        assert_eq!(
            base_foundation,
            Candidate::compute_foundation(CandidateKind::Host, base, &Transport::Udp, None)
        );
        // Any of the four differing ⇒ different foundation.
        assert_ne!(
            base_foundation,
            Candidate::compute_foundation(
                CandidateKind::ServerReflexive,
                base,
                &Transport::Udp,
                None
            )
        );
        assert_ne!(
            base_foundation,
            Candidate::compute_foundation(CandidateKind::Host, other_base, &Transport::Udp, None)
        );
        assert_ne!(
            base_foundation,
            Candidate::compute_foundation(
                CandidateKind::Host,
                base,
                &Transport::Other("TCP".into()),
                None
            )
        );
        assert_ne!(
            Candidate::compute_foundation(
                CandidateKind::ServerReflexive,
                base,
                &Transport::Udp,
                Some(server)
            ),
            Candidate::compute_foundation(
                CandidateKind::ServerReflexive,
                base,
                &Transport::Udp,
                Some(other_server)
            ),
            "candidates from different STUN servers have different foundations"
        );
        // And it fits the wire grammar.
        assert!(base_foundation.len() <= MAX_FOUNDATION_LEN);
        assert!(base_foundation.bytes().all(is_ice_char));
    }

    #[test]
    fn parses_a_host_candidate() {
        let candidate =
            Candidate::parse("a=candidate:1 1 UDP 2130706431 203.0.113.7 30000 typ host")
                .expect("valid host candidate");
        assert_eq!(candidate.foundation, "1");
        assert_eq!(candidate.component, 1);
        assert_eq!(candidate.transport, Transport::Udp);
        assert_eq!(candidate.priority, HOST_COMPONENT_1);
        assert_eq!(
            candidate.address,
            "203.0.113.7:30000".parse::<SocketAddr>().expect("addr")
        );
        assert_eq!(candidate.kind, CandidateKind::Host);
        assert_eq!(candidate.related, None);
    }

    #[test]
    fn parses_a_server_reflexive_candidate_with_its_related_address() {
        let candidate = Candidate::parse(
            "candidate:3 1 udp 1694498815 198.51.100.7 45000 typ srflx raddr 10.0.0.5 rport 45000",
        )
        .expect("valid srflx candidate");
        assert_eq!(candidate.kind, CandidateKind::ServerReflexive);
        assert_eq!(
            candidate.transport,
            Transport::Udp,
            "the transport token is case-insensitive"
        );
        assert_eq!(
            candidate.related,
            Some("10.0.0.5:45000".parse().expect("addr")),
            "raddr/rport is the base address"
        );
    }

    #[test]
    fn parses_ipv6_and_preserves_unknown_extensions() {
        let candidate = Candidate::parse(
            "a=candidate:9 2 UDP 2130706430 2001:db8::1 30001 typ host generation 0 network-id 3",
        )
        .expect("valid v6 candidate");
        assert_eq!(candidate.component, 2, "the RTCP component under non-mux");
        assert!(candidate.address.is_ipv6());
        assert_eq!(
            candidate.extensions,
            vec![
                ("generation".to_string(), "0".to_string()),
                ("network-id".to_string(), "3".to_string())
            ],
            "a peer's extensions survive a round trip"
        );
    }

    #[test]
    fn formats_back_to_the_line_it_parsed() {
        for line in [
            "a=candidate:1 1 UDP 2130706431 203.0.113.7 30000 typ host",
            "a=candidate:3 1 UDP 1694498815 198.51.100.7 45000 typ srflx raddr 10.0.0.5 rport 45000",
            "a=candidate:7 1 UDP 16777215 192.0.2.9 50000 typ relay raddr 198.51.100.7 rport 45000",
            "a=candidate:9 2 UDP 2130706430 2001:db8::1 30001 typ host generation 0",
        ] {
            let candidate = Candidate::parse(line).expect("parses");
            assert_eq!(candidate.to_attribute_line(), line, "round trip");
        }
    }

    #[test]
    fn rejects_malformed_candidates_without_panicking() {
        for (line, expected) in [
            ("a=ice-lite", CandidateParseError::NotACandidate),
            (
                "a=candidate:1 1 UDP 2130706431 203.0.113.7 30000 typ",
                CandidateParseError::TooFewFields(7),
            ),
            (
                "a=candidate:1 1 UDP 2130706431 203.0.113.7 30000 xyz host",
                CandidateParseError::MissingTyp,
            ),
            (
                "a=candidate:1 0 UDP 2130706431 203.0.113.7 30000 typ host",
                CandidateParseError::MalformedComponent("0".into()),
            ),
            (
                "a=candidate:1 257 UDP 2130706431 203.0.113.7 30000 typ host",
                CandidateParseError::MalformedComponent("257".into()),
            ),
            (
                "a=candidate:1 1 UDP 0 203.0.113.7 30000 typ host",
                CandidateParseError::MalformedPriority("0".into()),
            ),
            (
                "a=candidate:1 1 UDP 4294967295 203.0.113.7 30000 typ host",
                CandidateParseError::MalformedPriority("4294967295".into()),
            ),
            (
                "a=candidate:1 1 UDP 2130706431 203.0.113.7 70000 typ host",
                CandidateParseError::MalformedPort("70000".into()),
            ),
            (
                "a=candidate:1 1 UDP 2130706431 203.0.113.7 30000 typ bogus",
                CandidateParseError::UnknownCandidateType("bogus".into()),
            ),
            (
                "a=candidate:1 1 UDP 2130706431 203.0.113.7 30000 typ srflx raddr 10.0.0.5",
                CandidateParseError::IncompleteRelatedAddress,
            ),
            (
                "a=candidate: 1 UDP 2130706431 203.0.113.7 30000 typ host",
                CandidateParseError::TooFewFields(7),
            ),
        ] {
            assert_eq!(Candidate::parse(line), Err(expected), "line: {line}");
        }
    }

    #[test]
    fn an_mdns_candidate_is_reported_as_an_unresolved_hostname() {
        // What Chrome/Firefox actually send. We do not resolve `.local`; the caller must be able to
        // skip this one line rather than discard the peer's whole list — connectivity still works via
        // peer-reflexive discovery from the browser's own checks.
        let error = Candidate::parse(
            "a=candidate:1 1 UDP 2130706431 4b2ee7f1-9c1e-4e0e-8f7a-1c3e5d7b9a11.local 30000 typ host",
        )
        .expect_err("hostnames are not resolved");
        assert!(error.is_unresolved_hostname());
        // A genuinely malformed address is not mistaken for one.
        let error = Candidate::parse("a=candidate:1 1 UDP 2130706431 999 30000 typ host")
            .expect_err("not an address");
        assert!(!error.is_unresolved_hostname());
    }

    #[test]
    fn builds_a_candidate_with_the_derived_priority() {
        let address: SocketAddr = "203.0.113.7:30000".parse().expect("addr");
        let candidate = Candidate::new("abc", 1, address, CandidateKind::Host, 65535);
        assert_eq!(candidate.priority, HOST_COMPONENT_1);
        assert_eq!(
            candidate.to_attribute_line(),
            "a=candidate:abc 1 UDP 2130706431 203.0.113.7 30000 typ host"
        );
        let relayed = Candidate::new("xyz", 1, address, CandidateKind::Relayed, 65535)
            .with_related("198.51.100.7:45000".parse().expect("addr"));
        assert!(relayed.kind.has_related_address());
        assert!(relayed.to_attribute_line().contains("raddr 198.51.100.7"));
    }

    #[test]
    fn dual_stack_local_preferences_interleave_the_families() {
        let addresses: Vec<IpAddr> = ["192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2"]
            .iter()
            .map(|address| address.parse().expect("ip"))
            .collect();
        let preferences = interleaved_local_preferences(&addresses);
        // RFC 8421 §4: families alternate, IPv6 first — so the ranking is v6, v4, v6, v4 and no
        // family is starved behind the whole of the other.
        assert!(
            preferences[2] > preferences[0],
            "first v6 outranks first v4"
        );
        assert!(
            preferences[0] > preferences[3],
            "first v4 outranks second v6"
        );
        assert!(
            preferences[3] > preferences[1],
            "second v6 outranks second v4"
        );
        // All distinct, so no two candidates collide on priority.
        let mut sorted = preferences.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), preferences.len());
    }

    #[test]
    fn single_family_local_preferences_simply_descend() {
        let addresses: Vec<IpAddr> = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
            .iter()
            .map(|address| address.parse().expect("ip"))
            .collect();
        let preferences = interleaved_local_preferences(&addresses);
        assert_eq!(preferences, vec![u16::MAX, u16::MAX - 1, u16::MAX - 2]);
        assert!(interleaved_local_preferences(&[]).is_empty());
    }

    #[test]
    fn parses_ice_options() {
        let options = IceOptions::parse("a=ice-options:trickle ice2");
        assert!(options.supports_trickle());
        assert!(options.has("ice2"));
        assert!(!options.has("renomination"));
        assert_eq!(options.tokens().len(), 2);
        // Case-insensitive, and a line without options yields nothing.
        assert!(IceOptions::parse("ice-options:TRICKLE").supports_trickle());
        assert!(IceOptions::parse("a=ice-lite").is_empty());
        assert!(!IceOptions::parse("a=ice-lite").supports_trickle());
    }

    #[test]
    fn unsupported_transports_parse_but_are_never_paired() {
        // An RFC 6544 peer's TCP candidate must not break parsing of the rest of its SDP; it is
        // preserved and simply not paired (this agent is UDP-only).
        let candidate = Candidate::parse(
            "a=candidate:2 1 TCP 2128609279 203.0.113.7 9 typ host tcptype active",
        )
        .expect("parses");
        assert!(!candidate.transport.is_supported());
        assert_eq!(candidate.transport.token(), "TCP");
        assert!(Transport::Udp.is_supported());
    }

    proptest::proptest! {
        /// Any candidate we can build survives a format→parse round trip unchanged. The generator
        /// covers all four kinds, both families, both components, and the optional related address.
        #[test]
        fn round_trips_arbitrary_candidates(
            foundation in "[a-zA-Z0-9+/]{1,32}",
            component in 1u16..=256,
            local_preference in any_u16(),
            kind_index in 0usize..4,
            v6 in proptest::bool::ANY,
            port in any_u16(),
            related_port in any_u16(),
        ) {
            let kind = [
                CandidateKind::Host,
                CandidateKind::ServerReflexive,
                CandidateKind::PeerReflexive,
                CandidateKind::Relayed,
            ][kind_index];
            let ip: IpAddr = if v6 {
                "2001:db8::1".parse().expect("ip")
            } else {
                "203.0.113.7".parse().expect("ip")
            };
            let mut candidate = Candidate::new(
                foundation,
                component,
                SocketAddr::new(ip, port),
                kind,
                local_preference,
            );
            if kind.has_related_address() {
                candidate = candidate.with_related(SocketAddr::new(ip, related_port));
            }
            let line = candidate.to_attribute_line();
            let parsed = Candidate::parse(&line).expect("our own output must parse");
            proptest::prop_assert_eq!(parsed, candidate);
        }

        /// Hostile input never panics — it parses or it errors. (The fuzz target covers the same
        /// surface with coverage guidance; this keeps the invariant in the unit suite.)
        #[test]
        fn never_panics_on_arbitrary_input(line in ".{0,200}") {
            let _ = Candidate::parse(&line);
            let _ = IceOptions::parse(&line);
        }
    }

    /// `proptest`'s `any::<u16>()` spelled out once, so the macro bodies above stay readable.
    fn any_u16() -> impl proptest::strategy::Strategy<Value = u16> {
        proptest::prelude::any::<u16>()
    }
}

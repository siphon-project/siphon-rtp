//! Named media interfaces and per-leg selection (rtpengine-style).
//!
//! A carrier/SBC deploy needs two things the bare bind IP cannot express:
//!
//! 1. **Advertise a reachable public IP** in the rewritten SDP that is *decoupled* from the socket
//!    bind address — bind a private or wildcard address, advertise the routable one. (See
//!    `docs/security-and-nat.md`; the advertised IP never feeds the source gate or latch, so this is
//!    not an RTPbleed vector.)
//! 2. **Named interfaces** so the caller-facing leg lands on one network (e.g. `internal`) and the
//!    callee-facing leg on another (`external`), selected per call by the control `direction` pair.
//!
//! The advertised-IP override is the *degenerate single-interface case* of the named-interface model,
//! so this module provides one mechanism — [`InterfaceTable`] — and both fall out. The table is pure
//! policy (name → bind/advertised address per family); the datapath binds whatever IP the engine
//! resolves via [`Datapath::alloc_endpoint_on`](siphon_rtp_datapath::Datapath::alloc_endpoint_on).

use std::net::IpAddr;

use siphon_rtp_datapath::AddressFamily;
use tracing::warn;

/// One local address of a named interface: the IP the datapath binds/sources media from, and the
/// (possibly-different) public IP advertised in rewritten SDP. `advertised == bind` for a directly
/// reachable interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceAddress {
    /// The local IP the datapath binds and transmits from.
    pub bind: IpAddr,
    /// The IP advertised in the rewritten SDP `c=`/`o=`/ICE-candidate lines. Defaults to `bind`.
    pub advertised: IpAddr,
}

impl InterfaceAddress {
    /// The address family of this address (decided by `bind`).
    #[must_use]
    pub fn family(&self) -> AddressFamily {
        AddressFamily::of(self.bind)
    }
}

/// A named local interface (rtpengine's `interface=NAME/BIND!ADVERTISED`). Holds one address per
/// family it serves (typically one v4 and/or one v6), so the same name works for a `c=IN IP4` and a
/// `c=IN IP6` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// The interface name matched against the control `direction` pair.
    pub name: String,
    /// This interface's local addresses, at most one per family.
    pub addresses: Vec<InterfaceAddress>,
}

impl Interface {
    /// The interface's address of **exactly** `family`, or `None` when it serves no address of that
    /// family. The engine never cross-family-substitutes a bind IP (a v4 address in a `c=IN IP6` line
    /// is invalid SDP); a `None` here means "fall back to the datapath's family default" — so a v6 call
    /// on a v4-only interface still binds the datapath's v6 default rather than the wrong family.
    #[must_use]
    pub fn exact_address_for(&self, family: AddressFamily) -> Option<InterfaceAddress> {
        self.addresses
            .iter()
            .copied()
            .find(|address| address.family() == family)
    }
}

/// A flat interface definition as it comes from config — the name may repeat (once per family). The
/// [`InterfaceTable`] merges same-named entries into one [`Interface`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    /// The interface name (repeat for a second family).
    pub name: String,
    /// The local bind IP.
    pub bind: IpAddr,
    /// The advertised public IP; `None` ⇒ advertise the bind IP.
    pub advertised: Option<IpAddr>,
}

impl InterfaceEntry {
    /// A convenience constructor.
    #[must_use]
    pub fn new(name: impl Into<String>, bind: IpAddr, advertised: Option<IpAddr>) -> Self {
        Self {
            name: name.into(),
            bind,
            advertised,
        }
    }
}

/// The engine's resolved set of named interfaces plus the default. Maps a control `direction` pair to
/// each leg's bind and advertised address. Cheap to clone-share via `Arc`; lookups are a linear scan
/// of a handful of interfaces (no per-call allocation).
#[derive(Debug, Clone)]
pub struct InterfaceTable {
    /// Non-empty, in config order.
    interfaces: Vec<Interface>,
    /// Index into `interfaces` of the interface used when `direction` is absent or names an unknown
    /// interface. Construction guarantees it is in range.
    default_index: usize,
}

impl InterfaceTable {
    /// Build a table from flat config entries, merging same-named entries (one per family) into one
    /// [`Interface`]. `default_name` picks the fallback interface; `None` uses the first defined.
    ///
    /// # Errors
    /// Returns an error string if `entries` is empty, if one interface name carries two addresses of
    /// the same family, or if `default_name` is set but names no configured interface.
    pub fn from_entries(
        entries: Vec<InterfaceEntry>,
        default_name: Option<&str>,
    ) -> Result<Self, String> {
        if entries.is_empty() {
            return Err("interface table needs at least one interface".to_string());
        }
        let mut interfaces: Vec<Interface> = Vec::new();
        for entry in entries {
            let address = InterfaceAddress {
                bind: entry.bind,
                advertised: entry.advertised.unwrap_or(entry.bind),
            };
            match interfaces.iter_mut().find(|iface| iface.name == entry.name) {
                Some(iface) => {
                    if iface
                        .addresses
                        .iter()
                        .any(|existing| existing.family() == address.family())
                    {
                        return Err(format!(
                            "interface `{}` has two {:?} addresses",
                            entry.name,
                            address.family()
                        ));
                    }
                    iface.addresses.push(address);
                }
                None => interfaces.push(Interface {
                    name: entry.name,
                    addresses: vec![address],
                }),
            }
        }
        let default_index = match default_name {
            Some(name) => interfaces
                .iter()
                .position(|iface| iface.name == name)
                .ok_or_else(|| format!("default_interface `{name}` is not a configured interface"))?,
            None => 0,
        };
        Ok(Self {
            interfaces,
            default_index,
        })
    }

    /// A single-interface table — the advertised-IP override / no-named-interfaces case. `bind` is the
    /// relay bind IP; `advertised` (when set) is the public IP put into SDP.
    #[must_use]
    pub fn single(bind: IpAddr, advertised: Option<IpAddr>) -> Self {
        Self {
            interfaces: vec![Interface {
                name: "default".to_string(),
                addresses: vec![InterfaceAddress {
                    bind,
                    advertised: advertised.unwrap_or(bind),
                }],
            }],
            default_index: 0,
        }
    }

    /// The fallback interface (used when `direction` is absent or unknown).
    #[must_use]
    pub fn default_interface(&self) -> &Interface {
        // `default_index` is validated in range at construction and `interfaces` is never empty.
        &self.interfaces[self.default_index]
    }

    /// Look up an interface by name.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&Interface> {
        self.interfaces.iter().find(|iface| iface.name == name)
    }

    /// Resolve a single `direction` slot to an interface: the named one, or the default (with a
    /// `warn!`) when the slot is empty or names an interface that is not configured. Never fails, so a
    /// stale `direction` from the proxy keeps the call flowing (per the deploy decision).
    fn resolve_slot(&self, name: Option<&str>) -> &Interface {
        match name.filter(|slot| !slot.is_empty()) {
            None => self.default_interface(),
            Some(slot) => match self.find(slot) {
                Some(iface) => iface,
                None => {
                    warn!(
                        interface = %slot,
                        default = %self.default_interface().name,
                        "unknown direction interface; falling back to the default interface"
                    );
                    self.default_interface()
                }
            },
        }
    }

    /// Resolve a control `direction` pair to `(near, far)` interfaces. `direction[0]` selects the
    /// **near** (offerer / A) leg and `direction[1]` the **far** (answerer / B) leg — the side the
    /// offer came from first, matching rtpengine. Absent or unknown slots fall back to the default.
    #[must_use]
    pub fn resolve_direction(&self, direction: &[String]) -> (&Interface, &Interface) {
        let near = self.resolve_slot(direction.first().map(String::as_str));
        let far = self.resolve_slot(direction.get(1).map(String::as_str));
        (near, far)
    }

    /// The distinct advertised IPs across all interfaces (skipping unspecified/wildcard), for the
    /// cluster `node_info.media_addresses` advertisement.
    #[must_use]
    pub fn advertised_media_addresses(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for iface in &self.interfaces {
            for address in &iface.addresses {
                if address.advertised.is_unspecified() {
                    continue;
                }
                let rendered = address.advertised.to_string();
                if !out.contains(&rendered) {
                    out.push(rendered);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn single_defaults_advertised_to_bind() {
        let table = InterfaceTable::single(v4(10, 0, 0, 1), None);
        let iface = table.default_interface();
        let address = iface.exact_address_for(AddressFamily::V4).expect("v4 address");
        assert_eq!(address.bind, v4(10, 0, 0, 1));
        assert_eq!(address.advertised, v4(10, 0, 0, 1));
    }

    #[test]
    fn single_carries_a_distinct_advertised_ip() {
        let table = InterfaceTable::single(v4(0, 0, 0, 0), Some(v4(203, 0, 113, 5)));
        let address = table
            .default_interface()
            .exact_address_for(AddressFamily::V4)
            .expect("v4 address");
        assert_eq!(address.bind, v4(0, 0, 0, 0));
        assert_eq!(address.advertised, v4(203, 0, 113, 5));
    }

    #[test]
    fn direction_selects_near_and_far_interfaces() {
        let table = InterfaceTable::from_entries(
            vec![
                InterfaceEntry::new("internal", v4(10, 0, 0, 1), None),
                InterfaceEntry::new("external", v4(0, 0, 0, 0), Some(v4(203, 0, 113, 5))),
            ],
            None,
        )
        .expect("table");
        // direction[0] = near (A), direction[1] = far (B).
        let (near, far) =
            table.resolve_direction(&["external".to_string(), "internal".to_string()]);
        assert_eq!(near.name, "external");
        assert_eq!(far.name, "internal");
        assert_eq!(
            near.exact_address_for(AddressFamily::V4)
                .expect("v4")
                .advertised,
            v4(203, 0, 113, 5)
        );
        assert_eq!(
            far.exact_address_for(AddressFamily::V4).expect("v4").bind,
            v4(10, 0, 0, 1)
        );
    }

    #[test]
    fn unknown_direction_falls_back_to_default() {
        let table = InterfaceTable::from_entries(
            vec![
                InterfaceEntry::new("internal", v4(10, 0, 0, 1), None),
                InterfaceEntry::new("external", v4(203, 0, 113, 5), None),
            ],
            Some("external"),
        )
        .expect("table");
        let (near, far) =
            table.resolve_direction(&["does-not-exist".to_string(), String::new()]);
        assert_eq!(near.name, "external", "unknown slot falls back to default");
        assert_eq!(far.name, "external", "empty slot falls back to default");
    }

    #[test]
    fn empty_direction_uses_default() {
        let table = InterfaceTable::from_entries(
            vec![
                InterfaceEntry::new("a", v4(10, 0, 0, 1), None),
                InterfaceEntry::new("b", v4(10, 0, 0, 2), None),
            ],
            Some("b"),
        )
        .expect("table");
        let (near, far) = table.resolve_direction(&[]);
        assert_eq!(near.name, "b");
        assert_eq!(far.name, "b");
    }

    #[test]
    fn same_name_merges_two_families() {
        let table = InterfaceTable::from_entries(
            vec![
                InterfaceEntry::new("edge", v4(203, 0, 113, 5), None),
                InterfaceEntry::new(
                    "edge",
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5)),
                    None,
                ),
            ],
            None,
        )
        .expect("table");
        let edge = table.find("edge").expect("edge");
        assert_eq!(edge.addresses.len(), 2, "v4 and v6 merged under one name");
        assert!(edge
            .exact_address_for(AddressFamily::V4)
            .expect("v4")
            .bind
            .is_ipv4());
        assert!(edge
            .exact_address_for(AddressFamily::V6)
            .expect("v6")
            .bind
            .is_ipv6());
    }

    #[test]
    fn exact_address_for_returns_none_for_a_missing_family() {
        // A v4-only interface asked for a v6 leg yields None, so the engine falls back to the
        // datapath's v6 default rather than binding the wrong family / advertising a v4 addr in a v6 line.
        let table = InterfaceTable::single(v4(10, 0, 0, 1), None);
        assert!(table
            .default_interface()
            .exact_address_for(AddressFamily::V6)
            .is_none());
    }

    #[test]
    fn empty_entries_is_an_error() {
        assert!(InterfaceTable::from_entries(Vec::new(), None).is_err());
    }

    #[test]
    fn duplicate_family_on_one_name_is_an_error() {
        let error = InterfaceTable::from_entries(
            vec![
                InterfaceEntry::new("dup", v4(10, 0, 0, 1), None),
                InterfaceEntry::new("dup", v4(10, 0, 0, 2), None),
            ],
            None,
        )
        .expect_err("two v4 addresses on one name must be rejected");
        assert!(error.contains("dup"), "error names the offending interface");
    }

    #[test]
    fn unknown_default_name_is_an_error() {
        assert!(InterfaceTable::from_entries(
            vec![InterfaceEntry::new("a", v4(10, 0, 0, 1), None)],
            Some("missing"),
        )
        .is_err());
    }

    #[test]
    fn advertised_media_addresses_dedup_and_skip_wildcard() {
        let table = InterfaceTable::from_entries(
            vec![
                InterfaceEntry::new("a", v4(0, 0, 0, 0), Some(v4(203, 0, 113, 5))),
                InterfaceEntry::new("b", v4(0, 0, 0, 0), None), // advertised == wildcard, skipped
                InterfaceEntry::new("c", v4(203, 0, 113, 5), None), // duplicate advertised, deduped
            ],
            None,
        )
        .expect("table");
        assert_eq!(table.advertised_media_addresses(), vec!["203.0.113.5"]);
    }
}

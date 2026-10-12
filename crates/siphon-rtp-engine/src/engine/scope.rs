//! The call key: how `(scope, call_id)` names a call inside the engine.
//!
//! Every registry in the engine, and every actor that reports on a call, names the call by one
//! string. For a call without a scope that string **is** the controller's `call_id`, which is why
//! nothing about an unscoped call changed when scopes arrived: not a map key, not a log field,
//! not a file name, not a byte of a snapshot. A scoped call's key is the `call_id` followed by a
//! marker and the scope:
//!
//! ```text
//! 7f9a2b1c@192.0.2.20<US> scope=bgcf
//! ```
//!
//! `<US>` is U+001F, the unit separator. A `call_id` that contains it is refused at the control
//! entry, so no `call_id` can spell another call's key and the mapping is one to one. The visible
//! ` scope=` after it is for the reader: a log line that prints a key as `call_id=...` shows the
//! scope as a field of its own without any call site knowing scopes exist.
//!
//! The key is composed where a command enters ([`Engine::handle_scoped`](super::Engine)) and
//! taken apart wherever a call's name leaves the engine: an event ([`scoped_event`]), an error
//! string (`Key`'s `Display`), `list`, a snapshot, a recording's file name, a capture's
//! correlation id.

use std::borrow::Cow;
use std::fmt;

use siphon_rtp_proto::{Event, Scoped};

/// U+001F, which no `call_id` may contain.
const SEPARATOR: char = '\u{1f}';
/// What sits between a `call_id` and its scope in a key.
const MARKER: &str = "\u{1f} scope=";

/// The key of the call `call_id` names under `scope`.
///
/// `scope` has been through [`siphon_rtp_proto::normalize_scope`]. Refuses a `call_id` holding the
/// separator, which is what keeps a key from being forged as a `call_id`.
pub(crate) fn compose(scope: Option<&str>, call_id: &str) -> Result<String, String> {
    if call_id.contains(SEPARATOR) {
        return Err("call_id must not contain the control character U+001F".to_string());
    }
    Ok(match scope {
        None => call_id.to_string(),
        Some(scope) => format!("{call_id}{MARKER}{scope}"),
    })
}

/// A key taken apart: the controller's `call_id`, and the scope if the call has one.
pub fn split(key: &str) -> (&str, Option<&str>) {
    match key.split_once(MARKER) {
        Some((call_id, scope)) => (call_id, Some(scope)),
        None => (key, None),
    }
}

/// The controller's `call_id` for a key, without its scope: what a SIP capture correlates on.
pub(crate) fn call_id(key: &str) -> &str {
    split(key).0
}

/// Whether `key` names a scoped call.
pub(crate) fn is_scoped(key: &str) -> bool {
    key.contains(MARKER)
}

/// Whether `key` names a call in exactly `scope` (`None` being the unscoped calls).
pub(crate) fn is_in(key: &str, scope: Option<&str>) -> bool {
    split(key).1 == scope
}

/// A name for the call that is safe in a file name or a stream identifier and still differs
/// between two scopes of one `call_id`: the `call_id` itself, with `.<scope>` after it when scoped.
pub(crate) fn external(key: &str) -> Cow<'_, str> {
    match split(key) {
        (call_id, Some(scope)) => Cow::Owned(format!("{call_id}.{scope}")),
        (call_id, None) => Cow::Borrowed(call_id),
    }
}

/// A key as an error string names it: the `call_id`, and `(scope <scope>)` after it when scoped.
pub(crate) struct Key<'a>(pub(crate) &'a str);

impl fmt::Display for Key<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match split(self.0) {
            (call_id, Some(scope)) => write!(formatter, "{call_id} (scope {scope})"),
            (call_id, None) => formatter.write_str(call_id),
        }
    }
}

/// Take the key out of an event the engine emitted: its `call_id` becomes the controller's own
/// again, and the scope moves to the frame.
///
/// The engine's event channel ([`Engine::register_client`](super::Engine::register_client))
/// carries events as its actors wrote them, keyed. The control server passes each one through
/// here before it reaches the wire, and so must anything else that hands events to a controller.
/// An event about an unscoped call comes back untouched.
pub fn scoped_event(mut event: Event) -> Scoped<Event> {
    let mut scope = None;
    if let Some(call_id) = event.call_id_mut() {
        if let Some((plain, found)) = call_id.split_once(MARKER) {
            scope = Some(found.to_string());
            let plain_len = plain.len();
            call_id.truncate(plain_len);
        }
    }
    Scoped::new(scope, event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_proto::MediaTimeoutReason;

    #[test]
    fn an_unscoped_key_is_the_call_id_itself() {
        let key = compose(None, "7f9a2b1c@192.0.2.20").expect("compose");
        assert_eq!(key, "7f9a2b1c@192.0.2.20");
        assert_eq!(split(&key), ("7f9a2b1c@192.0.2.20", None));
        assert!(!is_scoped(&key));
        assert_eq!(external(&key), "7f9a2b1c@192.0.2.20");
        assert_eq!(Key(&key).to_string(), "7f9a2b1c@192.0.2.20");
    }

    #[test]
    fn a_scoped_key_splits_back_into_its_parts() {
        let key = compose(Some("bgcf"), "7f9a2b1c@192.0.2.20").expect("compose");
        assert_eq!(split(&key), ("7f9a2b1c@192.0.2.20", Some("bgcf")));
        assert_eq!(call_id(&key), "7f9a2b1c@192.0.2.20");
        assert!(is_scoped(&key));
        assert!(is_in(&key, Some("bgcf")));
        assert!(!is_in(&key, Some("bgc")));
        assert!(!is_in(&key, None));
        assert_eq!(external(&key), "7f9a2b1c@192.0.2.20.bgcf");
        assert_eq!(Key(&key).to_string(), "7f9a2b1c@192.0.2.20 (scope bgcf)");
    }

    #[test]
    fn a_key_prints_its_scope_as_a_field_of_its_own() {
        let key = compose(Some("bgcf"), "abc").expect("compose");
        assert_eq!(key.replace(SEPARATOR, ""), "abc scope=bgcf");
    }

    #[test]
    fn no_call_id_can_spell_a_scoped_key() {
        let forged = compose(Some("bgcf"), "abc").expect("compose");
        assert!(compose(None, &forged).is_err());
        assert!(compose(Some("mrf"), &forged).is_err());
        // The visible half of the marker alone is an ordinary call id.
        let lookalike = compose(None, "abc scope=bgcf").expect("compose");
        assert_eq!(split(&lookalike), ("abc scope=bgcf", None));
    }

    #[test]
    fn two_scopes_and_no_scope_give_three_keys() {
        let keys = [
            compose(None, "abc").expect("compose"),
            compose(Some("a"), "abc").expect("compose"),
            compose(Some("b"), "abc").expect("compose"),
        ];
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }

    #[test]
    fn an_event_gives_its_scope_to_the_frame() {
        let timeout = |call_id: String| Event::MediaTimeout {
            call_id,
            from_tag: "a7c31f".into(),
            reason: MediaTimeoutReason::NoMedia,
        };
        let scoped = scoped_event(timeout(compose(Some("bgcf"), "abc").expect("compose")));
        assert_eq!(scoped.scope.as_deref(), Some("bgcf"));
        assert_eq!(scoped.inner, timeout("abc".into()));

        let plain = scoped_event(timeout("abc".into()));
        assert_eq!(plain.scope, None);
        assert_eq!(plain.inner, timeout("abc".into()));
    }

    #[test]
    fn an_event_about_no_call_passes_through() {
        let speaker = Event::ActiveSpeaker {
            conference_id: "room-1".into(),
            from_tag: None,
        };
        assert_eq!(scoped_event(speaker.clone()), Scoped::unscoped(speaker));
    }
}

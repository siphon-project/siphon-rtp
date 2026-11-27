//! Level-triggered `epoll(7)`, and the registration of a media socket with Tokio: the crate's only
//! unsafe code.
//!
//! Level-triggered on purpose. A socket that still holds a datagram after one read is simply
//! reported again by the next `epoll_wait`, so the relay reads exactly once per readiness report.
//! An edge-triggered loop (Tokio's, mio's) must instead read until `EAGAIN` before it may wait
//! again, which for media arriving one packet per ptime is a second, empty `recvfrom` on every
//! packet: a third kernel crossing on top of the receive and the send (docs/capacity.md).
//!
//! The surface is deliberately tiny (create, add, delete, wait, register) so the unsafe calls stay
//! auditable.

#![allow(
    unsafe_code,
    reason = "epoll has no std or socket2 binding, and Tokio's fd registration is unsafe; each call \
              carries its own SAFETY argument"
)]

use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

/// Register `socket` with the current Tokio runtime for writability only (see
/// [`super::reactor::MediaSocket`]). Must run inside a runtime.
pub(super) fn register_writable(
    socket: std::net::UdpSocket,
) -> io::Result<super::reactor::MediaSocket> {
    // SAFETY: the `AsyncFd` takes ownership of `socket`, which owns its descriptor: it stays open,
    // and `as_raw_fd` keeps returning it, until the `AsyncFd` drops the socket. Nothing else holds or
    // closes that descriptor (the relay reactor only borrows it through the `AsyncFd`).
    unsafe {
        tokio::io::unix::AsyncFd::register_with_interest(socket, tokio::io::Interest::WRITABLE)
    }
    .map_err(|error| error.into_parts().1)
}

/// An epoll instance, closed on drop.
pub(super) struct Epoll {
    fd: OwnedFd,
}

/// The buffer one `epoll_wait` fills, and how much of it the last call filled.
pub(super) struct Events {
    buffer: Vec<libc::epoll_event>,
    ready: usize,
}

impl Events {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: vec![libc::epoll_event { events: 0, u64: 0 }; capacity.max(1)],
            ready: 0,
        }
    }

    /// The tokens of the descriptors the last [`Epoll::wait`] reported ready.
    pub(super) fn tokens(&self) -> impl Iterator<Item = u64> + '_ {
        // `epoll_event` is packed on x86-64; copying the field out (never borrowing it) is sound.
        self.buffer[..self.ready].iter().map(|event| event.u64)
    }
}

impl Epoll {
    pub(super) fn new() -> io::Result<Self> {
        // SAFETY: `epoll_create1` takes no pointers. A non-negative return is a new descriptor.
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned open by `epoll_create1` and nothing else owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { fd })
    }

    /// Watch `source` for readability, level-triggered, reporting it as `token`.
    pub(super) fn add(&self, source: &impl AsFd, token: u64) -> io::Result<()> {
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: token,
        };
        self.control(libc::EPOLL_CTL_ADD, source, &mut event)
    }

    /// Stop watching `source`. Once this returns no later `wait` reports it, though a `wait` that
    /// already returned may still hold its token.
    pub(super) fn delete(&self, source: &impl AsFd) -> io::Result<()> {
        // Ignored by the kernel for a delete, but must be non-null before Linux 2.6.9.
        let mut event = libc::epoll_event { events: 0, u64: 0 };
        self.control(libc::EPOLL_CTL_DEL, source, &mut event)
    }

    fn control(
        &self,
        operation: libc::c_int,
        source: &impl AsFd,
        event: &mut libc::epoll_event,
    ) -> io::Result<()> {
        // SAFETY: both descriptors are open for the whole call (borrowed from owners that outlive
        // it), and `event` is a valid, exclusively borrowed `epoll_event` the kernel only reads.
        let result = unsafe {
            libc::epoll_ctl(
                self.fd.as_raw_fd(),
                operation,
                source.as_fd().as_raw_fd(),
                event,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Block until at least one watched descriptor is ready (or `timeout_ms` passes; `-1` waits
    /// indefinitely) and record the ready ones in `events`. An interrupted wait reports nothing ready.
    pub(super) fn wait(&self, events: &mut Events, timeout_ms: libc::c_int) -> io::Result<()> {
        events.ready = 0;
        let capacity = libc::c_int::try_from(events.buffer.len()).unwrap_or(libc::c_int::MAX);
        // SAFETY: `events.buffer` holds `capacity` initialised `epoll_event`s and is exclusively
        // borrowed for the call; the kernel writes at most `capacity` of them.
        let ready = unsafe {
            libc::epoll_wait(
                self.fd.as_raw_fd(),
                events.buffer.as_mut_ptr(),
                capacity,
                timeout_ms,
            )
        };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(error);
        }
        events.ready = usize::try_from(ready).unwrap_or(0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    fn bound() -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket.set_nonblocking(true).expect("nonblocking");
        socket
    }

    #[test]
    fn a_readable_socket_is_reported_by_its_token() {
        let epoll = Epoll::new().expect("epoll");
        let socket = bound();
        epoll.add(&socket, 42).expect("add");
        bound()
            .send_to(b"x", socket.local_addr().expect("addr"))
            .expect("send");
        let mut events = Events::with_capacity(8);
        epoll.wait(&mut events, 1000).expect("wait");
        assert_eq!(events.tokens().collect::<Vec<_>>(), vec![42]);
    }

    #[test]
    fn level_triggered_reports_again_while_a_datagram_is_left_unread() {
        // The property the relay relies on: read one datagram per report, never read to EAGAIN.
        let epoll = Epoll::new().expect("epoll");
        let socket = bound();
        epoll.add(&socket, 7).expect("add");
        let sender = bound();
        let target = socket.local_addr().expect("addr");
        sender.send_to(b"one", target).expect("send");
        sender.send_to(b"two", target).expect("send");
        let mut events = Events::with_capacity(8);
        let mut buffer = [0u8; 16];

        epoll.wait(&mut events, 1000).expect("wait");
        assert_eq!(events.tokens().count(), 1);
        let (len, _) = socket.recv_from(&mut buffer).expect("first");
        assert_eq!(&buffer[..len], b"one");

        epoll.wait(&mut events, 1000).expect("wait again");
        assert_eq!(
            events.tokens().collect::<Vec<_>>(),
            vec![7],
            "still ready: one datagram is left"
        );
        let (len, _) = socket.recv_from(&mut buffer).expect("second");
        assert_eq!(&buffer[..len], b"two");

        epoll.wait(&mut events, 0).expect("drained");
        assert_eq!(events.tokens().count(), 0, "nothing left, nothing reported");
    }

    #[test]
    fn a_deleted_socket_is_never_reported() {
        let epoll = Epoll::new().expect("epoll");
        let socket = bound();
        epoll.add(&socket, 1).expect("add");
        epoll.delete(&socket).expect("delete");
        bound()
            .send_to(b"x", socket.local_addr().expect("addr"))
            .expect("send");
        let mut events = Events::with_capacity(8);
        epoll.wait(&mut events, 50).expect("wait");
        assert_eq!(events.tokens().count(), 0);
    }

    #[test]
    fn deleting_a_socket_that_was_never_added_is_an_error() {
        let epoll = Epoll::new().expect("epoll");
        assert!(epoll.delete(&bound()).is_err());
    }
}

//! An in-house AF_XDP socket over the raw kernel uapi — UMEM + the four rings, `bind`, and batched
//! RX/TX — with zero C library dependency (no `libxsk`/`xsk-rs`/`libbpf-sys`).
//!
//! AF_XDP (Linux `Documentation/networking/af_xdp.rst`, uapi `<linux/if_xdp.h>`) gives userspace a
//! shared-memory fast path to a NIC queue:
//!
//! - a **UMEM**: one contiguous, page-aligned, `mmap`'d region carved into fixed-size *frames*; every
//!   packet — RX or TX — lives in a frame, addressed by its byte offset into the UMEM.
//! - four single-producer/single-consumer **rings**, each its own `mmap` at a magic page offset:
//!   - **FILL** (userspace → kernel): frame addrs we lend the kernel to receive into.
//!   - **RX** (kernel → userspace): `xdp_desc`s for frames the kernel filled with received packets.
//!   - **TX** (userspace → kernel): `xdp_desc`s for frames we want transmitted.
//!   - **COMPLETION** (kernel → userspace): frame addrs the kernel finished transmitting.
//!
//! The eBPF classifier's `XDP_REDIRECT` into the `XSKS` map lands a packet on this socket's RX ring
//! (when bound to the same queue the packet arrived on). Userspace must keep the FILL ring stocked or
//! the kernel has nowhere to put RX packets.
//!
//! ## Safety
//!
//! This module is the one place `unsafe` is unavoidable: raw syscalls (`socket`/`setsockopt`/`mmap`/
//! `bind`/`sendto`) and direct reads/writes of the kernel-shared ring memory. Every `unsafe` block
//! is scoped to one operation and carries a `SAFETY:` note tying it to the uapi contract. The ring
//! producer/consumer indices are shared with the kernel and accessed through volatile/atomic
//! operations with the acquire/release fences the AF_XDP ring protocol requires.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};

/// Errors from setting up or driving an AF_XDP socket.
#[derive(Debug, thiserror::Error)]
pub enum XskError {
    /// A ring/UMEM size was not a power of two (the kernel requires it).
    #[error("ring size {0} must be a non-zero power of two")]
    RingSize(u32),
    /// `socket(AF_XDP, …)` failed.
    #[error("socket(AF_XDP): {0}")]
    Socket(#[source] io::Error),
    /// A `setsockopt` (UMEM_REG / *_RING) failed.
    #[error("setsockopt({option}): {source}")]
    SetSockOpt {
        /// The option name (`XDP_UMEM_REG`, `XDP_RX_RING`, …).
        option: &'static str,
        /// The underlying errno.
        #[source]
        source: io::Error,
    },
    /// `getsockopt(XDP_MMAP_OFFSETS)` failed.
    #[error("getsockopt(XDP_MMAP_OFFSETS): {0}")]
    GetOffsets(#[source] io::Error),
    /// `mmap` of the UMEM area or a ring failed.
    #[error("mmap {area}: {source}")]
    Mmap {
        /// Which region failed to map.
        area: &'static str,
        /// The underlying errno.
        #[source]
        source: io::Error,
    },
    /// `bind(sockaddr_xdp)` to the interface/queue failed.
    #[error("bind(ifindex={ifindex}, queue={queue}): {source}")]
    Bind {
        /// The interface index bound to.
        ifindex: u32,
        /// The queue id bound to.
        queue: u32,
        /// The underlying errno.
        #[source]
        source: io::Error,
    },
}

/// Configuration for an [`XskSocket`]. All ring sizes are entry counts and must be powers of two.
#[derive(Clone, Copy, Debug)]
pub struct XskConfig {
    /// Number of frames in the UMEM (each `frame_size` bytes). Power of two recommended.
    pub frame_count: u32,
    /// Size of each UMEM frame in bytes (≥ MTU + headroom; 2048 is the conventional chunk).
    pub frame_size: u32,
    /// FILL ring depth (entries).
    pub fill_size: u32,
    /// COMPLETION ring depth (entries).
    pub completion_size: u32,
    /// RX ring depth (entries).
    pub rx_size: u32,
    /// TX ring depth (entries).
    pub tx_size: u32,
    /// Bind flags (`XDP_COPY` for the generic/SKB dev path, `XDP_ZEROCOPY` for a ZC-capable driver,
    /// `0` to let the kernel choose; may be OR'd with `XDP_USE_NEED_WAKEUP`).
    pub bind_flags: u16,
}

impl Default for XskConfig {
    fn default() -> Self {
        // 4096 × 2 KiB = 8 MiB UMEM; ring depths sized for a single media queue. Copy-mode by
        // default — works on veth / generic XDP (the dev/CI posture) where ZC is unavailable.
        Self {
            frame_count: 4096,
            frame_size: 2048,
            fill_size: 2048,
            completion_size: 2048,
            rx_size: 2048,
            tx_size: 2048,
            bind_flags: libc::XDP_COPY,
        }
    }
}

/// The UMEM: a page-aligned `mmap`'d region carved into fixed-size frames, plus a free-list of frame
/// offsets not currently lent to the kernel (FILL) or in flight (TX awaiting COMPLETION).
struct Umem {
    /// Base of the mapped region.
    area: NonNull<u8>,
    /// Total mapped length in bytes (`frame_count * frame_size`).
    len: usize,
    /// Frame size in bytes.
    frame_size: usize,
    /// Free frame offsets (byte addresses into the UMEM) available to allocate.
    free: Vec<u64>,
}

// SAFETY: `Umem` owns its mapping exclusively; the raw pointer is only dereferenced through the
// owning `XskSocket`, which is not itself shared without external synchronisation (the RX thread
// owns it). Sending it across threads (to the busy-poll thread) is sound.
unsafe impl Send for Umem {}

impl Umem {
    /// Allocate and map the UMEM region (anonymous, page-aligned), seeding the free-list with every
    /// frame offset.
    fn new(frame_count: u32, frame_size: u32) -> Result<Self, XskError> {
        let len = frame_count as usize * frame_size as usize;
        // SAFETY: a fresh anonymous mapping; no fd, no offset. Length is non-zero (frame_count ≥ 1
        // is enforced by the power-of-two ring check upstream). On failure mmap returns MAP_FAILED.
        let area = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if area == libc::MAP_FAILED {
            return Err(XskError::Mmap {
                area: "umem",
                source: io::Error::last_os_error(),
            });
        }
        let area = NonNull::new(area.cast::<u8>()).ok_or_else(|| XskError::Mmap {
            area: "umem",
            source: io::Error::from(io::ErrorKind::Other),
        })?;
        let mut free = Vec::with_capacity(frame_count as usize);
        for index in 0..frame_count as u64 {
            free.push(index * frame_size as u64);
        }
        Ok(Self {
            area,
            len,
            frame_size: frame_size as usize,
            free,
        })
    }

    /// Take a free frame offset, or `None` when the UMEM is fully lent out.
    fn alloc(&mut self) -> Option<u64> {
        self.free.pop()
    }

    /// Return a frame offset to the free-list (after RX consume or TX completion).
    fn free_frame(&mut self, addr: u64) {
        // Mask off any unaligned-mode offset bits (we run aligned mode, so the addr is frame-aligned
        // already; the floor-divide keeps a stray byte offset from corrupting the free-list).
        let aligned = (addr / self.frame_size as u64) * self.frame_size as u64;
        self.free.push(aligned);
    }

    /// A mutable byte slice over the frame at `addr` for `len` bytes (TX fill / RX read).
    ///
    /// # Safety
    /// `addr + len` must lie within the mapped region and not alias a frame the kernel currently
    /// owns (one not on the free-list and not the descriptor being processed).
    unsafe fn frame_mut(&mut self, addr: u64, len: usize) -> &mut [u8] {
        debug_assert!(addr as usize + len <= self.len, "frame out of UMEM bounds");
        std::slice::from_raw_parts_mut(self.area.as_ptr().add(addr as usize), len)
    }

    /// A shared byte slice over the frame at `addr` for `len` bytes (RX read).
    ///
    /// # Safety
    /// As [`Umem::frame_mut`], shared access.
    unsafe fn frame(&self, addr: u64, len: usize) -> &[u8] {
        debug_assert!(addr as usize + len <= self.len, "frame out of UMEM bounds");
        std::slice::from_raw_parts(self.area.as_ptr().add(addr as usize), len)
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        // SAFETY: `area`/`len` are exactly what `mmap` returned and have not been unmapped elsewhere.
        unsafe {
            libc::munmap(self.area.as_ptr().cast::<libc::c_void>(), self.len);
        }
    }
}

/// One AF_XDP ring mapped into userspace. The kernel and userspace each own one index (producer or
/// consumer depending on direction) of a shared SPSC queue; `entries` is the ring body.
///
/// `T` is the ring entry type: `u64` for FILL/COMPLETION (frame addresses), [`libc::xdp_desc`] for
/// RX/TX. `mask` is `size - 1` (size is a power of two), so `index & mask` wraps without a modulo.
struct Ring<T> {
    /// Pointer to the kernel-shared producer index (`__u32`).
    producer: *const AtomicU32,
    /// Pointer to the kernel-shared consumer index (`__u32`).
    consumer: *const AtomicU32,
    /// Pointer to the ring entry array (`size` elements of `T`).
    entries: *mut T,
    /// `size - 1`; bitmask for wrapping ring indices.
    mask: u32,
    /// The mmap base + length, kept for `munmap` on drop.
    map: (NonNull<u8>, usize),
    /// A cached copy of our own index, so we batch the shared-index write to one release per burst.
    cached_index: u32,
}

// SAFETY: the ring is only driven by the single thread that owns the `XskSocket`; moving it to that
// thread is sound. The kernel-shared indices use atomic ops with the required fences.
unsafe impl<T> Send for Ring<T> {}

impl<T: Copy> Ring<T> {
    /// Map one ring: `setsockopt` its size, then `mmap` at `page_offset`, then resolve the
    /// producer/consumer/desc field offsets from `offsets` (filled by `XDP_MMAP_OFFSETS`).
    ///
    /// `ring_offset` selects which of the four `xdp_ring_offset`s in `offsets` to use.
    fn map(
        fd: RawFd,
        size: u32,
        sockopt: RingOption,
        page_offset: libc::off_t,
        ring_offset: &libc::xdp_ring_offset,
    ) -> Result<Self, XskError> {
        // The ring memory spans the producer/consumer indices plus `size` entries past `desc`.
        let map_len = ring_offset.desc as usize + size as usize * std::mem::size_of::<T>();
        // SAFETY: maps the kernel-prepared ring for this fd at the documented magic page offset
        // (XDP_PGOFF_*). PROT_READ|WRITE + MAP_SHARED|MAP_POPULATE per the AF_XDP setup sequence.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                page_offset,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(XskError::Mmap {
                area: sockopt.name,
                source: io::Error::last_os_error(),
            });
        }
        let base = addr.cast::<u8>();
        // SAFETY: the kernel placed the producer/consumer u32s and the entry array at the byte
        // offsets it reported in `ring_offset`; we form pointers within the mapping we just made.
        let (producer, consumer, entries) = unsafe {
            (
                base.add(ring_offset.producer as usize).cast::<AtomicU32>() as *const AtomicU32,
                base.add(ring_offset.consumer as usize).cast::<AtomicU32>() as *const AtomicU32,
                base.add(ring_offset.desc as usize).cast::<T>(),
            )
        };
        Ok(Self {
            producer,
            consumer,
            entries,
            mask: size - 1,
            map: (
                NonNull::new(base).ok_or_else(|| XskError::Mmap {
                    area: sockopt.name,
                    source: io::Error::from(io::ErrorKind::Other),
                })?,
                map_len,
            ),
            cached_index: 0,
        })
    }

    /// Load the kernel-owned producer index with acquire ordering (so entries it wrote are visible).
    fn producer_load_acquire(&self) -> u32 {
        // SAFETY: `producer` points at the kernel-shared `__u32`, valid for the mapping's lifetime.
        unsafe { (*self.producer).load(Ordering::Acquire) }
    }

    /// Load the kernel-owned consumer index with acquire ordering.
    fn consumer_load_acquire(&self) -> u32 {
        // SAFETY: as above for the consumer index.
        unsafe { (*self.consumer).load(Ordering::Acquire) }
    }

    /// Publish our producer index with release ordering (so the entries we wrote are visible first).
    fn producer_store_release(&self, value: u32) {
        // SAFETY: as above; release pairs with the kernel's acquire on the producer index.
        unsafe { (*self.producer).store(value, Ordering::Release) };
    }

    /// Publish our consumer index with release ordering.
    fn consumer_store_release(&self, value: u32) {
        // SAFETY: as above; release pairs with the kernel's acquire on the consumer index.
        unsafe { (*self.consumer).store(value, Ordering::Release) };
    }

    /// Read the entry at ring slot `index & mask`.
    fn entry(&self, index: u32) -> T {
        // SAFETY: `(index & mask)` is always < ring size, so the offset is in-bounds of the array.
        unsafe { *self.entries.add((index & self.mask) as usize) }
    }

    /// Write `value` into ring slot `index & mask`.
    fn set_entry(&mut self, index: u32, value: T) {
        // SAFETY: `(index & mask)` is in-bounds as above; we hold the producer side exclusively.
        unsafe { *self.entries.add((index & self.mask) as usize) = value };
    }
}

impl<T> Drop for Ring<T> {
    fn drop(&mut self) {
        // SAFETY: `map` is exactly the base/length from `mmap`, unmapped once here on drop.
        unsafe {
            libc::munmap(self.map.0.as_ptr().cast::<libc::c_void>(), self.map.1);
        }
    }
}

/// A ring's human name, used only for error reporting from [`Ring::map`].
#[derive(Clone, Copy)]
struct RingOption {
    name: &'static str,
}

/// An AF_XDP socket: the fd, its UMEM, and the four rings, bound to one interface queue.
///
/// Single-owner: created and driven by one thread (the busy-poll RX/TX loop). It is `Send` so the
/// engine can move it onto a dedicated datapath thread, but it is **not** `Sync` — concurrent access
/// to the rings is undefined.
pub struct XskSocket {
    /// The AF_XDP socket fd (closed on drop).
    fd: OwnedFd,
    umem: Umem,
    fill: Ring<u64>,
    completion: Ring<u64>,
    rx: Ring<libc::xdp_desc>,
    tx: Ring<libc::xdp_desc>,
    /// Whether the bind requested `XDP_USE_NEED_WAKEUP` (then TX/FILL may need a syscall kick).
    need_wakeup: bool,
}

/// A received datagram read off the RX ring: the source frame offset (already returned to FILL) and
/// the copied bytes. (The copy keeps the UMEM frame available to recycle immediately; the media
/// hot path is small datagrams, so the copy is cheap relative to a stalled FILL ring.)
pub struct XskReceived {
    /// The raw frame bytes (full Ethernet frame as the NIC/kernel delivered it).
    pub frame: Vec<u8>,
}

impl XskSocket {
    /// Create, configure, map, and bind an AF_XDP socket on `ifindex`/`queue`.
    ///
    /// Follows the uapi setup sequence (`Documentation/networking/af_xdp.rst`): `socket` →
    /// `XDP_UMEM_REG` → size the FILL/COMPLETION/RX/TX rings via `setsockopt` → `XDP_MMAP_OFFSETS`
    /// → `mmap` each ring → `bind`. On success the FILL ring is fully stocked so the kernel can
    /// receive immediately.
    pub fn new(ifindex: u32, queue: u32, config: &XskConfig) -> Result<Self, XskError> {
        for size in [
            config.frame_count,
            config.fill_size,
            config.completion_size,
            config.rx_size,
            config.tx_size,
        ] {
            if size == 0 || !size.is_power_of_two() {
                return Err(XskError::RingSize(size));
            }
        }

        // SAFETY: a standard socket() call; on failure it returns -1 and sets errno.
        let raw = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(XskError::Socket(io::Error::last_os_error()));
        }
        // Own the fd immediately so any early return closes it.
        // SAFETY: `raw` is a fresh, valid, owned fd from a successful `socket()`.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let umem = Umem::new(config.frame_count, config.frame_size)?;

        // Register the UMEM (XDP_UMEM_REG).
        let mut reg: libc::xdp_umem_reg = unsafe { std::mem::zeroed() };
        reg.addr = umem.area.as_ptr() as u64;
        reg.len = umem.len as u64;
        reg.chunk_size = config.frame_size;
        reg.headroom = 0;
        reg.flags = 0;
        set_sockopt(
            fd.as_raw_fd(),
            libc::XDP_UMEM_REG,
            "XDP_UMEM_REG",
            &reg,
        )?;

        // Size the four rings (entry counts).
        set_sockopt(
            fd.as_raw_fd(),
            libc::XDP_UMEM_FILL_RING,
            "XDP_UMEM_FILL_RING",
            &config.fill_size,
        )?;
        set_sockopt(
            fd.as_raw_fd(),
            libc::XDP_UMEM_COMPLETION_RING,
            "XDP_UMEM_COMPLETION_RING",
            &config.completion_size,
        )?;
        set_sockopt(
            fd.as_raw_fd(),
            libc::XDP_RX_RING,
            "XDP_RX_RING",
            &config.rx_size,
        )?;
        set_sockopt(
            fd.as_raw_fd(),
            libc::XDP_TX_RING,
            "XDP_TX_RING",
            &config.tx_size,
        )?;

        // Resolve the ring memory offsets the kernel chose (XDP_MMAP_OFFSETS).
        let offsets = get_mmap_offsets(fd.as_raw_fd())?;

        let fill = Ring::<u64>::map(
            fd.as_raw_fd(),
            config.fill_size,
            RingOption { name: "fill" },
            libc::XDP_UMEM_PGOFF_FILL_RING as libc::off_t,
            &offsets.fr,
        )?;
        let completion = Ring::<u64>::map(
            fd.as_raw_fd(),
            config.completion_size,
            RingOption {
                name: "completion",
            },
            libc::XDP_UMEM_PGOFF_COMPLETION_RING as libc::off_t,
            &offsets.cr,
        )?;
        let rx = Ring::<libc::xdp_desc>::map(
            fd.as_raw_fd(),
            config.rx_size,
            RingOption { name: "rx" },
            libc::XDP_PGOFF_RX_RING,
            &offsets.rx,
        )?;
        let tx = Ring::<libc::xdp_desc>::map(
            fd.as_raw_fd(),
            config.tx_size,
            RingOption { name: "tx" },
            libc::XDP_PGOFF_TX_RING,
            &offsets.tx,
        )?;

        // Bind to the interface queue (sockaddr_xdp).
        let mut addr: libc::sockaddr_xdp = unsafe { std::mem::zeroed() };
        addr.sxdp_family = libc::AF_XDP as u16;
        addr.sxdp_flags = config.bind_flags;
        addr.sxdp_ifindex = ifindex;
        addr.sxdp_queue_id = queue;
        // SAFETY: `addr` is a fully-initialised sockaddr_xdp; we pass its size exactly. bind returns
        // -1 / errno on failure.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_xdp>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(XskError::Bind {
                ifindex,
                queue,
                source: io::Error::last_os_error(),
            });
        }

        let need_wakeup = config.bind_flags & libc::XDP_USE_NEED_WAKEUP != 0;
        let mut socket = Self {
            fd,
            umem,
            fill,
            completion,
            rx,
            tx,
            need_wakeup,
        };
        // Stock the FILL ring so the kernel has frames to receive into from the first packet.
        socket.replenish_fill();
        Ok(socket)
    }

    /// The raw fd — what gets written into the eBPF `XSKS` map so `XDP_REDIRECT` lands here.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Lend the kernel as many free UMEM frames as the FILL ring can hold, so RX never starves.
    /// Returns the number of frames enqueued.
    pub fn replenish_fill(&mut self) -> usize {
        let prod = self.fill.cached_index;
        let cons = self.fill.consumer_load_acquire();
        let capacity = (self.fill.mask + 1) - prod.wrapping_sub(cons);
        let mut enqueued = 0u32;
        while enqueued < capacity {
            let Some(addr) = self.umem.alloc() else {
                break;
            };
            self.fill.set_entry(prod.wrapping_add(enqueued), addr);
            enqueued += 1;
        }
        if enqueued > 0 {
            let new_prod = prod.wrapping_add(enqueued);
            self.fill.cached_index = new_prod;
            self.fill.producer_store_release(new_prod);
        }
        enqueued as usize
    }

    /// Drain up to `max` received frames off the RX ring, recycling each frame back to FILL.
    /// Each returned [`XskReceived`] is a copy of the frame bytes (see the type's note).
    pub fn rx_burst(&mut self, max: usize) -> Vec<XskReceived> {
        let cons = self.rx.cached_index;
        let prod = self.rx.producer_load_acquire();
        let available = prod.wrapping_sub(cons);
        let take = (available as usize).min(max);
        let mut out = Vec::with_capacity(take);
        for offset in 0..take as u32 {
            let desc = self.rx.entry(cons.wrapping_add(offset));
            let addr = desc.addr;
            let len = desc.len as usize;
            // SAFETY: the kernel produced this descriptor; `addr`/`len` index a frame it filled and
            // now hands us. We copy out, then return the frame to the free-list / FILL ring.
            let bytes = unsafe { self.umem.frame(addr, len) }.to_vec();
            out.push(XskReceived { frame: bytes });
            self.umem.free_frame(addr);
        }
        if take > 0 {
            let new_cons = cons.wrapping_add(take as u32);
            self.rx.cached_index = new_cons;
            self.rx.consumer_store_release(new_cons);
            // Frames just freed can go straight back to the kernel.
            self.replenish_fill();
        }
        out
    }

    /// Enqueue one frame for transmission: copy `frame_bytes` into a free UMEM frame and push a TX
    /// descriptor. Returns `false` (without consuming a frame) if the UMEM or TX ring is full — the
    /// caller drops the datagram (late media is worthless; never grow an unbounded queue). The caller
    /// must follow a batch of `tx_push` with [`XskSocket::tx_kick`] to notify the kernel.
    #[must_use]
    pub fn tx_push(&mut self, frame_bytes: &[u8]) -> bool {
        // A frame larger than the UMEM chunk would write past the frame into a neighbour — refuse it
        // (single-buffer frames only; we do not split with XDP_USE_SG).
        if frame_bytes.is_empty() || frame_bytes.len() > self.umem.frame_size {
            return false;
        }
        let prod = self.tx.cached_index;
        let cons = self.tx.consumer_load_acquire();
        // Outstanding == ring depth (mask + 1) means full; `> mask` says the same without overflow.
        if prod.wrapping_sub(cons) > self.tx.mask {
            return false; // TX ring full
        }
        let Some(addr) = self.umem.alloc() else {
            return false; // UMEM exhausted
        };
        // SAFETY: `addr` is a fresh free frame we exclusively own until the kernel completes it; the
        // length is bounded by `frame_size` (the caller pre-sizes; we additionally guard here).
        let frame = unsafe { self.umem.frame_mut(addr, frame_bytes.len()) };
        frame.copy_from_slice(frame_bytes);
        self.tx.set_entry(
            prod,
            libc::xdp_desc {
                addr,
                len: frame_bytes.len() as u32,
                options: 0,
            },
        );
        let new_prod = prod.wrapping_add(1);
        self.tx.cached_index = new_prod;
        self.tx.producer_store_release(new_prod);
        true
    }

    /// Notify the kernel that TX descriptors are ready (and, in `NEED_WAKEUP` mode, that FILL was
    /// replenished). A non-blocking `sendto` with no buffer is the documented TX kick.
    pub fn tx_kick(&self) -> io::Result<()> {
        // In NEED_WAKEUP mode the kick is only needed when the ring flags ask for it; otherwise we
        // always kick (copy-mode generic XDP requires the syscall to drive TX).
        // SAFETY: a sendto with a null buffer and MSG_DONTWAIT — the AF_XDP TX wake-up call. EAGAIN /
        // EBUSY are benign (the kernel is already draining); we surface only real errors.
        let rc = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EBUSY) | Some(libc::ENOBUFS) => Ok(()),
                _ => Err(err),
            }
        } else {
            Ok(())
        }
    }

    /// Reap completed TX frames off the COMPLETION ring, returning them to the free-list. Returns the
    /// number reclaimed. Call periodically (after `tx_kick`) so transmitted frames are reusable.
    pub fn complete_tx(&mut self, max: usize) -> usize {
        let cons = self.completion.cached_index;
        let prod = self.completion.producer_load_acquire();
        let available = prod.wrapping_sub(cons);
        let take = (available as usize).min(max);
        for offset in 0..take as u32 {
            let addr = self.completion.entry(cons.wrapping_add(offset));
            self.umem.free_frame(addr);
        }
        if take > 0 {
            let new_cons = cons.wrapping_add(take as u32);
            self.completion.cached_index = new_cons;
            self.completion.consumer_store_release(new_cons);
        }
        take
    }

    /// Whether the bind requested `NEED_WAKEUP` semantics (informational).
    #[must_use]
    pub fn needs_wakeup(&self) -> bool {
        self.need_wakeup
    }
}

/// `setsockopt(fd, SOL_XDP, option, &value)` with a typed value (`xdp_umem_reg` or a `u32` size).
fn set_sockopt<T>(
    fd: RawFd,
    option: libc::c_int,
    name: &'static str,
    value: &T,
) -> Result<(), XskError> {
    // SAFETY: `value` is a valid `&T`; we pass its address and exact size. SOL_XDP options take a
    // pointer to either `xdp_umem_reg` or a `u32` ring size, matching the typed call sites.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_XDP,
            option,
            std::ptr::from_ref(value).cast::<libc::c_void>(),
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(XskError::SetSockOpt {
            option: name,
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

/// `getsockopt(XDP_MMAP_OFFSETS)` — the kernel reports where in each ring mapping the producer index,
/// consumer index, and entry array live.
fn get_mmap_offsets(fd: RawFd) -> Result<libc::xdp_mmap_offsets, XskError> {
    let mut offsets: libc::xdp_mmap_offsets = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::xdp_mmap_offsets>() as libc::socklen_t;
    // SAFETY: `offsets`/`len` are a correctly-sized out-buffer for XDP_MMAP_OFFSETS; the kernel fills
    // it and writes the actual length back into `len`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_XDP,
            libc::XDP_MMAP_OFFSETS,
            std::ptr::from_mut(&mut offsets).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(XskError::GetOffsets(io::Error::last_os_error()));
    }
    Ok(offsets)
}

/// Resolve a network interface name to its kernel ifindex (`if_nametoindex(3)`), `0` on failure.
#[must_use]
pub fn ifindex(interface: &str) -> u32 {
    let Ok(name) = std::ffi::CString::new(interface) else {
        return 0;
    };
    // SAFETY: `name` is a valid NUL-terminated C string for the duration of the call.
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifindex_of_loopback_is_nonzero() {
        // `lo` exists on every Linux host (incl. the docker build container), index ≥ 1.
        assert!(ifindex("lo") >= 1, "loopback must resolve to a real ifindex");
    }

    #[test]
    fn ifindex_of_bogus_interface_is_zero() {
        assert_eq!(ifindex("definitely-not-an-interface-xyz"), 0);
    }

    #[test]
    fn rejects_non_power_of_two_ring_sizes() {
        let config = XskConfig {
            rx_size: 1000, // not a power of two
            ..XskConfig::default()
        };
        // The size check fails before any syscall, so this never touches a NIC.
        let result = XskSocket::new(ifindex("lo"), 0, &config);
        assert!(matches!(result, Err(XskError::RingSize(1000))));
    }

    #[test]
    fn umem_alloc_and_free_round_trips_frames() {
        // The UMEM mapping itself needs no privileges (anonymous mmap), so the frame book-keeping is
        // testable NIC-free.
        let mut umem = Umem::new(4, 2048).expect("map umem");
        let mut taken = Vec::new();
        while let Some(addr) = umem.alloc() {
            assert_eq!(addr % 2048, 0, "frames are frame-aligned");
            taken.push(addr);
        }
        assert_eq!(taken.len(), 4, "all four frames allocate");
        assert!(umem.alloc().is_none(), "exhausted UMEM yields None");
        for addr in taken {
            umem.free_frame(addr);
        }
        assert!(umem.alloc().is_some(), "freed frames allocate again");
    }
}

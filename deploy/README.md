# Running siphon-rtp in Docker (incl. XDP)

The image is a fully static musl binary on distroless — the zero-C decision is what makes that
clean. Two compose profiles mirror the plan's dev/prod split.

## Dev — veth + SKB-mode XDP (any kernel ≥ 5.10)

```bash
docker compose --profile dev up --build
```

The `runtime-dev` image ([`dev-entrypoint.sh`](dev-entrypoint.sh)) mounts bpffs and creates a veth
pair (`siphon0` ↔ `siphon-peer`, `10.201.0.1/2`) before starting the binary. Both profiles build the **UDP-backend** `siphon-rtp` binary — this proves
the bpffs / veth / caps wiring the kernel datapath needs, but the binary does not itself attach an XDP
program. To run the in-kernel datapath, build `siphon-rtp-xdp-daemon` (see below) and start it with
`--xdp-interface siphon0` in this same environment; SKB (generic) mode needs no NIC-driver zero-copy
support, so it runs on any kernel, including CI. Inject test traffic on `siphon-peer` to drive the
in-kernel classifier. Control plane is on `localhost:8080`.

Caps: `NET_ADMIN` (attach XDP / manage veth), `BPF` (load programs/maps), `SYS_ADMIN` (bpffs mount
on kernels < 5.8); `memlock=-1` for BPF maps/UMEM.

## Prod — host network + native/zero-copy XDP

```bash
docker compose --profile prod up --build
```

`network_mode: host` exposes the host NIC for AF_XDP; the `runtime` image is distroless and, like dev,
ships the UDP-backend binary today. Run `siphon-rtp-xdp-daemon --xdp-interface <NIC>` for the kernel
datapath — native/ZC XDP needs driver support, and the daemon degrades ZC → copy → SKB → UDP backend
by capability detection.

## XDP datapath

The XDP datapath is a separate crate (`crates/siphon-rtp-xdp`) and a separate binary
(`siphon-rtp-xdp-daemon`), not a Cargo feature on `siphon-rtp`. Build/verify it with the dedicated
Dockerfile:

```bash
docker build -f deploy/Dockerfile.xdp -t siphon-rtp-xdp-check .
```

The default image ships the UDP backend; `CARGO_FEATURES` only toggles `amr`.

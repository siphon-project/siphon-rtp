# Running siphon-rtp in Docker (incl. XDP)

The image is a fully static musl binary on distroless — the zero-C decision is what makes that
clean. Two compose profiles mirror the plan's dev/prod split.

## Dev — veth + SKB-mode XDP (any kernel ≥ 5.10)

```bash
docker compose --profile dev up --build
```

The `runtime-dev` image ([`dev-entrypoint.sh`](dev-entrypoint.sh)) mounts bpffs and creates a veth
pair (`siphon0` ↔ `siphon-peer`, `10.201.0.1/2`) before starting the engine. The engine attaches
its XDP program to `siphon0` in **SKB (generic) mode**, which needs no NIC-driver zero-copy support
— so it runs on any kernel, including in CI. Inject test traffic on `siphon-peer` to drive the
in-kernel classifier. Control plane is on `localhost:8080`.

Caps: `NET_ADMIN` (attach XDP / manage veth), `BPF` (load programs/maps), `SYS_ADMIN` (bpffs mount
on kernels < 5.8); `memlock=-1` for BPF maps/UMEM.

## Prod — host network + native/zero-copy XDP

```bash
docker compose --profile prod up --build
```

`network_mode: host` puts AF_XDP on the host NIC; the `runtime` image is distroless. Native/ZC XDP
needs driver support — the engine degrades ZC → copy → SKB → UDP backend by capability detection.

## XDP feature flag

Both profiles build the **UDP-loopback** binary by default (proving the caps/bpffs/veth wiring on
any host). Once `crates/siphon-rtp-ebpf` lands, set `build.args.CARGO_FEATURES: "xdp"` in
[`docker-compose.yml`](../docker-compose.yml) (or `--build-arg CARGO_FEATURES=xdp`) to compile the
aya XDP datapath. With **no** caps at all the same image still runs — it falls back to the UDP
backend with a `tracing::warn!`.
```bash
docker build --build-arg CARGO_FEATURES=xdp -t siphon-rtp:xdp .
```

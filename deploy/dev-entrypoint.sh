#!/usr/bin/env bash
# Dev XDP harness entrypoint.
#
# Sets up a veth pair that the engine attaches its XDP program to (SKB / generic mode, so it works
# on any kernel >= 5.10 without NIC-driver zero-copy support), mounts bpffs for pinned maps, then
# execs the engine. Requires NET_ADMIN + BPF (+ SYS_ADMIN for the bpffs mount on kernels < 5.8).
set -euo pipefail

# bpffs for pinned BPF maps. The compose also bind-mounts the host's /sys/fs/bpf; mount here too in
# case it is not already a bpf mount inside the container's mount namespace.
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  mount -t bpf bpf /sys/fs/bpf 2>/dev/null || echo "dev-entrypoint: could not mount bpffs (need SYS_ADMIN on older kernels)" >&2
fi

# veth pair: siphon0 <-> siphon-peer. The engine attaches XDP to siphon0; traffic injected on
# siphon-peer drives the in-kernel classifier. SKB mode needs no driver support.
if ! ip link show siphon0 >/dev/null 2>&1; then
  ip link add siphon0 type veth peer name siphon-peer
  ip addr add 10.201.0.1/24 dev siphon0
  ip addr add 10.201.0.2/24 dev siphon-peer
  ip link set siphon0 up
  ip link set siphon-peer up
  echo "dev-entrypoint: veth siphon0 <-> siphon-peer up (10.201.0.1/2)" >&2
fi

exec /usr/local/bin/siphon-rtp-engine "$@"

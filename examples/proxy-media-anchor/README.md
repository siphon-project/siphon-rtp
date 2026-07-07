# Proxy media anchor: Kamailio + siphon-rtp over NG

A SIP proxy that anchors every call's media through siphon-rtp, so the endpoints never see each
other's media address (topology hiding / NAT traversal). Because siphon-rtp speaks the rtpengine NG
protocol, this is a stock Kamailio `rtpengine` setup with the socket pointed at siphon-rtp's `--ng`
listener. `kamailio.cfg` is the same config you would use with a real rtpengine; the only
siphon-rtp-specific line is the socket address.

## Run

Start the engine with the NG listener and a routable media posture:

```sh
siphon-rtp \
  --ng 127.0.0.1:22222 \
  --relay-bind-ip <your-routable-ip> \
  --port-min 30000 --port-max 40000
```

Then run Kamailio with `kamailio.cfg`:

```sh
kamailio -f kamailio.cfg -D -E    # foreground, log to stderr
```

Place a call through the proxy. Its `rtpengine_manage()` calls become NG `offer` / `answer` /
`delete` to the engine; the rewritten SDP advertises `--relay-bind-ip` and a port inside the
`--port-min`/`--port-max` window, and media relays through the engine.

## Verify

- Kamailio's rtpengine keepalives succeed (`kamcmd rtpengine.show all` shows the node enabled);
  siphon-rtp answers NG `ping` with `pong`.
- A test call's rewritten SDP carries the engine's media address and a port in your range.
- Two-way audio flows through the engine. Endpoints behind symmetric NAT may need the proxy to pass
  the `received-from` hint or the `symmetric` flag (siphon-rtp does not blind-latch; see
  [Security & NAT](../../docs/security-and-nat.md)).
- `siphon-rtp --metrics-addr` + Prometheus, or NG `query` (returns a `totals` counter dict), show
  the traffic.

Full cutover guide, parity table, and the behavioural differences from rtpengine:
[docs/migrating-from-rtpengine.md](../../docs/migrating-from-rtpengine.md). OpenSIPS's `rtpengine`
module takes the same `rtpengine_sock` parameter and works identically.

#!/usr/bin/env bash
# Independent-decoder check for the protected MCPTT floor stream: have a keyed forwarding-room seat
# build a Floor Granted, feed it to Wireshark and assert the clear SRTCP header reads back as
# intended (RTCP APP, name MCPT, the engine's SSRC), with no malformed marker. The APP body stays
# encrypted (Wireshark has no key), which is expected. Needs tshark and text2pcap; not part of
# `cargo test`.
set -euo pipefail

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
port=5006

FLOOR_SRTCP_HEX_OUT="$work/packet.hex" \
  cargo test -p siphon-rtp --lib emit_protected_floor_granted_hex_for_tshark -- --ignored >/dev/null

text2pcap -u "$port,$port" -q "$work/packet.hex" "$work/packet.pcap" >/dev/null 2>&1

fields="$(tshark -r "$work/packet.pcap" -d "udp.port==$port,rtcp" -T fields \
  -e rtcp.version -e rtcp.pt -e rtcp.length)"
echo "fields: $fields"
# V=2, PT=204 (APP), length 5 (RFC 3550 §6.7: 16 octets of packet before protection).
[ "$fields" = "$(printf '2\t204\t5')" ] || { echo "FAIL: header fields"; exit 1; }

verbose="$(tshark -r "$work/packet.pcap" -d "udp.port==$port,rtcp" -V)"
if grep -q -i 'malformed' <<<"$verbose"; then
  echo "FAIL: malformed marker"
  echo "$verbose"
  exit 1
fi
echo "OK: tshark reads the protected floor stream's SRTCP header, no [Malformed]"

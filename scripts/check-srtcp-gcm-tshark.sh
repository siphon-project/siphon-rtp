#!/usr/bin/env bash
# Independent-decoder check for the SRTCP AEAD_AES_128_GCM encoder: feed a protected packet to
# Wireshark and assert the clear SRTCP header fields read back as intended, with no malformed
# marker. The payload stays encrypted (Wireshark has no key), which is expected. Needs tshark and
# text2pcap; not part of `cargo test`.
set -euo pipefail

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
port=5005

SRTCP_GCM_HEX_OUT="$work/packet.hex" \
  cargo test -p siphon-rtp-srtp --lib emit_protected_packet_hex_for_tshark -- --ignored >/dev/null

text2pcap -u "$port,$port" -q "$work/packet.hex" "$work/packet.pcap" >/dev/null 2>&1

# Packet: V=2 P=0 RC=1, PT=200 (SR), length=13, sender SSRC 0x4d617273 ("Mars").
fields="$(tshark -r "$work/packet.pcap" -d "udp.port==$port,rtcp" -T fields \
  -e rtcp.version -e rtcp.pt -e rtcp.length -e rtcp.senderssrc)"
echo "fields: $fields"
[ "$fields" = "$(printf '2\t200\t13\t0x4d617273')" ] || { echo "FAIL: header fields"; exit 1; }

verbose="$(tshark -r "$work/packet.pcap" -d "udp.port==$port,rtcp" -V)"
if grep -q -i 'malformed' <<<"$verbose"; then
  echo "FAIL: malformed marker"
  echo "$verbose"
  exit 1
fi
echo "OK: tshark reads the SRTCP header, no [Malformed]"

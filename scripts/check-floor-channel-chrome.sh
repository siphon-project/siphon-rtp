#!/usr/bin/env bash
# Acceptance test of the MCPTT floor data channel against a real browser: headless Chrome joins a
# forwarding room over DTLS-SRTP + a WebRTC data channel and exchanges TS 24.380 floor messages with
# the engine's JSON control plane. No npm packages: Node's built-in WebSocket speaks the DevTools
# protocol and node:net speaks the control protocol.
#
#   scripts/check-floor-channel-chrome.sh            # builds the engine, then runs
#   ENGINE_BIN=/path/to/siphon-rtp CHROME_BIN=... scripts/check-floor-channel-chrome.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [[ -z "${ENGINE_BIN:-}" ]]; then
  cargo build -p siphon-rtp
  ENGINE_BIN="$(cargo metadata --format-version 1 --no-deps | node -e \
    'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).target_directory))')/debug/siphon-rtp"
fi
export ENGINE_BIN
export CHROME_BIN="${CHROME_BIN:-$(command -v google-chrome || command -v google-chrome-stable || command -v chromium)}"

exec node "$root/scripts/floor-channel-chrome.mjs"

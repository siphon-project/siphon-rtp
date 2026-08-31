#!/usr/bin/env bash
# Fetch the third-party X2/X3 Wireshark dissector used as an independent decoder for the
# TS 103 221-2 framing, and verify it against a pinned hash. See README.md.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target="${script_dir}/x2x3PduDissector.lua"

url="https://raw.githubusercontent.com/hyavari/x2x3PduDissector/main/x2x3PduDissector.lua"
expected_sha256="431ef56da4c6753c349cc1c0824eabec322effd3865e8e23fce6de30cb49a545"

echo "fetching ${url}"
curl -sSfL -o "${target}.tmp" "${url}"

actual_sha256="$(sha256sum "${target}.tmp" | cut -d' ' -f1)"
if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
  rm -f "${target}.tmp"
  echo "SHA-256 mismatch — refusing to install." >&2
  echo "  expected ${expected_sha256}" >&2
  echo "  actual   ${actual_sha256}" >&2
  echo "The upstream dissector changed. Review the diff, then re-pin the hash in this script" >&2
  echo "and in README.md as a deliberate commit." >&2
  exit 1
fi

mv "${target}.tmp" "${target}"
echo "installed ${target}"
echo "sha256 ${actual_sha256} (pinned)"

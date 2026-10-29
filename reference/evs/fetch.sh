#!/usr/bin/env bash
# Fetch the EVS fixed-point reference C (3GPP TS 26.442) this port follows and the TS 26.444
# conformance sequences that are its acceptance criteria, verified against pinned hashes. See
# README.md.
#
#   fetch.sh                 the reference C plus every conformance member (about 1.8 GB unpacked)
#   fetch.sh PATTERN...      the reference C plus only the members matching the fnmatch PATTERNs,
#                            e.g. 'testvec/Readme*' 'testvec/testv/bitstreams/wb/*'
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
agent="Mozilla/5.0" # the 3GPP file server's CDN answers 403 to clients without a browser agent

# TS 26.442 v16.4.0 — the release TS 26.444's own Readme.txt names as the one its sequences were
# generated with. Its c-code tree is byte-identical to the later v19.0.0 (j00).
code_url="https://www.3gpp.org/ftp/Specs/archive/26_series/26.442/26442-g40.zip"
code_sha256="3f99f40b9feb578fa5a204282e3784cb92c2b893e9afe5e78a1508db37704688"

# TS 26.444 BASOP (fixed-point) sequences. Too large to pin by a whole-file hash without a 1.8 GB
# download over a slow server, so the pin is the sha256 of the archive's central directory — every
# member's name, size and CRC-32 — and Python's zipfile checks each member's CRC-32 as it extracts.
vectors_url="https://www.3gpp.org/ftp/Specs/archive/26_series/26.444/test_sequences/26444_ce0_da0_e60_f40_g50-TestSeq_BASOP_26442.zip"
vectors_digest="faa95385a508b5e66fd34be4e904fbdc5b5a67ddc7d943fc6961077f27ed28a6"

refuse() {
  echo "$1" >&2
  echo "3GPP republished it. Review what changed, then re-pin the hash in this script and in" >&2
  echo "README.md as a deliberate commit." >&2
  exit 1
}

archive="${script_dir}/.26442-g40.zip"
if [[ -f "${archive}" ]] && [[ "$(sha256sum "${archive}" | cut -d' ' -f1)" == "${code_sha256}" ]]; then
  echo "using cached ${archive}"
else
  echo "fetching ${code_url}"
  curl -sSfL -A "${agent}" -o "${archive}.tmp" "${code_url}"
  [[ "$(sha256sum "${archive}.tmp" | cut -d' ' -f1)" == "${code_sha256}" ]] \
    || { rm -f "${archive}.tmp"; refuse "SHA-256 mismatch on ${code_url}"; }
  mv "${archive}.tmp" "${archive}"
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
echo "extracting reference C -> ${script_dir}/c-code"
unzip -q -o "${archive}" '26442-g40-ANSI-C_source_code.zip' -d "${work}"
unzip -q -o "${work}/26442-g40-ANSI-C_source_code.zip" -d "${work}/source"
rm -rf "${script_dir}/c-code"
mv "${work}/source/c-code" "${script_dir}/c-code"
# The package ships prebuilt Windows binaries next to the sources. Nothing here runs them.
rm -f "${script_dir}/c-code/EVS_cod.exe" "${script_dir}/c-code/EVS_dec.exe"

echo "verifying the conformance archive's central directory"
actual_digest="$(python3 -I "${script_dir}/remote_zip.py" digest "${vectors_url}")"
[[ "${actual_digest}" == "${vectors_digest}" ]] \
  || refuse "central-directory digest mismatch on ${vectors_url}: ${actual_digest}"

patterns=("$@")
if [[ ${#patterns[@]} -eq 0 ]]; then
  # One range-request stream per directory: the server is slow per connection, not in aggregate.
  patterns=('testvec/*.txt' 'testvec/*.cfg' 'testvec/switchPaths/*' 'testvec/testv/input/*'
    'testvec/testv/preparedBitstreams/*')
  for band in nb wb swb fb amrwb preparedBS_nb preparedBS_wb preparedBS_swb preparedBS_fb; do
    patterns+=("testvec/testv/bitstreams/${band}/*" "testvec/testv/decoded/${band}/*")
  done
fi
echo "extracting ${#patterns[@]} pattern(s) -> ${script_dir}/testvec"
pids=()
for pattern in "${patterns[@]}"; do
  python3 -I "${script_dir}/remote_zip.py" get "${vectors_url}" "${script_dir}" "${pattern}" > /dev/null &
  pids+=("$!")
done
failed=0
for pid in "${pids[@]}"; do
  wait "${pid}" || failed=1
done
[[ ${failed} -eq 0 ]] || { echo "some members failed to download; rerun to resume" >&2; exit 1; }

echo
echo "installed:"
echo "  $(find "${script_dir}/c-code" -type f | wc -l) reference C files under c-code/"
echo "  $(find "${script_dir}/testvec" -type f 2>/dev/null | wc -l) conformance files under testvec/"
echo "next: sh ${script_dir}/oracle/build.sh"

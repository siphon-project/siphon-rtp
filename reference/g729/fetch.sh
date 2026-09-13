#!/usr/bin/env bash
# Fetch the ITU-T G.729 Release 3 software package — the fixed-point reference C this port follows
# and the official test vectors that are its acceptance criteria — and verify it against a pinned
# hash. See README.md.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
archive="${script_dir}/.g729-release3.zip"

# The in-force Recommendation's "SOFT-ZST" electronic attachment (G.729 (06/2012), Software
# Release 3). Byte-stable across downloads, hence the pin.
url="https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-G.729-201206-I!!SOFT-ZST-E&type=items"
expected_sha256="979680ff3b52b13a5701453178efd32b53e340114638fd330fdb6669eec86620"

if [[ -f "${archive}" ]] && [[ "$(sha256sum "${archive}" | cut -d' ' -f1)" == "${expected_sha256}" ]]; then
  echo "using cached ${archive}"
else
  echo "fetching ${url}"
  curl -sSfL -o "${archive}.tmp" "${url}"
  actual_sha256="$(sha256sum "${archive}.tmp" | cut -d' ' -f1)"
  if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
    rm -f "${archive}.tmp"
    echo "SHA-256 mismatch — refusing to install." >&2
    echo "  expected ${expected_sha256}" >&2
    echo "  actual   ${actual_sha256}" >&2
    echo "The ITU republished the attachment. Review what changed, then re-pin the hash in this" >&2
    echo "script and in README.md as a deliberate commit." >&2
    exit 1
  fi
  mv "${archive}.tmp" "${archive}"
fi

release="Software/G729_Release3"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# The reference C this port covers: the base codec, Annex A (reduced complexity, bitstream-
# interoperable) and Annex B (VAD/DTX/CNG). Annex B ships twice, once on the base codec (c_codeB =
# G.729B) and once on Annex A (c_codeBA = G.729AB); both are kept because both combinations appear on
# the wire. The remaining annexes ship in the same archive and are deliberately left out — nothing
# here implements them.
echo "extracting reference C -> ${script_dir}/c-code"
rm -rf "${script_dir}/c-code"
mkdir -p "${script_dir}/c-code"
for module in g729/c_code:g729 g729AnnexA/c_code:annex-a g729AnnexB/c_codeB:annex-b g729AnnexB/c_codeBA:annex-ba; do
  src="${module%%:*}"
  dst="${module##*:}"
  unzip -q -o -j "${archive}" "${release}/${src}/*" -d "${script_dir}/c-code/${dst}"
done

# The official test vectors: *.in input PCM, *.bit encoded bitstream, *.pst decoded PCM. The
# acceptance criterion runs both directions — encode(.in) must equal .bit and decode(.bit) must
# equal .pst, byte for byte.
echo "extracting test vectors -> ${script_dir}/testv"
rm -rf "${script_dir}/testv"
for module in g729:base g729AnnexA:annexa g729AnnexB:annexb; do
  src="${module%%:*}"
  dst="${module##*:}"
  unzip -q -o -j "${archive}" "${release}/${src}/test_vectors/*" -d "${work}/${dst}"
  mkdir -p "${script_dir}/testv/${dst}"
  # Upstream ships DOS-uppercase names; lowercase them so the conformance test can name a vector the
  # way the ITU documentation does without caring which extraction produced the tree.
  for file in "${work}/${dst}"/*; do
    [[ -f "${file}" ]] || continue
    base="$(basename "${file}")"
    mv "${file}" "${script_dir}/testv/${dst}/$(echo "${base}" | tr '[:upper:]' '[:lower:]')"
  done
done

echo
echo "installed:"
echo "  $(find "${script_dir}/c-code" -type f | wc -l) reference C files under c-code/"
echo "  $(find "${script_dir}/testv" -type f | wc -l) test-vector files under testv/"
echo "sha256 ${expected_sha256} (pinned)"

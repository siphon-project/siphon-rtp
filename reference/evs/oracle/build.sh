#!/usr/bin/env bash
# Build the out-of-tree EVS oracles from the reference sources fetch.sh installed:
#   build/EVS_dec, build/EVS_cod   the TS 26.442 reference codec, to reproduce the vectors and probe
#   build/basop_oracle             the basic-operator oracle tests/evs_basop_oracle.rs replays
#
# Everything is compiled with -fwrapv. The reference relies on signed overflow wrapping (L_add_c,
# L_lshl, ...), which C leaves undefined; without the flag gcc may optimise those checks away and
# the build stops reproducing the vectors. See README.md.
set -euo pipefail

evs_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="${evs_dir}/c-code"
build_dir="${evs_dir}/build"

if [[ ! -d "${source_dir}/lib_com" ]]; then
  echo "no reference sources in ${source_dir}; run fetch.sh first" >&2
  exit 1
fi
mkdir -p "${build_dir}"

echo "building the reference codec"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
cp -r "${source_dir}/." "${work}/"
make -C "${work}" -j"$(nproc)" RELEASE=1 DEBUG=0 CC="gcc -fwrapv" > "${work}/build.log" 2>&1 \
  || { tail -20 "${work}/build.log" >&2; exit 1; }
cp "${work}/EVS_dec" "${work}/EVS_cod" "${build_dir}/"

echo "building the basic-operator oracle"
gcc -O2 -fwrapv -w \
  -I"${source_dir}/basic_op" -I"${source_dir}/basic_math" -I"${source_dir}/lib_com" \
  -o "${build_dir}/basop_oracle" \
  "${evs_dir}/oracle/basop_oracle.c" \
  "${source_dir}/basic_op/basop32.c" "${source_dir}/basic_op/enh1632.c" \
  "${source_dir}/basic_op/enhUL32.c" "${source_dir}/basic_op/enh40.c" \
  "${source_dir}/basic_op/control.c" "${source_dir}/basic_op/count.c" \
  "${source_dir}/basic_math/oper_32b.c" "${source_dir}/basic_math/math_32.c" \
  "${source_dir}/lib_com/basop_mpy.c"

echo "built: $(ls "${build_dir}" | tr '\n' ' ')"

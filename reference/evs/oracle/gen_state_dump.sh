#!/usr/bin/env bash
# Regenerate the whole-decoder-state dump used by the state-level oracles:
#   reference/evs/oracle/fn/init_dec.c                  C side (rd_dump_* / rd_fill_* spliced in)
#   crates/siphon-rtp-codec/tests/evs_fn_oracle/state_dump.rs   Rust side (dump / fill / load)
#
# One gdb walk of Decoder_State_fx (gen/state_dump_export.py, field naming as state_export.py) emits
# both, so the two sides cannot drift. Rerun whenever gen_state.sh changes the generated state.
set -euo pipefail

evs_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="${evs_dir}/c-code"
crate_dir="${evs_dir}/../../crates/siphon-rtp-codec"
gen="${evs_dir}/oracle/gen"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

gcc -c -g -O0 -w -DRELEASE -I"${source_dir}/basic_op" -I"${source_dir}/basic_math" -I"${source_dir}/lib_com" \
  -I"${source_dir}/lib_dec" -I"${source_dir}/lib_enc" -o "${work}/init_dec.o" "${source_dir}/lib_dec/init_dec_fx.c"
grep -o '^pub struct [A-Za-z0-9_]*' "${crate_dir}/src/evs/rom/types.rs" | awk '{print $3}' > "${work}/rom_types.txt"
STATE_DUMP_C_OUT="${work}/dump.c" STATE_DUMP_RUST_OUT="${work}/dump.rs" STATE_DUMP_ROM_TYPES="${work}/rom_types.txt" \
  gdb -batch -nx -x "${gen}/state_dump_export.py" "${work}/init_dec.o"
cat "${gen}/init_dec_head.c" "${work}/dump.c" "${gen}/init_dec_tail.c" > "${evs_dir}/oracle/fn/init_dec.c"
cat "${gen}/state_dump_head.rs" "${work}/dump.rs" > "${crate_dir}/tests/evs_fn_oracle/state_dump.rs"
rustfmt --edition 2021 "${crate_dir}/tests/evs_fn_oracle/state_dump.rs"
echo "wrote fn/init_dec.c and tests/evs_fn_oracle/state_dump.rs"

#!/usr/bin/env bash
# Regenerate reference/evs/oracle/fn/core_dec_init.c (the open_decoder_LPD oracle) from its template
# and the field spec in gen/core_dec_init_spec.py, which also defines what the Rust test compares.
set -euo pipefail
gen="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/gen"
out="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fn/core_dec_init.c"
python3 -I - "${gen}" "${out}" <<'PY'
import subprocess, sys
gen, out = sys.argv[1], sys.argv[2]
template = open(f"{gen}/core_dec_init_template.c").read()
dump = subprocess.check_output(["python3", "-I", f"{gen}/core_dec_init_spec.py", "c"]).decode().rstrip("\n")
fill = subprocess.check_output(["python3", "-I", f"{gen}/core_dec_init_spec.py", "fill"]).decode().rstrip("\n")
open(out, "w").write(template.replace("@@DUMP@@", dump).replace("@@FILL@@", fill))
PY
echo "wrote ${out}"

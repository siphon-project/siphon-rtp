"""Regenerate crates/siphon-rtp-codec/src/evs/cnst/ from the TS 26.442 constant headers.

usage: python3 -I gen_cnst.py C_CODE_DIR OUT_DIR

The headers (`cnst_fx.h`, `basop_util.h`, the decoder/common headers that define sizes) are full of
macros built from other macros and arithmetic. Instead of re-parsing that, this asks gcc for every
object-like macro the decoder sees (`gcc -dM -E`), keeps the ones that are integer constant
expressions, and has a generated C program print each one's value as the compiler computes it.

Type: C macros are untyped, the port is not. A value that fits `i16` and is written without an `L`
suffix becomes `i16` (the reference's `Word16` uses), anything else `i32`. Call sites cast where the
reference uses a macro in the other width.
"""
import os
import re
import subprocess
import sys
import tempfile

source, out = os.path.abspath(sys.argv[1]), sys.argv[2]
includes = [f"-I{source}/{d}" for d in ("basic_op", "basic_math", "lib_com", "lib_dec", "lib_enc")]
headers = ["options.h", "cnst_fx.h", "stl.h", "basop_util.h", "stat_dec_fx.h", "prot_fx.h"]
probe = "".join(f'#include "{header}"\n' for header in headers)

def self_contained(body):
    """Whether a macro body means the same wherever it is pasted.

    `#define HIBND_ACB_L_FAC 5/2` evaluates to 2 on its own, but the reference writes
    `L_SUBFR*HIBND_ACB_L_FAC`, which the preprocessor turns into `L_SUBFR*5/2` = 160, not 128. A body
    with a binary operator outside parentheses has no single value, so it is not exported; a port
    writes the C expression out where it is used. Leading unary minus/plus and casts are fine.
    """
    text = body.strip()
    if text.startswith("(") and matching_paren(text) == len(text) - 1:
        return True  # wholly parenthesised: one value wherever it is pasted
    text = re.sub(r"^\((?:const\s+)?(?:unsigned\s+)?\w+\)\s*", "", text)  # a leading cast
    text = re.sub(r"^[-+~]\s*", "", text)
    depth = 0
    for index, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and char in "+-*/%<>&|^?" and index > 0:
            return False
    return True


def matching_paren(text):
    depth = 0
    for index, char in enumerate(text):
        depth += {"(": 1, ")": -1}.get(char, 0)
        if depth == 0:
            return index
    return -1


with tempfile.TemporaryDirectory() as work:
    with open(os.path.join(work, "probe.c"), "w") as handle:
        handle.write(probe)
    macros = subprocess.run(["gcc", "-dM", "-E", "-DRELEASE", *includes, os.path.join(work, "probe.c")],
                            capture_output=True, text=True, check=True).stdout

    # Only macros defined in the reference's own headers, not libc's.
    origin = subprocess.run(["gcc", "-E", "-dD", "-DRELEASE", *includes, os.path.join(work, "probe.c")],
                            capture_output=True, text=True, check=True).stdout
    current_file, defined_in = "", {}
    for line in origin.splitlines():
        marker = re.match(r'# \d+ "([^"]+)"', line)
        if marker:
            current_file = marker.group(1)
            continue
        definition = re.match(r"#define (\w+) (.+)", line)
        if definition and current_file.startswith(source):
            defined_in[definition.group(1)] = (os.path.relpath(current_file, source), definition.group(2).strip())

    candidates = []
    not_self_contained = []  # (name, body): a binary operator outside parentheses; see self_contained
    for line in macros.splitlines():
        match = re.match(r"#define (\w+) (.+)$", line)
        if not match or "(" in match.group(1):
            continue
        name, body = match.group(1), match.group(2).strip()
        # A float literal (`1.5`, `1e5`) disqualifies the body; the digits of a hex literal must not
        # (`0x5e728433` contains `5e7`, which once dropped DELTA_MANTISSA_W32), so strip hex first.
        if name not in defined_in or re.search(r'["\'{;]|\.\d|\d\.|\d[eE][-+]?\d',
                                               re.sub(r'0[xX][0-9a-fA-F]+', '0', body)):
            continue
        if not self_contained(body):
            not_self_contained.append((name, body))
            continue
        candidates.append((name, body))

    # Probe each macro on its own so one that is not an integer constant expression cannot sink the rest.
    program = probe + "#include <stdio.h>\nint main(void) {\n"
    for name, _body in candidates:
        program += (f'#if 1\n  {{ _Static_assert(1, ""); long long v = (long long)({name}); '
                    f'printf("%s %lld\\n", "{name}", v); }}\n#endif\n')
    program += "  return 0;\n}\n"
    with open(os.path.join(work, "dump.c"), "w") as handle:
        handle.write(program)
    good = []
    while True:
        result = subprocess.run(["gcc", "-w", "-DRELEASE", *includes, "-o", os.path.join(work, "dump"),
                                 os.path.join(work, "dump.c"), "-lm"], capture_output=True, text=True)
        if result.returncode == 0:
            break
        bad = set(re.findall(r'"(\w+)", v\)', result.stderr))
        # Errors inside a macro body are reported at the header line, with a note pointing back at
        # the dump.c line that expanded it; collect every dump.c line mentioned either way.
        lines = set(int(n) for n in re.findall(r"dump\.c:(\d+):\d+:", result.stderr))
        text = program.splitlines()
        drop = {re.search(r'"(\w+)", v', text[n - 1]).group(1) for n in lines if '", v)' in text[n - 1]}
        if not drop:
            sys.exit(result.stderr[-3000:])
        candidates = [(n, b) for n, b in candidates if n not in drop]
        program = probe + "#include <stdio.h>\nint main(void) {\n" + "".join(
            f'#if 1\n  {{ _Static_assert(1, ""); long long v = (long long)({n}); printf("%s %lld\\n", "{n}", v); }}\n#endif\n'
            for n, _ in candidates) + "  return 0;\n}\n"
        with open(os.path.join(work, "dump.c"), "w") as handle:
            handle.write(program)
    values = subprocess.run([os.path.join(work, "dump")], capture_output=True, text=True, check=True).stdout

rust_keywords = {"SELF", "SUPER", "CRATE"}
header = [
    "//! The TS 26.442 integer constants, generated by `reference/evs/oracle/gen_cnst.py`; do not edit.",
    "//!",
    "//! Every object-like macro of the reference's headers that is an integer constant expression,",
    "//! with the value gcc computes for it. A value that fits `i16` and has no `L` suffix in the",
    "//! source is `i16`, anything else `i32`; call sites cast where the reference uses the other width.",
    "",
]
entries = {}  # Rust name -> (value, file, name, body, rust)


def kind_of(value, body):
    wide = re.search(r"\d[lL]\b|0x[0-9a-fA-F]{5,}", body) or not -32768 <= value <= 32767
    return "u32" if value >= 2**31 else ("i32" if wide else "i16")
for line in values.splitlines():
    name, value = line.split()
    value = int(value)
    if not -(2**31) <= value < 2**32 or name.upper() in rust_keywords:
        continue
    file, body = defined_in[name]
    kind = kind_of(value, body)
    key = name.upper()
    if key in entries and entries[key][0] == value:
        continue  # two spellings of one constant
    if key in entries:
        # Two macros that differ only in case and disagree (`NUM_BITS_SHB_FRAMEGAIN` = 5 vs
        # `NUM_BITS_SHB_FrameGain` = 6). The one spelled in upper case keeps the upper-case name; the
        # other keeps its exact C spelling, so neither is lost and neither shadows the other.
        other = entries.pop(key)
        for entry in (other, (value, file, name, body, None)):
            v, f, n, b, _ = entry
            k = n.upper() if n == n.upper() else n
            r = (f"pub const {k}: {kind_of(v, b)} = {v};" if k == n.upper()
                 else f"#[allow(non_upper_case_globals)]\npub const {k}: {kind_of(v, b)} = {v};")
            entries[k] = (v, f, n, b, r)
        continue
    entries[key] = (value, file, name, body, f"pub const {key}: {kind} = {value};")

os.makedirs(out, exist_ok=True)
modules, chunk, count, part = [], [], 0, 1
def flush():
    global chunk, count, part
    module = f"cnst_{part:02}"
    modules.append(module)
    with open(os.path.join(out, module + ".rs"), "w") as handle:
        handle.write("//! Part of the generated TS 26.442 constants; see `mod.rs`.\n\n" + "\n".join(chunk) + "\n")
    chunk, count, part = [], 0, part + 1
for key in sorted(entries, key=lambda k: (entries[k][1], k)):
    value, file, name, body, rust = entries[key]
    doc = f"/// `{name}` = `{body}` ({file})" if len(body) < 70 else f"/// `{name}` ({file})"
    if count + 2 > 1400:
        flush()
    chunk += [doc, rust]
    count += 1 + rust.count("\n") + 1
if chunk:
    flush()
with open(os.path.join(out, "mod.rs"), "w") as handle:
    handle.write("\n".join(header))
    handle.write("//!\n//! Not exported, because the macro has no value of its own (a binary operator outside\n"
                 "//! parentheses, so its meaning depends on where the preprocessor pastes it); write the C\n"
                 "//! expression out at the use site instead:\n//!\n")
    for name, body in sorted(not_self_contained):
        handle.write(f"//! - `{name}` = `{' '.join(body.split())}`\n")
    handle.write("\n")
    handle.write("#![allow(clippy::unreadable_literal)]\n\n")
    handle.write("".join(f"mod {m};\n" for m in modules) + "\n")
    handle.write("".join(f"pub use {m}::*;\n" for m in modules))
print(f"{len(entries)} constants in {len(modules)} files")

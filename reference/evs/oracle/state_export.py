"""gdb script: export the decoder state structs of the EVS reference as Rust, with their exact layout.

Run by gen_state.sh as `gdb -batch -x state_export.py init_dec.o` with STATE_OUT (output directory),
STATE_ROOT (the root typedef, `Decoder_State_fx`) and STATE_COMMENTS (a JSON file mapping field name
to the comment the header gives it).

Every struct reachable from the root by value or through a handle is emitted:

- integer fields and arrays keep their exact width and dimensions (gdb has already evaluated every
  macro in the array bounds);
- a struct by value becomes the generated Rust struct;
- a pointer to a struct (the reference's `HANDLE_*`, allocated with `calloc` and null-checked)
  becomes `Option<Box<T>>`;
- any other pointer cannot be translated mechanically (it may point into a ROM table, into another
  field, or at a separately allocated buffer), so it takes the hand design in `DESIGNS`, and a
  pointer without one stops the export rather than being guessed at.

Field names are the reference's, snake-cased, with a trailing `_fx` dropped unless that would collide
with another field of the same struct. Struct names are the typedef names in CamelCase, `_fx` dropped.
"""
import json
import os
import re

import gdb  # noqa: provided by the gdb runtime

OUT = os.environ["STATE_OUT"]
ROOT = os.environ["STATE_ROOT"]
COMMENTS = json.load(open(os.environ["STATE_COMMENTS"]))

# Hand designs for the pointer fields (see pointers.txt for the raw list). A pointer into a ROM table
# is a static slice (empty = NULL); a pointer to a buffer the reference `calloc`s for this struct is a
# `Vec` it owns; a pointer into another array of the state is an element offset into that array
# (`Option` where the reference sets it NULL). Each entry: (rust type, zero, doc).
DESIGNS = {
    "Decoder_State_fx.bit_stream_fx": ("[u16; 2576]", "[0; 2576]",
        "The frame's bits, one per word, plus 16 zero bits for the arithmetic coder flush "
        "(`MAX_BITS_PER_FRAME + 16`). The reference points this at a buffer in `decoder.c`; here the state owns it."),
    "Decoder_State_fx.old_synthFB_fx": ("usize", "0", "Offset into `synth_history`."),
    "Decoder_State_fx.prev_good_synth_fx": ("usize", "0", "Offset into `synth_history`."),
    "Decoder_State_fx.ptr_mem_stp_swb_fx": ("usize", "0", "Offset into `mem_stp_swb`."),
    "Decoder_State_fx.p_bpf_noise_buf": ("Option<usize>", "None", "Offset into `bpf_noise_buf`, or NULL."),
    "CLDFB_FILTER_BANK.p_filter": ("&'static [i16]", "&[]", "ROM prototype filter."),
    "CLDFB_FILTER_BANK.rRotVctr": ("&'static [i16]", "&[]", "ROM rotation vector (real)."),
    "CLDFB_FILTER_BANK.iRotVctr": ("&'static [i16]", "&[]", "ROM rotation vector (imaginary)."),
    "CLDFB_FILTER_BANK.FilterStates": ("Vec<i16>", "Vec::new()", "Allocated by `openCldfb`."),
    "CLDFB_FILTER_BANK.memory": ("Vec<i16>", "Vec::new()", "Allocated by the CLDFB state save; empty = NULL."),
    "FD_CNG_SETUP.sidPartitions": ("&'static [i16]", "&[]", "ROM partition table."),
    "FD_CNG_SETUP.shapingPartitions": ("&'static [i16]", "&[]", "ROM partition table."),
    "FD_CNG_COM.olapBufferAna": ("Option<usize>", "None",
        "Offset into the owning `FdCngDec::olap_buffer_ana`, or NULL."),
    "FD_CNG_COM.olapBufferSynth2": ("Option<usize>", "None",
        "Offset into the owning `FdCngDec::olap_buffer_synth2`, or NULL."),
    "tonalmdctconceal.pMDSTData": ("Option<usize>", "None", "Never assigned by the reference."),
    "tonalmdctconceal.lastPcmOut": ("Option<usize>", "None", "Offset into `time_data_buffer`, or NULL."),
    "tonalmdctconceal.secondLastPcmOut": ("Option<usize>", "None", "Offset into `time_data_buffer`, or NULL."),
    "tonalmdctconceal.secondLastPowerSpectrum": ("Option<usize>", "None",
        "Which of `spectral_data_buffers` it aliases (the second-last block's spectral data), or NULL."),
    "blockData.spectralData": ("Option<usize>", "None", "Index into `spectral_data_buffers`, or NULL."),
    "blockData.scaleFactors": ("Option<usize>", "None", "Index into `scale_factors_buffers`, or NULL."),
    "blockData.scaleFactors_exp": ("Option<usize>", "None", "Index into `scale_factors_buffers_exp`, or NULL."),
    "TCX_config.tcx_mdct_window": ("&'static [crate::evs::rom::types::PWord16]", "&[]",
        "ROM window (`getSineWindowTable`); empty = NULL."),
    "TCX_config.tcx_mdct_window_half": ("&'static [crate::evs::rom::types::PWord16]", "&[]",
        "ROM window; empty = NULL."),
    "TCX_config.tcx_mdct_window_minimum": ("&'static [crate::evs::rom::types::PWord16]", "&[]",
        "ROM window; empty = NULL."),
    "TCX_config.tcx_mdct_window_trans": ("&'static [crate::evs::rom::types::PWord16]", "&[]",
        "ROM window; empty = NULL."),
    "TCX_config.pCurrentTnsConfig": ("Option<(usize, usize)>", "None",
        "Index into `tns_config` (`[i][j]`), or NULL."),
    "tonalmdctconceal.tcx_cfg": ("()", "()",
        "Always the owning decoder's `tcx_cfg` in the reference; a port passes `&st.tcx_cfg` instead."),
    "tonalmdctconceal.pTCI": ("()", "()",
        "In the reference a `TonalComponentsInfo` laid over the start of `timeDataBuffer`, and the PCM "
        "history pointers can overlap it (at 960 samples `secondLastPcmOut` is offset 0): a port must "
        "read and write that overlay through `time_data_buffer`, not a separate copy."),
    "IGFSCFDEC_INSTANCE.cf_se00": ("&'static [i16]", "&[]", "ROM arithmetic-coder table."),
    "IGFSCFDEC_INSTANCE.cf_se01": ("&'static [i16]", "&[]", "ROM arithmetic-coder table."),
    "IGFSCFDEC_INSTANCE.cf_se02": ("&'static [i16]", "&[]", "ROM arithmetic-coder table."),
    "IGFSCFDEC_INSTANCE.cf_off_se02": ("&'static [i16]", "&[]", "ROM arithmetic-coder table."),
    "IGFSCFDEC_INSTANCE.cf_se10": ("&'static [i16]", "&[]", "ROM arithmetic-coder table."),
    "IGFSCFDEC_INSTANCE.cf_se11": ("&'static [i16]", "&[]", "ROM arithmetic-coder table."),
    "IGFSCFDEC_INSTANCE.cf_off_se11": ("&'static [i16]", "&[]", "ROM arithmetic-coder table."),
}

# Fields the Rust state carries that the reference keeps elsewhere: (rust field, type, zero, doc).
EXTRA = {
    "Decoder_State_fx": [
        ("stl", "crate::itu::stl2009::StlFlags", "crate::itu::stl2009::StlFlags::default()",
         "The reference's process-wide STL `Overflow` / `Carry` globals, scoped to this decoder. A few "
         "routines read a carry an earlier call left behind (`arith_coder_dec.c`), so it persists here "
         "exactly as the global does in the single-instance reference."),
    ],
}

# Struct types the ROM tables already define: the state uses those, so a window read from a table and
# one stored in the state are the same type. (rust type, zero)
# Struct types the ROM tables already define (rom/types.rs): the state uses those, so a value read
# from a table and one stored in the state are the same type. (rust type, zero)
SHARED_TYPES = {
    name: (f"crate::evs::rom::types::{name}", f"crate::evs::rom::types::{name}::zeroed()")
    for name in open(os.environ["STATE_ROM_TYPES"]).read().split()
}

structs = {}  # rust name -> (fields, c name); fields = [(rust field, rust type, zero, c field)]
order = []
pointers = []


def camel(name):
    name = re.sub(r"_fx$", "", name)
    parts = [part for part in re.split(r"_+", name) if part]
    return "".join(part.capitalize() if part.isupper() or part.islower() else part[0].upper() + part[1:]
                   for part in parts)


def snake(name):
    name = re.sub(r"(?<=[a-z0-9])([A-Z])", lambda m: "_" + m.group(1), name)
    name = re.sub(r"(?<=[A-Z])([A-Z][a-z])", lambda m: "_" + m.group(1), name)
    return re.sub(r"_+", "_", name).lower()


KEYWORDS = {"type", "mod", "fn", "loop", "match", "ref", "box", "move", "use", "impl", "in", "where"}


def type_name(gdb_type, hint):
    unqualified = gdb_type.unqualified()
    name = unqualified.name or unqualified.tag
    return camel(name) if name else hint


def scalar(gdb_type):
    stripped = gdb_type.strip_typedefs()
    if stripped.code in (gdb.TYPE_CODE_INT, gdb.TYPE_CODE_CHAR, gdb.TYPE_CODE_ENUM):
        size, signed = stripped.sizeof, (stripped.code == gdb.TYPE_CODE_ENUM or stripped.is_signed)
        return ({1: "i8", 2: "i16", 4: "i32", 8: "i64"} if signed else {1: "u8", 2: "u16", 4: "u32", 8: "u64"})[size]
    if stripped.code == gdb.TYPE_CODE_FLT:
        return {4: "f32", 8: "f64"}[stripped.sizeof]
    return None


def translate(gdb_type, hint, where):
    """(rust type, zero expression) for a field type."""
    stripped = gdb_type.strip_typedefs()
    kind = scalar(gdb_type)
    if kind:
        return kind, ("0.0" if kind.startswith("f") else "0")
    if stripped.code == gdb.TYPE_CODE_ARRAY:
        low, high = stripped.range()
        inner, zero = translate(stripped.target(), hint, where)
        count = high - low + 1
        # Scalars and arrays of scalars are Copy and repeat; anything else is built element by element.
        copyable = re.fullmatch(r"[\[\]0-9.; ]+", zero) is not None
        return f"[{inner}; {count}]", f"[{zero}; {count}]" if copyable else f"core::array::from_fn(|_| {zero})"
    if stripped.code == gdb.TYPE_CODE_STRUCT:
        name = type_name(gdb_type, hint)
        if name in SHARED_TYPES:
            return SHARED_TYPES[name]
        emit_struct(stripped, name, gdb_type.unqualified().name or gdb_type.unqualified().tag or name)
        return name, f"{name}::zeroed()"
    if stripped.code == gdb.TYPE_CODE_PTR:
        if where in DESIGNS:
            return DESIGNS[where][0], DESIGNS[where][1]
        target = stripped.target()
        if target.strip_typedefs().code == gdb.TYPE_CODE_STRUCT and type_name(target, hint) in SHARED_TYPES:
            # A pointer to a ROM struct type (the sine/ALDO windows) points into a ROM table.
            return f"&'static [{SHARED_TYPES[type_name(target, hint)][0]}]", "&[]"
        if target.strip_typedefs().code == gdb.TYPE_CODE_STRUCT:
            name = type_name(target, hint)
            emit_struct(target.strip_typedefs(), name, target.unqualified().name or target.unqualified().tag or name)
            return f"Option<Box<{name}>>", "None"
        if where in DESIGNS:
            return DESIGNS[where][0], DESIGNS[where][1]
        raise RuntimeError(f"{where}: pointer field without a design ({gdb_type}); add it to DESIGNS")
    raise RuntimeError(f"{where}: unsupported type {gdb_type}")


def emit_struct(stripped, name, c_name):
    if name in structs:
        return
    structs[name] = None
    fields = []
    raw = [field.name for field in stripped.fields()]
    for field in stripped.fields():
        base = re.sub(r"_fx$", "", field.name)
        if base != field.name and base in raw:
            base = field.name  # dropping `_fx` would collide with a sibling
        rust_field = snake(base)
        if rust_field in KEYWORDS:
            rust_field = "r#" + rust_field
        rust_type, zero = translate(field.type, name + camel(field.name), f"{c_name}.{field.name}")
        fields.append((rust_field, rust_type, zero, field.name))
    # Case-only twins in the reference (`seed_fx` / `Seed_fx`, `prev_r_fx` / `prev_R_fx`): the one
    # spelled in lower case takes the snake name, the other keeps its exact C spelling.
    names = [f[0] for f in fields]
    for index, (rust_field, rust_type, zero, c_field) in enumerate(fields):
        if names.count(rust_field) > 1 and c_field != c_field.lower():
            exact = re.sub(r"_fx$", "", c_field)
            fields[index] = (exact, rust_type, zero, c_field)
    names = [f[0] for f in fields]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise RuntimeError(f"{c_name}: field names collide: {duplicates}")
    for rust_field, rust_type, zero, doc in EXTRA.get(c_name, []):
        fields.append((rust_field, rust_type, zero, None))
        COMMENTS[f"{c_name}.None.{rust_field}"] = doc
    structs[name] = (fields, c_name)
    order.append(name)


def main():
    root = gdb.lookup_type(ROOT)
    emit_struct(root.strip_typedefs(), camel(ROOT), ROOT)
    os.makedirs(OUT, exist_ok=True)
    files = []
    for name in reversed(order):
        fields, c_name = structs[name]
        module = snake(name)
        files.append(module)
        lines = [f"//! `{c_name}`, generated by `reference/evs/oracle/gen_state.sh` from the reference's",
                 "//! debug info; edit only the hand-designed pointer fields, then regenerate the rest.",
                 "", "#[allow(unused_imports)]", "use super::*;", "",
                 f"/// The reference's `{c_name}`. Field order and widths are the reference's.",
                 "#[derive(Debug, Clone)]"]
        if any(rust_field != rust_field.lower() for rust_field, *_ in fields):
            # rustc honours this lint only at struct level, not on the case-twin field itself.
            lines.append("#[allow(non_snake_case)]")
        lines.append(f"pub struct {name} {{")
        for rust_field, rust_type, _zero, c_field in fields:
            if c_field is None:
                lines.append(f"    /// {COMMENTS[f'{c_name}.None.{rust_field}']}")
                lines.append(f"    pub {rust_field}: {rust_type},")
                continue
            design = DESIGNS.get(f"{c_name}.{c_field}")
            comment = design[2] if design else (COMMENTS.get(f"{c_name}.{c_field}") or COMMENTS.get(c_field))
            # a C comment's `buf[LEN]` would read as an intra-doc link; rustdoc -D warnings refuses it
            if comment:
                comment = comment.replace("[", "\\[").replace("]", "\\]")
            doc = f"`{c_field}`" + (f": {comment}" if comment else "")
            lines.append(f"    /// {doc}")
            lines.append(f"    pub {rust_field}: {rust_type},")
        lines += ["}", ""]
        init = [f"impl {name} {{",
                "    /// All fields zero, as the reference's `calloc` leaves them before initialisation.",
                "    #[must_use]",
                "    #[allow(clippy::too_many_lines)] // generated: one line per field of the reference struct",
                "    pub fn zeroed() -> Self {", "        Self {"]
        for rust_field, _rust_type, zero, _c in fields:
            init.append(f"            {rust_field}: {zero},")
        init += ["        }", "    }", "}", ""]
        if len(lines) + len(init) > 1400:
            files.append(module + "_zeroed")
            with open(os.path.join(OUT, module + "_zeroed.rs"), "w") as handle:
                handle.write(f"//! `{name}::zeroed`, split from `{module}.rs` to keep both under the file-size gate.\n\n"
                             "#[allow(unused_imports)]\nuse super::*;\n\n" + "\n".join(init))
        else:
            lines += init
        with open(os.path.join(OUT, module + ".rs"), "w") as handle:
            handle.write("\n".join(lines))
    with open(os.path.join(OUT, "modules.txt"), "w") as handle:
        handle.write("\n".join(files) + "\n")
    print(f"{len(order)} structs, {sum(len(structs[n][0]) for n in order)} fields, {len(pointers)} pointers")


main()

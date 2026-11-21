"""gdb script: export the EVS reference ROM tables as Rust source, exactly as the compiler laid them out.

Run by gen_rom.sh as `gdb -batch -x rom_export.py romdump`, with ROM_SYMBOLS naming a file of
`name address size object` lines (from `nm -S`) and ROM_OUT the output directory.

Why gdb and not a parser: the tables are written with macros, casts, constant expressions and
pointers into other tables. The compiler has already resolved all of that, and the debug info says
exactly what type every symbol has, so reading the values back out of the binary is the one
conversion that cannot misread the source. Pointers are resolved to (target table, element offset)
and emitted as a slice from that offset to the end of the target, a null pointer as an empty slice.
"""
import os
import re
import struct

import gdb  # noqa: provided by the gdb runtime

MAX_LINES_PER_FILE = 1400
SYMBOLS = os.environ["ROM_SYMBOLS"]
OUT = os.environ["ROM_OUT"]

inferior = None
symbols = []  # (name, start, size, object)
for line in open(SYMBOLS):
    name, start, size, obj = line.split()
    symbols.append((name, int(start, 16), int(size, 16), obj))
symbols.sort(key=lambda entry: entry[1])
names = {entry[0] for entry in symbols}

struct_defs = {}  # rust struct name -> definition text
unsupported = {}  # symbol -> reason


class Unsupported(Exception):
    pass


def rust_ident(name):
    if name in {"type", "mod", "fn", "loop", "match", "ref", "box", "move", "use", "impl", "in"}:
        return "r#" + name
    return name


# Names the generated constants (evs::cnst) already use. A table whose upper-cased name would clash
# with one keeps its exact C spelling instead (`Nb` beside the constant `NB`).
reserved = set(open(os.environ["ROM_RESERVED"]).read().split()) if os.environ.get("ROM_RESERVED") else set()


def const_name(name):
    return name if name.upper() in reserved else name.upper()


anonymous_names = {}  # str(type) of an anonymous inner struct -> the name it was given


def camel(name):
    """`SCALE_TCX_SETUP` / `pulse_config` / `PWord16` -> `ScaleTcxSetup` / `PulseConfig` / `PWord16`."""
    parts = [part for part in name.split("_") if part]
    return "".join(part.capitalize() if part.isupper() or part.islower() else part[0].upper() + part[1:]
                   for part in parts)


def snake(name):
    """`bitrateFrom` -> `bitrate_from`; already-snake names are unchanged."""
    return re.sub(r"(?<=[a-z0-9])([A-Z])", lambda m: "_" + m.group(1).lower(), name).lower()


def struct_name(gdb_type, hint=None):
    unqualified = gdb_type.unqualified()
    name = unqualified.name or unqualified.tag
    if name:
        return camel(name)
    key = str(gdb_type.strip_typedefs().unqualified())
    if key not in anonymous_names:
        if not hint:
            raise Unsupported("anonymous struct without a typedef name")
        anonymous_names[key] = hint
    return anonymous_names[key]


def value_of(name):
    symbol = gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)
    if symbol is None:
        raise Unsupported(f"no symbol {name}")
    return symbol.value()


def scalar_type(gdb_type):
    stripped = gdb_type.strip_typedefs()
    if stripped.code == gdb.TYPE_CODE_INT or stripped.code == gdb.TYPE_CODE_CHAR:
        size = stripped.sizeof
        signed = stripped.is_signed
        return {1: "i8", 2: "i16", 4: "i32", 8: "i64"}[size] if signed else {1: "u8", 2: "u16", 4: "u32", 8: "u64"}[size]
    if stripped.code == gdb.TYPE_CODE_FLT:
        return {4: "f32", 8: "f64"}[stripped.sizeof]
    if stripped.code == gdb.TYPE_CODE_BOOL:
        return "bool"
    return None


def rust_type(gdb_type, hint=None):
    stripped = gdb_type.strip_typedefs()
    scalar = scalar_type(gdb_type)
    if scalar:
        return scalar
    if stripped.code == gdb.TYPE_CODE_ARRAY:
        low, high = stripped.range()
        return f"[{rust_type(stripped.target(), hint)}; {high - low + 1}]"
    if stripped.code == gdb.TYPE_CODE_STRUCT:
        define_struct(gdb_type, hint)
        return struct_name(gdb_type, hint)
    if stripped.code == gdb.TYPE_CODE_PTR:
        target = stripped.target()
        if target.strip_typedefs().code == gdb.TYPE_CODE_FUNC:
            raise Unsupported("function pointer")
        return f"&'static [{rust_type(target)}]"
    raise Unsupported(f"type code {stripped.code}")


def define_struct(gdb_type, hint=None):
    name = struct_name(gdb_type, hint)
    if name in struct_defs:
        return
    struct_defs[name] = None  # reserve against recursion
    fields, zeros = [], []
    for field in gdb_type.strip_typedefs().fields():
        kind = rust_type(field.type, name + camel(field.name))
        fields.append(f"    pub {rust_ident(snake(field.name))}: {kind},")
        zeros.append((rust_ident(snake(field.name)), zero_of(kind)))
    zeroed = ""
    if all(zero is not None for _, zero in zeros):
        zeroed = (f"\nimpl {name} {{\n    /// All fields zero.\n    #[must_use]\n    pub const fn zeroed() -> Self {{\n"
                  "        Self { " + ", ".join(f"{k}: {z}" for k, z in zeros) + " }\n    }\n}\n")
    struct_defs[name] = (
        f"/// The reference's `{gdb_type.unqualified().name or gdb_type.unqualified().tag or name}`.\n"
        "#[derive(Debug, Clone, Copy)]\n"
        f"pub struct {name} {{\n" + "\n".join(fields) + "\n}\n" + zeroed
    )


def zero_of(kind):
    """A const zero for a generated field type, or None when it has none."""
    if kind in ("i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64"):
        return "0"
    if kind in ("f32", "f64"):
        return "0.0"
    if kind.startswith("&'static ["):
        return "&[]"  # an empty slice is the generated tables' NULL
    array = re.fullmatch(r"\[(.*); (\d+)\]", kind)
    if array:
        inner = zero_of(array.group(1))
        return None if inner is None else f"[{inner}; {array.group(2)}]"
    if re.fullmatch(r"[A-Z]\w*", kind) and kind in struct_defs:
        return f"{kind}::zeroed()"
    return None


def flatten_depth_and_element(gdb_type):
    """Array nesting depth and the innermost element type of a symbol's type."""
    depth = 0
    stripped = gdb_type.strip_typedefs()
    while stripped.code == gdb.TYPE_CODE_ARRAY:
        depth += 1
        gdb_type = stripped.target()
        stripped = gdb_type.strip_typedefs()
    return depth, gdb_type


def resolve_pointer(address, pointee):
    if address == 0:
        return "&[]"
    # A pointer to a table's first element can also be one-past-the-end of the table before it, so
    # containment wins and the one-past-the-end reading is only the fallback.
    candidates = [entry for entry in symbols if entry[1] <= address < entry[1] + entry[2]]
    candidates = candidates or [entry for entry in symbols if entry[2] > 0 and address == entry[1] + entry[2]]
    if not candidates:
        raise Unsupported(f"pointer {address:#x} outside every table")
    name, start, size, _obj = candidates[0]
    target = value_of(name)
    depth, element = flatten_depth_and_element(target.type)
    element_size = element.strip_typedefs().sizeof
    pointee_size = pointee.strip_typedefs().sizeof
    if element_size != pointee_size:
        raise Unsupported(f"pointer into {name} with element size {element_size} != {pointee_size}")
    offset = (address - start) // element_size
    if (address - start) % element_size:
        raise Unsupported(f"pointer into the middle of an element of {name}")
    if name not in names:
        raise Unsupported(f"pointer to non-exported {name}")
    if depth == 0:
        return f"core::slice::from_ref(&{const_name(name)})"
    flat = f"&{const_name(name)}" if depth == 1 else const_name(name) + ".as_flattened()" * (depth - 1)
    return f"tail({flat}, {offset})"


def value_text(value, indent):
    gdb_type = value.type
    stripped = gdb_type.strip_typedefs()
    scalar = scalar_type(gdb_type)
    if scalar in ("f32", "f64"):
        raw = bytes(value.bytes)
        if scalar == "f32":
            return f"f32::from_bits({struct.unpack('<I', raw)[0]:#010x})"
        return f"f64::from_bits({struct.unpack('<Q', raw)[0]:#018x})"
    if scalar == "bool":
        return "true" if int(value) else "false"
    if scalar:
        return str(int(value))
    if stripped.code == gdb.TYPE_CODE_ARRAY:
        low, high = stripped.range()
        items = [value_text(value[index], indent + 4) for index in range(low, high + 1)]
        if all("\n" not in item for item in items) and sum(len(item) + 2 for item in items) < 90:
            return "[" + ", ".join(items) + "]"
        pad = " " * (indent + 4)
        lines, current = [], ""
        for item in items:
            if "\n" in item or len(item) > 40:
                if current:
                    lines.append(pad + current.rstrip())
                    current = ""
                lines.append(pad + item + ",")
                continue
            if len(pad) + len(current) + len(item) + 2 > 100:
                lines.append(pad + current.rstrip())
                current = ""
            current += item + ", "
        if current:
            lines.append(pad + current.rstrip())
        return "[\n" + "\n".join(lines) + "\n" + " " * indent + "]"
    if stripped.code == gdb.TYPE_CODE_STRUCT:
        define_struct(gdb_type)
        pad = " " * (indent + 4)
        values = [(rust_ident(snake(field.name)), value_text(value[field.name], indent + 4))
                  for field in stripped.fields()]
        inline = struct_name(gdb_type) + " { " + ", ".join(f"{k}: {v}" for k, v in values) + " }"
        if all("\n" not in v for _, v in values) and len(inline) <= 60:
            return inline
        parts = [f"{pad}{k}: {v}," for k, v in values]
        return struct_name(gdb_type) + " {\n" + "\n".join(parts) + "\n" + " " * indent + "}"
    if stripped.code == gdb.TYPE_CODE_PTR:
        return resolve_pointer(int(value), stripped.target())
    raise Unsupported(f"value of type code {stripped.code}")


def main():
    by_object = {}
    for name, start, size, obj in symbols:
        try:
            value = value_of(name)
            allow = "#[allow(non_upper_case_globals)]\n" if const_name(name) != name.upper() else ""
            # A static's own type needs no `'static` on its references (clippy), struct fields do.
            declared = rust_type(value.type).replace("&'static [", "&[")
            text = (f"/// `{name}` ({obj}.c).\n{allow}"
                    f"pub static {const_name(name)}: {declared} = {value_text(value, 0)};\n")
        except (Unsupported, gdb.error) as error:
            unsupported[name] = str(error)
            continue
        by_object.setdefault(obj, []).append(text)

    os.makedirs(OUT, exist_ok=True)
    modules = []
    for obj, items in by_object.items():
        part, lines, buffer = 1, 0, []
        def flush():
            module = f"{obj}_{part:02}"
            modules.append(module)
            with open(os.path.join(OUT, module + ".rs"), "w") as handle:
                handle.write(f"//! Generated from the TS 26.442 `{obj}.c` by `reference/evs/oracle/gen_rom.sh`; do not edit.\n\n")
                handle.write("#[allow(unused_imports)]\nuse super::*;\n\n")
                handle.write("\n".join(buffer))
        for item in items:
            count = item.count("\n") + 1
            if buffer and lines + count > MAX_LINES_PER_FILE:
                flush()
                part, lines, buffer = part + 1, 0, []
            buffer.append(item)
            lines += count
        if buffer:
            flush()

    with open(os.path.join(OUT, "types.rs"), "w") as handle:
        handle.write("//! Struct types of the TS 26.442 ROM tables, generated by `gen_rom.sh`; do not edit.\n\n")
        handle.write("#[allow(unused_imports)]\nuse super::types::*;\n\n" if False else "")
        handle.write("\n".join(definition for definition in struct_defs.values() if definition))
    with open(os.path.join(OUT, "modules.txt"), "w") as handle:
        handle.write("\n".join(modules) + "\n")
    with open(os.path.join(OUT, "unsupported.txt"), "w") as handle:
        for name, reason in sorted(unsupported.items()):
            handle.write(f"{name}\t{reason}\n")
    print(f"exported {sum(len(v) for v in by_object.values())} tables into {len(modules)} files, "
          f"{len(struct_defs)} struct types, {len(unsupported)} unsupported")


main()

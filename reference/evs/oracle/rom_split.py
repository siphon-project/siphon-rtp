"""Re-split the formatted ROM modules so no file holds more than MAX_LINES lines.

rom_export.py chunks the tables by the lines it writes, but rustfmt then puts every field of a
struct-array entry on its own line, so a chunk can grow several times over. This runs after rustfmt:
for each `<object>_NN.rs` group it cuts at top-level item boundaries (never inside a table), writes
`<object>_01.rs`, `<object>_02.rs`, ... afresh and rewrites the `mod` / `pub use` lists in mod.rs.
Every table keeps its exact text, except a table that alone passes MAX_LINES, which is written one
entry per line under `#[rustfmt::skip]` (same tokens, see `compact`).

usage: rom_split.py ROM_DIR
"""
import os
import re
import sys

MAX_LINES = 1400
HEADER_END = "use super::*;"


def items_of(body):
    """Split a module body into top-level items (attributes and doc comments stay with their item)."""
    items, current, depth = [], [], 0
    for line in body.split("\n"):
        if not current and not line.strip():
            continue
        current.append(line)
        code = "" if line.lstrip().startswith("//") else line
        depth += code.count("[") + code.count("{") + code.count("(")
        depth -= code.count("]") + code.count("}") + code.count(")")
        if depth == 0 and code.rstrip().endswith((";", "}")):
            items.append("\n".join(current))
            current = []
    if current or depth != 0:
        raise SystemExit(f"unbalanced item at the end of a module: {current[:3]}")
    return items


def compact(item):
    """One table entry per line, kept that way by `#[rustfmt::skip]`: for a table that alone would pass
    MAX_LINES once rustfmt spreads each struct entry over several lines. Only whitespace and the
    trailing commas inside an entry change."""
    head, _, rest = item.partition("= [\n")
    body, _, tail = rest.rpartition("\n]")
    entries, current, depth = [], [], 0
    for char in body:
        if char in "[{(":
            depth += 1
        elif char in "]})":
            depth -= 1
        if char == "," and depth == 0:
            entries.append("".join(current))
            current = []
        else:
            current.append(char)
    if "".join(current).strip():
        entries.append("".join(current))
    lines = []
    for entry in entries:
        text = " ".join(entry.split())
        text = re.sub(r",\s*}", " }", text)
        lines.append(f"    {text},")
    # attributes and doc comments stay above the `#[rustfmt::skip]`
    prefix, _, declaration = head.rpartition("\n")
    prefix = prefix + "\n" if prefix else ""
    return f"{prefix}#[rustfmt::skip]\n{declaration}= [\n" + "\n".join(lines) + "\n]" + tail


def main():
    rom_dir = sys.argv[1]
    groups = {}
    for name in sorted(os.listdir(rom_dir)):
        match = re.fullmatch(r"(rom_\w+?)_(\d\d)\.rs", name)
        if match:
            groups.setdefault(match.group(1), []).append(name)

    modules = []
    for group, files in groups.items():
        header, items = None, []
        for name in files:
            text = open(os.path.join(rom_dir, name)).read()
            cut = text.index(HEADER_END) + len(HEADER_END)
            header = header or text[:cut]
            items += items_of(text[cut:])
            os.remove(os.path.join(rom_dir, name))
        budget = MAX_LINES - header.count("\n") - 2
        items = [compact(item) if item.count("\n") + 2 > budget else item for item in items]
        parts, buffer, lines = [], [], header.count("\n") + 2
        for item in items:
            count = item.count("\n") + 2  # the item and the blank line after it
            if buffer and lines + count > MAX_LINES:
                parts.append(buffer)
                buffer, lines = [], header.count("\n") + 2
            buffer.append(item)
            lines += count
        if buffer:
            parts.append(buffer)
        for number, part in enumerate(parts, 1):
            module = f"{group}_{number:02}"
            modules.append(module)
            with open(os.path.join(rom_dir, module + ".rs"), "w") as handle:
                handle.write(header + "\n\n" + "\n\n".join(part) + "\n")

    mod_path = os.path.join(rom_dir, "mod.rs")
    lines = open(mod_path).read().split("\n")
    kept = [line for line in lines if not re.fullmatch(r"(pub use |mod )rom_\w+_\d\d(::\*)?;", line)]
    at = kept.index("pub mod types;") + 1
    use_at = kept.index("pub use types::*;")
    out = (kept[:at] + [f"mod {module};" for module in modules] + kept[at:use_at]
           + [f"pub use {module}::*;" for module in modules] + kept[use_at:])
    open(mod_path, "w").write("\n".join(out))
    print(f"{len(modules)} ROM modules, at most {MAX_LINES} lines each")


main()

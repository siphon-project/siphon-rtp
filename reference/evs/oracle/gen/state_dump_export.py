"""gdb script: generate a whole-state dump of Decoder_State_fx for the function oracles.

From the reference's debug info, emits
  - STATE_DUMP_C_OUT:    C code (spliced into reference/evs/oracle/fn/init_dec.c) with
                  rd_dump_DecoderState(pre, st)  print every leaf as ` key=v,v,...`
                  rd_fill_DecoderState(st)       fill every integer leaf from a deterministic pattern
  - STATE_DUMP_RUST_OUT: Rust (tests/evs_fn_oracle/state_dump.rs) with the same walk over the generated
                  Rust DecoderState (dump, fill with the same pattern, or load from a dump).
Field naming follows reference/evs/oracle/state_export.py exactly, so the paths match the
generated state. One field list, two emitters: the sides cannot drift.
"""
import os
import re

import gdb  # noqa

SHARED = set(open(os.environ["STATE_DUMP_ROM_TYPES"]).read().split())
KEYWORDS = {"type", "mod", "fn", "loop", "match", "ref", "box", "move", "use", "impl", "in", "where"}

# Inputs the init oracle sets before init_decoder_fx; the pattern fill leaves them alone.
NO_FILL = {("Decoder_State_fx", "output_Fs_fx"), ("Decoder_State_fx", "output_frame_fx")}

# Pointer fields: (struct C name, field) -> (kind, extra)
#   rom16 / romp16: ROM table, compared on its first 8 entries (NULL = empty)
#   tns: TnsParameters table id; skip: not represented in Rust
#   off_usize(base) / off_opt(base): offset into an array of the same struct (NULL = 0 / -1)
#   off_parent(base): offset into an array of the parent FdCngDec
#   row(base): which row of a 2-D array of the parent tonalmdctconceal (or self) it points at
#   vec(len_expr): an owned buffer; C prints len_expr values (NULL = empty)
#   tnsptr: TCX_config.pCurrentTnsConfig
POINTERS = {
    ("Decoder_State_fx", "bit_stream_fx"): ("skip", None),
    ("Decoder_State_fx", "old_synthFB_fx"): ("off_usize", "synth_history_fx"),
    ("Decoder_State_fx", "prev_good_synth_fx"): ("off_usize", "synth_history_fx"),
    ("Decoder_State_fx", "ptr_mem_stp_swb_fx"): ("off_usize", "mem_stp_swb_fx"),
    ("Decoder_State_fx", "p_bpf_noise_buf"): ("off_opt", "bpf_noise_buf"),
    ("CLDFB_FILTER_BANK", "p_filter"): ("rom16", None),
    ("CLDFB_FILTER_BANK", "rRotVctr"): ("rom16", None),
    ("CLDFB_FILTER_BANK", "iRotVctr"): ("rom16", None),
    ("CLDFB_FILTER_BANK", "FilterStates"): ("vec", "rd_cldfb_states_length(p)"),
    ("CLDFB_FILTER_BANK", "memory"): ("vec", "p->memory_length + CLDFB_NO_COL_MAX + 9 + 1"),
    ("FD_CNG_COM", "olapBufferAna"): ("off_parent", "olapBufferAna"),
    ("FD_CNG_COM", "olapBufferSynth2"): ("off_parent", "olapBufferSynth2"),
    ("FD_CNG_COM", "olapWinAna"): ("romp16", None),
    ("FD_CNG_COM", "olapWinSyn"): ("romp16", None),
    ("FD_CNG_SETUP", "sidPartitions"): ("rom16", None),
    ("FD_CNG_SETUP", "shapingPartitions"): ("rom16", None),
    ("TCX_config", "tcx_mdct_window"): ("romp16", None),
    ("TCX_config", "tcx_mdct_window_half"): ("romp16", None),
    ("TCX_config", "tcx_mdct_window_minimum"): ("romp16", None),
    ("TCX_config", "tcx_mdct_window_trans"): ("romp16", None),
    ("TCX_config", "tcx_mdct_windowFB"): ("romp16", None),
    ("TCX_config", "tcx_mdct_window_halfFB"): ("romp16", None),
    ("TCX_config", "tcx_mdct_window_minimumFB"): ("romp16", None),
    ("TCX_config", "tcx_mdct_window_transFB"): ("romp16", None),
    ("TCX_config", "pCurrentTnsConfig"): ("tnsptr", None),
    ("STnsConfig", "pTnsParameters"): ("tns", None),
    ("tonalmdctconceal", "tcx_cfg"): ("skip", None),
    ("tonalmdctconceal", "pTCI"): ("skip", None),
    ("tonalmdctconceal", "pMDSTData"): ("off_opt", None),
    ("tonalmdctconceal", "lastPcmOut"): ("off_opt", "timeDataBuffer"),
    ("tonalmdctconceal", "secondLastPcmOut"): ("off_opt", "timeDataBuffer"),
    ("tonalmdctconceal", "secondLastPowerSpectrum"): ("row_self", "spectralDataBuffers"),
    ("blockData", "spectralData"): ("row", "spectralDataBuffers"),
    ("blockData", "scaleFactors"): ("row", "scaleFactorsBuffers"),
    ("blockData", "scaleFactors_exp"): ("row", "scaleFactorsBuffers_exp"),
    ("IGFSCFDEC_INSTANCE", "cf_se00"): ("rom16", None),
    ("IGFSCFDEC_INSTANCE", "cf_se01"): ("rom16", None),
    ("IGFSCFDEC_INSTANCE", "cf_se02"): ("rom16", None),
    ("IGFSCFDEC_INSTANCE", "cf_off_se02"): ("rom16", None),
    ("IGFSCFDEC_INSTANCE", "cf_se10"): ("rom16", None),
    ("IGFSCFDEC_INSTANCE", "cf_se11"): ("rom16", None),
    ("IGFSCFDEC_INSTANCE", "cf_off_se11"): ("rom16", None),
}


def camel(name):
    name = re.sub(r"_fx$", "", name)
    parts = [p for p in re.split(r"_+", name) if p]
    return "".join(p.capitalize() if p.isupper() or p.islower() else p[0].upper() + p[1:] for p in parts)


def snake(name):
    name = re.sub(r"(?<=[a-z0-9])([A-Z])", lambda m: "_" + m.group(1), name)
    name = re.sub(r"(?<=[A-Z])([A-Z][a-z])", lambda m: "_" + m.group(1), name)
    return re.sub(r"_+", "_", name).lower()


def type_name(t, hint):
    u = t.unqualified()
    n = u.name or u.tag
    return camel(n) if n else hint


structs = {}  # rust name -> dict(c=cname, ctype=..., fields=[...])
order = []


def scalar(t):
    s = t.strip_typedefs()
    if s.code in (gdb.TYPE_CODE_INT, gdb.TYPE_CODE_CHAR, gdb.TYPE_CODE_ENUM):
        signed = s.code == gdb.TYPE_CODE_ENUM or s.is_signed
        return ("i" if signed else "u") + str(8 * s.sizeof)
    if s.code == gdb.TYPE_CODE_FLT:
        raise RuntimeError("float field")
    return None


def describe(t, hint):
    s = t.strip_typedefs()
    k = scalar(t)
    if k:
        return {"k": "scalar", "t": k}
    if s.code == gdb.TYPE_CODE_ARRAY:
        lo, hi = s.range()
        return {"k": "array", "n": hi - lo + 1, "of": describe(s.target(), hint)}
    if s.code == gdb.TYPE_CODE_STRUCT:
        name = type_name(t, hint)
        if name in SHARED:
            return {"k": "shared", "name": name}
        walk(s, name, t.unqualified().name or t.unqualified().tag or name, str(t.unqualified()))
        return {"k": "struct", "name": name}
    if s.code == gdb.TYPE_CODE_PTR:
        tgt = s.target()
        if tgt.strip_typedefs().code == gdb.TYPE_CODE_STRUCT and type_name(tgt, hint) not in SHARED:
            name = type_name(tgt, hint)
            walk(tgt.strip_typedefs(), name, tgt.unqualified().name or tgt.unqualified().tag or name,
                 str(tgt.unqualified()))
            return {"k": "handle", "name": name}
        return {"k": "ptr"}
    raise RuntimeError(f"unsupported {t}")


def walk(s, name, cname, ctype):
    if name in structs:
        return
    structs[name] = None
    raw = [f.name for f in s.fields()]
    fields = []
    for f in s.fields():
        base = re.sub(r"_fx$", "", f.name)
        if base != f.name and base in raw:
            base = f.name
        r = snake(base)
        if r in KEYWORDS:
            r = "r#" + r
        fields.append({"c": f.name, "r": r, "ty": describe(f.type, name + camel(f.name))})
    names = [f["r"] for f in fields]
    for f in fields:
        if names.count(f["r"]) > 1 and f["c"] != f["c"].lower():
            f["r"] = re.sub(r"_fx$", "", f["c"])
    structs[name] = {"c": cname, "ctype": ctype, "fields": fields}
    order.append(name)


def rsnake(name):
    return snake(name)


def leaf_count(ty):
    n = 1
    while ty["k"] == "array":
        n *= ty["n"]
        ty = ty["of"]
    return n, ty


def emit():
    c, r = [], []
    for name in order:
        st = structs[name]
        cname, ctype = st["c"], st["ctype"]
        c.append(f"static void rd_dump_{name}(const char *pre, {ctype} *p);")
        c.append(f"static void rd_fill_{name}({ctype} *p);")
    for name in order:
        st = structs[name]
        cname, ctype = st["c"], st["ctype"]
        dump, fill = [], []
        rust = []
        for f in st["fields"]:
            cf, rf, ty = f["c"], f["r"], f["ty"]
            key = cf
            ptr = POINTERS.get((cname, cf))
            if ty["k"] == "ptr" or ptr:
                if ptr is None:
                    raise RuntimeError(f"{cname}.{cf}: pointer without a dump design")
                kind, extra = ptr
                if kind == "skip":
                    continue
                if kind == "rom16":
                    dump.append(f'    rd_put_rom16(pre, "{key}", (const Word16 *)p->{cf});')
                    rust.append(f'    v.rom16(pre, "{key}", p.{rf});')
                elif kind == "romp16":
                    dump.append(f'    rd_put_romp16(pre, "{key}", (const PWord16 *)p->{cf});')
                    rust.append(f'    v.romp16(pre, "{key}", p.{rf});')
                elif kind == "tns":
                    dump.append(f'    rd_put1(pre, "{key}", rd_tns_table_id(p->{cf}));')
                    rust.append(f'    v.tns(pre, "{key}", &mut p.{rf});')
                elif kind == "tnsptr":
                    dump.append(f'    rd_put1(pre, "{key}", p->{cf} == NULL ? -1 : (long long)(p->{cf} - &p->tnsConfig[0][0]));')
                    rust.append(f'    v.tns_pointer(pre, "{key}", &mut p.{rf});')
                elif kind == "off_usize":
                    dump.append(f'    rd_put1(pre, "{key}", p->{cf} == NULL ? 0 : (long long)(p->{cf} - p->{extra}));')
                    rust.append(f'    v.offset(pre, "{key}", &mut p.{rf});')
                elif kind == "off_opt":
                    if extra is None:
                        dump.append(f'    rd_put1(pre, "{key}", p->{cf} == NULL ? -1 : -2);')
                    else:
                        dump.append(f'    rd_put1(pre, "{key}", p->{cf} == NULL ? -1 : (long long)(p->{cf} - p->{extra}));')
                    rust.append(f'    v.offset_opt(pre, "{key}", &mut p.{rf});')
                elif kind == "off_parent":
                    dump.append(f'    rd_put1(pre, "{key}", p->{cf} == NULL ? -1 : (long long)(p->{cf} - rd_parent_fd_cng_dec->{extra}));')
                    rust.append(f'    v.offset_opt(pre, "{key}", &mut p.{rf});')
                elif kind in ("row", "row_self"):
                    base = "p" if kind == "row_self" else "rd_parent_tonal"
                    dump.append(f'    rd_put1(pre, "{key}", rd_row((const Word16 *)p->{cf}, (const Word16 *){base}->{extra}[0], (const Word16 *){base}->{extra}[1]));')
                    rust.append(f'    v.offset_opt(pre, "{key}", &mut p.{rf});')
                elif kind == "vec":
                    dump.append(f'    if (p->{cf} == NULL) rd_put16(pre, "{key}", NULL, 0); else rd_put16(pre, "{key}", p->{cf}, {extra});')
                    rust.append(f'    v.vec16(pre, "{key}", &mut p.{rf});')
                continue
            if ty["k"] == "handle":
                sub = ty["name"]
                setp = ""
                if sub == "FdCngCom":
                    setp = "rd_parent_fd_cng_dec = p; "
                dump.append(f'    {{ char b[256]; snprintf(b, sizeof b, "%s{key}.", pre); rd_put1(pre, "{key}", p->{cf} != NULL); if (p->{cf} != NULL) {{ {setp}rd_dump_{sub}(b, p->{cf}); }} }}')
                fill.append(f'    if (p->{cf} != NULL) rd_fill_{sub}(p->{cf});')
                rust.append(f'    if let Some(h) = v.handle(pre, "{key}", &mut p.{rf}) {{')
                rust.append(f'        let b = format!("{{pre}}{key}.");')
                rust.append(f'        visit_{rsnake(sub)}(v, &b, h);')
                rust.append("    }")
                continue
            count, inner = leaf_count(ty)
            if inner["k"] == "scalar":
                t = inner["t"]
                ctyp = {"i8": "signed char", "u8": "unsigned char", "i16": "Word16", "u16": "UWord16",
                        "i32": "Word32", "u32": "UWord32", "i64": "long long", "u64": "unsigned long long"}[t]
                dump.append(f'    rd_put_{t}(pre, "{key}", ({ctyp} *)&p->{cf}, {count});')
                if (cname, cf) not in NO_FILL:
                    fill.append(f'    rd_fill_{t}(({ctyp} *)&p->{cf}, {count});')
                    rust.append(f'    v.leaf(pre, "{key}", &mut p.{rf});')
                else:
                    rust.append(f'    v.leaf_no_fill(pre, "{key}", &mut p.{rf});')
                continue
            if inner["k"] == "shared" and inner["name"] == "PWord16":
                dump.append(f'    rd_put_i16(pre, "{key}", (Word16 *)&p->{cf}, {2 * count});')
                fill.append(f'    rd_fill_i16((Word16 *)&p->{cf}, {2 * count});')
                rust.append(f'    v.leaf(pre, "{key}", &mut p.{rf});')
                continue
            if inner["k"] == "shared" and inner["name"] == "FdCngSetup" and count == 1:
                g = f"p->{cf}"
                dump.append(f'    {{ char b[256]; snprintf(b, sizeof b, "%s{key}.", pre);')
                dump.append(f'      rd_put_i16(b, "fftlen", &{g}.fftlen, 1); rd_put_i16(b, "stopFFTbin", &{g}.stopFFTbin, 1);')
                dump.append(f'      rd_put_i16(b, "numPartitions", &{g}.numPartitions, 1); rd_put_rom16(b, "sidPartitions", {g}.sidPartitions);')
                dump.append(f'      rd_put_i16(b, "numShapingPartitions", &{g}.numShapingPartitions, 1); rd_put_rom16(b, "shapingPartitions", {g}.shapingPartitions); }}')
                fill.append(f'    rd_fill_i16(&{g}.fftlen, 1); rd_fill_i16(&{g}.stopFFTbin, 1); rd_fill_i16(&{g}.numPartitions, 1); rd_fill_i16(&{g}.numShapingPartitions, 1);')
                rust.append(f'    {{ let b = format!("{{pre}}{key}."); let s = &mut p.{rf};')
                rust.append('      v.leaf(&b, "fftlen", &mut s.fftlen); v.leaf(&b, "stopFFTbin", &mut s.stop_fftbin);')
                rust.append('      v.leaf(&b, "numPartitions", &mut s.num_partitions); v.rom16(&b, "sidPartitions", s.sid_partitions);')
                rust.append('      v.leaf(&b, "numShapingPartitions", &mut s.num_shaping_partitions); v.rom16(&b, "shapingPartitions", s.shaping_partitions); }')
                continue
            if inner["k"] == "struct":
                sub = inner["name"]
                dims = []
                t2 = ty
                while t2["k"] == "array":
                    dims.append(t2["n"])
                    t2 = t2["of"]
                idx = [f"i{n}" for n in range(len(dims))]
                setp = "rd_parent_tonal = p; " if sub == "BlockData" else ""
                cpath = f"p->{cf}" + "".join(f"[{i}]" for i in idx)
                fmt = "".join("[%d]" for _ in idx)
                args = "".join(f", {i}" for i in idx)
                loops = "".join(f"for (int {i} = 0; {i} < {n}; {i}++) " for i, n in zip(idx, dims))
                dump.append(f'    {loops}{{ char b[256]; snprintf(b, sizeof b, "%s{key}{fmt}.", pre{args}); {setp}rd_dump_{sub}(b, &{cpath}); }}')
                fill.append(f'    {loops}{{ rd_fill_{sub}(&{cpath}); }}')
                rloops = "".join(f"for {i} in 0..{n} {{ " for i, n in zip(idx, dims))
                rclose = "}" * len(dims)
                rfmt = "".join(f"[{{{i}}}]" for i in idx)
                rpath = f"p.{rf}" + "".join(f"[{i}]" for i in idx)
                rust.append(f'    {rloops}let b = format!("{{pre}}{key}{rfmt}."); visit_{rsnake(sub)}(v, &b, &mut {rpath}); {rclose}')
                continue
            raise RuntimeError(f"{cname}.{cf}: unhandled {ty}")
        c.append(f"static void rd_dump_{name}(const char *pre, {ctype} *p)\n{{")
        c += dump
        c.append("}")
        c.append(f"static void rd_fill_{name}({ctype} *p)\n{{")
        c += fill if fill else ["    (void)p;"]
        c.append("}")
        if name == "TonalComponentsInfo":
            continue
        r.append("#[allow(clippy::too_many_lines)]")
        r.append(f"fn visit_{rsnake(name)}(v: &mut StateVisitor, pre: &str, p: &mut {name}) {{")
        r += rust
        r.append("}")
        r.append("")
    open(os.environ["STATE_DUMP_C_OUT"], "w").write("\n".join(c) + "\n")
    open(os.environ["STATE_DUMP_RUST_OUT"], "w").write("\n".join(r) + "\n")
    print(len(order), "structs")


root = gdb.lookup_type("Decoder_State_fx")
walk(root.strip_typedefs(), "DecoderState", "Decoder_State_fx", "Decoder_State_fx")
emit()

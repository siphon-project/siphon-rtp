# 3GPP EVS — reference C and conformance sequences

`fetch.sh` pulls the EVS fixed-point reference C (3GPP TS 26.442) and the TS 26.444 conformance
sequences generated with it, verifies both against pinned hashes, and lays them out as:

| path | what it is |
|---|---|
| `c-code/` | TS 26.442 v16.4.0 ANSI-C fixed-point ("BASOP") reference: `lib_com`, `lib_dec`, `lib_enc`, `basic_op`, `basic_math` |
| `testvec/Readme_*.txt` | upstream's own scripts listing every conformance case and how to run it |
| `testvec/testv/bitstreams/{nb,wb,swb,fb,amrwb}` | G.192 bitstreams (`*.COD`): encoder output, decoder input |
| `testvec/testv/decoded/…` | reference decoder output (`*.OUT`, 16-bit LE PCM) |
| `testvec/testv/input/…` | encoder input (`*.INP`, 16-bit LE PCM) |
| `testvec/switchPaths/` | bit-rate / bandwidth switching schedules the encoder cases use |
| `build/` | the out-of-tree oracles, built by `oracle/build.sh` |

Nothing in this directory is compiled into, packaged with, or shipped by siphon-rtp. The C is read
as the algorithm the Rust port follows function by function, and run out of tree as an oracle; the
sequences are the acceptance criteria. Everything except our own scripts is gitignored (see
`.gitignore`).

## The acceptance criterion

TS 26.444 §7.1: an implementation of the fixed-point reference is conformant only if its encoder and
decoder outputs match the sequences **bit-exactly**; for a TS 26.442-based port "this is the only
conformance method". The float reference (TS 26.443) has a tolerance-based alternative (§7.2) and is
deliberately not what this port follows.

The cases are upstream's, read straight from the scripts that ship with the sequences:

| script | cases | form |
|---|---|---|
| `Readme_EVS_dec.txt` | 979 | `EVS_dec <kHz> in.COD out.OUT` |
| `Readme_AMRWB_IO_dec.txt` | 1590 | same, AMR-WB interoperable bitstreams |
| `Readme_EVS_enc.txt` | 288 | `EVS_cod [options] <bit rate or switching schedule> <kHz> in.INP out.COD` |
| `Readme_AMRWB_IO_enc.txt` | 530 | same, AMR-WB interoperable mode |
| `Readme_JBM_dec.txt` | 202 | jitter-buffer cases; **out of scope**, the engine has its own jitter buffer |

Every decoder case takes the output rate and nothing else: no MIME or RTP input, no options. A
decode `*.COD` → `*.OUT` must match byte for byte, and each output is exactly one 20 ms frame at the
requested rate per input frame (which `tests/evs_conformance.rs` already checks over the whole set).

## Provenance

| | |
|---|---|
| Reference C | TS 26.442 v16.4.0, `26442-g40.zip`, sha256 `3f99f40b9feb578fa5a204282e3784cb92c2b893e9afe5e78a1508db37704688`. The sequences' own `Readme.txt` names this release as the one they were generated with. Its `c-code` tree is byte-identical to the later v19.0.0 (`26442-j00.zip`). |
| Sequences | `26444_ce0_da0_e60_f40_g50-TestSeq_BASOP_26442.zip`, 1 843 592 537 bytes, 6155 members |
| Sequence pin | sha256 of the archive's central directory (every member's name, size and CRC-32, sorted): `faa95385a508b5e66fd34be4e904fbdc5b5a67ddc7d943fc6961077f27ed28a6`. Pinning the whole file would mean a 1.8 GB download over a server that is slow per connection; the central-directory pin catches any changed member, and `zipfile` checks each member's CRC-32 as it extracts. |
| Terms | 3GPP specification attachments; the copyright on the reference software is a separate axis from the patent posture on the codec, both recorded in [`docs/codec-licensing.md`](../../docs/codec-licensing.md) |

The 3GPP server's CDN refuses clients without a browser-like User-Agent (HTTP 403) and occasionally
ignores a `Range` header, answering 200 with the whole archive. `remote_zip.py` handles both: it
reads the archive's central directory from the end of the file and fetches only the members asked
for, one range-request stream per directory, retrying any response that is not a 206.

## Building the oracle

```sh
sh reference/evs/fetch.sh            # or narrower: fetch.sh 'testvec/Readme*' 'testvec/testv/bitstreams/wb/*'
sh reference/evs/oracle/build.sh     # build/EVS_dec, build/EVS_cod, build/basop_oracle
```

**Everything is compiled with `-fwrapv`.** The reference relies on signed overflow wrapping, which C
leaves undefined: `L_add_c` computes `L_var1 + L_var2` and *then* tests the sign of the result,
`L_lshl` shifts bits into the sign. Without the flag gcc is entitled to fold those tests away. With
it, `build/EVS_cod` reproduces all 818 encoder cases (EVS and AMR-WB IO) and `build/EVS_dec` every
decoder case checked, byte for byte. Reproduce the vectors with your own build before trusting it as
an oracle for anything.

`build/basop_oracle` links the reference's STL2009 operators (`basop32.c`, `enh1632.c`,
`enhUL32.c`, `enh40.c`) and EVS's multiply/divide helpers (`basop_mpy.c`, `oper_32b.c`,
`math_32.c`). `basop_oracle eval OP ARG...` prints one reference result; `basop_oracle corpus N SEED`
prints an edge-heavy pseudo-random corpus that `tests/evs_basop_oracle.rs` replays through the Rust
port (33 operators × 20 000 calls, flags included for the carry operators).

## Reading the reference: through the preprocessor, never raw

The sources carry alternative bodies under `#if`, and the one that compiles is not always the one
that reads first. `i_mult` is the case that bit: raw, it opens with `return a*b;` (wrapping), but
that line sits under `#ifdef ORIGINAL_G7231`, which TS 26.442 never defines; the compiled operator
saturates and raises `Overflow`. Likewise `Madd_32_16` / `Msub_32_16` have a 40-bit branch and a
DPF fallback, and `stl.h` defines `ALLOW_40bits`, so the 40-bit one is live.

Read a function as the build sees it:

```sh
cd reference/evs/c-code
gcc -E -P -DRELEASE -Ibasic_op -Ibasic_math -Ilib_com -Ilib_dec lib_dec/<file>.c | less
```

and settle any doubt about an operator with `build/basop_oracle eval`, not by inspection.

## The reference's hidden state

Two STL globals change results, and a port has to carry them explicitly:

- **`Carry`**: read *and* written by `L_add_c`, `L_sub_c`, `L_macNs`, `L_msuNs`. They are 64-bit
  accumulate idioms (`er_dec_tcx.c`, `fd_cng_dec.c`, `dec_tcx.c`, `igf_base.c`, `basop_util.c`),
  and at least one site (`arith_coder_dec.c:60`) consumes whatever carry an earlier call left behind.
  The Rust operators take an `StlFlags` the decoder owns.
- **`Overflow`**: written by many operators, read in about 40 places in `lib_dec` / `lib_com`
  (`lsf_tools_fx.c`, `tcq_core_dec_fx.c`, `env_stab_fx.c`, `swb_bwe_com_fx.c`, `tools_fx.c`, ...).
  Each read site is audited as it is ported: whether the code clears the flag first decides whether
  the result depends on operators far upstream of it. G.729 already observes this flag; see
  `g729/overflow.rs` for the method (compare the saturated result with the same arithmetic done wide).

## Using the reference as an oracle for the codec

The sequences say *whether* the decoder is right, not *where* it went wrong. The method that made the
G.729 port work, and the only one that did, applies unchanged (see `../g729/README.md`): build the
reference, confirm the build reproduces the sequences, then add an `fprintf` behind an environment
variable at each stage boundary and diff the Rust against the reference's own intermediates, frame by
frame. Check the probe before doubting the port: a probe placed at the wrong point in the reference
reads values that never reach the next stage.

The decoder selects its core per frame from the bit rate (`lib_com/bitstream_fx.c`,
`decoder_selectCodec`): MODE1 (ACELP / HQ-MDCT, `evs_dec_fx`) at 7.2, 8.0, 13.2, 32 and 64 kbit/s;
MODE2 (the LPD ACELP / TCX core, `dec_acelp_tcx_frame`) at 9.6, 16.4, 24.4, 48, 96 and 128 kbit/s;
the AMR-WB interoperable core for the AMR-WB frame sizes. Two exceptions pull MODE2 into MODE1
rates, and they decide the port's order: at 13.2 and 32 kbit/s a MODE1 frame whose core decision
reads `TCX_20` is decoded by MODE2's TCX (`mdct_switching_dec`, the `mdct_sw` read-ahead), and a
channel-aware (RF) frame is always MODE2 (`getPartialCopyInfo`). So 7.2 and 8.0 kbit/s are the only
rates whose sequences pure MODE1 can reproduce, and 13.2 kbit/s needs the TCX core as well.

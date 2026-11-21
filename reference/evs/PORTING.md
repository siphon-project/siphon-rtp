# Porting the EVS reference: conventions

How a TS 26.442 function becomes Rust in `crates/siphon-rtp-codec/src/evs/`. The port is done file by
file, leaf functions first, often by several people at once, so these rules are what keeps the
result one codebase. Read `README.md` in this directory first (oracle build, reading the C through
the preprocessor, the hidden `Overflow` / `Carry` state).

## Where things go

| reference | Rust |
|---|---|
| `lib_com/foo_fx.c`, `basic_math/foo.c` | `src/evs/com/foo.rs` (`_fx` dropped from the file name) |
| `lib_dec/foo_fx.c` | `src/evs/dec/foo.rs` |
| ROM tables (`rom_*.c`) | `src/evs/rom/`, **generated** by `oracle/gen_rom.sh`; never edit |
| integer `#define`s | `src/evs/cnst/`, **generated** by `oracle/gen_cnst.py`. A macro whose body has an operator outside parentheses (`HIBND_ACB_L_FAC` = `5/2`) has no value of its own and is deliberately absent: `cnst/mod.rs` lists them; write the C expression out at the use site (`L_SUBFR*HIBND_ACB_L_FAC` is `L_SUBFR*5/2` = 160) |
| `Decoder_State_fx` and the structs it reaches | `src/evs/dec/state/`, **generated** by `oracle/gen_state.sh` |
| STL operators | `crate::itu::basic_ops`, `crate::itu::stl2009`, `crate::evs::basop` |

A file-local `static const` table inside a `.c` file is ported into that file's Rust module as a
`static`, keeping its C name upper-cased. A Rust file is one reference file; if it would pass the
1500-production-line gate, split it into `foo.rs` + `foo/part.rs` submodules, never across reference
files.

## Names

Traceability to a 290k-line reference beats prose names here, so the reference's identifiers are kept:

- **functions**: the C name snake-cased, trailing `_fx` dropped: `acelp_core_dec_fx` → `acelp_core_dec`,
  `E_UTIL_synthesis` → `e_util_synthesis`, `BASOP_Util_Divide3216_Scale` → `basop_util_divide3216_scale`.
  If dropping `_fx` collides with another function, keep it.
- **state fields**: as generated (C name snake-cased, `_fx` dropped; the doc comment gives the C name).
- **tables / constants**: the C name upper-cased (`Nb` stays `Nb` where it would clash with the
  constant `NB`; the generators already resolved every clash).
- **locals and parameters**: the C names, snake-cased. Do not rename to prose; a reader diffs this
  against the C.

## Operators

`Word16` = `i16`, `Word32` = `i32`, `UWord16` = `u16`, `UWord32` = `u32`, `Word8` = `i8`, `UWord8` = `u8`.
Port every expression operator for operator, in the reference's order. Mapping:

| C | Rust |
|---|---|
| `add sub mult mult_r L_mult L_add L_sub L_mac L_msu shl shr L_shl L_shr norm_s norm_l div_s abs_s L_abs negate L_negate extract_h extract_l L_deposit_h L_deposit_l shr_r L_shr_r` | same name snake-cased in `itu::basic_ops` |
| `round_fx` | `basic_ops::round_word` |
| `L_mult0 L_mac0 L_msu0 i_mult mac_r msu_r L_mls div_l lshl lshr L_lshl L_lshr shl_r L_shl_r norm_ul UL_* Mpy_32_16_ss Mpy_32_32_ss Mpy_32_16_uu Mpy_32_32_uu` | snake-cased in `itu::stl2009` |
| `L_add_c L_sub_c L_macNs L_msuNs` | `itu::stl2009::{l_add_c, l_sub_c, l_mac_ns, l_msu_ns}` with `&mut StlFlags` |
| `Mpy_32_16_1 Mpy_32_16_r Mpy_32_32 Mpy_32_32_r Madd_32_16 Msub_32_16 Div_32 L_Extract_lc Mac_32_16 Msu_32_16` | `evs::basop` |
| `Mpy_32 Mpy_32_16(hi,lo,n) L_Extract L_Comp` | `itu::oper_32b` |
| `s_max s_min L_max L_min` | `.max()` / `.min()` |
| `s_and s_or s_xor L_and L_or L_xor` | `&` `|` `^` |
| `move16 move32 test logic16 ...` (WMOPS counters) | nothing |

`i_mult` saturates in this build (see README). When in doubt about an operator, run
`build/basop_oracle eval OP ARGS...` instead of reasoning about it.

## Hidden state

- **`Carry`**: carry-operator code takes `flags: &mut StlFlags`; the decoder owns one in
  `DecoderState::stl`. Set `flags.carry = false` exactly where the C writes `Carry = 0`.
- **`Overflow`**: where the C *reads* `Overflow`, find which operators since the last `Overflow = 0`
  could have set it, and reproduce the flag exactly (compare the saturated result with the same
  arithmetic done wide, as `g729/overflow.rs` does, or route those calls through `StlFlags`). Never
  approximate it, and say in a comment which operators feed it.

## Pointers and arrays

- A `const Word16 *x` / `Word16 *y` parameter becomes `&[i16]` / `&mut [i16]`.
- **Negative indexing** (`exc[-L_INTERPOL]`, `mem[i - 1]` before the start): pass the whole buffer plus
  the index the C pointer points at (`exc: &mut [i16], exc_at: usize`) and index `exc[exc_at + i - k]`.
  Name the offset parameter `<buffer>_at`.
- **Aliasing** (the C passes the same buffer as input and output, `syn_filt(a, x, x, ...)`): reproduce
  the exact read/write order. If the function is written in-place-safe in C, one `&mut [i16]` variant
  is fine; if the caller relies on a particular overlap, copy to a local array first, exactly as the
  aliasing would behave.
- A pointer field in a generated struct follows its documented design (offset into a named array,
  static ROM slice, owned `Vec`); see `oracle/state_export.py`'s `DESIGNS`.
- Scratch arrays the C declares on the stack stay on the stack as fixed-size arrays sized by the same
  constants. **No heap allocation per frame**: no `Vec`, `Box` or `collect()` in anything called per
  frame. Init-time allocation (`openCldfb`'s `calloc`s) is fine.

## No stand-ins, no copies

- **No floating point, ever.** Every reference function is ported operator for operator, including the
  ones that look like a textbook formula (`getSqrtWord32` is an `Isqrt_lc` estimate plus integer
  corrections, not `sqrt`). An equivalent-looking `f64` shortcut is not a port, even if an oracle passes.
- **One implementation per reference function.** If another module already ports a function you need,
  import it; if it belongs to a file nobody has ported yet, port it into that file's module (or stop and
  report), never as a private copy in yours.

- **Every branch is ported.** A branch that calls a function nobody has ported yet is not left
  unwritten behind a `debug_assert!`, an early return or a TODO: that is a stub. Port the callee into
  its own file's module (with an oracle), or stop and report the function as blocked.

## Robustness and lints

- No `unwrap` / `expect` / `panic!` in production. Indices derived from bitstream fields are bounded by
  the reference's own tables; where the C would read out of bounds on a hostile frame, clamp or return
  early, and comment why. (Fuzzing the decoder is a later phase; do not make it harder.)
- `clippy::too_many_arguments` is allowed module-wide (mirroring reference signatures); `too_many_lines`
  (300) is not: split an oversized function into helpers at a natural seam, named
  `<function>_<what it does>`, never by `#[allow]`.
- Cite the reference at the top of every Rust file (`TS 26.442 lib_dec/foo_fx.c`) and the TS 26.445
  clause where one is obvious. Keep the C's comments where they explain *why*.
- `cargo fmt --all` and `cargo clippy -p siphon-rtp-codec --all-targets --features evs -- -D warnings`
  clean before every commit.

## Proving a function: the oracle test

Every ported function with arithmetic in it is proven against the C before anything calls it:

1. `reference/evs/oracle/fn/<file stem>.c`: a harness with `corpus FUNCTION COUNT SEED`, one case per
   line, `inputs -> outputs` (see `fn/harness.h` and `fn/weight_a.c`). Generate inputs in the ranges the
   decoder actually feeds the function (read the call sites), plus edge values. Include every in/out
   buffer and every piece of state the function touches in the outputs. For a function taking
   `Decoder_State_fx *st`, `calloc` one, `init_decoder_fx`-style initialise what it reads, randomise the
   fields it uses, and print them before and after.
2. `sh reference/evs/oracle/build.sh fn` builds `build/fn_<file stem>` against `build/libevsref.a`.
   `#include "../../c-code/lib_dec/foo_fx.c"` in the harness reaches `static` functions.
3. `crates/siphon-rtp-codec/tests/evs_fn_oracle/<file stem>.rs`, registered in `main.rs`, replays the
   corpus through the Rust function and compares every output (`tests/evs_fn_oracle/weight_a.rs` is
   the template). Run with `SIPHON_RTP_REQUIRE_VECTORS=1` so a missing oracle fails instead of skipping.
4. Check the test can fail: break the port deliberately once and see it caught.

Trivial functions (`Copy`, `set16_fx`) need no oracle; a unit test is enough. A function the decoder
only reaches through others may be proven through its caller's oracle instead; say so in the test.

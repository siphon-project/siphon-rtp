//! The ITU-T fixed-point primitives every ITU-lineage speech codec in this crate is written
//! against: the G.191 STL basic operators, the double-precision 32-bit helpers built on them, and
//! the interpolation tables their transcendental approximations index.
//!
//! These are not specific to any one codec. The AMR reference C (3GPP TS 26.073 / TS 26.173) and the
//! G.729 reference C (ITU-T G.729 Release 3) are both written in terms of the same `basic_op.c` and
//! `oper_32b.c`, so a second codec must reuse this rather than restate it — a saturating operator
//! reimplemented twice is two chances to get a corner wrong, and the corner is exactly where
//! bit-exactness lives.
//!
//! **What is shared here is the arithmetic and the data, not the routines built on them.** The
//! transcendental approximations (`Inv_sqrt`, `Pow2`, `Log2`) index the identical tables in both
//! lineages, but their wrappers differ in output Q format, in the direction of the denormalising
//! shift, and in what they return for a non-positive input. They are therefore *not* shared, and
//! [`tables`] carries that warning next to the data. Sharing the wrappers would be a bit-exactness
//! bug that no round trip could see.

pub mod basic_ops;
pub mod oper_32b;
pub mod tables;

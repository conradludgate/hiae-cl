#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![deny(clippy::multiple_unsafe_ops_per_block)]

pub use aead;
pub use cipher;
pub use digest;
pub use hybrid_array;

/// high level internals
pub mod high;
/// middle level internals, including the core AEGIS functions
pub mod low;
/// low level internals, including AES hardware optimisations.
pub mod mid;

pub use high::{HiAe, HiAeMac};

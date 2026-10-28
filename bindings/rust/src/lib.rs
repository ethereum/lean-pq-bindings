#![doc = include_str!("../README.md")]

#[cfg(feature = "aggregation")]
mod aggregate;
mod error;
pub mod sphincs;
pub mod xmss;

#[cfg(feature = "aggregation")]
pub use aggregate::{aggregate, setup, Aggregate, MAX_CHILDREN};
pub use error::{Encoding, Error};

/// Byte length of a message, the 256-bit digest both schemes sign.
///
/// Hash a longer message to 32 bytes before signing it.
pub const MESSAGE_LEN: usize = 32;

/// Byte length of a public key in both schemes.
///
/// A key is a 16-byte Merkle root followed by its 16-byte public parameter.
pub const PUBLIC_KEY_LEN: usize = 32;

/// A message both schemes sign.
pub type Message = [u8; MESSAGE_LEN];

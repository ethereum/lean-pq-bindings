//! leanXMSS: a synchronized many-time hash-based signature.
//!
//! It instantiates the generalized XMSS of Drake, Khovratovich, Kudinov and Wagner.
//!
//! - Paper: "Hash-Based Multi-Signatures for Post-Quantum Ethereum".
//! - Venue: IACR Communications in Cryptology 2(1), 2025.
//! - Normative source: the leanXMSS specification in leanVM's `crates/signatures`.
//!
//! ```text
//!     hash         Keccak-256, truncated to n = 16 bytes
//!     one-time     WOTS+C: w = 2, v = 58 chains, digit sum T = 106
//!     trees        two XMSS layers of height 16
//!     top leaf     signs the root of one bottom tree
//!     bottom leaf  signs one message
//!     lifetime     2^16 * 2^16 = 2^32 leaf indices
//!     verify       186 Keccak permutations
//! ```
//!
//! A leaf index plays the paper's epoch.
//!
//! Strong unforgeability (Theorem 1) holds only while each leaf index signs one message.
//!
//! A second message at the same leaf index exposes chain values that let anyone forge there.

use std::fmt;

use rand::random;
use signatures::lean_xmss::{
    key_gen_from_seed, sign as xmss_sign, verify as xmss_verify, LeafIndex as UpstreamLeafIndex,
    LeanXmssPublicKey, LeanXmssSecretKey, LeanXmssSignature, Seed as UpstreamSeed, PUB_KEY_SIZE,
    SEED_LEN as UPSTREAM_SEED_LEN, SIG_SIZE,
};

use crate::{Encoding, Error, Message, PUBLIC_KEY_LEN};

/// Byte length of a seed, the whole secret material of a key.
pub const SEED_LEN: usize = 32;

/// Byte length of an encoded secret key, which is its seed.
pub const SECRET_KEY_LEN: usize = SEED_LEN;

/// Byte length of an encoded signature.
///
/// ```text
///     leaf index      4
///     bottom layer 1200 = randomizer 16 + 58 chain values * 16 + 16 path nodes * 16
///     top layer    1200   same layout
///     total        2404
/// ```
pub const SIGNATURE_LEN: usize = 2404;

/// Position of the one-time key a signature uses.
///
/// ```text
///     bits 31..16   which bottom tree
///     bits 15..0    which leaf in it
/// ```
pub type LeafIndex = u32;

/// The seed a key is derived from.
pub type Seed = [u8; SEED_LEN];

// Invariant: the sizes and types above are the upstream ones, checked at compile time.
const _: () = assert!(SEED_LEN == UPSTREAM_SEED_LEN);
const _: () = assert!(SIGNATURE_LEN == SIG_SIZE);
const _: () = assert!(PUBLIC_KEY_LEN == PUB_KEY_SIZE);
const _: fn(UpstreamLeafIndex) -> LeafIndex = |index| index;
const _: fn(UpstreamSeed) -> Seed = |seed| seed;

/// A leanXMSS public key: a Merkle root and its public parameter.
///
/// Keys order by their encoded bytes, the order aggregate claims are sorted in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey(pub(crate) LeanXmssPublicKey);

impl PublicKey {
    /// Decodes a public key.
    ///
    /// Every 32-byte string is a well-formed key.
    ///
    /// # Errors
    ///
    /// Fails when the input is not 32 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // A slice converts into the array only when its length is exactly 32.
        let array = bytes.try_into().map_err(|_| Error::InvalidLength {
            encoding: Encoding::XmssPublicKey,
            expected: PUBLIC_KEY_LEN,
            actual: bytes.len(),
        })?;
        Ok(Self(LeanXmssPublicKey::from_bytes(array)))
    }

    /// Encodes the key as its root followed by its public parameter.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.flatten()
    }

    /// Checks a signature of a message under this key.
    ///
    /// The leaf index travels inside the signature.
    ///
    /// # Errors
    ///
    /// Fails, naming the leaf index and the rejecting step, when the signature does not verify.
    pub fn verify(&self, message: &Message, signature: &Signature) -> Result<(), Error> {
        xmss_verify(&self.0, message, &signature.0).map_err(|reason| Error::XmssVerify {
            leaf_index: signature.leaf_index(),
            reason,
        })
    }
}

/// A leanXMSS secret key.
///
/// - It keeps the top tree and the bottom tree it last signed in.
/// - Signing in another bottom tree first builds that tree.
/// - The key holds no record of used leaf indices: the caller must keep one.
///
/// Its memory is not zeroized on drop.
pub struct SecretKey {
    /// The seed every secret derives from, kept so the key can be encoded.
    seed: Seed,
    /// The expanded key: top tree and cached bottom tree.
    inner: LeanXmssSecretKey,
}

impl SecretKey {
    /// Generates a key from the operating system's randomness.
    #[must_use]
    pub fn generate() -> Self {
        Self::from_seed(random())
    }

    /// Derives a key from its seed, deterministically.
    ///
    /// The seed is the whole secret: never derive a second key from it.
    #[must_use]
    pub fn from_seed(seed: Seed) -> Self {
        // Key generation also returns the public key, which the expanded key already holds.
        let (inner, _) = key_gen_from_seed(seed);
        Self { seed, inner }
    }

    /// Decodes a key from its 32-byte seed.
    ///
    /// # Errors
    ///
    /// Fails when the input is not 32 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // A slice converts into the seed only when its length is exactly 32.
        let seed = bytes.try_into().map_err(|_| Error::InvalidLength {
            encoding: Encoding::XmssSecretKey,
            expected: SECRET_KEY_LEN,
            actual: bytes.len(),
        })?;
        Ok(Self::from_seed(seed))
    }

    /// Encodes the key as its seed.
    ///
    /// The bytes are secret key material.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.seed
    }

    /// Returns the key's public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.inner.public_key())
    }

    /// Builds the bottom tree holding a leaf index, ahead of signing there.
    ///
    /// Signing builds it on demand, so this only moves the cost earlier.
    ///
    /// # Errors
    ///
    /// Fails when `2^32` randomizers give no admissible encoding of the bottom root.
    pub fn prepare(&self, leaf_index: LeafIndex) -> Result<(), Error> {
        self.inner
            .prepare(leaf_index)
            .map_err(|reason| Error::XmssSign { leaf_index, reason })
    }

    /// Signs a message at a leaf index.
    ///
    /// Never sign two different messages at the same leaf index.
    ///
    /// # Errors
    ///
    /// Fails when `2^32` randomizers give no admissible encoding of the message.
    pub fn sign(&self, message: &Message, leaf_index: LeafIndex) -> Result<Signature, Error> {
        xmss_sign(&self.inner, message, leaf_index)
            .map(Signature)
            .map_err(|reason| Error::XmssSign { leaf_index, reason })
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only public data: the seed must never reach a log.
        f.debug_struct("SecretKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

/// A leanXMSS signature: its leaf index and one Winternitz signature per layer.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(pub(crate) LeanXmssSignature);

impl Signature {
    /// Decodes a signature.
    ///
    /// Every 2404-byte string decodes, and re-encodes to the same bytes.
    ///
    /// # Errors
    ///
    /// Fails when the input is not 2404 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // A slice converts into the array only when its length is exactly 2404.
        let array = bytes.try_into().map_err(|_| Error::InvalidLength {
            encoding: Encoding::XmssSignature,
            expected: SIGNATURE_LEN,
            actual: bytes.len(),
        })?;
        Ok(Self(LeanXmssSignature::from_bytes(array)))
    }

    /// Encodes the signature.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0.to_bytes()
    }

    /// Returns the leaf index the signature was made at.
    #[must_use]
    pub fn leaf_index(&self) -> LeafIndex {
        self.0.leaf_index
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 2404 bytes would drown a log line: the leaf index identifies it.
        f.debug_struct("Signature")
            .field("leaf_index", &self.leaf_index())
            .finish_non_exhaustive()
    }
}

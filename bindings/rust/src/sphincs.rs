//! leanSPHINCS: a stateless hash-based signature.
//!
//! Normative source: the leanSPHINCS specification in leanVM's `crates/signatures`.
//!
//! ```text
//!     hash         Keccak-256, truncated to n = 16 bytes
//!     tree         one Merkle tree of height h = 26 over WOTS+C keys
//!     one-time     WOTS+C: w = 2, v = 64 chains, digit sum T = 123
//!     few-time     each WOTS+C key signs a two-level WOTS forest of 8 trees
//!     verify       267 Keccak permutations
//! ```
//!
//! The message digest picks the leaf, so no state is kept between signatures.
//!
//! A key may be pruned to a kept subtree of height `b <= 26`.
//!
//! ```text
//!     keeps     the 2^b leaves of one subtree
//!     replaces  the 26 - b siblings above it by pseudorandom nodes
//!     signer    retries randomizers until the leaf lands in the subtree
//! ```
//!
//! - Key generation builds `2^b` leaves, so a small `b` is fast.
//! - Signing retries about `2^(26 - b)` randomizers, so a small `b` signs slower.
//! - Every signature lands on one of `2^b` few-time keys, so a small `b` shortens the lifetime.
//!
//! The kept height also fixes the root: one seed with two kept heights gives two public keys.

use std::fmt;

use rand::random;
use signatures::lean_sphincs::{
    key_gen_from_seed, sign as sphincs_sign, verify as sphincs_verify, LeanSphincsPublicKey,
    LeanSphincsSecretKey, LeanSphincsSignature, MasterSecret, H, MASTER_SECRET_LEN, PUB_KEY_SIZE,
    SECRET_KEY_SIZE, SIG_SIZE,
};

use crate::{Encoding, Error, Message, PUBLIC_KEY_LEN};

/// Byte length of a seed, which derives the public parameter and every secret.
pub const SEED_LEN: usize = 32;

/// Byte length of an encoded secret key: the seed, then the kept height as one byte.
pub const SECRET_KEY_LEN: usize = SEED_LEN + 1;

/// Byte length of an encoded signature.
///
/// ```text
///     randomizer            16
///     forest              2816 = 8 trees * 22 values * 16
///     encoding counter       4
///     WOTS+C chains       1024 = 64 chains * 16
///     Merkle path          416 = 26 nodes * 16
///     total               4276
/// ```
pub const SIGNATURE_LEN: usize = 4276;

/// The tallest kept height: the full tree, height 26.
pub const MAX_KEPT_HEIGHT: usize = 26;

/// The seed a key is derived from.
pub type Seed = [u8; SEED_LEN];

// Invariant: the sizes and types above are the upstream ones, checked at compile time.
const _: () = assert!(SEED_LEN == MASTER_SECRET_LEN);
const _: () = assert!(SECRET_KEY_LEN == SECRET_KEY_SIZE);
const _: () = assert!(SIGNATURE_LEN == SIG_SIZE);
const _: () = assert!(PUBLIC_KEY_LEN == PUB_KEY_SIZE);
const _: () = assert!(MAX_KEPT_HEIGHT == H);
const _: fn(MasterSecret) -> Seed = |seed| seed;

/// A leanSPHINCS public key: a Merkle root and its public parameter.
///
/// Keys order by their encoded bytes, the order aggregate claims are sorted in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey(pub(crate) LeanSphincsPublicKey);

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
            encoding: Encoding::SphincsPublicKey,
            expected: PUBLIC_KEY_LEN,
            actual: bytes.len(),
        })?;
        Ok(Self(LeanSphincsPublicKey::from_bytes(array)))
    }

    /// Encodes the key as its root followed by its public parameter.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.flatten()
    }

    /// Checks a signature of a message under this key.
    ///
    /// # Errors
    ///
    /// Fails, naming the rejecting step, when the signature does not verify.
    pub fn verify(&self, message: &Message, signature: &Signature) -> Result<(), Error> {
        sphincs_verify(&self.0, message, &signature.0)
            .map_err(|reason| Error::SphincsVerify { reason })
    }
}

/// A leanSPHINCS secret key, pruned to its kept subtree.
///
/// Its memory is not zeroized on drop.
pub struct SecretKey(LeanSphincsSecretKey);

impl SecretKey {
    /// Generates a key from the operating system's randomness.
    ///
    /// # Errors
    ///
    /// Fails when the kept height exceeds 26.
    pub fn generate(kept_height: usize) -> Result<Self, Error> {
        Self::from_seed(random(), kept_height)
    }

    /// Derives a key from its seed and kept height, deterministically.
    ///
    /// The seed and kept height together are the whole secret.
    ///
    /// # Errors
    ///
    /// Fails when the kept height exceeds 26.
    pub fn from_seed(seed: Seed, kept_height: usize) -> Result<Self, Error> {
        // Reject before key generation, which would otherwise build an impossible subtree.
        if kept_height > MAX_KEPT_HEIGHT {
            return Err(Error::KeptHeightTooLarge {
                kept_height,
                max: MAX_KEPT_HEIGHT,
            });
        }
        // Key generation also returns the public key, which the secret key already holds.
        let (inner, _) = key_gen_from_seed(seed, kept_height);
        Ok(Self(inner))
    }

    /// Decodes a key from its seed and kept height, regenerating the kept subtree.
    ///
    /// # Errors
    ///
    /// - Fails when the input is not 33 bytes long.
    /// - Fails when the kept height byte exceeds 26.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // A slice converts into the array only when its length is exactly 33.
        let array: [u8; SECRET_KEY_LEN] = bytes.try_into().map_err(|_| Error::InvalidLength {
            encoding: Encoding::SphincsSecretKey,
            expected: SECRET_KEY_LEN,
            actual: bytes.len(),
        })?;
        // Layout: seed (32 bytes) | kept height (1 byte).
        //
        // The array pattern splits it with both lengths checked at compile time.
        let [seed @ .., kept_height] = array;
        Self::from_seed(seed, usize::from(kept_height))
    }

    /// Encodes the key as its seed followed by its kept height.
    ///
    /// The bytes are secret key material.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Returns the key's public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    /// Returns the height of the subtree the key keeps.
    #[must_use]
    pub fn kept_height(&self) -> usize {
        self.0.kept_height()
    }

    /// Signs a message.
    ///
    /// # Errors
    ///
    /// Fails when `2^32` randomizers miss the kept subtree, or `2^32` counters give no encoding.
    pub fn sign(&self, message: &Message) -> Result<Signature, Error> {
        sphincs_sign(&self.0, message)
            .map(Signature)
            .map_err(|reason| Error::SphincsSign { reason })
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only public data: the seed must never reach a log.
        f.debug_struct("SecretKey")
            .field("public_key", &self.public_key())
            .field("kept_height", &self.kept_height())
            .finish_non_exhaustive()
    }
}

/// A leanSPHINCS signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(pub(crate) LeanSphincsSignature);

impl Signature {
    /// Decodes a signature.
    ///
    /// Every 4276-byte string decodes, and re-encodes to the same bytes.
    ///
    /// # Errors
    ///
    /// Fails when the input is not 4276 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // A slice converts into the array only when its length is exactly 4276.
        let array = bytes.try_into().map_err(|_| Error::InvalidLength {
            encoding: Encoding::SphincsSignature,
            expected: SIGNATURE_LEN,
            actual: bytes.len(),
        })?;
        Ok(Self(LeanSphincsSignature::from_bytes(array)))
    }

    /// Encodes the signature.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0.to_bytes()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 4276 bytes would drown a log line.
        f.debug_struct("Signature").finish_non_exhaustive()
    }
}

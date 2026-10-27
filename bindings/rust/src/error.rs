//! The error type of every fallible operation.

use std::fmt;

use leanvm::lean_sphincs::{LeanSphincsSignError, LeanSphincsVerifyError};
use leanvm::lean_xmss::{LeanXmssSignError, LeanXmssVerifyError};
use leanvm::{AggregateVerifyError, AggregationError};

use crate::xmss::LeafIndex;

/// Why a lean-pq operation failed.
///
/// Every variant carries the values a caller needs to log or act on the failure.
///
/// Each message is self-contained: it already includes the upstream reason.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A byte encoding does not have its fixed length.
    #[error("{encoding} must be {expected} bytes, got {actual}")]
    InvalidLength {
        /// The encoding that was being decoded.
        encoding: Encoding,
        /// The only length that encoding has.
        expected: usize,
        /// The length that was supplied.
        actual: usize,
    },

    /// A leanSPHINCS kept height is taller than the tree.
    #[error("leanSPHINCS kept height {kept_height} exceeds the maximum {max}")]
    KeptHeightTooLarge {
        /// The requested kept height.
        kept_height: usize,
        /// The tallest kept height, the full tree's height.
        max: usize,
    },

    /// leanXMSS signing exhausted its randomizer trials without an admissible encoding.
    #[error("leanXMSS signing at leaf index {leaf_index} failed: {reason}")]
    XmssSign {
        /// The leaf index the key was asked to sign or prepare at.
        leaf_index: LeafIndex,
        /// The upstream failure.
        reason: LeanXmssSignError,
    },

    /// A leanXMSS signature does not verify.
    #[error("leanXMSS signature at leaf index {leaf_index} does not verify: {reason}")]
    XmssVerify {
        /// The leaf index the signature claims.
        leaf_index: LeafIndex,
        /// The verification step that rejected it.
        reason: LeanXmssVerifyError,
    },

    /// leanSPHINCS signing exhausted its randomizer or encoding-counter trials.
    #[error("leanSPHINCS signing failed: {reason}")]
    SphincsSign {
        /// The upstream failure.
        reason: LeanSphincsSignError,
    },

    /// A leanSPHINCS signature does not verify.
    #[error("leanSPHINCS signature does not verify: {reason}")]
    SphincsVerify {
        /// The verification step that rejected it.
        reason: LeanSphincsVerifyError,
    },

    /// A raw leanXMSS signature handed to aggregation does not verify.
    #[error("leanXMSS input {index} (leaf index {leaf_index}) does not verify: {reason}")]
    InvalidXmssInput {
        /// Position of the input in the leanXMSS list.
        index: usize,
        /// The leaf index the signature claims.
        leaf_index: LeafIndex,
        /// The verification step that rejected it.
        reason: LeanXmssVerifyError,
    },

    /// A raw leanSPHINCS signature handed to aggregation does not verify.
    #[error("leanSPHINCS input {index} does not verify: {reason}")]
    InvalidSphincsInput {
        /// Position of the input in the leanSPHINCS list.
        index: usize,
        /// The verification step that rejected it.
        reason: LeanSphincsVerifyError,
    },

    /// One aggregation was given more children than one proof can recurse over.
    #[error("aggregation takes at most {max} children, got {count}")]
    TooManyChildren {
        /// The number of children supplied.
        count: usize,
        /// The most children one proof accepts.
        max: usize,
    },

    /// The prover could not produce an aggregate.
    ///
    /// Empty input and too many signers for one proof both land here.
    #[error("aggregation failed: {reason}")]
    Aggregation {
        /// The upstream failure.
        reason: AggregationError,
    },

    /// An encoded aggregate is malformed or its proof does not verify.
    #[error("invalid aggregate: {reason}")]
    InvalidAggregate {
        /// The decoding or verification step that rejected it.
        reason: AggregateVerifyError,
    },
}

/// A fixed-length byte encoding this crate decodes.
///
/// It names the culprit of a length error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Encoding {
    /// A 32-byte leanXMSS public key.
    XmssPublicKey,
    /// A 32-byte leanXMSS secret key, its seed.
    XmssSecretKey,
    /// A 2404-byte leanXMSS signature.
    XmssSignature,
    /// A 32-byte leanSPHINCS public key.
    SphincsPublicKey,
    /// A 33-byte leanSPHINCS secret key, its seed then its kept height.
    SphincsSecretKey,
    /// A 4276-byte leanSPHINCS signature.
    SphincsSignature,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Human names, as they read inside a length error message.
        f.write_str(match self {
            Self::XmssPublicKey => "leanXMSS public key",
            Self::XmssSecretKey => "leanXMSS secret key",
            Self::XmssSignature => "leanXMSS signature",
            Self::SphincsPublicKey => "leanSPHINCS public key",
            Self::SphincsSecretKey => "leanSPHINCS secret key",
            Self::SphincsSignature => "leanSPHINCS signature",
        })
    }
}

//! Recursive aggregation of leanXMSS and leanSPHINCS signatures into one leanVM proof.
//!
//! It is the argument-based multi-signature of Drake, Khovratovich, Kudinov and Wagner.
//!
//! - Paper: "Hash-Based Multi-Signatures for Post-Quantum Ethereum", IACR Communications in Cryptology 2(1), 2025.
//! - Construction 4: an aggregate is a succinct argument of knowledge of every signature.
//! - Theorem 2: it is as unforgeable as the signatures, given adaptive knowledge soundness.

use std::fmt;
use std::sync::{Mutex, Once, PoisonError};

use leanvm::lean_sphincs::verify as verify_sphincs;
use leanvm::lean_xmss::verify as verify_xmss;
use leanvm::{aggregate as prove, setup_prover, EthereumProof, MAX_RECURSIONS};

use crate::{sphincs, xmss, Error, Message};

/// The most children one aggregation recurses over.
pub const MAX_CHILDREN: usize = 16;

// Invariant: the limit above is the guest's, checked at compile time.
const _: () = assert!(MAX_CHILDREN == MAX_RECURSIONS);

/// Exponent of the proof's Reed-Solomon code rate, `rho = 2^-2 = 1/4`.
///
/// - leanVM accepts exponents 1 to 4.
/// - A larger exponent gives a smaller proof but slower proving.
const LOG_INV_RATE: usize = 2;

/// Serializes proving, which leanVM forbids running twice at once in one process.
static PROVER: Mutex<()> = Mutex::new(());

/// Guards the one-time guest build.
static SETUP: Once = Once::new();

/// Builds the aggregation guest and its tables, once per process.
///
/// Aggregating and decoding call it themselves, so calling it only moves that cost earlier.
pub fn setup() {
    SETUP.call_once(setup_prover);
}

/// A verified recursive proof that each listed public key signed its message.
///
/// - Every value was either proven here or decoded and verified.
/// - It attests the claims it lists, not the claims a caller wanted: compare them.
/// - A claim names a public key and a message, never the leaf index used.
#[derive(Clone)]
pub struct Aggregate(EthereumProof);

impl Aggregate {
    /// Decodes an aggregate and verifies its proof.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are malformed or the proof does not verify.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // Verification needs the guest's tables.
        setup();
        // Parsing only checks shapes: nothing decoded is trusted until the proof verifies.
        let proof = EthereumProof::from_bytes(bytes)
            .map_err(|reason| Error::InvalidAggregate { reason })?;
        proof
            .verify()
            .map_err(|reason| Error::InvalidAggregate { reason })?;
        Ok(Self(proof))
    }

    /// Encodes the aggregate: its claims, then its proof.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Returns the proven leanXMSS claims, strictly sorted by public key then message.
    #[must_use]
    pub fn xmss_claims(&self) -> Vec<(xmss::PublicKey, Message)> {
        self.0
            .xmss_signers()
            .iter()
            .map(|&(key, message)| (xmss::PublicKey(key), message))
            .collect()
    }

    /// Returns the proven leanSPHINCS claims, strictly sorted by public key then message.
    #[must_use]
    pub fn sphincs_claims(&self) -> Vec<(sphincs::PublicKey, Message)> {
        self.0
            .lean_sphincs_signers()
            .iter()
            .map(|&(key, message)| (sphincs::PublicKey(key), message))
            .collect()
    }
}

impl fmt::Debug for Aggregate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Claim counts identify an aggregate in a log.
        // The proof bytes would drown it.
        f.debug_struct("Aggregate")
            .field("xmss_claims", &self.0.xmss_signers().len())
            .field("sphincs_claims", &self.0.lean_sphincs_signers().len())
            .finish_non_exhaustive()
    }
}

/// Proves raw signatures and child aggregates together as one aggregate.
///
/// ```text
///     claims(result) = claims(children) + claims(raw inputs)
///                      sorted, one entry per (public key, message)
/// ```
///
/// - Raw signatures are verified first, so a bad one is named by its index.
/// - Children are borrowed, and the guest re-verifies each one inside the new proof.
/// - One proof runs at a time per process, and concurrent calls wait.
///
/// # Errors
///
/// - Fails when more than 16 children are given.
/// - Fails when a raw signature does not verify, naming its list and index.
/// - Fails when the prover rejects the input, for example when it is empty.
pub fn aggregate(
    children: &[&Aggregate],
    xmss: &[(xmss::PublicKey, Message, xmss::Signature)],
    sphincs: &[(sphincs::PublicKey, Message, sphincs::Signature)],
) -> Result<Aggregate, Error> {
    // Reject an oversized fan-in before cloning any proof.
    if children.len() > MAX_CHILDREN {
        return Err(Error::TooManyChildren {
            count: children.len(),
            max: MAX_CHILDREN,
        });
    }

    // Why: the prover assumes every raw signature is valid and panics on a forged one.
    //
    // Checking here turns that panic into an error that names the culprit.
    for (index, (public_key, message, signature)) in xmss.iter().enumerate() {
        verify_xmss(&public_key.0, message, &signature.0).map_err(|reason| {
            Error::InvalidXmssInput {
                index,
                leaf_index: signature.leaf_index(),
                reason,
            }
        })?;
    }
    for (index, (public_key, message, signature)) in sphincs.iter().enumerate() {
        verify_sphincs(&public_key.0, message, &signature.0)
            .map_err(|reason| Error::InvalidSphincsInput { index, reason })?;
    }

    // The prover takes owned inputs: copy the proofs and unwrap the signature types.
    let children: Vec<EthereumProof> = children.iter().map(|child| child.0.clone()).collect();
    let xmss = xmss
        .iter()
        .map(|(public_key, message, signature)| (public_key.0, *message, signature.0.clone()))
        .collect();
    let sphincs = sphincs
        .iter()
        .map(|(public_key, message, signature)| (public_key.0, *message, signature.0.clone()))
        .collect();

    // Build the guest before taking the lock, so waiting callers do not also wait on it.
    setup();
    // A panic in an earlier proof poisons the lock but leaves no state behind, so proceed.
    let _prover = PROVER.lock().unwrap_or_else(PoisonError::into_inner);
    // No DA blobs, and keep every claim the inputs cover.
    prove(&children, xmss, sphincs, &[], None, LOG_INV_RATE)
        .map(Aggregate)
        .map_err(|reason| Error::Aggregation { reason })
}

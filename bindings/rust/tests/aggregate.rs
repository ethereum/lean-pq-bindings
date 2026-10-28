//! leanXMSS and leanSPHINCS aggregation through the safe facade.
#![cfg(feature = "aggregation")]

use std::sync::LazyLock;

use lean_pq::{aggregate, sphincs, xmss, Aggregate, Error, Message, MAX_CHILDREN};
use leanvm::lean_sphincs::LeanSphincsVerifyError;
use leanvm::lean_xmss::LeanXmssVerifyError;
use leanvm::{AggregateVerifyError, AggregationError, VerifierError};

/// Two signers, shared by every test so each key is generated once.
struct Signers {
    xmss: xmss::SecretKey,
    sphincs: sphincs::SecretKey,
}

static SIGNERS: LazyLock<Signers> = LazyLock::new(|| Signers {
    xmss: xmss::SecretKey::from_seed([5; 32]),
    sphincs: sphincs::SecretKey::from_seed([6; 32], 4).unwrap(),
});

/// One proven aggregate over a single leanXMSS claim, shared to prove only once.
static LEAF: LazyLock<Aggregate> =
    LazyLock::new(|| aggregate(&[], &[xmss_input(FIRST, 0)], &[]).unwrap());

const FIRST: Message = [0x11; 32];
const SECOND: Message = [0x22; 32];

fn xmss_input(message: Message, leaf_index: u32) -> (xmss::PublicKey, Message, xmss::Signature) {
    // A fresh leanXMSS signature of the message at the leaf index.
    let key = &SIGNERS.xmss;
    (
        key.public_key(),
        message,
        key.sign(&message, leaf_index).unwrap(),
    )
}

fn sphincs_input(message: Message) -> (sphincs::PublicKey, Message, sphincs::Signature) {
    // A fresh leanSPHINCS signature of the message.
    let key = &SIGNERS.sphincs;
    (key.public_key(), message, key.sign(&message).unwrap())
}

#[test]
fn aggregates_both_schemes_recursively_and_round_trips() {
    let xmss_key = SIGNERS.xmss.public_key();
    let sphincs_key = SIGNERS.sphincs.public_key();

    // Fixture state: a two-level tree of proofs.
    //
    //     LEAF  = { xmss: (key, FIRST) }
    //     right = { sphincs: (key, SECOND) }
    //     root  = LEAF + right + { xmss: (key, SECOND), (key, FIRST) again }
    let right = aggregate(&[], &[], &[sphincs_input(SECOND)]).unwrap();
    let root = aggregate(
        &[&LEAF, &right],
        &[xmss_input(SECOND, 1), xmss_input(FIRST, 2)],
        &[],
    )
    .unwrap();

    // Decoding verifies the proof again from bytes alone.
    let received = Aggregate::from_bytes(&root.to_bytes()).unwrap();

    // Claims are the union, sorted, with (key, FIRST) once though proven twice.
    assert_eq!(
        received.xmss_claims(),
        [(xmss_key, FIRST), (xmss_key, SECOND)]
    );
    assert_eq!(received.sphincs_claims(), [(sphincs_key, SECOND)]);
    assert_eq!(
        format!("{received:?}"),
        "Aggregate { xmss_claims: 2, sphincs_claims: 1, .. }"
    );
}

#[test]
fn rejects_an_invalid_raw_signature_by_list_and_index() {
    // Mutation: sign FIRST, then claim the signature is over SECOND.
    //
    //     xmss[0]    valid
    //     xmss[1]    (key, SECOND, sig over FIRST at leaf 4)  -> rejected
    let (key, _, forged) = xmss_input(FIRST, 4);
    let error = aggregate(&[], &[xmss_input(FIRST, 3), (key, SECOND, forged)], &[]).unwrap_err();
    assert_eq!(
        error,
        Error::InvalidXmssInput {
            index: 1,
            leaf_index: 4,
            reason: LeanXmssVerifyError::InvalidEncoding,
        }
    );

    // Same mutation on the leanSPHINCS list, at index 0.
    let (key, _, forged) = sphincs_input(FIRST);
    let error = aggregate(&[], &[], &[(key, SECOND, forged)]).unwrap_err();
    assert_eq!(
        error,
        Error::InvalidSphincsInput {
            index: 0,
            reason: LeanSphincsVerifyError::InadmissibleEncoding,
        }
    );
}

#[test]
fn rejects_more_children_than_one_proof_recurses_over() {
    // Boundary: 16 children fit, 17 do not.
    //
    // The count is checked before any proving, so one shared leaf suffices.
    let children = [&*LEAF; MAX_CHILDREN + 1];
    let error = aggregate(&children, &[], &[]).unwrap_err();
    assert_eq!(error, Error::TooManyChildren { count: 17, max: 16 });
    assert_eq!(
        error.to_string(),
        "aggregation takes at most 16 children, got 17"
    );
}

#[test]
fn rejects_empty_input() {
    // Nothing to prove: no children, no raw signatures.
    let error = aggregate(&[], &[], &[]).unwrap_err();
    assert_eq!(
        error,
        Error::Aggregation {
            reason: AggregationError::Empty,
        }
    );
    assert_eq!(
        error.to_string(),
        "aggregation failed: no signature claims or DA roots to publish"
    );
}

#[test]
fn rejects_tampered_and_truncated_bytes() {
    let bytes = LEAF.to_bytes();

    // Mutation 1: flip the last bit, inside the proof.
    let mut tampered = bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;

    // Mutation 2: drop the last byte.
    let truncated = &bytes[..bytes.len() - 1];

    // Each fails at a different step:
    //
    //     tampered   parses, then the proof's Merkle opening misses its root
    //     truncated  does not parse as an aggregate
    //
    // Bindings match on the "invalid aggregate: " prefix of the message.
    let cases = [
        (
            tampered.as_slice(),
            AggregateVerifyError::Snark(VerifierError::MerkleRootMismatch),
            "invalid aggregate: the snark did not verify: Merkle root mismatch",
        ),
        (
            truncated,
            AggregateVerifyError::MalformedEncoding,
            "invalid aggregate: not a valid aggregate encoding",
        ),
    ];
    for (bytes, reason, message) in cases {
        let error = Aggregate::from_bytes(bytes).unwrap_err();
        assert_eq!(error, Error::InvalidAggregate { reason });
        assert_eq!(error.to_string(), message);
    }
}

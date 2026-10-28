//! leanSPHINCS keys, signatures and their byte encodings.

use lean_pq::sphincs::{
    PublicKey, SecretKey, Signature, MAX_KEPT_HEIGHT, SECRET_KEY_LEN, SIGNATURE_LEN,
};
use lean_pq::{Encoding, Error, PUBLIC_KEY_LEN};
use proptest::collection::vec;
use proptest::prelude::*;
use signatures::lean_sphincs::LeanSphincsVerifyError;

#[test]
fn signs_verifies_and_rejects_another_message() {
    // Kept height 4: 2^4 leaves kept, so signing retries about 2^22 randomizers.
    let key = SecretKey::from_seed([1; 32], 4).unwrap();
    let message = [0x42; 32];
    let signature = key.sign(&message).unwrap();
    key.public_key().verify(&message, &signature).unwrap();

    // Mutation: verify the same signature against another message.
    //
    // The encoding counter no longer encodes the few-time key for the new digest.
    let error = key
        .public_key()
        .verify(&[0x43; 32], &signature)
        .unwrap_err();
    assert_eq!(
        error,
        Error::SphincsVerify {
            reason: LeanSphincsVerifyError::InadmissibleEncoding,
        }
    );
}

#[test]
fn secret_key_encodes_as_seed_then_kept_height() {
    let seed = [2; 32];
    let key = SecretKey::from_seed(seed, 3).unwrap();

    // Layout: seed (32 bytes) | kept height (1 byte).
    //
    //     [2, 2, ..., 2, 3]
    let bytes = key.to_bytes();
    assert_eq!(bytes[..32], seed);
    assert_eq!(bytes[32], 3);

    // Decoding regenerates the same key with the same kept height.
    let restored = SecretKey::from_bytes(&bytes).unwrap();
    assert_eq!(restored.public_key(), key.public_key());
    assert_eq!(restored.kept_height(), 3);
}

#[test]
fn kept_height_is_part_of_the_key() {
    // The kept height places the pseudorandom siblings, hence the root.
    //
    //     seed s, kept height 0  -> public key A
    //     seed s, kept height 1  -> public key B != A
    let low = SecretKey::from_seed([3; 32], 0).unwrap();
    let high = SecretKey::from_seed([3; 32], 1).unwrap();
    assert_ne!(low.public_key(), high.public_key());
}

#[test]
fn kept_height_above_the_tree_is_rejected() {
    // Boundary: 26 is the full tree, 27 does not exist.
    let too_tall = MAX_KEPT_HEIGHT + 1;
    let expected = Error::KeptHeightTooLarge {
        kept_height: too_tall,
        max: MAX_KEPT_HEIGHT,
    };

    // Each constructor rejects it before any key generation.
    assert_eq!(
        SecretKey::from_seed([4; 32], too_tall).unwrap_err(),
        expected
    );
    assert_eq!(SecretKey::generate(too_tall).unwrap_err(), expected);

    // Mutation: an encoded key whose last byte says 27.
    let mut bytes = [4; SECRET_KEY_LEN];
    bytes[32] = 27;
    assert_eq!(SecretKey::from_bytes(&bytes).unwrap_err(), expected);
    assert_eq!(
        expected.to_string(),
        "leanSPHINCS kept height 27 exceeds the maximum 26"
    );
}

#[test]
fn debug_output_never_contains_the_seed() {
    let key = SecretKey::from_seed([0xab; 32], 2).unwrap();

    // The rendering is exactly the public data and an elision marker.
    let public_key = key.public_key();
    assert_eq!(
        format!("{key:?}"),
        format!("SecretKey {{ public_key: {public_key:?}, kept_height: 2, .. }}")
    );
}

proptest! {
    #[test]
    fn public_key_bytes_round_trip(bytes in any::<[u8; PUBLIC_KEY_LEN]>()) {
        // Decoding is a plain split, so every 32-byte string round-trips exactly.
        let key = PublicKey::from_bytes(&bytes).unwrap();
        prop_assert_eq!(key.to_bytes(), bytes);
    }

    #[test]
    fn signature_bytes_round_trip(bytes in vec(any::<u8>(), SIGNATURE_LEN)) {
        // Every 4276-byte string decodes, and re-encodes to itself.
        let signature = Signature::from_bytes(&bytes).unwrap();
        prop_assert_eq!(&signature.to_bytes()[..], &bytes[..]);
    }

    #[test]
    fn decoders_reject_every_other_length(len in 0..2 * SIGNATURE_LEN) {
        let bytes = vec![0; len];

        // Fixture state: each decoder accepts exactly one length.
        //
        //     public key   32
        //     secret key   33
        //     signature    4276
        let cases = [
            (Encoding::SphincsPublicKey, PUBLIC_KEY_LEN, PublicKey::from_bytes(&bytes).err()),
            (Encoding::SphincsSecretKey, SECRET_KEY_LEN, SecretKey::from_bytes(&bytes).err()),
            (Encoding::SphincsSignature, SIGNATURE_LEN, Signature::from_bytes(&bytes).err()),
        ];
        for (encoding, expected, error) in cases {
            // Any other length fails, and the error names all three facts.
            if len != expected {
                prop_assert_eq!(
                    error.unwrap(),
                    Error::InvalidLength { encoding, expected, actual: len }
                );
            }
        }
    }
}

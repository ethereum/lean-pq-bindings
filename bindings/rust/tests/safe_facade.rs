use lean_pq::{aggregate, sphincs, xmss, Aggregate, Error};

#[test]
fn rejects_signatures_under_another_message() {
    let message = [0x42; 32];
    let other = [0x43; 32];
    let xmss_key = xmss::SecretKey::from_seed([1; 32]);
    let xmss_signature = xmss_key.sign(&message, 3).expect("leanXMSS signature");
    assert!(xmss::verify(&xmss_key.public_key(), &other, &xmss_signature).is_err());

    let sphincs_key = sphincs::SecretKey::from_seed([2; 32], 4).expect("leanSPHINCS key");
    let sphincs_signature = sphincs_key.sign(&message).expect("leanSPHINCS signature");
    assert!(sphincs::verify(&sphincs_key.public_key(), &other, &sphincs_signature).is_err());

    assert_eq!(
        aggregate(&[], &[(xmss_key.public_key(), other, xmss_signature)], &[]).unwrap_err(),
        Error::InvalidXmssSignature { index: 0 }
    );
}

#[test]
fn secret_keys_round_trip_through_bytes() {
    let message = [7; 32];
    let xmss_key = xmss::SecretKey::from_seed([3; 32]);
    let restored = xmss::SecretKey::from_bytes(&xmss_key.to_bytes()).expect("leanXMSS key bytes");
    assert_eq!(restored.public_key(), xmss_key.public_key());
    let signature = restored.sign(&message, 9).expect("signature");
    let signature = xmss::Signature::from_bytes(&signature.to_bytes()).expect("signature bytes");
    assert_eq!(signature.leaf_index(), 9);
    xmss::verify(&xmss_key.public_key(), &message, &signature).expect("verifies");

    let sphincs_key = sphincs::SecretKey::from_seed([4; 32], 3).expect("leanSPHINCS key");
    let restored =
        sphincs::SecretKey::from_bytes(&sphincs_key.to_bytes()).expect("leanSPHINCS key bytes");
    assert_eq!(restored.public_key(), sphincs_key.public_key());
    assert_eq!(restored.kept_height(), 3);
    assert_eq!(
        sphincs::SecretKey::from_seed([4; 32], sphincs::MAX_KEPT_HEIGHT + 1).unwrap_err(),
        Error::InvalidKeptHeight(sphincs::MAX_KEPT_HEIGHT + 1)
    );
}

#[test]
fn aggregates_both_schemes_recursively() {
    let first = [0x11; 32];
    let second = [0x22; 32];
    let xmss_key = xmss::SecretKey::from_seed([5; 32]);
    let sphincs_key = sphincs::SecretKey::from_seed([6; 32], 4).expect("leanSPHINCS key");

    let left = aggregate(
        &[],
        &[(
            xmss_key.public_key(),
            first,
            xmss_key.sign(&first, 0).unwrap(),
        )],
        &[],
    )
    .expect("leanXMSS leaf");
    let right = aggregate(
        &[],
        &[],
        &[(
            sphincs_key.public_key(),
            second,
            sphincs_key.sign(&second).unwrap(),
        )],
    )
    .expect("leanSPHINCS leaf");
    let root = aggregate(
        &[&left, &right],
        &[(
            xmss_key.public_key(),
            second,
            xmss_key.sign(&second, 1).unwrap(),
        )],
        &[],
    )
    .expect("root");

    let received = Aggregate::from_bytes(&root.to_bytes()).expect("verified root");
    let mut expected_xmss = vec![
        (xmss_key.public_key(), first),
        (xmss_key.public_key(), second),
    ];
    expected_xmss.sort();
    assert_eq!(received.xmss_claims(), expected_xmss);
    assert_eq!(
        received.sphincs_claims(),
        [(sphincs_key.public_key(), second)]
    );

    let mut tampered = root.to_bytes();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        Aggregate::from_bytes(&tampered),
        Err(Error::InvalidAggregate(_))
    ));
}

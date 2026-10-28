package leanpq

import (
	"reflect"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	message := bytes32(0x42)
	other := bytes32(0x43)

	xmssKey := mustXmssKey(t, bytes32(1))
	xmssPublicKey := mustXmssPublicKey(t, xmssKey)
	xmssSignature, err := xmssKey.Sign(message, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := XmssVerify(xmssPublicKey, message, xmssSignature); err != nil {
		t.Fatalf("leanXMSS signature must verify: %v", err)
	}
	if XmssVerify(xmssPublicKey, other, xmssSignature) == nil {
		t.Fatal("leanXMSS signature must not verify under another message")
	}

	sphincsKey := mustSphincsKey(t, bytes32(2), 4)
	sphincsPublicKey := mustSphincsPublicKey(t, sphincsKey)
	sphincsSignature, err := sphincsKey.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := SphincsVerify(sphincsPublicKey, message, sphincsSignature); err != nil {
		t.Fatalf("leanSPHINCS signature must verify: %v", err)
	}
	if SphincsVerify(sphincsPublicKey, other, sphincsSignature) == nil {
		t.Fatal("leanSPHINCS signature must not verify under another message")
	}
}

func TestSecretKeysRoundTripThroughBytes(t *testing.T) {
	message := bytes32(7)

	xmssKey := mustXmssKey(t, bytes32(3))
	encoded, err := xmssKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	restoredXmss, err := XmssSecretKeyFromBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer restoredXmss.Close()
	xmssPublicKey := mustXmssPublicKey(t, xmssKey)
	if mustXmssPublicKey(t, restoredXmss) != xmssPublicKey {
		t.Fatal("restored leanXMSS key must keep its public key")
	}
	xmssSignature, err := restoredXmss.Sign(message, 9)
	if err != nil {
		t.Fatal(err)
	}
	if err := XmssVerify(xmssPublicKey, message, xmssSignature); err != nil {
		t.Fatal(err)
	}

	sphincsKey := mustSphincsKey(t, bytes32(4), 3)
	encoded, err = sphincsKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	restoredSphincs, err := SphincsSecretKeyFromBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer restoredSphincs.Close()
	sphincsPublicKey := mustSphincsPublicKey(t, sphincsKey)
	if mustSphincsPublicKey(t, restoredSphincs) != sphincsPublicKey {
		t.Fatal("restored leanSPHINCS key must keep its public key")
	}
	keptHeight, err := restoredSphincs.KeptHeight()
	if err != nil {
		t.Fatal(err)
	}
	if keptHeight != 3 {
		t.Fatalf("kept height = %d, want 3", keptHeight)
	}
	sphincsSignature, err := restoredSphincs.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := SphincsVerify(sphincsPublicKey, message, sphincsSignature); err != nil {
		t.Fatal(err)
	}
}

func TestAggregateRecursively(t *testing.T) {
	if err := Setup(); err != nil {
		t.Fatal(err)
	}
	first := bytes32(0x11)
	second := bytes32(0x22)
	xmssKey := mustXmssKey(t, bytes32(5))
	xmssPublicKey := mustXmssPublicKey(t, xmssKey)
	sphincsKey := mustSphincsKey(t, bytes32(6), 4)
	sphincsPublicKey := mustSphincsPublicKey(t, sphincsKey)

	firstXmss, err := xmssKey.Sign(first, 0)
	if err != nil {
		t.Fatal(err)
	}
	left, err := AggregateSignatures(nil, []XmssSignedMessage{{xmssPublicKey, first, firstXmss}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()

	sphincsSignature, err := sphincsKey.Sign(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := AggregateSignatures(nil, nil, []SphincsSignedMessage{{sphincsPublicKey, first, sphincsSignature}})
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()

	secondXmss, err := xmssKey.Sign(second, 1)
	if err != nil {
		t.Fatal(err)
	}
	root, err := AggregateSignatures(
		[]*Aggregate{left, right}, []XmssSignedMessage{{xmssPublicKey, second, secondXmss}}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	encoded, err := root.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	received, err := AggregateFromBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer received.Close()

	expectedXmss := []Claim{{xmssPublicKey, first}, {xmssPublicKey, second}}
	xmssClaims, err := received.XmssClaims()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(xmssClaims, expectedXmss) {
		t.Fatalf("leanXMSS claims = %x, want %x", xmssClaims, expectedXmss)
	}
	sphincsClaims, err := received.SphincsClaims()
	if err != nil {
		t.Fatal(err)
	}
	if expected := []Claim{{sphincsPublicKey, first}}; !reflect.DeepEqual(sphincsClaims, expected) {
		t.Fatalf("leanSPHINCS claims = %x, want %x", sphincsClaims, expected)
	}

	encoded[len(encoded)-1] ^= 1
	if tampered, err := AggregateFromBytes(encoded); err == nil {
		tampered.Close()
		t.Fatal("tampered aggregate bytes must be rejected")
	}
}

func mustXmssKey(t *testing.T, seed [32]byte) *XmssSecretKey {
	t.Helper()
	key, err := XmssSecretKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Close)
	return key
}

func mustSphincsKey(t *testing.T, seed [32]byte, keptHeight uint32) *SphincsSecretKey {
	t.Helper()
	key, err := SphincsSecretKeyFromSeed(seed, keptHeight)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Close)
	return key
}

func mustXmssPublicKey(t *testing.T, key *XmssSecretKey) [32]byte {
	t.Helper()
	publicKey, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}

func mustSphincsPublicKey(t *testing.T, key *SphincsSecretKey) [32]byte {
	t.Helper()
	publicKey, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}

func bytes32(value byte) [32]byte {
	var result [32]byte
	for index := range result {
		result[index] = value
	}
	return result
}

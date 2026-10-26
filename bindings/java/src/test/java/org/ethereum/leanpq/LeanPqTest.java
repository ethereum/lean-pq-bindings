package org.ethereum.leanpq;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class LeanPqTest {
    @Test
    void signsVerifiesAndRejectsAnotherMessage() {
        byte[] message = bytes(0x42);
        byte[] other = bytes(0x43);
        try (XmssSecretKey xmss = XmssSecretKey.fromSeed(bytes(1));
             SphincsSecretKey sphincs = SphincsSecretKey.fromSeed(bytes(2), 4)) {
            byte[] xmssSignature = xmss.sign(message, 3);
            assertEquals(2404, xmssSignature.length);
            assertTrue(LeanPq.xmssVerify(xmss.publicKey(), message, xmssSignature));
            assertFalse(LeanPq.xmssVerify(xmss.publicKey(), other, xmssSignature));

            byte[] sphincsSignature = sphincs.sign(message);
            assertEquals(4276, sphincsSignature.length);
            assertTrue(LeanPq.sphincsVerify(sphincs.publicKey(), message, sphincsSignature));
            assertFalse(LeanPq.sphincsVerify(sphincs.publicKey(), other, sphincsSignature));
        }
    }

    @Test
    void secretKeysRoundTripThroughBytes() {
        byte[] message = bytes(7);
        try (XmssSecretKey xmss = XmssSecretKey.fromSeed(bytes(3));
             XmssSecretKey restored = XmssSecretKey.fromBytes(xmss.toBytes())) {
            assertArrayEquals(xmss.publicKey(), restored.publicKey());
            assertTrue(LeanPq.xmssVerify(xmss.publicKey(), message, restored.sign(message, 9)));
        }
        try (SphincsSecretKey sphincs = SphincsSecretKey.fromSeed(bytes(4), 3);
             SphincsSecretKey restored = SphincsSecretKey.fromBytes(sphincs.toBytes())) {
            assertArrayEquals(sphincs.publicKey(), restored.publicKey());
            assertEquals(3, restored.keptHeight());
            assertTrue(LeanPq.sphincsVerify(sphincs.publicKey(), message, restored.sign(message)));
        }
    }

    @Test
    void aggregatesBothSchemesRecursively() {
        byte[] first = bytes(0x11);
        byte[] second = bytes(0x22);
        try (XmssSecretKey xmss = XmssSecretKey.fromSeed(bytes(5));
             SphincsSecretKey sphincs = SphincsSecretKey.fromSeed(bytes(6), 4)) {
            byte[] xmssKey = xmss.publicKey();
            byte[] sphincsKey = sphincs.publicKey();
            try (Aggregate left = LeanPq.aggregate(
                     List.of(), List.of(new SignedMessage(xmssKey, first, xmss.sign(first, 0))), List.of());
                 Aggregate right = LeanPq.aggregate(
                     List.of(), List.of(), List.of(new SignedMessage(sphincsKey, second, sphincs.sign(second))));
                 Aggregate root = LeanPq.aggregate(
                     List.of(left, right), List.of(new SignedMessage(xmssKey, second, xmss.sign(second, 1))), List.of());
                 Aggregate received = Aggregate.fromBytes(root.toBytes())) {
                List<SignatureClaim> xmssClaims = received.xmssClaims();
                assertEquals(2, xmssClaims.size());
                assertEquals(
                    Set.of(new SignatureClaim(xmssKey, first), new SignatureClaim(xmssKey, second)),
                    Set.copyOf(xmssClaims));
                assertEquals(List.of(new SignatureClaim(sphincsKey, second)), received.sphincsClaims());

                byte[] tampered = root.toBytes();
                tampered[tampered.length - 1] ^= 1;
                assertThrows(LeanPqException.class, () -> Aggregate.fromBytes(tampered));
            }
        }
    }

    private static byte[] bytes(int value) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}

package org.ethereum.leanpq;

import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A verified proof that every listed public key signed its message, across leanXMSS and
 * leanSPHINCS. It attests the claims it lists, not the claims you wanted: compare
 * {@link #xmssClaims()} and {@link #sphincsClaims()} against what you expect.
 */
public final class Aggregate implements AutoCloseable {
    private static final int CLAIM_LENGTH = Native.PUBLIC_KEY_LENGTH + Native.MESSAGE_LENGTH;

    private final NativeHandle handle;

    Aggregate(MemorySegment pointer) {
        handle = new NativeHandle(pointer, Native::destroyAggregate);
    }

    /** Decodes and verifies an aggregate; throws {@link LeanPqException} if it does not verify. */
    public static Aggregate fromBytes(byte[] bytes) {
        return new Aggregate(Native.aggregateFromBytes(Objects.requireNonNull(bytes, "bytes")));
    }

    public byte[] toBytes() {
        try (NativeHandle.Borrow borrowed = handle.borrow()) {
            return Native.aggregateToBytes(borrowed.pointer());
        }
    }

    /** The proven leanXMSS claims, strictly sorted. */
    public List<SignatureClaim> xmssClaims() {
        try (NativeHandle.Borrow borrowed = handle.borrow()) {
            return claims(Native.xmssClaims(borrowed.pointer()));
        }
    }

    /** The proven leanSPHINCS claims, strictly sorted. */
    public List<SignatureClaim> sphincsClaims() {
        try (NativeHandle.Borrow borrowed = handle.borrow()) {
            return claims(Native.sphincsClaims(borrowed.pointer()));
        }
    }

    NativeHandle.Borrow borrow() {
        return handle.borrow();
    }

    @Override
    public void close() {
        handle.close();
    }

    private static List<SignatureClaim> claims(byte[] records) {
        if (records.length % CLAIM_LENGTH != 0) {
            throw new LeanPqException("native claim data is not a multiple of " + CLAIM_LENGTH + " bytes");
        }
        List<SignatureClaim> claims = new ArrayList<>(records.length / CLAIM_LENGTH);
        for (int offset = 0; offset < records.length; offset += CLAIM_LENGTH) {
            claims.add(new SignatureClaim(
                Arrays.copyOfRange(records, offset, offset + Native.PUBLIC_KEY_LENGTH),
                Arrays.copyOfRange(records, offset + Native.PUBLIC_KEY_LENGTH, offset + CLAIM_LENGTH)));
        }
        return List.copyOf(claims);
    }
}

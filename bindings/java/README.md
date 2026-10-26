# lean-pq Java bindings

Java 25 bindings for [leanVM](https://github.com/leanEthereum/leanVM)'s post-quantum signatures
and their zkVM-backed aggregation:

- **leanXMSS**: stateful. A key signs at unsigned 32-bit leaf indices; never sign two different
  messages at the same leaf index.
- **leanSPHINCS**: stateless. A key keeps one subtree of height `keptHeight` (at most 26), which
  trades signing capacity for key generation time.

Both schemes use 32-byte public keys and sign 32-byte messages. Signatures are plain `byte[]`
values: 2404 bytes for leanXMSS and 4276 bytes for leanSPHINCS. An `Aggregate` proves that each
listed public key signed its message, across both schemes, and can absorb earlier aggregates
recursively.

The public API is a named Java module, `org.ethereum.leanpq`, built on Java's finalized Foreign
Function & Memory API (FFM/Panama). Native objects are wrapped in `AutoCloseable` types; use
try-with-resources for `XmssSecretKey`, `SphincsSecretKey`, and `Aggregate`.

This is a source binding, not yet a published Maven artifact. Gradle builds the matching Rust
shared library before running tests.

## Requirements

- JDK 25
- Gradle 9.1 or newer
- Rust (stable toolchain)

## Build and test

From the repository root:

```sh
gradle -p bindings/java test
```

The test task builds the shared `lean_pq_native` library in release mode (debug builds of leanVM
prove roughly 30x slower) and supplies its path through `-Dlean.pq.native.path`.
Applications embedding the library must similarly build or package a platform-specific native
library and set that property before first use. One aggregation takes seconds and roughly 1.6 GB
of memory.

## Native-access permission

The library is a named module. A deployed modular application should grant native access narrowly:

```sh
java --enable-native-access=org.ethereum.leanpq ...
```

Gradle's JUnit runner executes on the class path, so the repository test task instead uses
`--enable-native-access=ALL-UNNAMED`. This broader permission is test-harness-only.

## Sign and verify

```java
import org.ethereum.leanpq.*;

try (XmssSecretKey xmss = XmssSecretKey.fromSeed(seed32);
     SphincsSecretKey sphincs = SphincsSecretKey.fromSeed(otherSeed32, 4)) {
    byte[] xmssSignature = xmss.sign(message32, 7);
    boolean xmssValid = LeanPq.xmssVerify(xmss.publicKey(), message32, xmssSignature);

    byte[] sphincsSignature = sphincs.sign(message32);
    boolean sphincsValid = LeanPq.sphincsVerify(sphincs.publicKey(), message32, sphincsSignature);
}
```

leanXMSS keys are stateful: persist your own durable high-water leaf index alongside
`XmssSecretKey.toBytes()` and advance it before publishing a signature. `prepare(leafIndex)`
precomputes signing state ahead of time. Secret-key bytes are secret material: the 32-byte
leanXMSS seed, or the 32-byte leanSPHINCS seed followed by its kept height.

## Aggregation

`LeanPq.aggregate(children, xmss, sphincs)` verifies every raw signature before proving, accepts
at most 16 children, and runs one proof at a time per process. `Aggregate.fromBytes` verifies the
proof it decodes and throws `LeanPqException` otherwise, so every `Aggregate` is proven. An
aggregate attests the claims it lists, not the claims you wanted: compare `xmssClaims()` and
`sphincsClaims()` against what you expect. `LeanPq.setup()` moves the one-time guest build ahead of
the first proof; calling it is optional and idempotent.

```java
import java.util.List;
import org.ethereum.leanpq.*;

try (Aggregate leaf = LeanPq.aggregate(
         List.of(),
         List.of(new SignedMessage(xmss.publicKey(), message32, xmss.sign(message32, 7))),
         List.of(new SignedMessage(sphincs.publicKey(), message32, sphincs.sign(message32))));
     Aggregate root = LeanPq.aggregate(List.of(leaf), List.of(), List.of());
     Aggregate received = Aggregate.fromBytes(root.toBytes())) {
    List<SignatureClaim> xmssClaims = received.xmssClaims();
    List<SignatureClaim> sphincsClaims = received.sphincsClaims();
}
```

The native ABI in [`../native`](../native) is an internal implementation detail shared by
managed-language bindings, not a stable C API.

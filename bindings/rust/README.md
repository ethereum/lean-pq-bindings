# lean-pq

Safe Rust bindings for [leanVM](https://github.com/leanEthereum/leanVM)'s post-quantum signatures and their aggregation.

- **leanXMSS** is synchronized: a key signs at `2^32` leaf indices, one message per leaf index.
- **leanSPHINCS** is stateless: a key keeps one subtree of height `kept_height`, at most 26.
- **Aggregation** proves many signatures of both schemes in one recursive leanVM proof.

Public keys and messages are 32 bytes in both schemes.

A smaller leanSPHINCS kept height generates keys faster, signs slower, and shortens the key's lifetime.

## Install

The crate is not on crates.io: it depends on leanVM by git revision.

<!-- x-release-please-start-version -->
```toml
[dependencies]
lean-pq = { git = "https://github.com/ethereum/lean-pq-bindings.git", tag = "v0.8.0" }
```
<!-- x-release-please-end -->

Build in release mode: debug builds of leanVM prove far slower.

Aggregation is the default `aggregation` feature, which pulls in leanVM's prover and verifier. To
only sign and verify, add `default-features = false` to the dependency: the crate then builds from
leanVM's `signatures` crate alone, and `aggregate`, `setup`, `Aggregate` and `MAX_CHILDREN` are
not compiled.

## Sign and verify

```rust
use lean_pq::{sphincs, xmss};

let message = [0x42; 32];

let xmss_key = xmss::SecretKey::from_seed([0x01; 32]);
let signature = xmss_key.sign(&message, 7)?;
xmss_key.public_key().verify(&message, &signature)?;

let sphincs_key = sphincs::SecretKey::from_seed([0x02; 32], 4)?;
let signature = sphincs_key.sign(&message)?;
sphincs_key.public_key().verify(&message, &signature)?;
# Ok::<(), lean_pq::Error>(())
```

A leanXMSS key keeps no record of the leaf indices it used.

Persist a durable high-water leaf index next to the key's bytes, and advance it before publishing a signature.

Secret key bytes are secret material: the leanXMSS seed, or the leanSPHINCS seed then its kept height.

## Aggregate

```rust,no_run
use lean_pq::{aggregate, sphincs, xmss, Aggregate};

let message = [0x42; 32];
let xmss_key = xmss::SecretKey::from_seed([0x01; 32]);
let sphincs_key = sphincs::SecretKey::from_seed([0x02; 32], 4)?;

let leaf = aggregate(
    &[],
    &[(xmss_key.public_key(), message, xmss_key.sign(&message, 7)?)],
    &[(sphincs_key.public_key(), message, sphincs_key.sign(&message)?)],
)?;
let root = aggregate(&[&leaf], &[], &[])?;

let received = Aggregate::from_bytes(&root.to_bytes())?;
assert_eq!(received.xmss_claims(), [(xmss_key.public_key(), message)]);
assert_eq!(received.sphincs_claims(), [(sphincs_key.public_key(), message)]);
# Ok::<(), lean_pq::Error>(())
```

- Aggregation verifies every raw signature before proving, and runs one proof at a time per process.
- Decoding verifies the proof, so every aggregate value is proven.
- An aggregate attests the claims it lists, not the ones you wanted: compare them.
- The first proof builds the aggregation guest; call `setup()` to pay that earlier.

## License

MIT OR Apache-2.0

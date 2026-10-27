# lean-pq

Safe Rust bindings for [leanVM](https://github.com/leanEthereum/leanVM)'s post-quantum
signatures and their zkVM-backed aggregation:

- **leanXMSS**: stateful. A key signs at `2^32` leaf indices; never sign two different
  messages at the same leaf index.
- **leanSPHINCS**: stateless. A key keeps one subtree of height `kept_height` (at most 26),
  which trades signing capacity for key generation time.

Both schemes use 32-byte public keys and sign 32-byte messages. An `Aggregate` proves that
each listed public key signed its message, across both schemes, and can absorb earlier
aggregates recursively. The proving parameters stay inside this crate.

## Install

<!-- x-release-please-start-version -->
```toml
[dependencies]
lean-pq = { git = "https://github.com/ethereum/lean-pq-bindings.git", tag = "v0.7.0" }
```
<!-- x-release-please-end -->

The crate is not published to crates.io: it depends on leanVM by git revision.

## Sign and verify

```rust
use lean_pq::{sphincs, xmss};

let message = [0x42; 32];

let xmss_key = xmss::SecretKey::from_seed([0x01; 32]);
let signature = xmss_key.sign(&message, 7)?;
xmss::verify(&xmss_key.public_key(), &message, &signature)?;

let sphincs_key = sphincs::SecretKey::from_seed([0x02; 32], 4)?;
let signature = sphincs_key.sign(&message)?;
sphincs::verify(&sphincs_key.public_key(), &message, &signature)?;
# Ok::<(), lean_pq::Error>(())
```

leanXMSS keys are stateful: persist your own durable high-water leaf index alongside
`SecretKey::to_bytes()` and advance it before publishing a signature. Secret key bytes are
secret material: the leanXMSS seed, or the leanSPHINCS seed followed by its kept height.

## Aggregation

`aggregate` verifies every raw signature before proving, and runs one proof at a time per
process. `Aggregate::from_bytes` verifies the proof it decodes, so every `Aggregate` value is
proven. An aggregate attests the claims it lists, not the claims you wanted: compare
`xmss_claims()` and `sphincs_claims()` against what you expect. `setup()` moves the one-time
guest build ahead of the first proof; calling it is optional and idempotent.

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

Build in release mode: debug builds of leanVM prove roughly 30x slower.

## License

MIT OR Apache-2.0

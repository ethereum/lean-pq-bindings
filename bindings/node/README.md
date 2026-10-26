# lean-pq Node.js bindings

Node.js bindings for [leanVM](https://github.com/leanEthereum/leanVM)'s post-quantum signatures,
leanXMSS and leanSPHINCS, and their recursive aggregation. Implemented with Rust and `napi-rs`
over the safe `lean-pq` Rust crate; they do not use the repository's C bridge.

- **leanXMSS** is stateful: a key signs at `2^32` leaf indices; never sign two different messages
  at the same leaf index.
- **leanSPHINCS** is stateless: a key keeps one subtree of height `keptHeight` (at most 26),
  trading signing capacity for key generation time.

Public keys and messages are 32-byte `Buffer`s; signatures are `Buffer`s of 2404 (leanXMSS) or
4276 (leanSPHINCS) bytes. Key generation, preparation, signing, setup, aggregation, and aggregate
decoding return Promises so their native work does not block the JavaScript event loop.

## Sign and verify

```js
const lpq = require('@ethereum/lean-pq')

const message = Buffer.alloc(32, 0x42)

const xmssKey = await lpq.XmssSecretKey.fromSeed(Buffer.alloc(32, 1))
const xmssSignature = await xmssKey.sign(message, 7)
lpq.xmssVerify(xmssKey.publicKey, message, xmssSignature) // throws if invalid

const sphincsKey = await lpq.SphincsSecretKey.fromSeed(Buffer.alloc(32, 2), 4)
const sphincsSignature = await sphincsKey.sign(message)
lpq.sphincsVerify(sphincsKey.publicKey, message, sphincsSignature)
```

Persist your own durable high-water leaf index alongside a leanXMSS key's `toBytes()` and advance
it before publishing a signature. `toBytes()` is secret material: the leanXMSS seed, or the
leanSPHINCS seed followed by its kept height. `XmssSecretKey.prepare(leafIndex)` builds the bottom
tree a leaf index falls in ahead of signing there.

## Aggregation

`aggregate` verifies every raw signature before proving and runs one proof at a time per process.
`Aggregate.fromBytes` verifies the proof it decodes, so every `Aggregate` is proven. An aggregate
attests the claims it lists, not the claims you wanted: compare `xmssClaims` and `sphincsClaims`
against what you expect. `setup()` moves the one-time guest build ahead of the first proof;
calling it is optional and idempotent.

```js
const leaf = await lpq.aggregate({
  xmss: [{ publicKey: xmssKey.publicKey, message, signature: xmssSignature }],
  sphincs: [{ publicKey: sphincsKey.publicKey, message, signature: sphincsSignature }],
})
const root = await lpq.aggregate({ children: [leaf] })

const received = await lpq.Aggregate.fromBytes(root.toBytes())
received.xmssClaims // [{ publicKey: xmssKey.publicKey, message }]
received.sphincsClaims // [{ publicKey: sphincsKey.publicKey, message }]
```

One aggregation takes seconds and about 1.6 GB of memory.

## Development

Install Node.js 18.17 or later and Rust, then run:

```sh
cd bindings/node
npm ci
npm run build
npm test
```

`npm run build` compiles in release mode; debug builds of leanVM prove roughly 30x slower.

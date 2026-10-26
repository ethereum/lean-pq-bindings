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

## Install

```sh
npm install @ethereum/lean-pq
```

npm installs a prebuilt binary through a per-platform optional dependency, so installing needs
no Rust toolchain. Prebuilt binaries cover Node.js 18.17 or later on:

| Platform                 | Package                              |
| ------------------------ | ------------------------------------ |
| Linux x64, glibc 2.17+   | `@ethereum/lean-pq-linux-x64-gnu`    |
| Linux arm64, glibc 2.17+ | `@ethereum/lean-pq-linux-arm64-gnu`  |
| Linux x64, musl          | `@ethereum/lean-pq-linux-x64-musl`   |
| Linux arm64, musl        | `@ethereum/lean-pq-linux-arm64-musl` |
| macOS x64                | `@ethereum/lean-pq-darwin-x64`       |
| macOS arm64              | `@ethereum/lean-pq-darwin-arm64`     |

The x64 binaries require a CPU with AVX2 and PCLMULQDQ. Installing with `--omit=optional` or
`--no-optional` skips the binary and leaves the package unable to load.

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

`npm/` holds the per-platform package manifests. `napi create-npm-dirs` generates them from
`package.json`'s `napi.targets`; rerun it and commit the result after changing the targets.

## Releasing

Each `vX.Y.Z` release tag publishes `@ethereum/lean-pq` and every platform package at version
`X.Y.Z` from `.github/workflows/release.yml`, independently of the PyPI publish:

1. `node-build` stamps the version and builds one addon per target.
2. `node-package` fills the platform packages, sets the root package's `optionalDependencies` with
   `napi pre-publish --skip-optional-publish`, and packs every tarball.
3. `node-test` installs the root and platform tarball on each platform and signs, verifies and
   aggregates through them (`scripts/install-check.sh`).
4. `node-publish` publishes the platform packages, then the root package, with npm trusted
   publishing. npm adds provenance automatically. Versions already on npm are skipped, so a
   failed run can be re-dispatched on the same tag: `gh workflow run release.yml --ref vX.Y.Z`.

CI checks the packaging without publishing: it packs the root and Linux x64 packages, installs both
tarballs into a fresh project, and runs `scripts/smoke.js` against them. To run it locally after
`npm run build`:

```sh
pack=$(mktemp -d)
cp lean_pq_node.linux-x64-gnu.node npm/linux-x64-gnu/
npm pack --ignore-scripts --pack-destination "$pack"
npm pack --ignore-scripts --pack-destination "$pack" ./npm/linux-x64-gnu
sh scripts/install-check.sh "$pack/ethereum-lean-pq-0.0.0-dev.tgz" \
  "$pack/ethereum-lean-pq-linux-x64-gnu-0.0.0-dev.tgz" --aggregate
```

### One-time npm setup

npm can attach a trusted publisher only to a package that already exists, so trusted publishing
cannot make the first publish of a new package. A maintainer bootstraps each package once:

1. Make sure the `ethereum` npm organization exists, that you can publish to it, and that your
   account has two-factor authentication enabled.
2. Publish a `0.0.0` placeholder for all seven package names, so every real version is published
   from CI with provenance:

   ```sh
   for name in @ethereum/lean-pq @ethereum/lean-pq-linux-x64-gnu @ethereum/lean-pq-linux-arm64-gnu \
       @ethereum/lean-pq-linux-x64-musl @ethereum/lean-pq-linux-arm64-musl \
       @ethereum/lean-pq-darwin-x64 @ethereum/lean-pq-darwin-arm64; do
     dir=$(mktemp -d)
     printf '{"name":"%s","version":"0.0.0","description":"Placeholder for the first CI release of %s","license":"MIT","repository":{"type":"git","url":"git+https://github.com/ethereum/lean-pq-bindings.git","directory":"bindings/node"}}\n' \
       "$name" "$name" > "$dir/package.json"
     (cd "$dir" && npm publish --access public)
   done
   ```

3. Add a trusted publisher to each of the seven packages, on npmjs.com under the package's
   **Settings → Trusted publishing**, or with npm 11.15 or later:

   ```sh
   npm trust github <package> --repo ethereum/lean-pq-bindings --file release.yml --env npm --allow-publish --yes
   ```

   The fields are repository `ethereum/lean-pq-bindings`, workflow `release.yml`, environment
   `npm`, with `npm publish` allowed. A new trusted publisher expires unless it completes a publish
   within two days, so add them shortly before a release tag, or re-dispatch the latest tag
   afterwards.
4. After the first CI release, set each package's **Settings → Publishing access** to "Require
   two-factor authentication and disallow tokens", and deprecate the placeholders with
   `npm deprecate <package>@0.0.0 "placeholder"`.

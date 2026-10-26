# lean-pq-bindings

Language bindings for [leanVM](https://github.com/leanEthereum/leanVM)'s post-quantum signatures:
stateful **leanXMSS**, stateless **leanSPHINCS**, and zkVM-backed recursive aggregation of both into
one proof. Every binding wraps the safe Rust facade in [`bindings/rust`](bindings/rust/README.md),
which pins leanVM by git revision and keeps the proving parameters internal.

## Bindings

- [`bindings/python`](bindings/python/README.md) — the `py-lean-pq` package for Python.
- [`bindings/rust`](bindings/rust/README.md) — the `lean-pq` crate for Rust.
- [`bindings/java`](bindings/java/README.md) — Java 25 bindings for JVM applications such as Teku.
- [`bindings/go`](bindings/go/README.md) — Go bindings linked through cgo.
- [`bindings/node`](bindings/node/README.md) — Node.js bindings built with napi-rs.
- [`bindings/zig`](bindings/zig/README.md) — Zig bindings linked to the shared native archive.

## Install and integrate

The release workflow publishes the Python package to PyPI:

```sh
python -m pip install py-lean-pq
```

The release workflow also publishes the Node.js package to npm, with prebuilt binaries for Linux
x64/arm64 (glibc and musl) and macOS x64/arm64:

```sh
npm install @ethereum/lean-pq
```

Rust applications can consume the safe facade directly from this repository:

```toml
[dependencies]
lean-pq = { git = "https://github.com/ethereum/lean-pq-bindings.git" }
```

Zig projects fetch the package attached to each GitHub release, with native archives bundled for
Linux x86_64/aarch64 (glibc) and macOS:

```sh
zig fetch --save=lean_pq https://github.com/ethereum/lean-pq-bindings/releases/download/v<version>/lean-pq-zig-<version>.tar.gz
```

Java 25 applications depend on `io.github.crate-crypto:lean-pq` from Maven Central. The jar bundles
native libraries for Linux x86_64/aarch64 (glibc 2.17+) and macOS; run with
`--enable-native-access=org.ethereum.leanpq`:

```kotlin
implementation("io.github.crate-crypto:lean-pq:<version>")
```

Go is a source integration today. Clone the repository, then follow the binding-specific
instructions below; the bindings build against the repository's pinned leanVM API rather than
requiring applications to choose its Rust dependencies themselves.

```sh
git clone https://github.com/ethereum/lean-pq-bindings.git
cd lean-pq-bindings
```

| Binding | Upstream integration | Prerequisites |
| --- | --- | --- |
| [Java 25](bindings/java/README.md) | Depend on `io.github.crate-crypto:lean-pq` (see above), or run `gradle -p bindings/java test` for a local build. | JDK 25; Gradle 9.1+ and Rust for source builds |
| [Node.js](bindings/node/README.md) | Run `npm install @ethereum/lean-pq`, or `npm ci && npm run build` in `bindings/node` for a local build. | Node.js 18.17+; Rust for source builds |
| [Go](bindings/go/README.md) | Stage the target-specific Rust archive, then use the local Go module. | Go 1.24+, cgo, Zig, `cargo-zigbuild` |
| [Zig](bindings/zig/README.md) | Use the release package above, or stage the target-specific Rust archive and invoke `zig build … -Dnative-dir=…`. | Zig 0.16+; `cargo-zigbuild` for source builds |

Go and Zig source builds need a static archive matching the application target. For a Linux x86_64 source build:

```sh
rustup target add x86_64-unknown-linux-gnu
cargo install cargo-zigbuild --locked
sh bindings/native/scripts/stage-static.sh x86_64-unknown-linux-gnu /tmp/lean-pq-native
```

Pass that directory as `-Dnative-dir=/tmp/lean-pq-native` for Zig. Go stages the same archive
under its package's `internal/native/linux_amd64` directory; its README gives the exact platform
layouts. Release packaging for Go archives is not available yet.

Each binding uses a language-native wrapper around the Rust implementation. The internal
[`bindings/native`](bindings/native/README.md) crate supplies a private C-shaped Rust ABI for
managed wrappers: Java consumes it through the finalized Foreign Function & Memory API, while Go
and Zig link its static archive. It is not a separate, supported C binding; future bindings can use
whichever wrapper best fits their language ecosystem.

## License

MIT OR Apache-2.0

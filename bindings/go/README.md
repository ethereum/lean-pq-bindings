# lean-pq Go bindings

Go bindings for leanXMSS and leanSPHINCS signatures and their recursive aggregation from
[leanVM](https://github.com/leanEthereum/leanVM), backed by a native Rust static archive linked into
the final program through cgo. The Go API uses normal Go values and `Close` methods; it does not
expose C pointers or the internal bridge ABI.

## Requirements

- Go 1.24 or newer with cgo enabled
- A C linker for the target platform
- [Zig](https://ziglang.org/) and [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild)
  when producing a native archive from source

The Go package expects a target-matched `liblean_pq_native.a` in its internal native-asset
directory. Go build tags select that archive and link it into the final Go binary. The release
distribution mechanism for those archives is intentionally separate from the build layout described
here.

## Source build and test

From the repository root, install the cross-build toolchain and stage the local Linux amd64 archive
in the layout used by the Go package:

```sh
rustup target add x86_64-unknown-linux-gnu
cargo install cargo-zigbuild --locked
sh bindings/native/scripts/stage-static.sh x86_64-unknown-linux-gnu bindings/go/internal/native/linux_amd64
cd bindings/go
go test ./...
```

The aggregation test proves recursively: expect seconds per proof and about 1.6 GB of memory.

The release build stages these target/archive pairs:

| Rust target | Go native-asset directory |
| --- | --- |
| `x86_64-unknown-linux-gnu` | `linux_amd64` |
| `aarch64-unknown-linux-gnu` | `linux_arm64` |
| `universal2-apple-darwin` | `darwin_universal` |

The universal macOS build requires both `x86_64-apple-darwin` and
`aarch64-apple-darwin` Rust targets and runs on macOS so `cargo-zigbuild` can use the installed SDK.

## Example

```go
package main

import (
    "log"

    leanpq "github.com/ethereum/lean-pq-bindings/bindings/go"
)

func main() {
    message := [32]byte{0x42}

    xmssKey, err := leanpq.XmssSecretKeyFromSeed([32]byte{0x01})
    if err != nil {
        log.Fatal(err)
    }
    defer xmssKey.Close()
    xmssPublicKey, err := xmssKey.PublicKey()
    if err != nil {
        log.Fatal(err)
    }
    xmssSignature, err := xmssKey.Sign(message, 7)
    if err != nil {
        log.Fatal(err)
    }
    if err := leanpq.XmssVerify(xmssPublicKey, message, xmssSignature); err != nil {
        log.Fatal(err)
    }

    sphincsKey, err := leanpq.SphincsSecretKeyFromSeed([32]byte{0x02}, 4)
    if err != nil {
        log.Fatal(err)
    }
    defer sphincsKey.Close()
    sphincsPublicKey, err := sphincsKey.PublicKey()
    if err != nil {
        log.Fatal(err)
    }
    sphincsSignature, err := sphincsKey.Sign(message)
    if err != nil {
        log.Fatal(err)
    }

    leaf, err := leanpq.AggregateSignatures(
        nil,
        []leanpq.XmssSignedMessage{{PublicKey: xmssPublicKey, Message: message, Signature: xmssSignature}},
        []leanpq.SphincsSignedMessage{{PublicKey: sphincsPublicKey, Message: message, Signature: sphincsSignature}},
    )
    if err != nil {
        log.Fatal(err)
    }
    defer leaf.Close()
    root, err := leanpq.AggregateSignatures([]*leanpq.Aggregate{leaf}, nil, nil)
    if err != nil {
        log.Fatal(err)
    }
    defer root.Close()

    encoded, err := root.Bytes()
    if err != nil {
        log.Fatal(err)
    }
    received, err := leanpq.AggregateFromBytes(encoded) // decodes and verifies
    if err != nil {
        log.Fatal(err)
    }
    defer received.Close()
    claims, err := received.XmssClaims()
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("leanXMSS claims: %x", claims)
}
```

leanXMSS keys are stateful: persist your own durable high-water leaf index alongside
`XmssSecretKey.Bytes()` and never sign two different messages at the same leaf index. leanSPHINCS
keys are stateless; `keptHeight` (at most 26) trades signing capacity for key generation time.

An aggregate attests the claims it lists, not the claims you wanted: compare `XmssClaims()` and
`SphincsClaims()` against what you expect. `AggregateSignatures` verifies every raw signature before
proving, and `AggregateFromBytes` verifies the proof it decodes, so every `Aggregate` is proven.
`Setup` moves the one-time setup ahead of the first proof; calling it is optional.

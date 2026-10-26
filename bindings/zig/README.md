# lean-pq Zig bindings

Safe Zig bindings for [leanVM](https://github.com/leanEthereum/leanVM)'s post-quantum signatures
and their zkVM-backed recursive aggregation:

- **leanXMSS**: stateful. A key signs at `2^32` leaf indices; never sign two different messages
  at the same leaf index.
- **leanSPHINCS**: stateless. A key keeps one subtree of height `kept_height` (at most 26), which
  trades signing capacity for key generation time.

Public keys and messages are `[32]u8`; signatures are `[2404]u8` (leanXMSS) and `[4276]u8`
(leanSPHINCS). `XmssSecretKey`, `SphincsSecretKey`, and `Aggregate` own native handles: call
`deinit` exactly once on each. Slices returned by `Aggregate.toBytes`, `xmssClaims`, and
`sphincsClaims` belong to the caller's allocator.

The binding links a target-matched static `liblean_pq_native.a` produced by the shared Rust
bridge. It supports Linux x86_64/aarch64 and universal macOS archives. The archive is an
implementation detail of this binding, not a public C API.

## Requirements

- Zig 0.16 or newer
- A target-matched `liblean_pq_native.a`

## Build from this repository

Install Zig 0.15.2 and `cargo-zigbuild` to stage the native archive; `cargo-zigbuild` currently
requires this version for cross-target Apple builds. Then use Zig 0.16 or newer to build and test
the binding. On Linux x86_64:

```sh
rustup target add x86_64-unknown-linux-gnu
cargo install cargo-zigbuild --locked
sh bindings/native/scripts/stage-static.sh x86_64-unknown-linux-gnu bindings/zig/.native
cd bindings/zig
zig build test -Dnative-dir=.native
```

For Linux aarch64, stage `aarch64-unknown-linux-gnu`; for macOS, stage
`universal2-apple-darwin` on macOS after adding both Apple Rust targets. The release process can
provide those same static archives instead of building them locally.

## Example

```zig
const std = @import("std");
const lpq = @import("lean_pq");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const message: lpq.Message = [_]u8{0x42} ** 32;

    var xmss_key = try lpq.XmssSecretKey.fromSeed([_]u8{0x01} ** 32);
    defer xmss_key.deinit();
    const xmss_signature = try xmss_key.sign(message, 7);
    try lpq.xmssVerify(try xmss_key.publicKey(), message, &xmss_signature);

    var sphincs_key = try lpq.SphincsSecretKey.fromSeed([_]u8{0x02} ** 32, 4);
    defer sphincs_key.deinit();
    const sphincs_signature = try sphincs_key.sign(message);
    try lpq.sphincsVerify(try sphincs_key.publicKey(), message, &sphincs_signature);

    var leaf = try lpq.Aggregate.create(&.{}, &.{.{
        .public_key = try xmss_key.publicKey(),
        .message = message,
        .signature = xmss_signature,
    }}, &.{.{
        .public_key = try sphincs_key.publicKey(),
        .message = message,
        .signature = sphincs_signature,
    }});
    defer leaf.deinit();
    var root = try lpq.Aggregate.create(&.{&leaf}, &.{}, &.{});
    defer root.deinit();

    const encoded = try root.toBytes(allocator);
    defer allocator.free(encoded);
    var received = try lpq.Aggregate.fromBytes(encoded);
    defer received.deinit();
    const claims = try received.xmssClaims(allocator);
    defer allocator.free(claims);
    std.debug.assert(claims.len == 1);
}
```

Verification failures return `error.InvalidSignature`; other native errors return
`error.NativeFailure` or `error.NativePanic`, and `lastError` copies the message.

leanXMSS keys are stateful: persist your own durable high-water leaf index alongside
`XmssSecretKey.toBytes()` and advance it before publishing a signature. Secret key bytes are secret
material: the leanXMSS seed, or the leanSPHINCS seed followed by its kept height.

`Aggregate.create` verifies every raw signature before proving and runs one proof at a time per
process; one aggregation takes seconds and about 1.6 GB of memory. `Aggregate.fromBytes` verifies
the proof it decodes, so every `Aggregate` value is proven. An aggregate attests the claims it
lists, not the claims you wanted: compare `xmssClaims` and `sphincsClaims` against what you expect.
`setup()` moves the one-time guest build ahead of the first proof; calling it is optional and
idempotent.

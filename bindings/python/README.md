# py-lean-pq

Python bindings for leanVM's post-quantum signatures, built on the safe Rust
facade `lean-pq`:

- **leanXMSS**: stateful hash-based signatures, `2^32` leaf indices per key.
- **leanSPHINCS**: stateless hash-based signatures.
- **Aggregation**: a recursive proof that every listed public key signed its
  message. Aggregates can be combined into larger aggregates.

Public keys and messages are 32 bytes. Signatures are plain fixed-length
`bytes` (2404 for leanXMSS, 4276 for leanSPHINCS). Errors raise
`LeanPqError`; a seed, message, public key, or signature of the wrong length
raises `ValueError`. Key generation, signing, verification, aggregation, and
aggregate decoding release the GIL.

Requires Python >= 3.11. Wheels are built for Linux (x86_64, aarch64; glibc +
musl) and macOS arm64.

## Install

```bash
pip install py-lean-pq
```

The same library is published for Node.js (`@kevaundray/lean-pq` on npm), Java
(`io.github.crate-crypto:lean-pq` on Maven Central), and Zig (a `zig fetch`
package on each GitHub release); see the
[repository README](https://github.com/ethereum/lean-pq-bindings#install-and-integrate).

## leanXMSS

```python
import py_lean_pq as lpq

key = lpq.XmssSecretKey.from_seed(b"\x01" * 32)  # or XmssSecretKey.generate()
message = b"\x42" * 32

key.prepare(5)  # optional: build the bottom tree for leaf 5 ahead of time
signature = key.sign(message, 5)
lpq.xmss_verify(key.public_key, message, signature)  # raises LeanPqError if invalid

restored = lpq.XmssSecretKey.from_bytes(key.to_bytes())
```

leanXMSS keys are stateful: never sign two different messages at the same leaf
index. Persist your own durable high-water leaf index alongside
`XmssSecretKey.to_bytes()` (the key's seed, secret material) and advance it
before publishing a signature.

## leanSPHINCS

A key keeps one subtree of height `kept_height` (at most 26), trading signing
capacity for key generation time.

```python
key = lpq.SphincsSecretKey.from_seed(b"\x02" * 32, 4)  # or SphincsSecretKey.generate(4)
signature = key.sign(message)
lpq.sphincs_verify(key.public_key, message, signature)

restored = lpq.SphincsSecretKey.from_bytes(key.to_bytes())
assert restored.kept_height == 4
```

## Aggregation

`aggregate` proves raw `(public_key, message, signature)` tuples of either
scheme together with up to 16 child aggregates. The result's claims are the
union of its inputs' claims. Raw signatures are verified before proving.

```python
xmss_key = lpq.XmssSecretKey.from_seed(b"\x05" * 32)
sphincs_key = lpq.SphincsSecretKey.from_seed(b"\x06" * 32, 4)
first, second = b"\x11" * 32, b"\x22" * 32

left = lpq.aggregate(xmss=[(xmss_key.public_key, first, xmss_key.sign(first, 0))])
right = lpq.aggregate(sphincs=[(sphincs_key.public_key, second, sphincs_key.sign(second))])
root = lpq.aggregate(
    children=[left, right],
    xmss=[(xmss_key.public_key, second, xmss_key.sign(second, 1))],
)

received = lpq.Aggregate.from_bytes(root.to_bytes())  # decodes and verifies
assert received.sphincs_claims == [(sphincs_key.public_key, second)]
```

Every `Aggregate` value has been proven or verified. It attests the claims it
lists, not the claims you wanted: compare `xmss_claims` and `sphincs_claims`
(sorted lists of `(public_key, message)`) against what you expect.

`aggregate` and `Aggregate.from_bytes` build the aggregation guest on first
use; call `setup()` to pay that cost earlier. It is safe to call repeatedly.
Proving is serialized process-wide and takes seconds and over a gigabyte of
memory.

## Development

```bash
uv run --extra dev maturin develop --release
uv run --extra dev pytest tests/ -v
uv run --extra dev python -m mypy.stubtest py_lean_pq --allowlist stubtest_allowlist.txt
```

Always build in release: debug builds of leanVM prove roughly 30x slower.

## License

MIT OR Apache-2.0

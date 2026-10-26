// Signs and verifies through an installed @kevaundray/lean-pq; `--aggregate` also proves and
// decodes one aggregate. scripts/install-check.sh runs it inside a fresh project.
const assert = require('node:assert/strict')
const path = require('node:path')

const lpq = require('@kevaundray/lean-pq')

async function main() {
  const installed = path.dirname(require.resolve('@kevaundray/lean-pq/package.json'))
  assert.ok(installed.startsWith(path.join(process.cwd(), 'node_modules')), installed)
  const { version } = require('@kevaundray/lean-pq/package.json')
  console.log(`@kevaundray/lean-pq ${version} from ${installed}`)

  const message = Buffer.alloc(32, 0x42)
  const other = Buffer.alloc(32, 0x43)

  const xmssKey = await lpq.XmssSecretKey.fromSeed(Buffer.alloc(32, 1))
  const xmssSignature = await xmssKey.sign(message, 7)
  lpq.xmssVerify(xmssKey.publicKey, message, xmssSignature)
  assert.throws(() => lpq.xmssVerify(xmssKey.publicKey, other, xmssSignature), /leanXMSS/)

  const sphincsKey = await lpq.SphincsSecretKey.fromSeed(Buffer.alloc(32, 2), 4)
  const sphincsSignature = await sphincsKey.sign(message)
  lpq.sphincsVerify(sphincsKey.publicKey, message, sphincsSignature)
  assert.throws(() => lpq.sphincsVerify(sphincsKey.publicKey, other, sphincsSignature), /leanSPHINCS/)
  console.log('sign/verify ok')

  if (process.argv.includes('--aggregate')) {
    const aggregate = await lpq.aggregate({
      xmss: [{ publicKey: xmssKey.publicKey, message, signature: xmssSignature }],
      sphincs: [{ publicKey: sphincsKey.publicKey, message, signature: sphincsSignature }],
    })
    const received = await lpq.Aggregate.fromBytes(aggregate.toBytes())
    assert.deepEqual(received.xmssClaims, [{ publicKey: xmssKey.publicKey, message }])
    assert.deepEqual(received.sphincsClaims, [{ publicKey: sphincsKey.publicKey, message }])
    console.log('aggregate ok')
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})

const assert = require('node:assert/strict')
const test = require('node:test')

const lpq = require('..')

const seed = (byte) => Buffer.alloc(32, byte)

test('signs and verifies with both schemes', async () => {
  const message = Buffer.alloc(32, 0x42)
  const other = Buffer.alloc(32, 0x43)

  const xmssKey = await lpq.XmssSecretKey.fromSeed(seed(1))
  const xmssSignature = await xmssKey.sign(message, 3)
  assert.equal(xmssSignature.length, 2404)
  lpq.xmssVerify(xmssKey.publicKey, message, xmssSignature)
  assert.throws(() => lpq.xmssVerify(xmssKey.publicKey, other, xmssSignature), /leanXMSS/)

  const sphincsKey = await lpq.SphincsSecretKey.fromSeed(seed(2), 4)
  const sphincsSignature = await sphincsKey.sign(message)
  assert.equal(sphincsSignature.length, 4276)
  lpq.sphincsVerify(sphincsKey.publicKey, message, sphincsSignature)
  assert.throws(() => lpq.sphincsVerify(sphincsKey.publicKey, other, sphincsSignature), /leanSPHINCS/)
})

test('round trips secret keys through bytes', async () => {
  const message = Buffer.alloc(32, 7)

  const xmssKey = await lpq.XmssSecretKey.fromSeed(seed(3))
  const xmssRestored = await lpq.XmssSecretKey.fromBytes(xmssKey.toBytes())
  assert.deepEqual(xmssRestored.publicKey, xmssKey.publicKey)
  lpq.xmssVerify(xmssKey.publicKey, message, await xmssRestored.sign(message, 9))

  const sphincsKey = await lpq.SphincsSecretKey.fromSeed(seed(4), 3)
  const sphincsRestored = await lpq.SphincsSecretKey.fromBytes(sphincsKey.toBytes())
  assert.deepEqual(sphincsRestored.publicKey, sphincsKey.publicKey)
  assert.equal(sphincsRestored.keptHeight, 3)
  lpq.sphincsVerify(sphincsKey.publicKey, message, await sphincsRestored.sign(message))
})

test('aggregates both schemes recursively', async () => {
  const first = Buffer.alloc(32, 0x11)
  const second = Buffer.alloc(32, 0x22)
  const xmssKey = await lpq.XmssSecretKey.fromSeed(seed(5))
  const sphincsKey = await lpq.SphincsSecretKey.fromSeed(seed(6), 4)

  const left = await lpq.aggregate({
    xmss: [{ publicKey: xmssKey.publicKey, message: first, signature: await xmssKey.sign(first, 0) }],
  })
  const right = await lpq.aggregate({
    sphincs: [{ publicKey: sphincsKey.publicKey, message: first, signature: await sphincsKey.sign(first) }],
  })
  const root = await lpq.aggregate({
    children: [left, right],
    xmss: [{ publicKey: xmssKey.publicKey, message: second, signature: await xmssKey.sign(second, 1) }],
  })

  const received = await lpq.Aggregate.fromBytes(root.toBytes())
  assert.deepEqual(received.xmssClaims, [
    { publicKey: xmssKey.publicKey, message: first },
    { publicKey: xmssKey.publicKey, message: second },
  ])
  assert.deepEqual(received.sphincsClaims, [{ publicKey: sphincsKey.publicKey, message: first }])

  const tampered = root.toBytes()
  tampered[tampered.length - 1] ^= 1
  await assert.rejects(lpq.Aggregate.fromBytes(tampered), /invalid aggregate/)
})

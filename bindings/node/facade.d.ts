/** A `(publicKey, message)` pair an aggregate attests. Both are 32 bytes. */
export interface Claim {
  publicKey: Buffer
  message: Buffer
}

/** A raw signature to aggregate: a 32-byte public key, a 32-byte message, and its signature. */
export interface SignedMessage {
  publicKey: Buffer
  message: Buffer
  signature: Buffer
}

/** Builds the aggregation guest ahead of the first proof. Optional and idempotent. */
export declare function setup(): Promise<void>

/**
 * A stateful leanXMSS secret key with `2^32` leaf indices. Never sign two different messages at
 * the same leaf index.
 */
export declare class XmssSecretKey {
  private constructor()
  static generate(): Promise<XmssSecretKey>
  static fromSeed(seed: Buffer): Promise<XmssSecretKey>
  static fromBytes(data: Buffer): Promise<XmssSecretKey>
  /** SECRET KEY MATERIAL: the 32-byte seed. */
  toBytes(): Buffer
  get publicKey(): Buffer
  /** Builds the bottom tree `leafIndex` falls in ahead of signing there. */
  prepare(leafIndex: number): Promise<void>
  /** Resolves to a 2404-byte signature. */
  sign(message: Buffer, leafIndex: number): Promise<Buffer>
}

/** Throws if `signature` is not a valid leanXMSS signature of `message` under `publicKey`. */
export declare function xmssVerify(publicKey: Buffer, message: Buffer, signature: Buffer): void

/** A stateless leanSPHINCS secret key keeping one subtree of height `keptHeight` (at most 26). */
export declare class SphincsSecretKey {
  private constructor()
  static generate(keptHeight: number): Promise<SphincsSecretKey>
  static fromSeed(seed: Buffer, keptHeight: number): Promise<SphincsSecretKey>
  static fromBytes(data: Buffer): Promise<SphincsSecretKey>
  /** SECRET KEY MATERIAL: the 32-byte seed, then the kept height. */
  toBytes(): Buffer
  get publicKey(): Buffer
  get keptHeight(): number
  /** Resolves to a 4276-byte signature. */
  sign(message: Buffer): Promise<Buffer>
}

/** Throws if `signature` is not a valid leanSPHINCS signature of `message` under `publicKey`. */
export declare function sphincsVerify(publicKey: Buffer, message: Buffer, signature: Buffer): void

/**
 * A recursive proof that each listed public key signed its message. Every instance has been
 * proven by `aggregate` or verified by `Aggregate.fromBytes`. It attests the claims it lists, not
 * the claims you wanted: compare `xmssClaims` and `sphincsClaims` against what you expect.
 */
export declare class Aggregate {
  private constructor()
  /** Decodes and verifies an aggregate. */
  static fromBytes(data: Buffer): Promise<Aggregate>
  toBytes(): Buffer
  /** Strictly sorted. */
  get xmssClaims(): Array<Claim>
  /** Strictly sorted. */
  get sphincsClaims(): Array<Claim>
}

/**
 * Proves every raw signature and every child's claims in one aggregate whose claims are their
 * union. Raw signatures are verified first; at most 16 children; empty input is rejected.
 */
export declare function aggregate(input?: {
  children?: Array<Aggregate>
  xmss?: Array<SignedMessage>
  sphincs?: Array<SignedMessage>
}): Promise<Aggregate>

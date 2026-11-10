/**
 * TensorCash PQ derivation, version 1 (docs/PQ_DERIVATION.md). Frozen by the vectors in
 * `__tests__/vectors/derivation-v1.json`; any change is a new version, never an edit of this one.
 *
 *   seed64   = BIP39(mnemonic, passphrase)                       (@scure/bip39, explicit passphrase)
 *   root     = HKDF-Extract(SHA256, salt = "TensorCash/PQ-root/v1", ikm = seed64)
 *   idSeed   = HKDF-Expand(SHA256, root, "TensorCash/PQ-identity/v1" || genesis32 || u32be(account), 32)
 *   policyId = TaggedHash("TensorCash/PQ-policy/v1", u8 protocolVersion || u8 scriptVersion || genesis32
 *              || nonce32 || u8 paramSet(0x41) || u8 k || u8 n || n × (u16be(len) || identityPk), sorted)
 *   spSeed   = HKDF-Expand(SHA256, root, "TensorCash/PQ-spend/v1" || genesis32 || u32be(account)
 *              || policyId32 || u8 branch || u32be(index), 32)
 *   key      = ML-DSA-65.KeyGen_internal(seed32)                  (FIPS 204 §6.1, @noble/post-quantum)
 *
 * `TaggedHash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)` (BIP340 form, as Core's TaggedHash).
 * Every field is fixed-width, big-endian where numeric; the only variable-length items (member
 * public keys) are length-prefixed. Labels, endpoints and configuration revisions never enter a key.
 *
 * ML-DSA is stateless: signing many messages with one spending key is not a security break. Fresh
 * per-index keys exist for address management and privacy, not for one-time use.
 *
 * Pure TypeScript, no Electron, DOM or filesystem.
 */
import { expand, extract } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { hex, utf8 } from '@scure/base';
import * as bip39 from '@scure/bip39';
import { wordlist as englishWordlist } from '@scure/bip39/wordlists/english.js';
import { mnemonicToSeed, normalizeMnemonic } from '../hd.js';
import type { Hex, NetworkParams, PqIdentity, PqParamSet, PqPolicyInputs } from '../types.js';

export class PqDerivationError extends Error {
  override readonly name = 'PqDerivationError';
}

/** Byte lengths of ML-DSA-65 (FIPS 204 Table 2) as `@noble/post-quantum` 0.7.1 reports them. */
export const MLDSA65_LENGTHS = Object.freeze({
  seed: 32,
  publicKey: 1952,
  secretKey: 4032,
  signature: 3309,
});

/** Version-1 constants. Strings are UTF-8 encoded exactly as written (no terminator, no length). */
export const PqDerivationV1 = Object.freeze({
  version: 1 as const,
  paramSet: 'ML-DSA-65' as PqParamSet,
  /** Core `pk_blob` algorithm byte for ML-DSA-65 (crypto/mldsaverify.h). */
  paramSetByte: 0x41,
  rootSalt: 'TensorCash/PQ-root/v1',
  identityInfo: 'TensorCash/PQ-identity/v1',
  policyTag: 'TensorCash/PQ-policy/v1',
  spendInfo: 'TensorCash/PQ-spend/v1',
  /** Branch values accepted by the spend domain. */
  branches: { receive: 0, change: 1 } as const,
  seedBytes: 64,
  rootBytes: 32,
  keySeedBytes: 32,
});

export type PqBranch = 0 | 1;

/** A derived ML-DSA-65 key pair with the 32-byte seed it came from. `wipePqKeyPair` zeroes it. */
export interface PqKeyPair {
  seed: Uint8Array;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

// ---------------------------------------------------------------------------
// Encoding helpers (exported so that verifiers and the vector test can reuse them)
// ---------------------------------------------------------------------------

export function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new PqDerivationError(`pq-derivation: u32 out of range: ${String(n)}`);
  const out = new Uint8Array(4);
  out[0] = (n >>> 24) & 0xff;
  out[1] = (n >>> 16) & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out[3] = n & 0xff;
  return out;
}

export function u16be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new PqDerivationError(`pq-derivation: u16 out of range: ${String(n)}`);
  return Uint8Array.of((n >>> 8) & 0xff, n & 0xff);
}

export function u8(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xff) throw new PqDerivationError(`pq-derivation: u8 out of range: ${String(n)}`);
  return Uint8Array.of(n);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** BIP340-style tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || payload)`. */
export function taggedHash(tag: string, payload: Uint8Array): Uint8Array {
  if (typeof tag !== 'string' || tag.length === 0) throw new PqDerivationError('pq-derivation: empty tag');
  const t = sha256(utf8.decode(tag));
  return sha256(concat(t, t, payload));
}

function bytesOf(value: Uint8Array | Hex, length: number, what: string): Uint8Array {
  let out: Uint8Array;
  if (typeof value === 'string') {
    if (!/^[0-9a-f]*$/.test(value) || value.length % 2 !== 0) throw new PqDerivationError(`pq-derivation: ${what} is not lowercase hex`);
    out = hex.decode(value);
  } else if (value instanceof Uint8Array) {
    out = Uint8Array.from(value);
  } else {
    throw new PqDerivationError(`pq-derivation: ${what} must be bytes or hex`);
  }
  if (out.length !== length) throw new PqDerivationError(`pq-derivation: ${what} must be ${length} bytes, got ${out.length}`);
  return out;
}

/** The 32 genesis bytes from a hex hash (Core display order), raw bytes or a NetworkParams. */
export function genesisBytes(genesis: Uint8Array | Hex | NetworkParams): Uint8Array {
  if (typeof genesis === 'object' && !(genesis instanceof Uint8Array)) {
    if (!genesis.genesisHash) throw new PqDerivationError(`pq-derivation: network ${genesis.name} has no genesisHash; PQ derivation needs one`);
    return bytesOf(genesis.genesisHash, 32, 'genesis hash');
  }
  return bytesOf(genesis, 32, 'genesis hash');
}

function checkAccount(account: number): void {
  if (!Number.isInteger(account) || account < 0 || account > 0xffffffff) throw new PqDerivationError(`pq-derivation: account must be a u32, got ${String(account)}`);
}

function checkBranch(branch: number): asserts branch is PqBranch {
  if (branch !== 0 && branch !== 1) throw new PqDerivationError(`pq-derivation: branch must be 0 (receive) or 1 (change), got ${String(branch)}`);
}

function checkIndex(index: number): void {
  if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) throw new PqDerivationError(`pq-derivation: index must be a u32, got ${String(index)}`);
}

function checkRoot(root: Uint8Array): void {
  if (!(root instanceof Uint8Array) || root.length !== PqDerivationV1.rootBytes) throw new PqDerivationError('pq-derivation: root must be 32 bytes');
}

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------

/** Root = HKDF-Extract(SHA256, salt "TensorCash/PQ-root/v1", ikm = 64-byte BIP39 seed). Caller wipes the result. */
export function pqRootFromSeed(seed: Uint8Array): Uint8Array {
  if (!(seed instanceof Uint8Array) || seed.length !== PqDerivationV1.seedBytes) throw new PqDerivationError(`pq-derivation: seed must be ${PqDerivationV1.seedBytes} bytes (BIP39)`);
  return extract(sha256, seed, utf8.decode(PqDerivationV1.rootSalt));
}

/** Root from a BIP39 mnemonic and an explicit passphrase (`''` when the user chose none; never implicit). */
export function pqRootFromMnemonic(mnemonic: string, passphrase = ''): Uint8Array {
  if (typeof passphrase !== 'string') throw new PqDerivationError('pq-derivation: passphrase must be a string');
  const seed = mnemonicToSeed(mnemonic, passphrase);
  try {
    return pqRootFromSeed(seed);
  } finally {
    seed.fill(0);
  }
}

/** BIP39 entropy (16, 20, 24, 28 or 32 bytes) to the English mnemonic. */
export function entropyToMnemonic(entropy: Uint8Array): string {
  if (!(entropy instanceof Uint8Array) || ![16, 20, 24, 28, 32].includes(entropy.length)) throw new PqDerivationError('pq-derivation: entropy must be 16, 20, 24, 28 or 32 bytes');
  return bip39.entropyToMnemonic(entropy, englishWordlist);
}

/** English mnemonic to its BIP39 entropy; throws on an invalid mnemonic. */
export function mnemonicToEntropy(mnemonic: string): Uint8Array {
  const m = normalizeMnemonic(mnemonic);
  if (!bip39.validateMnemonic(m, englishWordlist)) throw new PqDerivationError('pq-derivation: invalid mnemonic');
  return bip39.mnemonicToEntropy(m, englishWordlist);
}

/** Root from stored entropy (what the vault keeps) and an explicit passphrase. */
export function pqRootFromEntropy(entropy: Uint8Array, passphrase = ''): Uint8Array {
  return pqRootFromMnemonic(entropyToMnemonic(entropy), passphrase);
}

// ---------------------------------------------------------------------------
// Seeds
// ---------------------------------------------------------------------------

/** Info bytes of the identity seed: `"TensorCash/PQ-identity/v1" || genesis32 || u32be(account)`. */
export function identityInfoBytes(genesis: Uint8Array | Hex | NetworkParams, account: number): Uint8Array {
  checkAccount(account);
  return concat(utf8.decode(PqDerivationV1.identityInfo), genesisBytes(genesis), u32be(account));
}

/** 32-byte ML-DSA seed of the identity key. Caller wipes the result. */
export function identityKeySeed(root: Uint8Array, genesis: Uint8Array | Hex | NetworkParams, account: number): Uint8Array {
  checkRoot(root);
  return expand(sha256, root, identityInfoBytes(genesis, account), PqDerivationV1.keySeedBytes);
}

/**
 * Info bytes of a spending seed:
 * `"TensorCash/PQ-spend/v1" || genesis32 || u32be(account) || policyId32 || u8 branch || u32be(index)`.
 */
export function spendInfoBytes(genesis: Uint8Array | Hex | NetworkParams, account: number, policyId: Uint8Array | Hex, branch: PqBranch, index: number): Uint8Array {
  checkAccount(account);
  checkBranch(branch);
  checkIndex(index);
  return concat(
    utf8.decode(PqDerivationV1.spendInfo),
    genesisBytes(genesis),
    u32be(account),
    bytesOf(policyId, 32, 'policy id'),
    u8(branch),
    u32be(index),
  );
}

/** 32-byte ML-DSA seed of the spending key at `policyId`/`branch`/`index`. Caller wipes the result. */
export function spendingKeySeed(root: Uint8Array, genesis: Uint8Array | Hex | NetworkParams, account: number, policyId: Uint8Array | Hex, branch: PqBranch, index: number): Uint8Array {
  checkRoot(root);
  return expand(sha256, root, spendInfoBytes(genesis, account, policyId, branch, index), PqDerivationV1.keySeedBytes);
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/**
 * Seeded ML-DSA-65 key generation (FIPS 204 Algorithm 6, `ML-DSA.KeyGen_internal(ξ)` with the
 * 32-byte seed `ξ`). `@noble/post-quantum` 0.7.1: `keygen(seed?)` expands
 * `SHAKE256(ξ || k || ℓ)`; it validates the length and does not zero a caller-supplied seed.
 */
export function mlDsa65KeyPairFromSeed(seed: Uint8Array): PqKeyPair {
  if (!(seed instanceof Uint8Array) || seed.length !== MLDSA65_LENGTHS.seed) throw new PqDerivationError('pq-derivation: ML-DSA seed must be 32 bytes');
  const { publicKey, secretKey } = ml_dsa65.keygen(seed);
  if (publicKey.length !== MLDSA65_LENGTHS.publicKey || secretKey.length !== MLDSA65_LENGTHS.secretKey) {
    publicKey.fill(0);
    secretKey.fill(0);
    throw new PqDerivationError('pq-derivation: unexpected ML-DSA-65 key lengths');
  }
  return { seed, publicKey, secretKey };
}

export function wipePqKeyPair(kp: PqKeyPair): void {
  kp.seed.fill(0);
  kp.secretKey.fill(0);
}

/** Identity key pair for `genesis`/`account`. The caller wipes it (`wipePqKeyPair`). */
export function deriveIdentityKey(root: Uint8Array, genesis: Uint8Array | Hex | NetworkParams, account: number): PqKeyPair {
  return mlDsa65KeyPairFromSeed(identityKeySeed(root, genesis, account));
}

/** Spending key pair at `policyId`/`branch`/`index`. The caller wipes it (`wipePqKeyPair`). */
export function deriveSpendingKey(root: Uint8Array, genesis: Uint8Array | Hex | NetworkParams, account: number, policyId: Uint8Array | Hex, branch: PqBranch, index: number): PqKeyPair {
  return mlDsa65KeyPairFromSeed(spendingKeySeed(root, genesis, account, policyId, branch, index));
}

/** Public identity record (key + SHA256), secret material wiped before returning. */
export function deriveIdentity(root: Uint8Array, genesis: Uint8Array | Hex | NetworkParams, account: number): PqIdentity {
  const kp = deriveIdentityKey(root, genesis, account);
  try {
    return identityOfPublicKey(kp.publicKey);
  } finally {
    wipePqKeyPair(kp);
  }
}

export function identityOfPublicKey(publicKey: Uint8Array): PqIdentity {
  if (publicKey.length !== MLDSA65_LENGTHS.publicKey) throw new PqDerivationError('pq-derivation: identity public key must be 1952 bytes');
  return { publicKey: hex.encode(publicKey), publicKeyHash: hex.encode(sha256(publicKey)) };
}

// ---------------------------------------------------------------------------
// Policy id
// ---------------------------------------------------------------------------

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] as number) - (b[i] as number);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/**
 * Payload hashed by `derivePolicyId` (before the tag):
 * `u8 protocolVersion || u8 scriptVersion || genesis32 || nonce32 || u8 paramSet || u8 k || u8 n
 *  || for each member in byte-lexicographic order: u16be(len(pk)) || pk`.
 */
export function policyIdPayload(inputs: PqPolicyInputs): Uint8Array {
  if (inputs.paramSet !== PqDerivationV1.paramSet) throw new PqDerivationError(`pq-derivation: unsupported parameter set ${String(inputs.paramSet)}`);
  if (!Array.isArray(inputs.memberIdentityKeys)) throw new PqDerivationError('pq-derivation: memberIdentityKeys must be an array');
  const n = inputs.memberIdentityKeys.length;
  if (n < 1 || n > 255) throw new PqDerivationError(`pq-derivation: member count must be 1..255, got ${n}`);
  const k = inputs.threshold;
  if (!Number.isInteger(k) || k < 1 || k > n) throw new PqDerivationError(`pq-derivation: threshold must be 1..${n}, got ${String(k)}`);
  const members = inputs.memberIdentityKeys.map((m, i) => bytesOf(m, MLDSA65_LENGTHS.publicKey, `member identity key ${i}`));
  members.sort(compareBytes);
  for (let i = 1; i < members.length; i++) {
    if (compareBytes(members[i - 1] as Uint8Array, members[i] as Uint8Array) === 0) throw new PqDerivationError('pq-derivation: duplicate member identity key');
  }
  return concat(
    u8(inputs.protocolVersion),
    u8(inputs.scriptVersion),
    bytesOf(inputs.genesis, 32, 'genesis'),
    bytesOf(inputs.nonce, 32, 'nonce'),
    u8(PqDerivationV1.paramSetByte),
    u8(k),
    u8(n),
    ...members.map((pk) => concat(u16be(pk.length), pk)),
  );
}

/** Stable policy id: `TaggedHash("TensorCash/PQ-policy/v1", policyIdPayload)`, 32 bytes hex. */
export function derivePolicyId(inputs: PqPolicyInputs): Hex {
  return hex.encode(taggedHash(PqDerivationV1.policyTag, policyIdPayload(inputs)));
}

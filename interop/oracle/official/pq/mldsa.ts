/**
 * ML-DSA-65 (FIPS 204) primitives and the Core on-stack public-key encoding.
 *
 * - Signatures are pure ML-DSA with an empty context over the 32-byte Core digest: Core verifies with
 *   `OQS_SIG_verify(msg32)` (`src/crypto/mldsaverify.cpp`, `MLDSA_Verify`), i.e. the FIPS 204
 *   external interface, `ctx = ""`, no pre-hash. `@noble/post-quantum`'s top-level `sign`/`verify`
 *   is that interface; `internal.*` and `prehash(...)` would sign a different message.
 * - `pk_blob = 0x01 || 0x41 || compactsize(1952) || pk` exactly as `src/crypto/mldsaverify.h`
 *   (`ParsePublicKey`: exact alg id, known parameter set, minimal compactsize, exact length, no
 *   trailing bytes). The blob is what the leaf script pushes and what `OP_CHECKMLSIGVERIFY` parses.
 *
 * The compactsize helpers and the blob encoder/parser were copied from the web client's
 * `front-end/client/src/services/mldsaCrypto.ts` (pure functions, re-checked against Core) so the
 * treasury wallet does not depend on the browser application.
 *
 * Dependency pin: `@noble/post-quantum` 0.7.1 (exact, see packages/core/package.json).
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';

/** Algorithm id byte of the on-stack encoding (`mldsa::ALG_ID_MLDSA`). */
export const ALG_ID_MLDSA = 0x01;
/** Parameter-set bytes (`mldsa::ParamSet`). The wallet only ever produces ML-DSA-65. */
export const PARAM_SET_MLDSA_44 = 0x2c;
export const PARAM_SET_MLDSA_65 = 0x41;
export const PARAM_SET_MLDSA_87 = 0x57;

/** FIPS 204 sizes (`mldsa::GetParamSetSizes`). */
export const MLDSA_SIZES: Readonly<Record<number, { publicKey: number; signature: number }>> = Object.freeze({
  [PARAM_SET_MLDSA_44]: { publicKey: 1312, signature: 2420 },
  [PARAM_SET_MLDSA_65]: { publicKey: 1952, signature: 3309 },
  [PARAM_SET_MLDSA_87]: { publicKey: 2592, signature: 4627 },
});

export const MLDSA65_SEED_BYTES = 32;
export const MLDSA65_PUBLIC_KEY_BYTES = 1952;
export const MLDSA65_SECRET_KEY_BYTES = 4032;
export const MLDSA65_SIGNATURE_BYTES = 3309;
/** `1 + 1 + 3 (0xfd a0 07) + 1952`. */
export const MLDSA65_PK_BLOB_BYTES = 1957;
/** Signature as it sits on the witness stack: signature || hashtype byte. */
export const MLDSA65_WITNESS_SIG_BYTES = MLDSA65_SIGNATURE_BYTES + 1;

export interface Mldsa65Keypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

function assertLen(name: string, v: Uint8Array, len: number): void {
  if (!(v instanceof Uint8Array)) throw new Error(`${name}: expected bytes`);
  if (v.length !== len) throw new Error(`${name}: expected ${len} bytes, got ${v.length}`);
}

/** Deterministic ML-DSA-65 key generation from a 32-byte seed (FIPS 204 `ML-DSA.KeyGen_internal`). */
export function mldsa65Keygen(seed: Uint8Array): Mldsa65Keypair {
  assertLen('mldsa65Keygen seed', seed, MLDSA65_SEED_BYTES);
  const kp = ml_dsa65.keygen(seed);
  assertLen('mldsa65Keygen publicKey', kp.publicKey, MLDSA65_PUBLIC_KEY_BYTES);
  assertLen('mldsa65Keygen secretKey', kp.secretKey, MLDSA65_SECRET_KEY_BYTES);
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

/** The public key encoded in a secret key. */
export function mldsa65PublicKeyOf(secretKey: Uint8Array): Uint8Array {
  assertLen('mldsa65PublicKeyOf secretKey', secretKey, MLDSA65_SECRET_KEY_BYTES);
  const pk = ml_dsa65.getPublicKey(secretKey);
  assertLen('mldsa65PublicKeyOf publicKey', pk, MLDSA65_PUBLIC_KEY_BYTES);
  return pk;
}

export interface Mldsa65SignOptions {
  /**
   * `false`: deterministic signing (FIPS 204 `rnd = 0^32`, the ACVP "deterministic" vectors).
   * Bytes: caller-supplied 32-byte `rnd`. Omitted: hedged signing with fresh randomness (the
   * default; recommended by FIPS 204 and what the wallet uses).
   */
  extraEntropy?: Uint8Array | false;
}

/**
 * Sign a 32-byte Core digest. Returns the raw 3309-byte signature (no hashtype byte); the witness
 * builder appends the hashtype.
 */
export function mldsa65Sign(secretKey: Uint8Array, msg32: Uint8Array, opts: Mldsa65SignOptions = {}): Uint8Array {
  assertLen('mldsa65Sign secretKey', secretKey, MLDSA65_SECRET_KEY_BYTES);
  assertLen('mldsa65Sign message', msg32, 32);
  const signOpts: { extraEntropy?: Uint8Array | false } = {};
  if (opts.extraEntropy !== undefined) signOpts.extraEntropy = opts.extraEntropy;
  const sig = ml_dsa65.sign(msg32, secretKey, signOpts);
  assertLen('mldsa65Sign signature', sig, MLDSA65_SIGNATURE_BYTES);
  return sig;
}

/**
 * Verify a raw ML-DSA-65 signature over a 32-byte digest. Never throws on malformed input: wrong
 * lengths return `false`, as `mldsa::MLDSA_Verify` does.
 */
export function mldsa65Verify(publicKey: Uint8Array, msg32: Uint8Array, signature: Uint8Array): boolean {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== MLDSA65_PUBLIC_KEY_BYTES) return false;
  if (!(msg32 instanceof Uint8Array) || msg32.length !== 32) return false;
  if (!(signature instanceof Uint8Array) || signature.length !== MLDSA65_SIGNATURE_BYTES) return false;
  try {
    return ml_dsa65.verify(signature, msg32, publicKey);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// CompactSize (Bitcoin varint), minimal encoding enforced on read
// ---------------------------------------------------------------------------

export function writeCompactSize(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('compactSize: non-negative integer required');
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, (n >> 8) & 0xff);
  if (n <= 0xffffffff) return Uint8Array.of(0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
  throw new Error('compactSize: values above 32 bits are not supported');
}

/** Reads a minimal compactsize; returns undefined for truncated or non-minimal encodings. */
export function readCompactSize(buf: Uint8Array, offset: number): { value: number; bytesRead: number } | undefined {
  if (offset >= buf.length) return undefined;
  const first = buf[offset]!;
  if (first < 0xfd) return { value: first, bytesRead: 1 };
  if (first === 0xfd) {
    if (offset + 3 > buf.length) return undefined;
    const value = buf[offset + 1]! | (buf[offset + 2]! << 8);
    if (value < 0xfd) return undefined;
    return { value, bytesRead: 3 };
  }
  if (first === 0xfe) {
    if (offset + 5 > buf.length) return undefined;
    const value = (buf[offset + 1]! | (buf[offset + 2]! << 8) | (buf[offset + 3]! << 16) | (buf[offset + 4]! << 24)) >>> 0;
    if (value <= 0xffff) return undefined;
    return { value, bytesRead: 5 };
  }
  return undefined; // 0xff: 64-bit lengths never describe a public key
}

// ---------------------------------------------------------------------------
// On-stack public key blob
// ---------------------------------------------------------------------------

/** `0x01 || 0x41 || 0xfd 0xa0 0x07 || pk` for an ML-DSA-65 public key. */
export function encodePkBlob(publicKey: Uint8Array, paramSet: number = PARAM_SET_MLDSA_65): Uint8Array {
  const sizes = MLDSA_SIZES[paramSet];
  if (!sizes) throw new Error(`encodePkBlob: unknown parameter set 0x${paramSet.toString(16)}`);
  assertLen('encodePkBlob publicKey', publicKey, sizes.publicKey);
  const len = writeCompactSize(publicKey.length);
  const out = new Uint8Array(2 + len.length + publicKey.length);
  out[0] = ALG_ID_MLDSA;
  out[1] = paramSet;
  out.set(len, 2);
  out.set(publicKey, 2 + len.length);
  return out;
}

export interface ParsedPkBlob {
  paramSet: number;
  publicKey: Uint8Array;
}

/**
 * Strict inverse of `encodePkBlob`, mirroring `mldsa::ParsePublicKey`: exact algorithm id, a known
 * parameter set, a minimal compactsize equal to that set's key length and no trailing bytes.
 * Returns undefined on any deviation.
 */
export function parsePkBlob(blob: Uint8Array): ParsedPkBlob | undefined {
  if (!(blob instanceof Uint8Array) || blob.length < 3) return undefined;
  if (blob[0] !== ALG_ID_MLDSA) return undefined;
  const paramSet = blob[1]!;
  const sizes = MLDSA_SIZES[paramSet];
  if (!sizes) return undefined;
  const len = readCompactSize(blob, 2);
  if (!len) return undefined;
  if (len.value !== sizes.publicKey) return undefined;
  const start = 2 + len.bytesRead;
  if (blob.length - start !== len.value) return undefined;
  return { paramSet, publicKey: blob.subarray(start) };
}

/** `parsePkBlob` restricted to ML-DSA-65; throws with a reason otherwise. */
export function parseMldsa65PkBlob(blob: Uint8Array): Uint8Array {
  const parsed = parsePkBlob(blob);
  if (!parsed) throw new Error('pk blob: malformed (alg id, parameter set, length prefix or length)');
  if (parsed.paramSet !== PARAM_SET_MLDSA_65) throw new Error(`pk blob: parameter set 0x${parsed.paramSet.toString(16)} is not ML-DSA-65`);
  return parsed.publicKey;
}

/** Member identity used in PSBT keys and canonical ordering: sha256 of the full pk blob. */
export function pkBlobId(blob: Uint8Array): Uint8Array {
  parseMldsa65PkBlob(blob);
  return sha256(blob);
}

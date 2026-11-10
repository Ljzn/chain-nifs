/**
 * The PQ threshold leaf (plan §3.1): k-of-n over independent ML-DSA-65 keys, one
 * `OP_CHECKMLSIGVERIFY` per member, absent signers skipped by `OP_SIZE OP_0NOTEQUAL OP_IF`.
 *
 *   OP_0 OP_TOALTSTACK
 *   for each member i in canonical order (pk blobs sorted bytewise, no duplicates):
 *     OP_SIZE OP_0NOTEQUAL OP_IF
 *       <pk_blob_i> OP_CHECKMLSIGVERIFY
 *       OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK
 *     OP_ELSE
 *       OP_DROP
 *     OP_ENDIF
 *   OP_FROMALTSTACK <k> OP_GREATERTHANOREQUAL
 *
 * Stack discipline (Core `src/script/interpreter.cpp`): the slot of member 1 must be on top of the
 * initial stack, so the witness is `[slot_n, …, slot_2, slot_1, leaf, control]`. `OP_SIZE` pushes
 * the size and leaves the slot; `OP_0NOTEQUAL` turns it into `[]`/`[0x01]` (tapscript MINIMALIF
 * requires exactly those); `OP_CHECKMLSIGVERIFY` pops the pk blob (top) then the signature; an
 * empty slot is dropped by `OP_DROP`. Every non-empty slot is verified, so a wrong or
 * malformed signature fails the whole script. The witness count on the altstack ends on the main
 * stack as the only element: `count >= k`.
 *
 * Opcode bytes verified against `src/script/script.h`.
 */
import { compareBytes } from '../signer/utils.js';
import { MLDSA65_PK_BLOB_BYTES, parseMldsa65PkBlob } from './mldsa.js';

export const OP_0 = 0x00;
export const OP_PUSHDATA1 = 0x4c;
export const OP_PUSHDATA2 = 0x4d;
export const OP_1 = 0x51;
export const OP_16 = 0x60;
export const OP_IF = 0x63;
export const OP_ELSE = 0x67;
export const OP_ENDIF = 0x68;
export const OP_TOALTSTACK = 0x6b;
export const OP_FROMALTSTACK = 0x6c;
export const OP_DROP = 0x75;
export const OP_SIZE = 0x82;
export const OP_1ADD = 0x8b;
export const OP_0NOTEQUAL = 0x92;
export const OP_GREATERTHANOREQUAL = 0xa2;
export const OP_CHECKMLSIG = 0xbb;
export const OP_CHECKMLSIGVERIFY = 0xbc;

/** Leaf version of the single tapscript leaf (BIP342 `TAPROOT_LEAF_TAPSCRIPT`). */
export const PQ_LEAF_VERSION = 0xc0;

/** Relay policy, `src/policy/policy.h` (ML-DSA opcodes per leaf; PQ witness bytes per input; item/push cap). */
export const MAX_STANDARD_MLDSA_OPS_PER_INPUT = 8;
export const MAX_STANDARD_PQ_BYTES_PER_INPUT = 8192;
export const MAX_STANDARD_TAPSCRIPT_V2_STACK_ITEM_SIZE = 6144;
/** Witness items above this size count towards the PQ byte cap (`CountPQBytesInWitnessStack`). */
export const PQ_BYTE_COUNT_THRESHOLD = 65;
/** Bytes of one witness signature slot when filled: 3309 + hashtype. */
export const PQ_WITNESS_SIG_BYTES = 3310;

/** Minimal push of `data` as the script serialises it (`CScript << vector`). */
export function pushData(data: Uint8Array): Uint8Array {
  const len = data.length;
  let prefix: Uint8Array;
  if (len === 0) return Uint8Array.of(OP_0);
  if (len === 1 && data[0]! >= 1 && data[0]! <= 16) return Uint8Array.of(OP_1 + data[0]! - 1);
  if (len === 1 && data[0] === 0x81) return Uint8Array.of(0x4f);
  if (len <= 75) prefix = Uint8Array.of(len);
  else if (len <= 0xff) prefix = Uint8Array.of(OP_PUSHDATA1, len);
  else if (len <= 0xffff) prefix = Uint8Array.of(OP_PUSHDATA2, len & 0xff, (len >> 8) & 0xff);
  else throw new Error('pushData: too large');
  const out = new Uint8Array(prefix.length + len);
  out.set(prefix, 0);
  out.set(data, prefix.length);
  return out;
}

/** Minimal small-integer push: `OP_1`..`OP_16` (k is never 0). */
export function pushSmallInt(k: number): Uint8Array {
  if (!Number.isInteger(k) || k < 1 || k > 16) throw new Error(`pushSmallInt: ${k} out of 1..16`);
  return Uint8Array.of(OP_1 + k - 1);
}

export interface PqPolicyLimits {
  /** The leaf itself is buildable (k ≤ n, n ≤ 8 ML-DSA opcodes, no duplicates). */
  consensusOk: boolean;
  /** `k` filled slots fit the relay PQ byte cap. */
  relayOk: boolean;
  reasons: string[];
  /** PQ witness bytes counted by policy when exactly k slots are filled. */
  pqBytesAtK: number;
}

/** Whether a k-of-n leaf is buildable and whether its k-signature spend passes relay policy. */
export function checkPqPolicyLimits(k: number, n: number): PqPolicyLimits {
  const reasons: string[] = [];
  let consensusOk = true;
  if (!Number.isInteger(n) || n < 1) {
    reasons.push(`member count ${n} must be a positive integer`);
    consensusOk = false;
  }
  if (!Number.isInteger(k) || k < 1 || k > n) {
    reasons.push(`threshold ${k} out of 1..${n}`);
    consensusOk = false;
  }
  if (n > MAX_STANDARD_MLDSA_OPS_PER_INPUT) {
    reasons.push(`${n} members need ${n} ML-DSA opcodes; policy allows ${MAX_STANDARD_MLDSA_OPS_PER_INPUT} per leaf`);
    consensusOk = false; // not buildable under the supported policy envelope
  }
  const pqBytesAtK = Number.isInteger(k) && k > 0 ? k * PQ_WITNESS_SIG_BYTES : 0;
  let relayOk = consensusOk;
  if (pqBytesAtK > MAX_STANDARD_PQ_BYTES_PER_INPUT) {
    reasons.push(`${k} signatures are ${pqBytesAtK} PQ witness bytes; policy allows ${MAX_STANDARD_PQ_BYTES_PER_INPUT} per input`);
    relayOk = false;
  }
  return { consensusOk, relayOk, reasons, pqBytesAtK };
}

/**
 * Canonical member order: ML-DSA-65 pk blobs sorted bytewise (`std::lexicographical_compare`
 * semantics, the same comparator the Schnorr `sortedmulti_a` leaf uses). Rejects malformed blobs
 * and duplicates. Returns copies.
 */
export function canonicalMembers(pkBlobs: readonly Uint8Array[]): Uint8Array[] {
  if (!Array.isArray(pkBlobs) || pkBlobs.length === 0) throw new Error('pq leaf: at least one member required');
  const copies = pkBlobs.map((b, i) => {
    try {
      parseMldsa65PkBlob(b);
    } catch (e) {
      throw new Error(`pq leaf: member ${i}: ${(e as Error).message}`);
    }
    return Uint8Array.from(b);
  });
  copies.sort(compareBytes);
  for (let i = 1; i < copies.length; i++) {
    if (compareBytes(copies[i - 1]!, copies[i]!) === 0) throw new Error('pq leaf: duplicate member key');
  }
  return copies;
}

export interface PqLeaf {
  threshold: number;
  /** Canonical (sorted) pk blobs; slot i of the witness belongs to members[i]. */
  members: Uint8Array[];
  script: Uint8Array;
}

/** Build the threshold leaf for `threshold` of the given members (sorted here; input order is irrelevant). */
export function buildThresholdLeaf(threshold: number, pkBlobs: readonly Uint8Array[]): PqLeaf {
  const members = canonicalMembers(pkBlobs);
  const limits = checkPqPolicyLimits(threshold, members.length);
  if (!limits.consensusOk) throw new Error(`pq leaf: ${limits.reasons.join('; ')}`);
  const parts: Uint8Array[] = [Uint8Array.of(OP_0, OP_TOALTSTACK)];
  for (const blob of members) {
    parts.push(Uint8Array.of(OP_SIZE, OP_0NOTEQUAL, OP_IF));
    parts.push(pushData(blob));
    parts.push(Uint8Array.of(OP_CHECKMLSIGVERIFY, OP_FROMALTSTACK, OP_1ADD, OP_TOALTSTACK, OP_ELSE, OP_DROP, OP_ENDIF));
  }
  parts.push(Uint8Array.of(OP_FROMALTSTACK));
  parts.push(pushSmallInt(threshold));
  parts.push(Uint8Array.of(OP_GREATERTHANOREQUAL));
  const total = parts.reduce((a, p) => a + p.length, 0);
  const script = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    script.set(p, off);
    off += p.length;
  }
  return { threshold, members, script };
}

/** Exact serialised size of the leaf for n members (used by the fee model). */
export function thresholdLeafSize(n: number): number {
  const memberBlock = 3 + (3 + MLDSA65_PK_BLOB_BYTES) + 7;
  return 2 + n * memberBlock + 3;
}

/**
 * Strict parser: accepts only scripts `buildThresholdLeaf` produces (same bytes, canonical order,
 * no duplicates). Returns undefined for anything else, including a reordered or extended script,
 * so a reviewer can tell "the leaf we sign" from "a leaf that merely contains our keys".
 */
export function parseThresholdLeaf(script: Uint8Array): PqLeaf | undefined {
  if (!(script instanceof Uint8Array)) return undefined;
  let pos = 0;
  const need = (...bytes: number[]): boolean => {
    for (const b of bytes) {
      if (script[pos] !== b) return false;
      pos++;
    }
    return true;
  };
  if (!need(OP_0, OP_TOALTSTACK)) return undefined;
  const members: Uint8Array[] = [];
  while (script[pos] === OP_SIZE) {
    if (!need(OP_SIZE, OP_0NOTEQUAL, OP_IF)) return undefined;
    // pk blob push: always OP_PUSHDATA2 for 1957 bytes
    if (!need(OP_PUSHDATA2, MLDSA65_PK_BLOB_BYTES & 0xff, (MLDSA65_PK_BLOB_BYTES >> 8) & 0xff)) return undefined;
    const blob = script.slice(pos, pos + MLDSA65_PK_BLOB_BYTES);
    if (blob.length !== MLDSA65_PK_BLOB_BYTES) return undefined;
    pos += MLDSA65_PK_BLOB_BYTES;
    try {
      parseMldsa65PkBlob(blob);
    } catch {
      return undefined;
    }
    if (!need(OP_CHECKMLSIGVERIFY, OP_FROMALTSTACK, OP_1ADD, OP_TOALTSTACK, OP_ELSE, OP_DROP, OP_ENDIF)) return undefined;
    members.push(blob);
  }
  if (members.length === 0) return undefined;
  if (!need(OP_FROMALTSTACK)) return undefined;
  const kOp = script[pos++];
  if (kOp === undefined || kOp < OP_1 || kOp > OP_16) return undefined;
  const threshold = kOp - OP_1 + 1;
  if (!need(OP_GREATERTHANOREQUAL)) return undefined;
  if (pos !== script.length) return undefined;
  if (threshold > members.length) return undefined;
  for (let i = 1; i < members.length; i++) if (compareBytes(members[i - 1]!, members[i]!) >= 0) return undefined;
  if (members.length > MAX_STANDARD_MLDSA_OPS_PER_INPUT) return undefined;
  return { threshold, members, script: Uint8Array.from(script) };
}

/** Index of a member (by pk blob) in canonical order, or -1. */
export function memberIndexOf(members: readonly Uint8Array[], pkBlob: Uint8Array): number {
  return members.findIndex((m) => compareBytes(m, pkBlob) === 0);
}

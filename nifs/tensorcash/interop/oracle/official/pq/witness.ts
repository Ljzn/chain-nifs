/**
 * PSBT records and witness assembly for the PQ threshold policy (plan §3.3).
 *
 * Proprietary namespace (BIP174 key type 0xfc). The vendored PSBT coder keeps the bytes after the
 * 0xfc type byte as the map key, so a record key is:
 *
 *   compactsize(6) || "TSC-PQ" || compactsize(subtype) || keydata
 *
 *   subtype 0x01  PQ_POLICY      keydata = tapleaf hash (32)
 *                                value   = 0x01 (record version) || k (1) || n (1)
 *                                          || compactsize(len) || leaf script || control block (33)
 *   subtype 0x02  PQ_PARTIAL_SIG keydata = sha256(member pk blob) (32) || tapleaf hash (32)
 *                                value   = 0x01 (record version) || hashtype (1) || signature (3309)
 *
 * Partial signatures are keyed by the member's full public-key identity and the leaf they sign, so
 * two members, or one member over two leaves, never collide, and the PSBT key-map merge refuses a
 * second record under the same key with a different value. The single-signature fields
 * 0x1d/0x1e/0x1f/0x20 of the vendored signer are untouched and never consulted for this policy.
 *
 * Witness (plan §3.1, proven against Core in packages/flows/src/interop/pq.interop.test.ts):
 *
 *   [ slot_n, …, slot_2, slot_1, leaf script, control block ]
 *
 * slot_i belongs to members[i-1] in canonical order; member 1's slot is last before the script
 * because the script examines the top of the stack first. A filled slot is `signature || 0x01`;
 * an empty slot is the empty vector. Finalisation fills exactly k slots: the first k members (in
 * canonical order) whose signatures verify.
 */
import { compareBytes, equalBytes, taprootTweakPubkey } from '../signer/utils.js';
import { PQ_INTERNAL_KEY, pqTapleafHash } from './address.js';
import { MLDSA65_SIGNATURE_BYTES, pkBlobId, readCompactSize, writeCompactSize } from './mldsa.js';
import { MAX_STANDARD_PQ_BYTES_PER_INPUT, PQ_BYTE_COUNT_THRESHOLD, parseThresholdLeaf, type PqLeaf } from './script.js';

export const PQ_PSBT_IDENTIFIER = new TextEncoder().encode('TSC-PQ');
export const PQ_PSBT_SUBTYPE_POLICY = 0x01;
export const PQ_PSBT_SUBTYPE_PARTIAL_SIG = 0x02;
export const PQ_PSBT_RECORD_VERSION = 0x01;
export const PQ_HASHTYPE = 0x01;
/** Largest record value accepted when parsing (policy record with an 8-member leaf is ~15.8 KB). */
export const PQ_PSBT_MAX_VALUE_BYTES = 16_384;

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function encodePqPsbtKey(subtype: number, keydata: Uint8Array): Uint8Array {
  return concat(writeCompactSize(PQ_PSBT_IDENTIFIER.length), PQ_PSBT_IDENTIFIER, writeCompactSize(subtype), keydata);
}

/** Undefined when the key is not in the TSC-PQ namespace (other proprietary records are left alone). */
export function decodePqPsbtKey(key: Uint8Array): { subtype: number; keydata: Uint8Array } | undefined {
  const idLen = readCompactSize(key, 0);
  if (!idLen || idLen.value !== PQ_PSBT_IDENTIFIER.length) return undefined;
  const idStart = idLen.bytesRead;
  const id = key.subarray(idStart, idStart + idLen.value);
  if (id.length !== PQ_PSBT_IDENTIFIER.length || !equalBytes(id, PQ_PSBT_IDENTIFIER)) return undefined;
  const sub = readCompactSize(key, idStart + idLen.value);
  if (!sub) return undefined;
  return { subtype: sub.value, keydata: key.subarray(idStart + idLen.value + sub.bytesRead) };
}

export interface PqPolicyRecord {
  threshold: number;
  members: Uint8Array[];
  leafScript: Uint8Array;
  leafHash: Uint8Array;
  controlBlock: Uint8Array;
}

export function encodePqPolicyRecord(rec: PqPolicyRecord): [Uint8Array, Uint8Array] {
  if (rec.leafHash.length !== 32) throw new Error('pq policy record: leaf hash must be 32 bytes');
  if (rec.controlBlock.length !== 33) throw new Error('pq policy record: control block must be 33 bytes (single leaf)');
  const leaf = parseThresholdLeaf(rec.leafScript);
  if (!leaf) throw new Error('pq policy record: leaf script is not a canonical threshold leaf');
  if (leaf.threshold !== rec.threshold || leaf.members.length !== rec.members.length) throw new Error('pq policy record: threshold/members do not match the leaf');
  for (let i = 0; i < leaf.members.length; i++) if (compareBytes(leaf.members[i]!, rec.members[i]!) !== 0) throw new Error('pq policy record: member order does not match the leaf');
  const value = concat(
    Uint8Array.of(PQ_PSBT_RECORD_VERSION, rec.threshold, rec.members.length),
    writeCompactSize(rec.leafScript.length),
    rec.leafScript,
    rec.controlBlock,
  );
  return [encodePqPsbtKey(PQ_PSBT_SUBTYPE_POLICY, rec.leafHash), value];
}

export function decodePqPolicyRecord(keydata: Uint8Array, value: Uint8Array): PqPolicyRecord {
  if (keydata.length !== 32) throw new Error('pq policy record: key must carry the 32-byte leaf hash');
  if (value.length > PQ_PSBT_MAX_VALUE_BYTES) throw new Error('pq policy record: oversized');
  if (value.length < 3 || value[0] !== PQ_PSBT_RECORD_VERSION) throw new Error('pq policy record: unknown record version');
  const threshold = value[1]!;
  const n = value[2]!;
  const len = readCompactSize(value, 3);
  if (!len) throw new Error('pq policy record: bad leaf length');
  const start = 3 + len.bytesRead;
  const leafScript = value.slice(start, start + len.value);
  if (leafScript.length !== len.value) throw new Error('pq policy record: truncated leaf');
  const controlBlock = value.slice(start + len.value);
  if (controlBlock.length !== 33) throw new Error('pq policy record: control block must be 33 bytes');
  if ((controlBlock[0]! & 0xfe) !== 0xc0) throw new Error('pq policy record: control block leaf version is not 0xc0');
  const leaf = parseThresholdLeaf(leafScript);
  if (!leaf) throw new Error('pq policy record: leaf script is not a canonical threshold leaf');
  if (leaf.threshold !== threshold || leaf.members.length !== n) throw new Error('pq policy record: header does not match the leaf');
  // The record must be self-consistent: the key's leaf hash is the tapleaf hash of the value's
  // script, and the control block is the single-leaf NUMS block with the parity of that leaf.
  // Otherwise a record could name the treasury leaf in its key while carrying a foreign script in
  // its value, and a digest over the foreign script would be signed under the treasury's name.
  const leafHash = pqTapleafHash(leaf.script);
  if (!equalBytes(leafHash, keydata)) throw new Error('pq policy record: key leaf hash does not match the leaf script');
  if (!equalBytes(controlBlock.subarray(1), PQ_INTERNAL_KEY)) throw new Error('pq policy record: control block internal key is not the NUMS key');
  const [, parity] = taprootTweakPubkey(PQ_INTERNAL_KEY, leafHash);
  if ((controlBlock[0]! & 1) !== (parity & 1)) throw new Error('pq policy record: control block parity does not match the leaf');
  return { threshold, members: leaf.members, leafScript: leaf.script, leafHash, controlBlock };
}

export interface PqPartialSigRecord {
  /** sha256 of the member's pk blob. */
  memberId: Uint8Array;
  leafHash: Uint8Array;
  hashType: number;
  /** Raw 3309-byte signature (no hashtype byte). */
  signature: Uint8Array;
}

export function encodePqPartialSigRecord(rec: PqPartialSigRecord): [Uint8Array, Uint8Array] {
  if (rec.memberId.length !== 32 || rec.leafHash.length !== 32) throw new Error('pq partial signature: member id and leaf hash must be 32 bytes');
  if (rec.signature.length !== MLDSA65_SIGNATURE_BYTES) throw new Error(`pq partial signature: signature must be ${MLDSA65_SIGNATURE_BYTES} bytes`);
  if (rec.hashType !== PQ_HASHTYPE) throw new Error('pq partial signature: only SIGHASH_ALL (0x01) is allowed');
  return [encodePqPsbtKey(PQ_PSBT_SUBTYPE_PARTIAL_SIG, concat(rec.memberId, rec.leafHash)), concat(Uint8Array.of(PQ_PSBT_RECORD_VERSION, rec.hashType), rec.signature)];
}

export function decodePqPartialSigRecord(keydata: Uint8Array, value: Uint8Array): PqPartialSigRecord {
  if (keydata.length !== 64) throw new Error('pq partial signature: key must be member id || leaf hash (64 bytes)');
  if (value.length !== 2 + MLDSA65_SIGNATURE_BYTES) throw new Error(`pq partial signature: value must be ${2 + MLDSA65_SIGNATURE_BYTES} bytes`);
  if (value[0] !== PQ_PSBT_RECORD_VERSION) throw new Error('pq partial signature: unknown record version');
  const hashType = value[1]!;
  if (hashType !== PQ_HASHTYPE) throw new Error(`pq partial signature: hash type 0x${hashType.toString(16)} is not SIGHASH_ALL`);
  return { memberId: keydata.slice(0, 32), leafHash: keydata.slice(32), hashType, signature: value.slice(2) };
}

/** True when any proprietary entry is in the TSC-PQ namespace (parsed or not). */
export function hasPqRecords(proprietary: ReadonlyArray<[Uint8Array, Uint8Array]> | undefined): boolean {
  return (proprietary ?? []).some(([key]) => decodePqPsbtKey(key) !== undefined);
}

/** The PQ records among a PSBT input's proprietary entries. Non-PQ entries are ignored; malformed PQ entries throw. */
export function readPqRecords(proprietary: ReadonlyArray<[Uint8Array, Uint8Array]> | undefined): { policies: PqPolicyRecord[]; partialSigs: PqPartialSigRecord[] } {
  const policies: PqPolicyRecord[] = [];
  const partialSigs: PqPartialSigRecord[] = [];
  for (const [key, value] of proprietary ?? []) {
    const k = decodePqPsbtKey(key);
    if (!k) continue;
    if (k.subtype === PQ_PSBT_SUBTYPE_POLICY) policies.push(decodePqPolicyRecord(k.keydata, value));
    else if (k.subtype === PQ_PSBT_SUBTYPE_PARTIAL_SIG) partialSigs.push(decodePqPartialSigRecord(k.keydata, value));
    else throw new Error(`pq psbt: unknown TSC-PQ subtype ${k.subtype}`);
  }
  return { policies, partialSigs };
}

export function memberIds(leaf: PqLeaf): Uint8Array[] {
  return leaf.members.map(pkBlobId);
}

/**
 * Assemble the witness: `slots` has one entry per member in canonical order (raw signature or
 * undefined). Exactly `threshold` slots must be filled; the caller selects them.
 */
export function buildPqWitness(leaf: PqLeaf, slots: ReadonlyArray<Uint8Array | undefined>, controlBlock: Uint8Array, hashType: number = PQ_HASHTYPE): Uint8Array[] {
  if (slots.length !== leaf.members.length) throw new Error('pq witness: one slot per member required');
  if (controlBlock.length !== 33) throw new Error('pq witness: control block must be 33 bytes');
  const filled = slots.filter((s) => s !== undefined).length;
  if (filled !== leaf.threshold) throw new Error(`pq witness: ${filled} slots filled, threshold is ${leaf.threshold}`);
  const items: Uint8Array[] = [];
  for (let i = slots.length - 1; i >= 0; i--) {
    const s = slots[i];
    if (s === undefined) items.push(new Uint8Array(0));
    else {
      if (s.length !== MLDSA65_SIGNATURE_BYTES) throw new Error(`pq witness: slot ${i} signature must be ${MLDSA65_SIGNATURE_BYTES} bytes`);
      items.push(concat(s, Uint8Array.of(hashType)));
    }
  }
  items.push(Uint8Array.from(leaf.script), Uint8Array.from(controlBlock));
  return items;
}

/** Policy's PQ byte count for a witness (items above 65 bytes, script and control block excluded). */
export function pqWitnessPolicyBytes(witness: readonly Uint8Array[]): number {
  let total = 0;
  for (const item of witness.slice(0, Math.max(0, witness.length - 2))) if (item.length > PQ_BYTE_COUNT_THRESHOLD) total += item.length;
  return total;
}

export function pqWitnessIsRelayStandard(witness: readonly Uint8Array[]): boolean {
  return pqWitnessPolicyBytes(witness) <= MAX_STANDARD_PQ_BYTES_PER_INPUT;
}

/**
 * Deterministic finalisation choice: the first `threshold` members in canonical order that have a
 * verified signature. `verified[i]` is the raw signature of members[i] or undefined.
 */
export function selectFinalSlots(threshold: number, verified: ReadonlyArray<Uint8Array | undefined>): Array<Uint8Array | undefined> {
  const out: Array<Uint8Array | undefined> = new Array(verified.length).fill(undefined);
  let chosen = 0;
  for (let i = 0; i < verified.length && chosen < threshold; i++) {
    if (verified[i] !== undefined) {
      out[i] = verified[i];
      chosen++;
    }
  }
  if (chosen < threshold) throw new Error(`pq finalise: ${chosen} verified signatures, threshold is ${threshold}`);
  return out;
}

/**
 * Witness-v2 (script-only Taproot) address of a PQ threshold leaf.
 *
 * - Internal key: the BIP341 "nothing up my sleeve" point `H = lift_x(sha256(G_uncompressed))`,
 *   the same constant every classical taproot treasury uses (`TAPROOT_UNSPENDABLE_KEY` in the
 *   vendored signer, `TAPROOT_NUMS_KEY_HEX` in descriptor.ts). Nobody holds its discrete log, and
 *   Core rejects the v2 key path by consensus anyway (`SCRIPT_ERR_TAPROOT_KEYPATH_DISABLED`).
 * - Tree: exactly one leaf, version 0xc0; merkle root = tapleaf hash; output key =
 *   `TapTweak(H, root)`; control block `(0xc0 | parity) || H` (33 bytes, no merkle path).
 * - scriptPubKey `OP_2 <32-byte output key>`; address bech32m with witness version 2
 *   (`src/key_io.cpp`, `WitnessV2Taproot`), HRP `tc`/`tct`/`tcrt`.
 *
 * Mirrors `deriveFromPubkeys` in descriptor.ts for the classical `tr-sortedmulti_a` policy.
 */
import { bech32m } from '@scure/base';
import { tapLeafHash } from '../signer/payment.js';
import { TAPROOT_UNSPENDABLE_KEY, taprootTweakPubkey } from '../signer/utils.js';
import type { NetworkParams } from '../types.js';
import { MLDSA65_PK_BLOB_BYTES } from './mldsa.js';
import { PQ_LEAF_VERSION, PQ_WITNESS_SIG_BYTES, buildThresholdLeaf, checkPqPolicyLimits, thresholdLeafSize, type PqLeaf } from './script.js';

/** x-only NUMS internal key (32 bytes). */
export const PQ_INTERNAL_KEY: Uint8Array = TAPROOT_UNSPENDABLE_KEY;
export const WITNESS_V2 = 2;
export const OP_2 = 0x52;

export interface PqTreasuryAddress extends PqLeaf {
  leafVersion: number;
  leafHash: Uint8Array;
  internalKey: Uint8Array;
  merkleRoot: Uint8Array;
  outputKey: Uint8Array;
  parity: 0 | 1;
  controlBlock: Uint8Array;
  scriptPubKey: Uint8Array;
  address: string;
}

export function pqTapleafHash(script: Uint8Array): Uint8Array {
  return tapLeafHash(script, PQ_LEAF_VERSION);
}

export function pqControlBlock(parity: number, internalKey: Uint8Array = PQ_INTERNAL_KEY): Uint8Array {
  if (internalKey.length !== 32) throw new Error('control block: internal key must be 32 bytes');
  const out = new Uint8Array(33);
  out[0] = (PQ_LEAF_VERSION & 0xfe) | (parity & 1);
  out.set(internalKey, 1);
  return out;
}

export function v2ScriptPubKey(outputKey: Uint8Array): Uint8Array {
  if (outputKey.length !== 32) throw new Error('v2 scriptPubKey: output key must be 32 bytes');
  const out = new Uint8Array(34);
  out[0] = OP_2;
  out[1] = 0x20;
  out.set(outputKey, 2);
  return out;
}

export function isV2ScriptPubKey(spk: Uint8Array): boolean {
  return spk.length === 34 && spk[0] === OP_2 && spk[1] === 0x20;
}

export function encodeV2Address(outputKey: Uint8Array, network: NetworkParams): string {
  if (outputKey.length !== 32) throw new Error('v2 address: output key must be 32 bytes');
  return bech32m.encode(network.bech32Hrp, [WITNESS_V2, ...bech32m.toWords(outputKey)], 90);
}

/**
 * Decode a witness-v2 address of `network`. Rejects other HRPs, other witness versions (a `tc1p`
 * taproot or `tc1q` segwit address is not a PQ treasury) and bech32 (non-m) checksums.
 */
export function decodeV2Address(address: string, network: NetworkParams): Uint8Array {
  let decoded: { prefix: string; words: number[] };
  try {
    decoded = bech32m.decode(address, 90);
  } catch (e) {
    throw new Error(`v2 address: ${(e as Error).message}`);
  }
  if (decoded.prefix !== network.bech32Hrp) throw new Error(`v2 address: prefix "${decoded.prefix}" is not ${network.bech32Hrp}`);
  const [version, ...rest] = decoded.words;
  if (version !== WITNESS_V2) throw new Error(`v2 address: witness version ${version} is not 2`);
  const program = bech32m.fromWords(rest);
  if (program.length !== 32) throw new Error(`v2 address: program is ${program.length} bytes, not 32`);
  return program;
}

export interface BuildPqTreasuryOptions {
  /** Default true: refuse k whose k-signature spend exceeds relay policy (e.g. 3-of-n). */
  requireRelayStandard?: boolean;
}

/** Everything about a k-of-n PQ treasury address, from the members' pk blobs. */
export function buildPqTreasury(threshold: number, pkBlobs: readonly Uint8Array[], network: NetworkParams, opts: BuildPqTreasuryOptions = {}): PqTreasuryAddress {
  const leaf = buildThresholdLeaf(threshold, pkBlobs);
  const limits = checkPqPolicyLimits(threshold, leaf.members.length);
  if ((opts.requireRelayStandard ?? true) && !limits.relayOk) throw new Error(`pq treasury: ${limits.reasons.join('; ')}`);
  return fromLeaf(leaf, network);
}

/** The address facts of an already-built leaf (e.g. parsed back from a PSBT). */
export function pqTreasuryFromLeaf(leaf: PqLeaf, network: NetworkParams): PqTreasuryAddress {
  return fromLeaf(leaf, network);
}

function fromLeaf(leaf: PqLeaf, network: NetworkParams): PqTreasuryAddress {
  const leafHash = pqTapleafHash(leaf.script);
  const [outputKey, parityNum] = taprootTweakPubkey(PQ_INTERNAL_KEY, leafHash);
  const parity = (parityNum & 1) as 0 | 1;
  const scriptPubKey = v2ScriptPubKey(outputKey);
  return {
    ...leaf,
    leafVersion: PQ_LEAF_VERSION,
    leafHash,
    internalKey: PQ_INTERNAL_KEY,
    merkleRoot: leafHash,
    outputKey,
    parity,
    controlBlock: pqControlBlock(parity),
    scriptPubKey,
    address: encodeV2Address(outputKey, network),
  };
}

// ---------------------------------------------------------------------------
// Size and fee model
// ---------------------------------------------------------------------------

function varintSize(n: number): number {
  return n < 0xfd ? 1 : n <= 0xffff ? 3 : 5;
}

/** Serialised witness bytes of one input with exactly `k` filled slots out of `n`. */
export function pqWitnessSize(k: number, n: number): number {
  const leaf = thresholdLeafSize(n);
  return varintSize(n + 2) + k * (varintSize(PQ_WITNESS_SIG_BYTES) + PQ_WITNESS_SIG_BYTES) + (n - k) * 1 + varintSize(leaf) + leaf + 1 + 33;
}

/** Weight and vsize of a spend with `inputCount` PQ inputs (k-of-n each) to the given output scripts. */
export function pqSpendSize(inputCount: number, k: number, n: number, outputScriptLens: number[]): { base: number; witness: number; weight: number; vsize: number } {
  const base =
    4 +
    varintSize(inputCount) +
    inputCount * (32 + 4 + 1 + 4) +
    varintSize(outputScriptLens.length) +
    outputScriptLens.reduce((acc, len) => acc + 8 + varintSize(len) + len, 0) +
    4;
  const witness = inputCount ? 2 + inputCount * pqWitnessSize(k, n) : 0;
  const weight = base * 4 + witness;
  return { base, witness, weight, vsize: Math.ceil(weight / 4) };
}

export function pqFeeSats(vsize: number, feeRateSatPerVb: number): bigint {
  return BigInt(Math.ceil(vsize * feeRateSatPerVb));
}

export { MLDSA65_PK_BLOB_BYTES };

/**
 * ML-DSA script-path sighash, `TaggedHash("TapSighash/ML-DSA", msg)`, where `msg` is the BIP341
 * message exactly as Core's `SignatureHashMLDSA` builds it (`src/script/interpreter.cpp`):
 *
 *   epoch 0x00 | hash_type | version (i32 LE) | locktime (u32 LE)
 *   | sha256(prevouts) | sha256(amounts) | sha256(scriptPubKeys, each compactsize-prefixed) | sha256(sequences)
 *   | sha256(outputs)        -- every output as `SerTxOutWithExt`: amount | compactsize(spk) | spk
 *                              | [compactsize(ext) | ext]  (the extension field is present for
 *                              every output when any output carries a TensorCash extension)
 *   | spend_type 0x02        -- ext_flag 1 (tapscript), no annex
 *   | input index (u32 LE)
 *   | tapleaf hash | key_version 0x00 | codeseparator position 0xffffffff
 *
 * Only `SIGHASH_ALL` (0x01) is produced: the wallet never enables NONE/SINGLE/ANYONECANPAY, so
 * those branches are intentionally absent and `hashType !== 0x01` throws. The function takes the
 * structured transaction fields (not raw bytes) so the caller's codec — the vendored signer, which
 * already serialises extension-bearing outputs — is the single source of serialisation. The
 * vendored `Transaction.getMLDSASighash` computes the same digest from a PSBT; the unit test checks
 * both agree and the Core interop test checks Core accepts signatures over this digest.
 *
 * Copied in structure from `front-end/client/src/services/mldsaTaproot.ts` (`computeMLDSASighash`).
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, tagSchnorr } from '../signer/utils.js';
import { writeCompactSize } from './mldsa.js';

export const SIGHASH_ALL = 0x01;
export const PQ_SIGHASH_TAG = 'TapSighash/ML-DSA';
export const PQ_KEY_VERSION = 0x00;
export const PQ_CODESEP_POS = 0xffffffff;

export interface PqSighashInput {
  version: number;
  lockTime: number;
  /** All inputs: 36-byte prevout (txid in wire order || vout LE) and nSequence. */
  inputs: Array<{ prevout: Uint8Array; sequence: number }>;
  /** All spent outputs in input order. */
  spentOutputs: Array<{ value: bigint; scriptPubKey: Uint8Array }>;
  /** Every output, fully serialised as `SerTxOutWithExt` (extension field included when any output has one). */
  serializedOutputs: Uint8Array[];
  inputIndex: number;
  /** Leaf script bytes (the tapleaf hash is computed here with version 0xc0) or the 32-byte tapleaf hash. */
  leaf: { script: Uint8Array } | { leafHash: Uint8Array };
  hashType?: number;
}

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

function i32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setInt32(0, n, true);
  return b;
}

function u64le(v: bigint): Uint8Array {
  if (typeof v !== 'bigint' || v < 0n || v > 0xffffffffffffffffn) throw new Error('pq sighash: amount out of range');
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, v, true);
  return b;
}

export function pqSighash(opts: PqSighashInput): Uint8Array {
  const hashType = opts.hashType ?? SIGHASH_ALL;
  if (hashType !== SIGHASH_ALL) throw new Error(`pq sighash: hash type 0x${hashType.toString(16)} is not supported (SIGHASH_ALL only)`);
  const n = opts.inputs.length;
  if (n === 0 || opts.spentOutputs.length !== n) throw new Error('pq sighash: inputs and spent outputs must match and be non-empty');
  if (!Number.isInteger(opts.inputIndex) || opts.inputIndex < 0 || opts.inputIndex >= n) throw new Error('pq sighash: input index out of range');
  for (const i of opts.inputs) if (i.prevout.length !== 36) throw new Error('pq sighash: prevout must be 36 bytes');
  if (opts.serializedOutputs.length === 0) throw new Error('pq sighash: at least one output required');

  let leafHash: Uint8Array;
  if ('leafHash' in opts.leaf) {
    if (opts.leaf.leafHash.length !== 32) throw new Error('pq sighash: leaf hash must be 32 bytes');
    leafHash = opts.leaf.leafHash;
  } else {
    leafHash = tagSchnorr('TapLeaf', Uint8Array.of(0xc0), writeCompactSize(opts.leaf.script.length), opts.leaf.script);
  }

  const hashPrevouts = sha256(concatBytes(...opts.inputs.map((i) => i.prevout)));
  const hashAmounts = sha256(concatBytes(...opts.spentOutputs.map((o) => u64le(o.value))));
  const hashScripts = sha256(concatBytes(...opts.spentOutputs.map((o) => concatBytes(writeCompactSize(o.scriptPubKey.length), o.scriptPubKey))));
  const hashSequences = sha256(concatBytes(...opts.inputs.map((i) => u32le(i.sequence))));
  const hashOutputs = sha256(concatBytes(...opts.serializedOutputs));

  const msg = concatBytes(
    Uint8Array.of(0x00),
    Uint8Array.of(hashType),
    i32le(opts.version),
    u32le(opts.lockTime),
    hashPrevouts,
    hashAmounts,
    hashScripts,
    hashSequences,
    hashOutputs,
    Uint8Array.of(0x02),
    u32le(opts.inputIndex),
    leafHash,
    Uint8Array.of(PQ_KEY_VERSION),
    u32le(PQ_CODESEP_POS),
  );
  return tagSchnorr(PQ_SIGHASH_TAG, msg);
}

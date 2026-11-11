/**
 * HD key helpers: BIP39 mnemonics, BIP32 keys in the network's own encoding,
 * fingerprints, key origins and ranged child derivation.
 */
import { HDKey } from '@scure/bip32';
import * as bip39 from '@scure/bip39';
import { wordlist as englishWordlist } from '@scure/bip39/wordlists/english.js';
import { hex } from '@scure/base';
import { bip32Versions } from './network.js';
import type { DerivationPath, Fingerprint, NetworkParams } from './types.js';

export const HARDENED_OFFSET = 0x80000000;

// ---------------------------------------------------------------------------
// Mnemonics and seeds
// ---------------------------------------------------------------------------

/** Generate a BIP39 English mnemonic. `strength` is entropy bits (128..256, multiple of 32). */
export function generateMnemonic(strength = 256): string {
  return bip39.generateMnemonic(englishWordlist, strength);
}

export function validateMnemonic(mnemonic: string): boolean {
  return bip39.validateMnemonic(normalizeMnemonic(mnemonic), englishWordlist);
}

export function normalizeMnemonic(mnemonic: string): string {
  return mnemonic.normalize('NFKD').trim().toLowerCase().split(/\s+/).join(' ');
}

/** BIP39 seed (64 bytes). Caller must zero the result when done. */
export function mnemonicToSeed(mnemonic: string, passphrase = ''): Uint8Array {
  const m = normalizeMnemonic(mnemonic);
  if (!bip39.validateMnemonic(m, englishWordlist)) throw new Error('hd: invalid mnemonic');
  return bip39.mnemonicToSeedSync(m, passphrase);
}

/** Master HDKey with the network's bip32 version bytes. */
export function masterFromSeed(seed: Uint8Array, network: NetworkParams): HDKey {
  if (seed.length < 16 || seed.length > 64) throw new Error('hd: seed must be 16..64 bytes');
  return HDKey.fromMasterSeed(seed, bip32Versions(network));
}

export function masterFromMnemonic(mnemonic: string, network: NetworkParams, passphrase = ''): HDKey {
  const seed = mnemonicToSeed(mnemonic, passphrase);
  try {
    return masterFromSeed(seed, network);
  } finally {
    seed.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Fingerprints
// ---------------------------------------------------------------------------

/** 8 lowercase hex chars of the 4-byte BIP32 fingerprint. */
export function fingerprintHex(fp: number): Fingerprint {
  if (!Number.isInteger(fp) || fp < 0 || fp > 0xffffffff) throw new Error('hd: invalid fingerprint');
  return fp.toString(16).padStart(8, '0');
}

export function fingerprintOf(key: HDKey): Fingerprint {
  return fingerprintHex(key.fingerprint);
}

export function fingerprintToNumber(fp: Fingerprint): number {
  if (!isFingerprint(fp)) throw new Error(`hd: invalid fingerprint "${fp}"`);
  return parseInt(fp, 16) >>> 0;
}

export function isFingerprint(fp: unknown): fp is Fingerprint {
  return typeof fp === 'string' && /^[0-9a-f]{8}$/.test(fp);
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/** Parse "m/48'/0'/0'/2'" (also accepts `h`/`H` for hardened and no leading m) into child indices. */
export function parsePath(path: DerivationPath): number[] {
  const trimmed = path.trim();
  if (trimmed === '' || trimmed === 'm' || trimmed === 'M') return [];
  const parts = trimmed.replace(/^[mM]\//, '').split('/');
  const out: number[] = [];
  for (const part of parts) {
    const m = /^(\d+)(['hH]?)$/.exec(part);
    if (!m) throw new Error(`hd: invalid path component "${part}" in "${path}"`);
    const idx = Number(m[1]);
    if (!Number.isSafeInteger(idx) || idx >= HARDENED_OFFSET) throw new Error(`hd: index out of range in "${path}"`);
    out.push(m[2] ? idx + HARDENED_OFFSET : idx);
  }
  return out;
}

/** Format child indices as "m/48'/0'/0'/2'". */
export function formatPath(indices: number[], hardenedMark: "'" | 'h' = "'", withM = true): string {
  const parts = indices.map((i) => (i >= HARDENED_OFFSET ? `${i - HARDENED_OFFSET}${hardenedMark}` : `${i}`));
  return withM ? ['m', ...parts].join('/') : parts.join('/');
}

/** Normalise any accepted path spelling to the canonical "m/48'/0'/0'/2'" form. */
export function normalizePath(path: DerivationPath): DerivationPath {
  return formatPath(parsePath(path));
}

/** Key origin in descriptor form: `[fp/48h/0h/0h/2h]`. */
export function formatKeyOrigin(fingerprint: Fingerprint, path: DerivationPath): string {
  if (!isFingerprint(fingerprint)) throw new Error(`hd: invalid fingerprint "${fingerprint}"`);
  const indices = parsePath(path);
  return indices.length ? `[${fingerprint}/${formatPath(indices, 'h', false)}]` : `[${fingerprint}]`;
}

/** Parse `[fp/48h/0h/0h/2h]` into fingerprint and canonical path. */
export function parseKeyOrigin(origin: string): { fingerprint: Fingerprint; path: DerivationPath } {
  const m = /^\[([0-9a-fA-F]{8})((?:\/[0-9]+['hH]?)*)\]$/.exec(origin);
  if (!m) throw new Error(`hd: invalid key origin "${origin}"`);
  const fingerprint = m[1].toLowerCase();
  const path = m[2] ? formatPath(parsePath('m' + m[2])) : 'm';
  return { fingerprint, path };
}

export function derivePath(key: HDKey, path: DerivationPath): HDKey {
  let k = key;
  for (const idx of parsePath(path)) k = k.deriveChild(idx);
  return k;
}

// ---------------------------------------------------------------------------
// Extended public keys
// ---------------------------------------------------------------------------

/** Encode the account key as an extended public key with the network version bytes. */
export function encodeXpub(key: HDKey, network: NetworkParams): string {
  const pub = key.publicKey;
  if (!pub) throw new Error('hd: key has no public key');
  const versions = bip32Versions(network);
  if (key.versions.public === versions.public) return key.publicExtendedKey;
  // Re-wrap with the requested versions (bip32 keeps versions immutable on the instance).
  const rewrapped = new HDKey({
    versions,
    depth: key.depth,
    index: key.index,
    parentFingerprint: key.parentFingerprint,
    chainCode: key.chainCode ?? undefined,
    publicKey: pub,
  });
  return rewrapped.publicExtendedKey;
}

/** Decode an extended public key; throws unless the version bytes belong to `network`. */
export function decodeXpub(xpub: string, network: NetworkParams): HDKey {
  let key: HDKey;
  try {
    key = HDKey.fromExtendedKey(xpub, bip32Versions(network));
  } catch (e) {
    throw new Error(`hd: cannot decode extended key for ${network.name}: ${(e as Error).message}`);
  }
  if (key.privateKey) throw new Error('hd: expected an extended public key, got a private one');
  return key;
}

/** Account-level public key (xpub) for the key at `path`. */
export function accountXpub(master: HDKey, path: DerivationPath, network: NetworkParams): string {
  const acct = derivePath(master, path);
  const xpub = encodeXpub(acct, network);
  acct.wipePrivateData();
  return xpub;
}

// ---------------------------------------------------------------------------
// Ranged child derivation
// ---------------------------------------------------------------------------

/** Compressed child pubkey at account/<branch>/<index>. */
export function childPubkey(account: HDKey, branch: number, index: number): Uint8Array {
  checkUnhardened(branch);
  checkUnhardened(index);
  const pub = account.deriveChild(branch).deriveChild(index).publicKey;
  if (!pub) throw new Error('hd: derived key has no public key');
  return pub;
}

/** Child pubkeys for account/<branch>/<from..to>. */
export function childPubkeys(account: HDKey, branch: number, from: number, to: number): Uint8Array[] {
  checkUnhardened(branch);
  if (from > to) throw new Error('hd: invalid index range');
  const branchKey = account.deriveChild(branch);
  const out: Uint8Array[] = [];
  for (let i = from; i <= to; i++) {
    const pub = branchKey.deriveChild(i).publicKey;
    if (!pub) throw new Error('hd: derived key has no public key');
    out.push(pub);
  }
  return out;
}

export function checkUnhardened(index: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= HARDENED_OFFSET)
    throw new Error(`hd: index must be an unhardened integer, got ${index}`);
}

export const pubkeyHex = (pub: Uint8Array): string => hex.encode(pub);

export type { HDKey };

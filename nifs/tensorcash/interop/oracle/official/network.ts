/**
 * Network parameters for the TensorCash chains and adapters for the signer.
 *
 * Values are taken from Core `src/kernel/chainparams.cpp` (see README table).
 */
import type { NetworkName, NetworkParams, ScriptPolicy } from './types.js';
import type { BTC_NETWORK } from './signer/utils.js';

/** Environment variable that overrides the chain API origins (comma separated). */
export const CHAIN_API_ORIGINS_ENV = 'LTW_CHAIN_API_ORIGINS';

export const NETWORKS: Record<NetworkName, NetworkParams> = {
  mainnet: {
    name: 'mainnet',
    coreChain: 'tensor',
    bech32Hrp: 'tc',
    p2pkhPrefix: 0x42,
    p2shPrefix: 0x13,
    wifPrefix: 0xd2,
    bip32: { public: 0x04544350, private: 0x04544358 },
    coinType: 0,
    p2pPort: 39241,
    chainApiOrigins: ['https://api.tensorcash.org/esplora/api', 'https://api2.tensorcash.org/esplora/api'],
    explorerBase: 'https://scan.tensorcash.org',
    coinbaseMaturity: 100,
    // Asserted in Core chainparams.cpp (CTensorMainParams) and served by /esplora/api/block-height/0.
    genesisHash: '8fe43be4634dc48def074fa840e25a71bbdc32576eb29abf3ce2458605343720',
  },
  testnet: {
    name: 'testnet',
    coreChain: 'tensor-test',
    bech32Hrp: 'tct',
    p2pkhPrefix: 0x43,
    p2shPrefix: 0x14,
    wifPrefix: 0xe2,
    bip32: { public: 0x04744350, private: 0x04744358 },
    coinType: 1,
    p2pPort: 29241,
    // No public testnet chain API exists yet (2026-11-05: mempool-testnet.tensorcash.org/api
    // serves tip, block and tx routes only; no address, outspends, fee-estimates or batch routes,
    // see docs/WORKED_EXAMPLE_TESTNET.md). Set LTW_CHAIN_API_ORIGINS (comma separated) to a
    // deployment of the mainnet chain API service for testnet, see resolveNetwork().
    chainApiOrigins: [],
    coinbaseMaturity: 100,
    // Not asserted in chainparams.cpp (computed at start-up, "Tensor Test genesis: full=…");
    // read from a local tensor-test node (getblockhash 0) and from mempool-testnet.tensorcash.org
    // /api/block-height/0 on 2026-11-06.
    genesisHash: '196d19dfe2fd0ad447703cb88fdbc08945a5aa558f9bebc495a8ddc7facf3276',
  },
  regtest: {
    name: 'regtest',
    coreChain: 'tensor-reg',
    bech32Hrp: 'tcrt',
    p2pkhPrefix: 0x44,
    p2shPrefix: 0x15,
    wifPrefix: 0xf2,
    bip32: { public: 0x04724350, private: 0x04724358 },
    coinType: 1,
    p2pPort: 19241,
    chainApiOrigins: [],
    coinbaseMaturity: 100,
    // tensor-reg genesis (getblockhash 0 of a fresh local node built from chainparams.cpp
    // CTensorRegParams, 2026-11-06). Deterministic: fixed nTime/nNonce/VDF proof, no activation flags.
    genesisHash: '294d0915be3486fb43e312d534187a43e81f67dbb39e0e66b3df24ce3dd1b1f1',
  },
};

export type EnvLike = Record<string, string | undefined>;

export function isNetworkName(name: string): name is NetworkName {
  return name === 'mainnet' || name === 'testnet' || name === 'regtest';
}

/** Parse a comma separated origin list; trims entries, drops empties, strips trailing slashes. */
export function parseOriginList(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((s) => s.trim().replace(/\/+$/, ''))
    .filter((s) => s.length > 0);
}

/**
 * Resolve network params for `name`, applying the `LTW_CHAIN_API_ORIGINS` override from `env`
 * (defaults to `process.env` when available). Returns a fresh copy; NETWORKS is never mutated.
 */
export function resolveNetwork(name: NetworkName, env?: EnvLike): NetworkParams {
  if (!isNetworkName(name)) throw new Error(`network: unknown network "${String(name)}"`);
  const base = NETWORKS[name];
  const source: EnvLike = env ?? (typeof process !== 'undefined' && process.env ? process.env : {});
  const override = parseOriginList(source[CHAIN_API_ORIGINS_ENV]);
  for (const origin of override) {
    if (!/^https?:\/\//.test(origin)) throw new Error(`network: invalid chain API origin "${origin}"`);
  }
  return {
    ...base,
    bip32: { ...base.bip32 },
    chainApiOrigins: override.length ? override : [...base.chainApiOrigins],
  };
}

/** Adapter for the signer's `network` parameter (address encoding only). */
export function toSignerNetwork(p: NetworkParams): BTC_NETWORK {
  return { bech32: p.bech32Hrp, pubKeyHash: p.p2pkhPrefix, scriptHash: p.p2shPrefix, wif: p.wifPrefix };
}

/** BIP32 version bytes in the shape `@scure/bip32` expects. */
export function bip32Versions(p: NetworkParams): { public: number; private: number } {
  return { public: p.bip32.public, private: p.bip32.private };
}

/** The PQ policy literal (`tr2-mldsa65-threshold`), which has no BIP32/BIP48 derivation at all. */
export const PQ_POLICY: ScriptPolicy = 'tr2-mldsa65-threshold';

/** Whether a policy is the PQ (ML-DSA-65 threshold, witness v2) policy. */
export function isPqPolicy(policy: string | undefined): policy is 'tr2-mldsa65-threshold' {
  return policy === PQ_POLICY;
}

/**
 * BIP48 script-type index of a treasury policy: 2' for P2WSH (`wsh-sortedmulti`), 3' for the
 * taproot script-path policy (`tr-sortedmulti_a`; the index several multisig wallets use for
 * taproot multisig, so a key is never shared between the two script types).
 *
 * The PQ policy (`tr2-mldsa65-threshold`) has no BIP48 path: its keys are ML-DSA-65 keys derived
 * by `pq/derivation.ts`, never secp256k1 children of an xpub. Asking for its script type is an
 * error, so nothing can silently derive classical keys for a PQ treasury.
 */
export function policyScriptType(policy: ScriptPolicy = 'wsh-sortedmulti'): 2 | 3 {
  switch (policy) {
    case 'wsh-sortedmulti':
      return 2;
    case 'tr-sortedmulti_a':
      return 3;
    case 'tr2-mldsa65-threshold':
      throw new Error('network: the PQ policy tr2-mldsa65-threshold has no BIP48 script type; PQ keys come from pq/derivation.ts (no xpub, no BIP32 path)');
    default:
      throw new Error(`network: unknown policy "${String(policy)}"`);
  }
}

/** The BIP48 account path for a network and policy: m/48'/<coin>'/<account>'/<2'|3'>. Throws for the PQ policy (no BIP32 path). */
export function accountPath(p: NetworkParams, account = 0, policy: ScriptPolicy = 'wsh-sortedmulti'): string {
  if (isPqPolicy(policy)) throw new Error('network: the PQ policy tr2-mldsa65-threshold has no BIP48 account path; PQ keys come from pq/derivation.ts');
  return `m/48'/${p.coinType}'/${account}'/${policyScriptType(policy)}'`;
}

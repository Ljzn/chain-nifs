/**
 * Shared contracts for the Light Treasury Wallet core.
 *
 * Every package codes against these types. Implementations live in sibling
 * modules; the desktop app and the flow tests inject them. Keep this file
 * free of runtime dependencies (types only, plus small constant unions).
 */

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

/** Build-time network flavour. Mainnet and testnet are shipped as separate builds. */
export type NetworkName = 'mainnet' | 'testnet' | 'regtest';

export interface NetworkParams {
  name: NetworkName;
  /** Core chain name as reported by getblockchaininfo.chain */
  coreChain: 'tensor' | 'tensor-test' | 'tensor-reg';
  bech32Hrp: string; // tc | tct | tcrt
  p2pkhPrefix: number; // 0x42 | 0x43 | 0x44
  p2shPrefix: number; // 0x13 | 0x14 | 0x15
  wifPrefix: number; // 0xD2 | 0xE2 | 0xF2
  bip32: { public: number; private: number }; // 0x04544350/58 | 0x04744350/58 | 0x04724350/58
  /** SLIP-44 style coin type used in BIP48 paths. Mainnet default 0, testnet 1. */
  coinType: number;
  p2pPort: number; // 39241 | 29241 | 19241
  /** Default chain API origins (Esplora-compatible wallet API base URLs ending in /esplora/api). */
  chainApiOrigins: string[];
  /** Explorer base for links (TSCScan). */
  explorerBase?: string;
  /** Coinbase maturity in blocks (Bitcoin default 100). */
  coinbaseMaturity: number;
  /**
   * Hash of the chain's genesis block as Core prints it (`getblockhash 0`, display byte order),
   * lowercase hex. The PQ derivation (`pq/derivation.ts`) binds every key to it; optional only so
   * that test fixtures and stubs that build their own NetworkParams keep compiling. `NETWORKS`
   * always carries it.
   */
  genesisHash?: Hex;
}

// ---------------------------------------------------------------------------
// Keys and cosigners
// ---------------------------------------------------------------------------

/** Hex string (lowercase). */
export type Hex = string;

/** Master key fingerprint, 8 hex chars. */
export type Fingerprint = string;

/** Derivation path string, e.g. "m/48'/0'/0'/2'". */
export type DerivationPath = string;

/** Public record one participant exports during the ceremony. */
export interface CosignerRecord {
  version: 1;
  network: NetworkName;
  /** Human label chosen by the participant (display only). */
  label: string;
  fingerprint: Fingerprint;
  /** Account-level path the xpub was derived at. */
  path: DerivationPath;
  /** Account extended public key in the network's own encoding (vJe3… on mainnet). */
  xpub: string;
  /** Ceremony session token this record was produced for. */
  sessionToken: string;
  /**
   * BIP-322 signature over `${sessionToken}|${fingerprint}|${path}|${xpub}` made with the
   * first external child key (path/0/0), proving possession. Base64.
   */
  proof?: string;
  createdAt: string; // ISO 8601
}

// ---------------------------------------------------------------------------
// Treasury configuration (public, shareable, must be backed up by every member)
// ---------------------------------------------------------------------------

/**
 * Treasury script policy.
 * - `wsh-sortedmulti`: `wsh(sortedmulti(k, …))`, witness v0, BIP48 script type 2'.
 * - `tr-sortedmulti_a`: `tr(NUMS, sortedmulti_a(k, …))`, witness v1 (taproot) with a single
 *   script-path leaf and the BIP341 unspendable internal key, BIP48 script type 3'. Lets the
 *   treasury hold outputs whose asset policy allows P2TR only.
 * - `tr2-mldsa65-threshold`: witness v2 (`OP_2 <32>`), one tapscript leaf with
 *   `OP_CHECKMLSIGVERIFY` per member under a k-of-n threshold (docs/PQ_POLICY.md). No BIP48 path
 *   and no xpub: addresses come from the members' published spending-key pools
 *   (`PqAddressSource`); script family `SPK_P2TR_V2` for asset holdability.
 */
export type ScriptPolicy = 'wsh-sortedmulti' | 'tr-sortedmulti_a' | 'tr2-mldsa65-threshold';

export interface TreasuryConfig {
  version: 1;
  /** Stable identifier: sha256 of the external descriptor with checksum, hex. */
  id: Hex;
  name: string;
  network: NetworkName;
  policy: ScriptPolicy;
  threshold: number; // k
  cosigners: CosignerRecord[]; // n entries, order as given (descriptor uses sortedmulti)
  descriptors: {
    external: string; // wsh(sortedmulti(k,[fp/48h/c/0h/2h]xpub/0/*,...))#checksum or tr(NUMS,sortedmulti_a(k,[fp/48h/c/0h/3h]xpub/0/*,...))#checksum
    internal: string; // same with /1/*
  };
  /** First three external and internal addresses, recorded for the ceremony receipt. */
  firstAddresses: { external: string[]; internal: string[] };
  /** Unix time (seconds) before which no activity exists; 0 = scan from genesis. */
  birthTime: number;
  createdAt: string;
  /** Present once the configuration has been confirmed on this device. */
  receipt?: CeremonyReceipt;
  /**
   * PQ treasury (`policy === 'tr2-mldsa65-threshold'`): the public manifest (roster, pools,
   * acknowledgments; docs/PQ_CEREMONY.md). For such a configuration `id` is the stable policy id,
   * `cosigners` is empty, `descriptors` hold the informational placeholder
   * `tr2-mldsa65-threshold(<policyId>)` and `firstAddresses` the first receive/change address.
   * Absent on classical treasuries, so classical code keeps compiling and reading unchanged.
   */
  pq?: PqTreasuryManifest;
}

export interface CeremonyReceipt {
  configId: Hex;
  descriptorChecksum: string;
  fingerprints: Fingerprint[];
  firstAddresses: { external: string[]; internal: string[] };
  confirmedAt: string;
  /** sha256 over the canonical JSON of the TreasuryConfig without `receipt`, hex. */
  configHash: Hex;
  /**
   * PQ treasury only: the manifest revision this receipt confirms and how many of the n members
   * had acknowledged it on this device at confirmation time. `descriptorChecksum` carries the
   * first 8 hex characters of `revisionHash`; `fingerprints` the members' PQ fingerprints.
   */
  pq?: { policyId: Hex; revision: number; revisionHash: Hex; acknowledgments: number; readyToFund: boolean };
  /**
   * The fingerprint of the key on the confirming device whose account key (or PQ identity) was
   * derived and found equal to its member record (`CeremonyEngine.confirm` with `own`): a
   * signing-member receipt. Absent on a receipt issued without a local key.
   */
  confirmedBy?: Fingerprint;
}

/** How the configuration relates to the key on this device (`CeremonyEngine.verify`). */
export type MembershipStatus =
  /** The account key (or PQ identity) derived on this device equals the member record that names it. */
  | 'verified'
  /** No record names this device's key, or the record naming its fingerprint carries another key. */
  | 'not-a-member'
  /** No local key was supplied, or only a fingerprint: membership was not proven (watch-only view). */
  | 'unverified';

/** This device's classical account key, derived from the unlocked vault at the record's path. */
export interface OwnAccountKey {
  fingerprint: Fingerprint;
  path: DerivationPath;
  xpub: string;
}

/**
 * What `verify` compares the configuration against: a bare fingerprint proves nothing beyond
 * "named" (a fingerprint is public metadata any record can claim); the derived account key or
 * the PQ identity establishes membership.
 */
export type OwnIdentity = Fingerprint | OwnAccountKey | PqIdentity;

export interface ConfigVerification {
  /** Structurally valid: records, proofs, descriptors, checksums, id and first addresses agree. */
  ok: boolean;
  problems: string[];
  firstAddresses: TreasuryConfig['firstAddresses'];
  membership: MembershipStatus;
}

// ---------------------------------------------------------------------------
// Key storage abstraction
// ---------------------------------------------------------------------------

/**
 * A KeyStore holds exactly one participant's secret and can produce signatures.
 * Implementations: LocalVault (argon2id-wrapped seed on disk), and later a
 * PasskeyVault (seed wrapped by a WebAuthn PRF-derived key, hosted deployment).
 * The renderer never sees secret material; only the main process / host does.
 */
export interface KeyStore {
  readonly kind: 'local-vault' | 'passkey-vault' | 'memory' | 'local-pq-vault' | 'memory-pq';
  readonly fingerprint: Fingerprint;
  /** Account xpub for the given path, in network encoding. */
  getAccountXpub(path: DerivationPath): Promise<string>;
  /** Whether the store is unlocked (secret decrypted in memory). */
  isUnlocked(): boolean;
  unlock(credential: UnlockCredential): Promise<void>;
  lock(): void;
  /**
   * Sign all inputs of the PSBT that belong to this key (matched by bip32Derivation
   * fingerprint + path). Returns the PSBT with partial signatures added and NOT finalised.
   */
  signPsbt(psbt: Uint8Array, opts?: { sighash?: number }): Promise<Uint8Array>;
  /** BIP-322 simple signature with the key at `path`, base64. */
  signMessage(path: DerivationPath, message: string): Promise<string>;
  /**
   * The 32-byte DEK store secret of this signer (keystore/dek-store-secret.ts): a pure function
   * of the recovery words (and passphrase), identical whatever the vault file, password or salt,
   * so a DEK store or a saved pairing sealed under it survives a restore from the words. A fresh
   * copy the caller zeroes; throws `KeyStoreLockedError` while locked.
   */
  dekStoreSecret(): Uint8Array;
}

export type UnlockCredential =
  | { kind: 'password'; password: string }
  | { kind: 'passkey'; prfOutput: Uint8Array };

export interface VaultFile {
  version: 1;
  kind: 'local-vault';
  network: NetworkName;
  fingerprint: Fingerprint;
  kdf: { name: 'argon2id'; salt: Hex; memoryKiB: number; iterations: number; parallelism: number };
  cipher: { name: 'aes-256-gcm'; iv: Hex; ciphertext: Hex };
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Post-quantum (ML-DSA-65) identity, policy and signer contracts (docs/PQ_DERIVATION.md)
// ---------------------------------------------------------------------------

/** The only ML-DSA parameter set the wallet supports (Core pk_blob algorithm byte 0x41). */
export type PqParamSet = 'ML-DSA-65';

/**
 * Script policy of a PQ treasury: a single tapscript leaf with `OP_CHECKMLSIGVERIFY` per member
 * under a k-of-n threshold, witness v2 (docs/PQ_POLICY.md). The literal is also a member of
 * `ScriptPolicy`; this alias names the PQ case where a PQ-only value is meant.
 */
export type PqPolicyKind = 'tr2-mldsa65-threshold';

/**
 * Where a PQ treasury's addresses come from. There is no PQ xpub: the address at (branch, index)
 * is the threshold leaf over the n members' published spending public keys at that index, taken
 * from the verified pool manifest (plan §4.3). The engine, the descriptor wallet and the signer
 * helper depend on this small data-only interface, never on the manifest internals;
 * `pq/manifest.ts` adapts a manifest to it (`pqAddressSourceOf`).
 */
export interface PqAddressSource {
  /** Stable policy id (`derivePolicyId`), 32 bytes hex. */
  readonly policyId: Hex;
  /** k of the k-of-n script. */
  readonly threshold: number;
  /**
   * The n members' identity public-key hashes (`PqIdentity.publicKeyHash`, hex) in roster
   * order. The first 8 hex characters of an entry are the member's `PqSigner.fingerprint`, which
   * is how `Proposal.signedBy` and `ProposalReview.signedBy` name a PQ member (a spending key
   * changes with every index; the identity does not).
   */
  readonly memberIds: readonly Hex[];
  /**
   * The n members' spending public keys at (branch, index), one per member in roster order
   * (aligned with `memberIds`), either as Core pk blobs (1957 bytes, `encodePkBlob`) or as raw
   * ML-DSA-65 public keys (1952 bytes); the leaf builder sorts them canonically. `undefined`
   * when no published entry covers the index on every member (the pool is exhausted or has a
   * gap there).
   */
  memberBlobsAt(branch: 0 | 1, index: number): Uint8Array[] | undefined;
  /**
   * Number of consecutive indices from 0 for which every member has a published entry, per
   * branch: `receive` for branch 0, `change` for branch 1. The engine scans every one of them.
   */
  capacity(): { receive: number; change: number };
}

/** A member's identity key: the ML-DSA-65 public key (1952 bytes, hex) and its SHA256 (hex). */
export interface PqIdentity {
  publicKey: Hex;
  publicKeyHash: Hex;
}

/**
 * Inputs of the stable policy id (`derivePolicyId`). Labels and transport endpoints are
 * deliberately absent; `memberIdentityKeys` are the n full identity public keys (hex, any order,
 * sorted canonically before hashing).
 */
export interface PqPolicyInputs {
  protocolVersion: number;
  scriptVersion: number;
  /** Genesis hash as Core prints it, hex (`NetworkParams.genesisHash`). */
  genesis: Hex;
  /** Ceremony nonce, 32 bytes hex. */
  nonce: Hex;
  paramSet: PqParamSet;
  threshold: number;
  memberIdentityKeys: Hex[];
}

// ---------------------------------------------------------------------------
// PQ public-key pools, treasury manifest and ceremony records (docs/PQ_CEREMONY.md)
// ---------------------------------------------------------------------------

/** Pool branch: 0 receive, 1 change. */
export type PqPoolBranch = 0 | 1;

/**
 * A signed batch of one member's spending public keys for one branch (plan §4.3). `keys[j]` is
 * the Core pk blob (1957 bytes, hex) of index `fromIndex + j`; `possessionProofs[j]` is an
 * ML-DSA-65 signature by that spending key over
 * `TaggedHash("TensorCash/PQ-pool-possession/v1", policyId32 || u8 branch || u32be(index) || sha256(pkBlob))`;
 * `identitySignature` is the member's identity signature over the canonical JSON of the batch
 * without that field (`signIdentityChallenge("TensorCash/PQ-pool-batch/v1", utf8(canonicalJson))`).
 * `previousBatchHash` is `sha256(canonicalJson(previous batch))` or 64 zeros for the first batch
 * of the branch. A 32-key batch is about 170 KB of JSON (32 × (1957 + 3309) bytes as hex).
 */
export interface PqKeyBatch {
  version: 1;
  network: NetworkName;
  genesis: Hex;
  policyId: Hex;
  member: PqIdentity;
  branch: PqPoolBranch;
  fromIndex: number;
  count: number;
  previousBatchHash: Hex;
  keys: Hex[];
  possessionProofs: Hex[];
  identitySignature: Hex;
}

/** One member's batches for one branch, in index order; `identity` is the member's key hash. */
export interface PqMemberPool {
  identity: Hex;
  batches: PqKeyBatch[];
}

/** A roster entry: identity and display label. Watch-only observers are not members. */
export interface PqMember {
  identity: PqIdentity;
  label: string;
}

/**
 * A member's signed acknowledgment of a manifest revision: identity signature over
 * `TaggedHash("TensorCash/PQ-config-ack/v1", revisionHash32)`.
 */
export interface PqConfigAck {
  version: 1;
  policyId: Hex;
  revision: number;
  revisionHash: Hex;
  identity: PqIdentity;
  signature: Hex;
  createdAt: string;
}

/**
 * The public PQ treasury configuration: spending-public, privacy-sensitive, kept by every
 * member with their recovery backup. `members` are canonically ordered by identity public key
 * (bytewise); `pools.receive[i]` / `pools.change[i]` belong to `members[i]`. `revisionHash` of a
 * manifest is `sha256(canonicalJson(manifest without acknowledgments))`; `previousRevisionHash`
 * chains replenishments (64 zeros for revision 1). Ready to fund = acknowledgments from all n
 * members over the current revision.
 */
export interface PqTreasuryManifest {
  version: 1;
  kind: 'pq-treasury';
  network: NetworkName;
  genesis: Hex;
  policy: PqPolicyKind;
  paramSet: PqParamSet;
  derivationVersion: 1;
  protocolVersion: number;
  scriptVersion: number;
  threshold: number;
  ceremonyNonce: Hex;
  members: PqMember[];
  policyId: Hex;
  pools: { receive: PqMemberPool[]; change: PqMemberPool[] };
  revision: number;
  previousRevisionHash: Hex;
  firstAddresses: { receive0: string; change0: string };
  acknowledgments: PqConfigAck[];
  createdAt: string;
}

/**
 * A member's ceremony record (round 1): identity, label and the proof
 * `signIdentityChallenge("TensorCash/PQ-ceremony-record/v2", invitationId32 || genesis32 || sha256(utf8(label)) || identityPk)`
 * where `invitationId` is the invitation's id (which binds the name, network, threshold,
 * participants, session token = `ceremonyId`, policy, nonce and genesis). Pools cannot be produced
 * before the roster is complete (the policy id depends on every identity), so `pools` is present
 * only when the member already knew the roster; otherwise batches follow as `PqKeyBatch`
 * messages against the roster (`PqRoster`).
 */
export interface PqMemberRecord {
  version: 1;
  kind: 'pq-member-record';
  network: NetworkName;
  genesis: Hex;
  ceremonyId: Hex;
  nonce: Hex;
  label: string;
  identity: PqIdentity;
  identityProof: Hex;
  pools?: { receive: PqKeyBatch[]; change: PqKeyBatch[] };
  createdAt: string;
}

/** The complete roster the coordinator publishes once all n records are in (public, unsigned; verified by recomputing `policyId`). */
export interface PqRoster {
  version: 1;
  kind: 'pq-roster';
  network: NetworkName;
  genesis: Hex;
  ceremonyId: Hex;
  nonce: Hex;
  protocolVersion: number;
  scriptVersion: number;
  threshold: number;
  members: PqMember[];
  policyId: Hex;
}

/** PQ extras of a ceremony draft / invitation: the nonce that enters the policy id and the genesis the ceremony is bound to. */
export interface PqCeremonyExtras {
  nonce: Hex;
  genesis: Hex;
  /** Invitation expiry, ISO 8601 (no secrets: the invitation is public). */
  expiresAt?: string;
}

/**
 * On-disk PQ vault (`keystore/pq-vault.ts`). Everything but `cipher` is the authenticated header
 * (AAD of the AES-256-GCM envelope); the ciphertext holds the BIP39 entropy and optional passphrase.
 */
export interface PqVaultFile {
  version: 1;
  kind: 'local-pq-vault';
  network: NetworkName;
  genesis: Hex;
  algorithm: PqParamSet;
  derivationVersion: 1;
  account: number;
  /** SHA256 of the identity public key, hex. */
  identityPublicKeyHash: Hex;
  /** The full identity public key, hex, so a configuration can be matched without unlocking. */
  identityPublicKey: Hex;
  kdf: { name: 'argon2id'; salt: Hex; memoryKiB: number; iterations: number; parallelism: number };
  cipher: { name: 'aes-256-gcm'; iv: Hex; ciphertext: Hex };
  createdAt: string;
}

/**
 * A PQ signer holds one member's recovery root while unlocked and signs with ML-DSA-65 keys
 * derived from it. Spending-key secret material exists only inside a call; seeds are never
 * exposed. `fingerprint` is the first 8 hex characters of `identity().publicKeyHash` so the
 * signer also satisfies the classical `KeyStore` surface the desktop session adopts (its
 * classical methods reject).
 */
export interface PqSigner extends KeyStore {
  readonly kind: 'local-pq-vault' | 'memory-pq';
  readonly algorithm: PqParamSet;
  readonly derivationVersion: 1;
  readonly network: NetworkName;
  readonly account: number;
  /** Identity public key and its hash (available while locked). */
  identity(): PqIdentity;
  /**
   * ML-DSA-65 signature (3309 bytes) over `identityChallengeDigest(domain, bytes)` with the
   * identity key, empty ML-DSA context. Signs setup, pool and channel records, never inputs.
   */
  signIdentityChallenge(domain: string, bytes: Uint8Array): Promise<Uint8Array>;
  /** Spending public key (1952 bytes) for `policyId`/`branch`/`index`. */
  spendingPublicKey(policyId: Hex | Uint8Array, branch: 0 | 1, index: number): Promise<Uint8Array>;
  /**
   * Pure ML-DSA-65 signature over the raw 32-byte digest, empty context, as Core's
   * `OP_CHECKMLSIG` verifies it (the hashtype byte is appended by the witness builder, not here).
   */
  signSpendDigest(policyId: Hex | Uint8Array, branch: 0 | 1, index: number, digest32: Uint8Array): Promise<Uint8Array>;
}

// ---------------------------------------------------------------------------
// Chain data (Esplora-compatible wallet API)
// ---------------------------------------------------------------------------

export interface TxStatus {
  confirmed: boolean;
  blockHeight?: number;
  blockHash?: Hex;
  blockTime?: number;
}

export interface Utxo {
  txid: Hex;
  vout: number;
  valueSats: bigint;
  status: TxStatus;
}

/** Esplora-shaped transaction summary as served by GET /tx/{txid}. */
export interface EsploraTx {
  txid: Hex;
  version: number;
  locktime: number;
  size?: number;
  weight?: number;
  fee?: number;
  vin: Array<{
    txid: Hex;
    vout: number;
    is_coinbase: boolean;
    sequence: number;
    prevout: { scriptpubkey: Hex; scriptpubkey_address?: string; value: number } | null;
    witness?: Hex[];
    scriptsig?: Hex;
  }>;
  vout: Array<{ scriptpubkey: Hex; scriptpubkey_type: string; scriptpubkey_address?: string; value: number }>;
  status: { confirmed: boolean; block_height?: number; block_hash?: Hex; block_time?: number };
}

export interface ChainTip {
  height: number;
  hash: Hex;
}

export interface ChainBackend {
  readonly network: NetworkName;
  tip(): Promise<ChainTip>;
  /** Batch route: POST /wallet/addresses. Returns per-address stats and UTXOs under one pinned view. */
  addresses(addresses: string[]): Promise<{ tip: ChainTip; view: string; entries: AddressEntry[] }>;
  utxos(address: string): Promise<Utxo[]>;
  history(address: string, opts?: { lastSeenTxid?: Hex }): Promise<EsploraTx[]>;
  tx(txid: Hex): Promise<EsploraTx>;
  txHex(txid: Hex): Promise<Hex>;
  txStatus(txid: Hex): Promise<TxStatus>;
  outspends(txid: Hex): Promise<Array<{ spent: boolean; txid?: Hex; vin?: number; status?: TxStatus }>>;
  feeEstimates(): Promise<Record<string, number>>; // target blocks -> sat/vB
  broadcast(rawTxHex: Hex): Promise<Hex>; // txid
  /**
   * TSCScan `/v1` asset routes on the same host as the Esplora API (discovery and cross-checks
   * only; balances and registrations are read from raw transactions). Absent when the backend
   * has no TSCScan.
   */
  tscscan?: TscScanClient;
}

// ---------------------------------------------------------------------------
// TSCScan /v1 asset routes (envelope `{ "data": ... }`, observed fields flattened)
// ---------------------------------------------------------------------------

/** `GET /v1/assets/{id}`; observed fields are flattened to their value when `state == "known"`. */
export interface TscScanAssetDetail {
  id: string;
  /** Latest issuer registration (or rotation) transaction. */
  registration_txid?: Hex;
  symbol?: string;
  precision?: number;
  policy_bits?: number;
  parent_id?: string;
  first_seen_height?: number;
  updated_height?: number;
}

/** `GET /v1/assets/{id}/policy`. */
export interface TscScanAssetPolicy {
  asset_id: Hex;
  policy_bits: number;
  mint_allowed: boolean;
  burn_allowed: boolean;
  burn_requires_icu: boolean;
  burn_requires_joint_authorization: boolean;
  kyc_required: boolean;
  policy_epoch?: number;
  quorum_bps?: number;
  delegate_asset_id?: Hex;
  documents_available?: boolean;
}

/** One row of `GET /v1/addresses/{a}/assets`; `balanceUnits` is undefined when TSCScan reports it unknown. */
export interface TscScanAddressAsset {
  asset_id: Hex;
  balanceUnits?: bigint;
  precision?: number;
  symbol?: string;
  parent_id?: string;
}

/**
 * `GET /v1/assets/{id}/supply`: `issued`, `burned`, `current` and `issuance_cap` amounts
 * (`{ precision, units }`, units as decimal strings) plus `unlimited`. Cap 0 = uncapped.
 */
export interface TscScanAssetSupply {
  asset_id: Hex;
  issuedUnits: bigint;
  burnedUnits: bigint;
  currentUnits: bigint;
  issuanceCapUnits: bigint;
  unlimited: boolean;
  precision?: number;
}

/** One row of `GET /v1/assets?limit=N&page=P` (listing used for the ticker-uniqueness pre-check). */
export interface TscScanAssetListRow {
  id: AssetId;
  symbol?: string;
  precision?: number;
  policy_bits?: number;
  currentUnits?: bigint;
}

export interface TscScanAssetListPage {
  assets: TscScanAssetListRow[];
  /** `page.total` / `page.total_pages` when the route serves them. */
  total?: number;
  totalPages?: number;
}

export interface TscScanClient {
  asset(id: AssetId): Promise<TscScanAssetDetail>;
  assetPolicy(id: AssetId): Promise<TscScanAssetPolicy>;
  addressAssets(address: string): Promise<TscScanAddressAsset[]>;
  /** Supply route; optional on older clients and test doubles (absent ⇒ supply unknown). */
  assetSupply?(id: AssetId): Promise<TscScanAssetSupply>;
  /** Asset listing, one page (1-based) of `limit` rows; optional as above. */
  listAssets?(page: number, limit?: number): Promise<TscScanAssetListPage>;
}

export interface AddressEntry {
  address: string;
  chainStats: { fundedTxoCount: number; fundedTxoSum: bigint; spentTxoCount: number; spentTxoSum: bigint; txCount: number };
  mempoolStats: { fundedTxoCount: number; fundedTxoSum: bigint; spentTxoCount: number; spentTxoSum: bigint; txCount: number };
  utxos?: Utxo[];
  error?: string;
}

// ---------------------------------------------------------------------------
// Output classification (what an output actually is)
// ---------------------------------------------------------------------------

export type OutputClass =
  | { kind: 'plain' }
  | { kind: 'coinbase'; matureAtHeight: number }
  | { kind: 'asset'; assetId: Hex; amount: bigint; tlvType: number }
  /** IssuerReg-bearing output (type 0x10): the ICU bond of `assetId` (explorer notation). Unspent on a treasury script it is an ICU held by this treasury. */
  | { kind: 'icu'; tlvType: number; assetId: AssetId }
  /**
   * Previous name of the ICU class, kept so consumers of it keep compiling. Produced only for an
   * IssuerReg-typed extension whose payload Core would not parse as a registration
   * (ParseIssuerReg returns nullopt), never for a valid ICU, which is `icu`.
   */
  | { kind: 'issuer-reg'; tlvType: number }
  /** ICU text chunk (0x30) or ICU key-wrap record (0x31): never spent, never emitted by this wallet. */
  | { kind: 'icu-text'; tlvType: number }
  | { kind: 'unknown-extension'; tlvType: number };

export interface ClassifiedUtxo extends Utxo {
  address: string;
  scriptPubKey: Hex;
  /** Which descriptor branch and index produced this address. */
  branch: 0 | 1;
  index: number;
  class: OutputClass;
  /** True when the output may be selected to fund a native TSC payment. */
  spendableForTsc: boolean;
  confirmations: number;
}

// ---------------------------------------------------------------------------
// Issued assets
// ---------------------------------------------------------------------------

/** Asset id in explorer/RPC notation: the 32 raw TLV bytes reversed, lowercase hex (as TSCScan prints it). */
export type AssetId = Hex;

/**
 * What the wallet knows about an asset's registration, parsed from the IssuerReg output of the
 * registration (or latest rotation) transaction fetched from the chain. TSCScan values are a
 * cross-check only; a disagreement is recorded in `tscscan.mismatch` and the parse wins.
 */
export interface AssetRegistry {
  assetId: AssetId;
  /** The 32 raw bytes as they sit in the TLV, hex. */
  rawId: Hex;
  ticker?: string;
  /** Undefined when the registration leaves decimals unset (0xFF). */
  decimals?: number;
  policyBits: number;
  /** `allowed_spk_families` as registered (0 = Core default applies; see `effectiveFamilies`). */
  allowedFamilies: number;
  kycRequired: boolean;
  tfrAnchorRequired: boolean;
  wrapRequired: boolean;
  burnJointRequired: boolean;
  /** The transaction TSCScan names as the current registration (the live ICU); its bytes hash to this id. */
  registrationTxid: Hex;
  /** Output index of the IssuerReg in `registrationTxid`: `registrationTxid:registrationVout` is the current ICU outpoint. */
  registrationVout?: number;
  /**
   * The IssuerReg output extension of the current registration, hex (type || compactsize || payload),
   * i.e. every field a rotation must restate; parse with `parseOutputExtension` + `parseIssuerReg`.
   * Kept as hex so the cache stays plain JSON.
   */
  registrationExt?: Hex;
  source: 'registration-tx' | 'rotation-tx';
  /**
   * When the current registration omits the ticker and/or decimals, the earlier registration in
   * the ICU input chain that set them (Core carries both forward unchanged on every rotation).
   */
  inheritedFrom?: Hex;
  /** Rotations walked back from `registrationTxid` to the registration that first set the fields. */
  icuDepth?: number;
  fetchedAt: string;
  tscscan?: {
    symbol?: string;
    precision?: number;
    policyBits?: number;
    kycRequired?: boolean;
    /**
     * Fields on which TSCScan disagrees with the parsed registration: `symbol`, `precision`,
     * `policy_bits`, `kyc_required`, `mint_allowed`, `burn_allowed`, `burn_requires_icu`,
     * `burn_requires_joint_authorization`. Any entry other than symbol/precision blocks sending.
     */
    mismatch?: string[];
    /** The cross-check could not be refreshed on this load; it is the last one recorded (`checkedAt`). */
    stale?: boolean;
    /** When the detail route (symbol, precision, policy bits) was last read from TSCScan. */
    checkedAt?: string;
    /**
     * When the policy route was last read, i.e. when the policy verdicts (`kycRequired`, the
     * policy flags in `mismatch`) were last evaluated. Older than `checkedAt` after a partial
     * outage in which the verdicts were carried over from an earlier load.
     */
    policyCheckedAt?: string;
  };
}

/** Per-asset holding of the treasury, aggregated from asset-tagged UTXOs on treasury scripts. */
export interface AssetBalance {
  assetId: AssetId;
  registry?: AssetRegistry;
  confirmedUnits: bigint;
  pendingUnits: bigint;
  utxoCount: number;
  /** The asset's effective script families admit the treasury's P2WSH scripts. */
  holdable: boolean;
  /** The wallet can build and sign a plain transfer of this asset. */
  sendable: boolean;
  blockedReason?: string;
}

export interface AssetPaymentRequest {
  assetId: AssetId;
  recipient: string;
  units: bigint;
  feeRateSatPerVb: number;
  /** Optional coin control over the asset inputs: restrict to these outpoints (all must carry this asset). */
  inputs?: Array<{ txid: Hex; vout: number }>;
  memo?: string;
}

// ---------------------------------------------------------------------------
// Issuer side (docs/ASSET_FULL_FUNCTIONALITY_SPEC_2026-11-06.md §8)
// ---------------------------------------------------------------------------

export type AssetOperationKind = 'transfer' | 'distribute' | 'register' | 'mint' | 'burn' | 'rotate';

/**
 * Every field of a v1/v2 IssuerReg payload except the raw id (docs/ASSET_RULES.md §1.3);
 * `assetId` in explorer notation. `buildIssuerReg` encodes exactly these, `parseIssuerReg`
 * decodes them (plus `rawId`). Commitments and the salt are 32/16 raw bytes as lowercase hex.
 */
export interface IssuerRegFields {
  assetId: AssetId;
  policyBits: number;
  allowedFamilies: number;
  /** 0x01 (v1) or 0x02 (v2, with `delegateAssetId`). */
  formatVersion: number;
  /** Undefined ⇒ `ticker_len 0` (inherited on rotation). */
  ticker?: string;
  /** Undefined ⇒ 0xFF (unset / inherited). */
  decimals?: number;
  unlockFeesSats: bigint;
  kycFlags: number;
  zkVkCommitment: Hex;
  maxRootAge: number;
  tfrFlags: number;
  complianceRootCommit: Hex;
  icuFlags: number;
  issuanceCapUnits: bigint;
  icuCtxtCommit: Hex;
  icuPlainCommit: Hex;
  kdfSalt: Hex;
  icuVersion: number;
  icuVisibility: number;
  corePolicyCommit: Hex;
  policyEpoch: number;
  policyQuorumBps: number;
  /** v2 only: compliance delegate asset id (explorer notation). */
  delegateAssetId?: AssetId;
}

export interface RegistrationRequest {
  /** Omitted ⇒ 32 random bytes. */
  assetId?: AssetId;
  /** Root ticker grammar (3..11 chars, `[A-Z][A-Z0-9]*`), not TSC/XTC/TAK. */
  ticker: string;
  /** 0..18; undefined ⇒ 0xFF (unset). */
  decimals?: number;
  /** MINT_ALLOWED | BURN_ALLOWED | BURN_REQUIRE_ICU only; any other bit is refused. */
  policyBits: number;
  /** Non-zero family mask; the wallet default is SPK_DEFAULT_ALLOWED. */
  allowedFamilies: number;
  /** ≥ 500 000 000 sats (5 TSC). */
  bondSats: bigint;
  /** Default = bondSats; must be ≥ bondSats. */
  unlockFeesSats?: bigint;
  /** Default 0n (uncapped). */
  issuanceCapUnits?: bigint;
  feeRateSatPerVb: number;
  memo?: string;
  /**
   * Optional ICU document (spec §11): the chunk payload (cipher plus the 40-byte "ICUM" trailer,
   * ready to be the 0x30 TLV payload) and the IssuerReg fields it commits to. The registration
   * then carries one ICU_TEXT_CHUNK output (546 sats at the internal index after the ICU, as
   * Core's `registerasset` does) and writes `icuCtxtCommit`, `icuPlainCommit`, `kdfSalt`,
   * `icuVisibility` and `icuVersion` from here.
   */
  icu?: IcuDocumentAttachment;
}

/** Prepared ICU document for a registration (produced by `assets/icu.ts`; raw byte order for the commits). */
export interface IcuDocumentAttachment {
  chunkPayload: Uint8Array;
  /** `SHA256(chunkPayload without trailer)`, hex in the byte order the IssuerReg carries. */
  ctxtCommitRaw: Hex;
  plainCommitRaw: Hex;
  /** 16 bytes, hex. */
  kdfSalt: Hex;
  visibility: 0 | 1;
  icuVersion: number;
}

export interface MintRequest {
  assetId: AssetId;
  units: bigint;
  /** Defaults to the treasury's next external address; any address in the family mask is allowed. */
  recipient?: string;
  /** Defaults to the previous bond; must be ≥ it. */
  newBondSats?: bigint;
  feeRateSatPerVb: number;
  memo?: string;
}

export interface BurnRequest {
  assetId: AssetId;
  units: bigint;
  newBondSats?: bigint;
  feeRateSatPerVb: number;
  memo?: string;
}

export interface RotateRequest {
  assetId: AssetId;
  newBondSats?: bigint;
  feeRateSatPerVb: number;
  memo?: string;
}

export interface DistributionRequest {
  assetId: AssetId;
  recipients: Array<{ address: string; units: bigint }>;
  feeRateSatPerVb: number;
  memo?: string;
}

/** The operation a proposal declares; review recomputes everything from the bytes and the chain regardless. */
export interface ProposalAssetOperation {
  kind: AssetOperationKind;
  assetId: AssetId;
  /** Minted / burned / total distributed (or transferred) units. */
  units?: bigint;
  recipients?: Array<{ address: string; units: bigint }>;
  /** ICU spent and re-issued (mint, burn, rotate): `changeIndex` is the internal index of the new ICU output. */
  icu?: { inputTxid: Hex; inputVout: number; outputIndex: number; bondSats: bigint; prevBondSats: bigint; changeIndex: number };
  /** Registration: the fields written (and, for an ICU spend, the fields restated). */
  registration?: IssuerRegFields;
  /** Registration: the ICU output index, bond and internal index of the new ICU. */
  icuOutput?: { outputIndex: number; bondSats: bigint; changeIndex: number };
  /** Registration with an ICU document: the ICU_TEXT_CHUNK carrier output (546 sats, internal `changeIndex`) and its payload hash. */
  icuChunk?: { outputIndex: number; changeIndex: number; ctxtCommit: Hex; payloadBytes: number };
  assetChange?: { units: bigint; changeIndex: number };
}

/** An ICU held by this treasury: an unspent IssuerReg-bearing output on a treasury script (spec §4). */
export interface IssuedAsset {
  assetId: AssetId;
  ticker?: string;
  decimals?: number;
  icu: { txid: Hex; vout: number; bondSats: bigint; confirmed: boolean; changeIndex: number };
  /** Parsed from the held output. */
  registration: IssuerRegFields;
  /** Chain-verified registry when loadable. */
  registry?: AssetRegistry;
  /**
   * `current`: the registry names this outpoint; `pending`: the held output is unconfirmed;
   * `superseded`: the registry names another registration (shown, never acted on);
   * `unindexed`: TSCScan has no entry yet (operations allowed once confirmed).
   */
  icuStatus: 'current' | 'pending' | 'superseded' | 'unindexed';
  supply?: { issuedUnits: bigint; burnedUnits: bigint; liveUnits: bigint; rotationCount?: number };
  canMint: boolean;
  canBurn: boolean;
  /** Why every operation on this ICU (rotation included) is refused. */
  blockedReason?: string;
  /** Why mint and burn are refused while a rotation is not (KYC / TFR flags: Core demands extensions the wallet never emits when units move). */
  unitsBlockedReason?: string;
}

export interface AssetLookup {
  registry: AssetRegistry;
  holdable: boolean;
  sendable: boolean;
  blockedReason?: string;
  supply?: { issuedUnits: bigint; burnedUnits: bigint; liveUnits: bigint; issuanceCapUnits: bigint; unlimited: boolean };
}

// ---------------------------------------------------------------------------
// Wallet state and engine
// ---------------------------------------------------------------------------

export interface WalletSnapshot {
  configId: Hex;
  tip: ChainTip;
  view?: string;
  confirmedSats: bigint;
  pendingSats: bigint;
  spendableSats: bigint;
  utxos: ClassifiedUtxo[];
  transactions: WalletTx[];
  nextExternalIndex: number;
  nextInternalIndex: number;
  scannedAt: string;
  /** Asset holdings per asset id (absent when no asset-tagged UTXO is held). */
  assets?: AssetBalance[];
  /** One entry per ICU held on a treasury script (absent when none). */
  issued?: IssuedAsset[];
  /**
   * PQ treasuries only: pool state after the scan. `published` is the number of entries per
   * branch the manifest covers, `capacity` the entries not yet used on chain
   * (`published − nextExternalIndex` / `published − nextInternalIndex`), `lowPool` whether either
   * branch is at or below the low-pool mark (`PQ_LOW_POOL_MIN` entries or a quarter of the
   * published count, whichever is larger). A PQ engine refuses a new receive address or new
   * change once the respective capacity is 0 (no reuse, no weaker policy).
   */
  pq?: { published: { receive: number; change: number }; capacity: { receive: number; change: number }; lowPool: boolean };
}

export interface WalletTx {
  txid: Hex;
  status: TxStatus;
  confirmations: number;
  /** Net effect on the treasury in sats (received − sent, fee included when we paid it). */
  netSats: bigint;
  feeSats?: bigint;
  direction: 'in' | 'out' | 'self';
  /** Our outputs in this tx and their classes. */
  ourOutputs: Array<{ vout: number; valueSats: bigint; branch: 0 | 1; index: number; class: OutputClass }>;
  /** Outputs to others when direction is out. */
  counterparties: Array<{ address?: string; valueSats: bigint }>;
  hasExtensions: boolean;
}

export interface PaymentRequest {
  outputs: Array<{ address: string; valueSats: bigint }>;
  feeRateSatPerVb: number;
  /** Optional coin control: restrict inputs to these outpoints. */
  inputs?: Array<{ txid: Hex; vout: number }>;
  memo?: string;
}

export interface Proposal {
  version: 1;
  configId: Hex;
  network: NetworkName;
  /** sha256 of the unsigned transaction (txid), hex. Signatures commit to this. */
  unsignedTxId: Hex;
  psbtBase64: string;
  memo?: string;
  createdAt: string;
  createdBy?: Fingerprint;
  /** Fingerprints that have contributed partial signatures in `psbtBase64`. */
  signedBy: Fingerprint[];
  feeSats: bigint;
  outputs: Array<{ address: string; valueSats: bigint; isChange: boolean; changeIndex?: number }>;
  /**
   * Internal index of the TSC change output when the build added one (the index the builder
   * took from the host's reservation hook or from the scan; see `WalletEngineOptions.changeIndexFor`).
   * Asset change, ICU and chunk indices stay on `asset` / `operation`.
   */
  changeIndex?: number;
  /**
   * Present for an asset transfer built by `createAssetProposal`: output 0 carries `units` of
   * `assetId` to `recipient`, output 1 (when `changeUnits > 0`) returns the rest to the treasury
   * internal address at `changeIndex`. A proposal without this field must not carry any output extension.
   */
  asset?: { assetId: AssetId; units: bigint; recipient: string; changeUnits: bigint; changeIndex?: number };
  /**
   * Declared asset operation for distributions and issuer operations (register, mint, burn,
   * rotate). Co-signer interchange must carry it; review recomputes everything from the bytes.
   */
  operation?: ProposalAssetOperation;
  /** Non-blocking findings recorded at creation (e.g. TSCScan could not be consulted for a registration). */
  warnings?: string[];
}

/** The core engine the desktop app and the flow tests drive. */
export interface WalletEngine {
  readonly network: NetworkParams;
  readonly config: TreasuryConfig;
  /** Scan with gap limit and return a fresh snapshot. */
  refresh(): Promise<WalletSnapshot>;
  snapshot(): WalletSnapshot | null;
  /** Next unused external address (does not persist allocation; caller records it). */
  nextReceiveAddress(): Promise<{ address: string; index: number }>;
  /** Derive the address at branch/index for verification displays. */
  deriveAddress(branch: 0 | 1, index: number): string;
  /** Build an unsigned proposal with coin selection over spendable UTXOs and change to the internal branch. */
  createProposal(req: PaymentRequest): Promise<Proposal>;
  /**
   * Build an unsigned plain transfer of one issued asset (docs/ASSET_RULES.md §3): asset inputs
   * largest-first, 1000-sat carriers, asset change to the internal branch, TSC fee inputs from
   * plain spendable UTXOs. Refuses assets the treasury cannot hold or send.
   */
  /** `extra.dek`: the asset's DEK for a WRAP_REQUIRED asset (else the engine's `dekProvider` is asked). */
  createAssetProposal(req: AssetPaymentRequest, extra?: { dek?: Uint8Array }): Promise<Proposal>;
  /** Registration facts for an asset (cached once parsed); rejects when no registration can be found. */
  assetRegistry(assetId: AssetId): Promise<AssetRegistry>;
  /** Spec §3.1: register a new asset with the ICU bond on the treasury's internal branch. */
  createRegistrationProposal(req: RegistrationRequest): Promise<Proposal>;
  /** Spec §3.2: spend the held ICU, re-issue it, mint `units` to the recipient. */
  createMintProposal(req: MintRequest, extra?: { dek?: Uint8Array }): Promise<Proposal>;
  /** Spec §3.3: spend the held ICU and treasury-held units, re-issue the ICU. */
  createBurnProposal(req: BurnRequest): Promise<Proposal>;
  /** Spec §3.4: move or raise the bond; no asset outputs. */
  createRotationProposal(req: RotateRequest): Promise<Proposal>;
  /** Spec §3.5: one asset to N recipients in one transaction. */
  createDistributionProposal(req: DistributionRequest, extra?: { dek?: Uint8Array }): Promise<Proposal>;
  /** Registry plus holdable/sendable verdicts and supply (when TSCScan serves it) for any asset id. */
  lookupAsset(assetId: AssetId): Promise<AssetLookup>;
  /**
   * Validate that a PSBT matches this treasury (inputs ours, change ours at plausible index,
   * network ok). `expected` is the envelope's declaration: a `ProposalAssetOperation` (or the
   * legacy `Proposal.asset` record), `null` for a native payment, undefined to infer from the bytes.
   */
  reviewProposal(psbtBase64: string, expected?: ProposalAssetOperation | Proposal['asset'] | null): Promise<ProposalReview>;
  /** Add this device's partial signatures using the given KeyStore. */
  signProposal(p: Proposal, ks: KeyStore): Promise<Proposal>;
  /** Merge partial signatures from several copies of the same proposal. */
  combineProposals(ps: Proposal[]): Proposal;
  /**
   * Finalise when the threshold is reached; returns the raw transaction hex and its txid.
   * Re-verifies every input against the chain at the time of the call (fresh tip, fresh spend
   * state) and re-runs the full review and fee policy, so an input spent since the last review
   * is refused here. Rejects if signatures are insufficient or the review fails.
   */
  finalizeProposal(p: Proposal): Promise<{ rawTxHex: Hex; txid: Hex }>;
  broadcast(rawTxHex: Hex): Promise<Hex>;
}

export interface ProposalReview {
  ok: boolean;
  problems: string[];
  inputs: Array<{ txid: Hex; vout: number; valueSats: bigint; ours: boolean; class?: OutputClass }>;
  outputs: Array<{
    address: string;
    valueSats: bigint;
    isChange: boolean;
    changeIndex?: number;
    hasExtension: boolean;
    /** Decoded from the output extension bytes: an AssetTag carrier, the issuer control output, or an ICU document chunk. */
    role?: 'asset' | 'issuer-reg' | 'icu-chunk';
    /** AssetTag carrier: the units it moves (explorer-notation asset id), as decoded from the bytes. */
    asset?: { assetId: AssetId; units: bigint };
  }>;
  feeSats: bigint;
  feeRateSatPerVb: number;
  signedBy: Fingerprint[];
  threshold: number;
  complete: boolean;
  /** Per-asset accounting when the transaction touches issued assets (inputs by prevout class, outputs by AssetTag). */
  assets?: Array<{
    assetId: AssetId;
    inUnits: bigint;
    outUnits: bigint;
    recipientUnits: bigint;
    changeUnits: bigint;
    changeIndex?: number;
    conserved: boolean;
    problems: string[];
  }>;
  /** Non-blocking findings (the review is still `ok`). */
  warnings?: string[];
  /** The operation the bytes perform (declared, or inferred for a bare PSBT) and whether it holds together. */
  operation?: { kind: AssetOperationKind; assetId: AssetId; ok: boolean; problems: string[] };
  /** ICU facts for an ICU-spending or registering transaction. */
  issuer?: {
    icuInput: { txid: Hex; vout: number } | null;
    icuOutput: { index: number; bondSats: bigint; prevBondSats: bigint; derivesToTreasury: boolean; fieldsUnchanged: boolean; problems: string[] } | null;
    registration?: { fields: IssuerRegFields; problems: string[] };
  };
}

// ---------------------------------------------------------------------------
// Ceremony state machine
// ---------------------------------------------------------------------------

export type CeremonyState =
  | {
      step: 'draft';
      name: string;
      network: NetworkName;
      threshold: number;
      participants: number;
      sessionToken: string;
      policy?: ScriptPolicy;
      pq?: PqCeremonyExtras;
      /**
       * PQ ceremony: the batches this device exported (`createPqBatches` + `rememberPqBatches`),
       * so a re-export returns the same signed copy (hedged signing would otherwise produce a
       * different batch with a different hash; only the published one counts).
       */
      myPqBatches?: PqKeyBatch[];
    }
  | {
      step: 'collecting';
      draft: Extract<CeremonyState, { step: 'draft' }>;
      /** Classical records; empty for a PQ ceremony. */
      records: CosignerRecord[];
      /** PQ ceremony: member records (round 1) and the key batches received against the roster (round 2). */
      pqRecords?: PqMemberRecord[];
      pqBatches?: PqKeyBatch[];
    }
  | { step: 'assembled'; config: TreasuryConfig }
  | { step: 'confirmed'; config: TreasuryConfig };

/**
 * Public invitation the coordinator shares with every participant (BSMS-style "round 1").
 * Importing it on another device yields a draft bound to the same session token, so the
 * records produced there are accepted by the coordinator. Contains nothing secret.
 */
export interface CeremonyInvitation {
  version: 1;
  name: string;
  network: NetworkName;
  threshold: number;
  participants: number;
  sessionToken: string;
  createdAt: string; // ISO 8601
  /** Display-only label of the coordinator. */
  coordinatorLabel?: string;
  /** Script policy of the treasury; absent means `wsh-sortedmulti`. Part of the invitation id when set. */
  policy?: ScriptPolicy;
  /** PQ ceremony: nonce, genesis and expiry (public; part of the invitation id). */
  pq?: PqCeremonyExtras;
}

/** Result of a PQ ceremony verification, the PQ counterpart of `CeremonyEngine.verify`'s result. */
export interface PqVerifyResult {
  ok: boolean;
  problems: string[];
  firstAddresses: { receive0: string; change0: string };
  /** Members (by identity key hash) whose acknowledgment of this revision verified. */
  acknowledgedBy: Hex[];
  readyToFund: boolean;
}

export interface CeremonyEngine {
  createDraft(input: { name: string; network: NetworkName; threshold: number; participants: number; policy?: ScriptPolicy }): CeremonyState;
  /** Validate and add a record: network match, coin type, duplicate key, proof signature. */
  addRecord(state: CeremonyState, record: CosignerRecord): CeremonyState;
  assemble(state: CeremonyState): CeremonyState; // builds descriptors, checksums, first addresses, id
  /**
   * Re-derive from the config on this device and compare to the embedded values. With `own`,
   * the result's `membership` says whether this device's key is in the treasury: `verified`
   * only when a derived account key (`OwnAccountKey`) or PQ identity equals the record naming
   * it; a bare fingerprint can at most be "named" (`unverified`) and is flagged when absent.
   */
  verify(config: TreasuryConfig, own?: OwnIdentity): ConfigVerification;
  /**
   * Attach this device's receipt. With `own`, membership must verify (`confirmedBy` is recorded);
   * without it the receipt records nothing about the local key.
   */
  confirm(config: TreasuryConfig, own?: OwnIdentity): TreasuryConfig;
  /** Invitation for the participants, from a draft or collecting state (coordinator side). */
  exportInvitation?(state: CeremonyState, opts?: { coordinatorLabel?: string }): CeremonyInvitation;
  /**
   * Draft state bound to the invitation's session token (participant side). Rejects
   * invitations for another network than the engine is bound to, bad thresholds and
   * malformed tokens.
   */
  importInvitation?(invitation: CeremonyInvitation): CeremonyState;
  /**
   * Stable identifier of an invitation for display and QR comparison: sha256 of the
   * canonical JSON of `{version, name, network, threshold, participants, sessionToken}`
   * (createdAt and coordinatorLabel excluded), hex.
   */
  invitationId?(invitation: CeremonyInvitation): Hex;

  // ---- PQ ceremony (policy `tr2-mldsa65-threshold`; docs/PQ_CEREMONY.md). Present on the core engine only. ----

  /** This member's round-1 record for a PQ draft (identity + proof), signed with the PQ signer. */
  createPqMemberRecord?(signer: PqSigner, state: CeremonyState, label: string, opts?: { createdAt?: string }): Promise<PqMemberRecord>;
  /** Coordinator: validate (network, genesis, ceremony id, nonce, proof, duplicate identity) and add a member record. */
  addPqRecord?(state: CeremonyState, record: PqMemberRecord): CeremonyState;
  /** Coordinator: the roster once all n records are in (policy id fixed); members build batches against it. */
  pqRoster?(state: CeremonyState): PqRoster;
  /**
   * This member's initial pools (receive + change batches) for a roster that contains its identity.
   * With `state` (this device's draft or collecting state) the roster is also checked against the
   * invitation facts (network, genesis, ceremony id, nonce, threshold, participants) and the copy
   * remembered by `rememberPqBatches` for the same policy id and identity is returned unchanged
   * instead of a freshly signed one.
   */
  createPqBatches?(signer: PqSigner, roster: PqRoster, opts?: { count?: number; state?: CeremonyState }): Promise<PqKeyBatch[]>;
  /** Store this device's exported batches on the draft (`myPqBatches`), so a later `createPqBatches` with the state returns the same copy. */
  rememberPqBatches?(state: CeremonyState, batches: PqKeyBatch[]): CeremonyState;
  /** Coordinator: verify (identity signature, possession proofs, continuity, membership) and add batches. */
  addPqBatches?(state: CeremonyState, batches: PqKeyBatch[]): CeremonyState;
  /** This member's acknowledgment of the manifest revision in `config.pq` after a successful local verification. */
  createPqAcknowledgment?(signer: PqSigner, config: TreasuryConfig, opts?: { createdAt?: string }): Promise<PqConfigAck>;
  /** Add a verified acknowledgment to `config.pq` (idempotent for an identical one). */
  addPqAcknowledgment?(config: TreasuryConfig, ack: PqConfigAck): TreasuryConfig;
  /** Full PQ verification with the acknowledgment and ready-to-fund facts (`verify` covers `ok`/`problems` only). */
  verifyPq?(config: TreasuryConfig, ownIdentity?: PqIdentity): PqVerifyResult;
}

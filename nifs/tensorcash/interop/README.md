# Independent official wallet oracle

Run from this directory with Node 22 (validated with v22.23.4 / npm 10.9.9):

    npm ci --cache .npm-cache --ignore-scripts --no-audit --no-fund
    npm run generate
    npm run check

Dependencies are locked in package-lock.json. Exact direct versions: @noble/post-quantum 0.7.1, @noble/hashes 2.0.1, @noble/curves 2.0.1, @scure/base 2.0.0, @scure/bip32 2.0.1, @scure/bip39 2.0.1, micro-packed 0.7.3, tsx 4.20.6. node_modules and the npm cache stay here and are ignored.

The generator writes ../test/fixtures/wallet-oracle-v1.json. Check mode regenerates in memory and compares complete bytes without changing the fixture. Both modes validate vendored source hashes, three ACVP keygen cases, deterministic and hedged ACVP signatures, the ACVP verification case, and both captured Core signature digests and signatures (including output extensions). Generated payments round-trip through the official parser and both official sighash implementations must agree. No Rust output is an oracle input. No RPC is used.

## Source and license provenance

oracle/official contains the complete 14-file transitive dependency closure used for cryptography, derivation, address, policy, witness, and transaction operations. The modules are copied byte-for-byte from ../tensorcash-research/apps/light-treasury-wallet/packages/core/src, snapshot at repository HEAD 443ebf7ef6a717116ef80f9d6e1f38711905c77a. oracle/source-manifest.json records every copied path and SHA-256; hashes identify the actual snapshot independently of repository worktree state. The official package declares Apache-2.0 AND MIT. The repository Apache license and vendored signer MIT copyright/license are preserved as oracle/LICENSE.Apache-2.0 and oracle/LICENSE.signer-MIT. oracle/generate.ts and oracle/crossverify.ts are new harness code; official modules are unmodified.

../test/fixtures/core-mldsa65-signature.json and ../test/fixtures/mldsa65-acvp-fips204.json are exact byte copies of official src/pq/__tests__/vectors files. The former contains two TensorCash Core 1.2.1 development liboqs signatures captured by the official regtest interop test; the latter is the official wallet subset of liboqs tests/ACVP_Vectors / NIST ML-DSA FIPS 204 internalProjection.json. They retain original source fields and schema. The generated fixture records their SHA-256 hashes.

ML-DSA seed32 means FIPS 204 KeyGen_internal, never global OQS RNG. Signing uses the external pure ML-DSA interface, empty context, over msg32. rnd0 is extraEntropy:false; fixed-rnd is explicit 32-byte entropy 20..3f. Secret keys are expanded 4032-byte FIPS keys. Public keys are 1952 bytes, raw signatures 3309 bytes, pk blobs 1957 bytes (0141fda007 || public key).

All seeds, mnemonics, expanded secrets and addresses are public synthetic vectors. Do not fund them. BIP39 uses the standard abandon/about mnemonic with passphrase TREZOR. Genesis is the explicit official regtest value 294d0915be3486fb43e312d534187a43e81f67dbb39e0e66b3df24ce3dd1b1f1, decoded in display order without reversal. account=0, policyId=42 repeated 32 bytes, branch=0, index=7.

## Exact generated fixture schema

Every property shown below is present; there are no optional fields. Hex is lowercase without a prefix. Amounts are decimal strings. txids/wtxids are Core display order. Numeric fields are JSON numbers. Each input references keygen.id through keyId; address entries reference that id too. Signature and witness arrays follow input order. Witness stack order is [rawSig || 01, leafScript, controlBlock].

~~~typescript
type Hex = string;
type Sats = string;
type Network = 'mainnet' | 'testnet' | 'regtest';
type Fixture = {
  schemaVersion: 1;
  provenance: {
    oracle: string; upstreamRevision: string; sourceManifest: string;
    keygen: string; signing: string; warning: string;
    copiedFixtures: {name: string; sha256: Hex}[];
  };
  keygen: {
    id: string; seedHex: Hex; publicKeyHex: Hex; secretKeyHex: Hex; pkBlobHex: Hex;
  }[];
  signatures: {
    id: string; keyId: string; msg32Hex: Hex; rndHex: Hex;
    signatureHex: Hex; verified: true;
  }[];
  derivation: {
    mnemonic: string; passphrase: string; bip39SeedHex: Hex; rootHex: Hex;
    genesisHex: Hex; genesisByteOrder: string; account: 0; policyIdHex: Hex;
    branch: 0; index: 7; spendInfoHex: Hex; spendingSeedHex: Hex; identitySeedHex: Hex;
    publicKeyHex: Hex; secretKeyHex: Hex;
  };
  addresses: {
    network: Network; hrp: string; threshold: 1; keyId: string; pkBlobHex: Hex;
    leafScriptHex: Hex; leafHashHex: Hex; internalKeyHex: Hex;
    outputKeyHex: Hex; parity: 0 | 1; controlBlockHex: Hex;
    scriptPubKeyHex: Hex; address: string;
  }[];
  transactions: {
    id: string; network: Network; version: 2; lockTime: 0; hashType: 1;
    feeSats: Sats; baseBytes: number; totalBytes: number; weight: number; vsize: number;
    inputs: {
      txid: Hex; vout: number; valueSats: Sats; scriptPubKeyHex: Hex;
      sequence: 4294967293; keyId: string;
    }[];
    outputs: {valueSats: Sats; scriptPubKeyHex: Hex}[];
    unsignedTxHex: Hex; sighashesHex: Hex[]; signaturesHex: Hex[];
    witnessesHex: Hex[][]; rawTxHex: Hex; txid: Hex; wtxid: Hex;
  }[];
};
~~~

There are 2 keygen cases, 4 signature cases, 1 HKDF derivation case, 6 addresses (2 keys x 3 networks), and 3 payment records (one per network). Payments share identical raw bytes across networks because network affects address HRPs, not transaction script serialization. Each has two inputs using ascending32 and two witness-v2 outputs (payment to zero32 and change to ascending32), version 2, locktime 0, sequence fffffffd. Fee=10000 sats; stripped size=178, total size=10832, weight=11366, vsize=2842. txid=73272b825a1706db4fd5f6cc140f463d08af03f6bb7690e96b34adec844cc511; wtxid=5f1320fe5a675b244094593b60dfbb13a3a3fe47e395137a7d9453f27662841b.

## Randomized cross-verification

Emit fresh randomized official-wallet signatures as JSON (use --silent for clean stdout):

    npm run --silent crossverify -- --emit

Pass Rust-produced JSON on stdin:

    npm run --silent crossverify < rust-signatures.json

Exact input/output-of-emit schema: {schemaVersion:1,cases:[{id:string,publicKeyHex:Hex,msg32Hex:Hex,signatureHex:Hex}]}. Verification emits {schemaVersion:1,results:[{id:string,verified:boolean}]} and exits nonzero if any signature fails. Fresh randomized signatures are checked by verification verdict, not byte equality. The verifier takes raw 3309-byte signatures without the witness hashtype suffix. Reproducible payments use rnd0 signatures.

Optional full-payment verification extends the same input object with payments. Signature cases remain unchanged; cases may be empty or omitted when at least one payment is supplied:

~~~typescript
type PaymentInput = {
  schemaVersion: 1;
  cases?: {id: string; publicKeyHex: Hex; msg32Hex: Hex; signatureHex: Hex}[];
  payments?: {
    rawTxHex: Hex;
    publicKeyHex: Hex;
    inputs: {txid: Hex; vout: number; amount: string; sequence: number}[];
  }[];
};
~~~

Each payment uses one public key for all inputs. Input txids are display order; amount is the known spent-output amount in decimal sats. The official parser must round-trip the raw transaction byte-for-byte. The verifier requires version 2, locktime 0, witness-only flags 00/01, an integer u32 sequence (0..0xffffffff) matching each supplied input, empty scriptSigs, witness-v2 outputs, and no output extensions. It reconstructs the official 1-of-1 policy and prevout script from publicKeyHex, compares every input txid/vout/sequence, and requires each witness to be exactly [signature3309 || 01, official leaf, official control block]. It attaches all supplied spent amounts, recomputes each getPqSighash, checks the second official sighash implementation agrees, and verifies each actual witness signature. Input/output sums must yield a nonnegative fee; fee zero is accepted locally and does not establish relay acceptance. The fixture uses fffffffd as an example, while crossverify and the NIF accept any integer u32 sequence. Neither establishes BIP68 relative-lock maturity or RBF policy compliance.

When payments is present, output adds paymentResults in payment order. Success entries are {index,verified:true,txid,wtxid,sighashesHex,weight,vsize,feeSats}; failure entries are {index,verified:false,error}. Any failure causes a nonzero exit. When payments is absent the existing output shape remains {schemaVersion:1,results:[...]}. Transaction ids use display order. This validates the full serialized payment against supplied prevout facts; it does not fetch or establish chain UTXO existence.

From the project root, benchmark output and historical replay use:

    ERL_FLAGS="+S 2:2" bin/run mix run bench/run.exs
    npm --prefix interop run --silent crossverify < results/generated/native-sample.json
    npm --prefix interop run --silent crossverify < results/native-sample.json

The benchmark creates results/generated/ before writing benchmark.json and native-sample.json there; that directory is ignored. Tracked results snapshots remain historical evidence and are not overwritten. Set TENSORCASH_NATIVE_LOCAL_COMPAT=1 on the benchmark command to also write the ignored interop/native.local.json compatibility copy. The last command replays the tracked historical sample without regenerating it.

The NIF prototype requires strictly positive input/output amounts, bounded individually and in each sum by MAX_MONEY=2_100_000_000_000_000. This positive-only restriction is narrower than MoneyRange in the pinned Core src/consensus/amount.h, which allows zero; the bound matches that header and is not a total-issuance claim. Crossverify is an independent wallet-format/signature oracle, not a replacement for every NIF limit. Raw transactions are network agnostic for the same witness programs: HRPs are address encodings and cannot be established from raw output scripts. Verification does not establish chain UTXO existence, maturity, or node relay policy.

Remote Linux CI has not yet been verified passing. Future CI evidence should retain npm audit and cargo audit JSON, benchmark and crossverify artifacts, tool versions, execution status and exit codes. Historical local results do not establish a current remote audit verdict.

Validated local signature pipeline:

    set -o pipefail
    npm run --silent crossverify -- --emit | npm run --silent crossverify

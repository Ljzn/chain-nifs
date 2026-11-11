# Independent Blocknet prototype oracles

The pinned official core checkout is ../blocknet-core-research at commit d4c7f78572e5dd637e7f322ea89573b65912e64c. No upstream files are modified. No PoW, hash module, node, CGO, or full wallet build is required.

Run from the prototype root:

~~~sh
interop/run-rust generate > /tmp/blocknet-new-vectors.json
interop/run-rust verify < test/fixtures/official_vectors.json
interop/run-go < test/fixtures/official_vectors.json
interop/run-go wire < test/fixtures/official_vectors.json
python3 interop/cross_verify.py
python3 interop/cross_verify.py path/to/fresh-native-export.json
python3 interop/verify_provenance.py ../blocknet-core-research
~~~

Rust uses bin/run's project caches by default, Rust 1.96.0 and the standalone locked Cargo manifest. CARGO_HOME and RUSTUP_HOME can select existing shared caches. Go uses a standalone standard-library-only module with Go 1.24.12; set GO to an existing Go 1.24+ executable to avoid a toolchain download. Go caches default to ignored interop subdirectories. All scripts can be called from any working directory.

The official-rust/src/upstream directory contains **byte-for-byte copies** of official crypto-rs/src/{ring,keys,stealth,commitment,rangeproof}.rs. The wrapper calls their original exported C ABI functions directly. Official Cargo.toml declares compatible version ranges and does not ship a Cargo.lock. This oracle selects exact versions within those ranges (curve25519-dalek 4.1.3, ed25519-dalek 2.2.0, rand 0.8.8, sha2 0.10.9, bulletproofs 5.0.0, merlin 3.0.0); Cargo.lock fixes transitive resolution. rand 0.8.8 satisfies the official 0.8 constraint and avoids the RUSTSEC-2026-0097 advisory affecting the previously selected 0.8.5. The official Bulletproofs 5 dependency still brings clear_on_drop 0.2.5, which has an unmaintained-crate advisory; this residual maintenance concern is documented without suppressing it or forking the official cryptographic algorithms. SHA3, JSON and hex dependencies belong only to the oracle wrapper.

The Go module is named blocknet to preserve original imports. wallet/memo.go and protocol/params/{memo,network,p2p}.go are exact files. wallet/{seed,blinding,amount}.go retain exact function bodies extracted from official mnemonic.go, scanner.go and builder.go; only local package/import/type preambles were added. SHA256SUMS.json records original line ranges and both file and extract hashes. The Go wallet seed test checks exact seed splitting using known Rust-oracle keypairs as a callback: it does not implement curve cryptography itself. Importing the entire upstream wallet would pull unrelated password/mnemonic dependencies and a Go 1.26 toolchain. The official transaction decoder lives in package main and cannot be imported, so both transaction parsers here are independently written against transaction.go Serialize and SigningHash. Go checks byte codec, signature embedded KI/pseudo binding, signing hash and txid; Rust additionally verifies every official RingCT signature, Bulletproof, commitment balance and point encoding.

## Input schema

~~~json
{
  "cases": [{
    "message_hex": "...",
    "ring_keys": ["16 canonical 32-byte point hex strings"],
    "ring_commitments": ["16 canonical 32-byte point hex strings"],
    "signature_hex": "1120-byte official RingCT signature"
  }],
  "payments": [{
    "raw_hex": "canonical signed transaction",
    "network": "blocknet_mainnet",
    "expected_received": [{"index": 0, "amount": 42, "memo_hex": "..."}],
    "receiver": {
      "spend_private_hex": "32-byte canonical scalar",
      "view_private_hex": "32-byte canonical scalar"
    }
  }]
}
~~~

Both arrays may be omitted. Receiver is optional; when present, matching outputs recover amount, raw blinding, indexed one-time private key and memo, and recompute the commitment. The cross_verify helper requires expected_received whenever receiver is supplied and checks recovered count, indices, amounts and memo bytes against that independent expectation. Network aliases mainnet/testnet normalize to blocknet_mainnet/blocknet_testnet. Receiver matching uses the official indexed shared-secret ABI plus official scalar addition/public-key ABI. The parser accepts version 1 signed payments with 1..16 inputs and outputs and exactly 16 ring members. It bounds proofs to 1024 bytes and validates every 32-byte Ristretto point before ABI calls. It rejects trailing/truncated bytes, duplicate KI, invalid proofs/signatures, unbalanced commitments, and KI/pseudo-output fields differing from those embedded in the signatures. This is cryptographic interop validation; it does not query chain membership, spent status, maturity, minimum fee or mempool policy.

Rust output is {cases:[{valid,...}],payments:[{valid,signing_hash_hex,txid_hex,inputs,outputs,fee,recovered:[{index,amount,blinding_raw_hex,one_time_private_hex,memo_hex}]}]}; failures have valid:false and error and cause exit 1. The cross_verify helper compares Rust and Go transaction hashes and metadata and checks external key-image tamper rejection, so a freshly exported NIF payment exercises the official verifier independently. It does not generate native outputs itself: supply a JSON export produced by the native prototype.

## Static fixture schema and provenance

The checked fixture contains schema, upstream_commit, synthetic_public_seeds_only, network, key_vectors, stealth, cases and payments. Each key vector has seed_hex, private_hex and public_hex. The standalone ring case signs an exact 32-byte SHA3-256 digest. Input key images in the deterministic transaction-key vector are derived from public repeated-byte seeds 0x0a and 0x0b. The stealth object has wallet_seed64_hex (32 bytes of 01 followed by 32 bytes of 02), spend/view seeds and keypairs, input key_images, deterministic tx_private_hex/tx_public_hex, and indexed outputs. Outputs include shared_sender_hex, shared_receiver_hex, one-time keys, amount, **unreduced** blinding_raw_hex, commitment_hex, encrypted_amount_hex, memo_hex, encrypted_memo_hex and range_proof_hex. Official wallet derivation splits a 64-byte seed; 32-byte seeds are only generic seeded Ristretto keygen inputs.

All seeds and private values are synthetic public data. Deterministic primitives reproduce exactly. Official unmodified RingCT signing and Bulletproof generation use randomness, so regenerating the fixture changes proof/signature bytes while preserving validity and deterministic primitive values. The memo fixture uses independently constructed public 0x42 padding, then verifies recovery through exact official Go DecryptMemo; this is a known-answer fixture convention, not an entropy replacement for production EncryptMemo. Mainnet domain separation is explicit. License terms are retained in official-rust/LICENSE.upstream and apply to all copied upstream sources.

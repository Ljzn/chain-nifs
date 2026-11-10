# Third-party provenance and modifications

Project-authored code is Apache-2.0; see LICENSE. This is an independent integration prototype, not an official TensorCash release.

## liboqs

vendor/liboqs is an unmodified git submodule of https://github.com/open-quantum-safe/liboqs at 97f6b86b1b6d109cfd43cf276ae39c2e776aed80 (0.15.0), the version pinned by TensorCash's main repository443ebf7ef6a717116ef80f9d6e1f38711905c77a. Preserve vendor/liboqs/LICENSE.txt (MIT) and algorithm-specific notices.

The selected ML-DSA65 reference implementation has CC0 OR Apache-2.0 licensing in vendor/liboqs/src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_ref/LICENSE. We elect Apache-2.0 for the adapted functions.

native/tensorcash_nif/adapter.c adapts crypto_sign_keypair from that implementation's sign.c:23-64 to take an explicit32byte seed in place of randombytes, preserving K/L domain expansion and all arithmetic, then adds workspace cleansing. No source is patched in vendor.

native/tensorcash_nif/signing_workspace.c adapts exactly sign.c:85-191: function symbol renamed to tensorcash_signature_internal, then OQS_MEM_cleanse calls inserted at the sole normal exit for seedbuf/mat/s1/y/z/t0/s2/w1/w0/h/cp. Rejection sampling and arithmetic remain unchanged. adapter.c supplies the Pure external interface prefix {0,0} and explicit32byte rnd from fallible Rust getrandom. These are deliberately coupled internal symbols; changing liboqs requires an adapter review and full official vectors, not only a gitlink update.

## Official wallet and node reference

Official main source https://git.tensorcash.org/tensorcash/tensorcash.git at443ebf7ef6a717116ef80f9d6e1f38711905c77a. Official Core consensus reference bcore38fabe7ed2d5ccec5d303c7a131c87ca3f4a7a52 (MIT). The complete node is not linked or required for builds.

interop/oracle/official contains14 verbatim transitive TypeScript modules from the official treasury wallet. interop/oracle/source-manifest.json records original paths and SHA256. Keep interop/oracle/LICENSE.Apache-2.0 and LICENSE.signer-MIT (the latter preserves the @scure/btc-signer fork's copyright). No official module was changed; generate.ts/crossverify.ts are new harness code.

The project Rust address/transaction modules implement the same explicit single-leaf1-of-1/ALL payment subset using that reference and node sighash rules. The signer code fork under interop is used only for testing, not production NIF execution.

## Test vectors

All seeds, mnemonics, secret keys and addresses in test fixtures are public synthetic material and must never be funded. wallet-oracle-v1.json is generated only by the independent TypeScript oracle. core-mldsa65-signature.json and mldsa65-acvp-fips204.json are exact copies from the official wallet pq/__tests__/vectors at the above revision, retain their provenance metadata, and include NIST/liboqs ACVP subset cases and two captured Core signatures. Their original sources and hashes are retained by the oracle manifest/fixture.

## Other build dependencies

Rust dependencies and exact resolutions are in native/tensorcash_nif/Cargo.lock; Elixir in mix.lock; test oracle npm dependencies in interop/package-lock.json. Their licenses remain their respective upstream licenses. Cargo/Rustler/CMake are not substitutes for reviewing the C adapter or proof of constant-time behavior. No production keys or chain state are included.

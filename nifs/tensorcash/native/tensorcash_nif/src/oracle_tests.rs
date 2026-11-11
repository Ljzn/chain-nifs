use super::{crypto, derivation};
use serde_json::Value;
fn oracle() -> Value {
    serde_json::from_str(include_str!("../../../test/fixtures/wallet-oracle-v1.json")).unwrap()
}
fn bytes(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}
#[test]
fn official_seeded_keys_match_including_expanded_secret() {
    for v in oracle()["keygen"].as_array().unwrap() {
        let kp = crypto::keypair(&bytes(v, "seedHex")).unwrap();
        assert_eq!(kp.public_key, bytes(v, "publicKeyHex"));
        assert_eq!(&kp.secret_key[..], bytes(v, "secretKeyHex"));
    }
}
#[test]
fn explicit_randomness_matches_official_pure_mldsa_vectors() {
    let o = oracle();
    for v in o["signatures"].as_array().unwrap() {
        let key = o["keygen"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["id"] == v["keyId"])
            .unwrap();
        let kp = crypto::keypair(&bytes(key, "seedHex")).unwrap();
        let message = bytes(v, "msg32Hex");
        let signature =
            crypto::sign_with_randomness(&kp.secret_key, &message, &bytes(v, "rndHex")).unwrap();
        assert_eq!(signature, bytes(v, "signatureHex"));
        assert!(crypto::verify_digest(&kp.public_key, &message, &signature).unwrap());
    }
}
#[test]
fn official_wallet_hkdf_spending_seed_is_reproduced() {
    let o = oracle();
    let v = &o["derivation"];
    let seed = derivation::derive(
        &bytes(v, "bip39SeedHex"),
        &bytes(v, "genesisHex"),
        v["account"].as_u64().unwrap() as u32,
        Some((
            &bytes(v, "policyIdHex"),
            v["branch"].as_u64().unwrap() as u8,
            v["index"].as_u64().unwrap() as u32,
        )),
    )
    .unwrap();
    assert_eq!(&seed[..], bytes(v, "spendingSeedHex"));
    let kp = crypto::keypair(&seed[..]).unwrap();
    assert_eq!(kp.public_key, bytes(v, "publicKeyHex"));
    assert_eq!(&kp.secret_key[..], bytes(v, "secretKeyHex"));
}
#[test]
fn official_wallet_identity_seed_is_reproduced() {
    let o = oracle();
    let v = &o["derivation"];
    let seed = derivation::derive(
        &bytes(v, "bip39SeedHex"),
        &bytes(v, "genesisHex"),
        v["account"].as_u64().unwrap() as u32,
        None,
    )
    .unwrap();
    assert_eq!(&seed[..], bytes(v, "identitySeedHex"));
}
#[test]
fn bounded_transaction_parser_mutation_corpus() {
    use crate::transaction::{self, Input};
    let o = oracle();
    let tx = &o["transactions"][0];
    let pk = bytes(&o["keygen"][1], "publicKeyHex");
    let inputs: Vec<Input> = tx["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Input {
            txid: v["txid"].as_str().unwrap().into(),
            vout: v["vout"].as_u64().unwrap() as u32,
            amount: v["valueSats"].as_str().unwrap().parse().unwrap(),
            sequence: v["sequence"].as_u64().unwrap() as u32,
        })
        .collect();
    let raw = bytes(tx, "rawTxHex");
    assert_eq!(transaction::verify(&raw, &pk, "mainnet", &inputs), Ok(true));
    for i in 0..512 {
        let offset = i * (raw.len() - 1) / 511;
        let mut mutated = raw.clone();
        mutated[offset] ^= 1 << (i % 8);
        assert_ne!(
            transaction::verify(&mutated, &pk, "mainnet", &inputs),
            Ok(true)
        );
        assert!(transaction::verify(&raw[..offset], &pk, "mainnet", &inputs).is_err());
    }
}
#[test]
fn crypto_rejects_ffi_buffer_length_errors() {
    assert!(crypto::keypair(&[0; 31]).is_err());
    assert!(crypto::sign_with_randomness(&[0; 4031], &[0; 32], &[0; 32]).is_err());
    assert!(crypto::verify_digest(&[0; 1951], &[0; 32], &[0; 3309]).is_err());
}

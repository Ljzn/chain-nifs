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
fn crypto_rejects_ffi_buffer_length_errors() {
    assert!(crypto::keypair(&[0; 31]).is_err());
    assert!(crypto::sign_with_randomness(&[0; 4031], &[0; 32], &[0; 32]).is_err());
    assert!(crypto::verify_digest(&[0; 1951], &[0; 32], &[0; 3309]).is_err());
}

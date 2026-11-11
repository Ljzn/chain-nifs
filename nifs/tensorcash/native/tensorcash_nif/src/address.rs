//! Ordinary TSC witness-v2, single-leaf ML-DSA-65 1-of-1 addresses.
//! Mirrors core/src/pq/{address,script,mldsa}.ts in the official wallet.
use bech32::{u5, FromBase32, ToBase32, Variant};
use rustler::NifMap;
use secp256k1::{Parity, Scalar, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

#[derive(NifMap, Clone, Debug)]
pub struct Address {
    pub address: String,
    pub script_pubkey_hex: String,
    pub leaf_script_hex: String,
    pub control_block_hex: String,
    pub output_key_hex: String,
    pub leaf_hash_hex: String,
}

pub(crate) struct Descriptor {
    pub script_pubkey: Vec<u8>,
    pub leaf_script: Vec<u8>,
    pub control_block: Vec<u8>,
    pub output_key: [u8; 32],
    pub leaf_hash: [u8; 32],
}

pub(crate) fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(message);
    h.finalize().into()
}

pub(crate) fn hrp(network: &str) -> Result<&'static str, String> {
    match network {
        "mainnet" => Ok("tc"),
        "testnet" => Ok("tct"),
        "regtest" => Ok("tcrt"),
        _ => Err("network must be mainnet, testnet, or regtest".into()),
    }
}

pub(crate) fn descriptor(pk: &[u8]) -> Result<Descriptor, String> {
    if pk.len() != 1952 {
        return Err("ML-DSA-65 public key must be 1952 raw bytes".into());
    }
    // buildThresholdLeaf(1, [01 41 compactsize(1952) || pk]), including
    // the conditional signature slot and altstack counter even for one key.
    let mut leaf_script = vec![
        0x00, 0x6b, 0x82, 0x92, 0x63, 0x4d, 0xa5, 0x07, 0x01, 0x41, 0xfd, 0xa0, 0x07,
    ];
    leaf_script.extend_from_slice(pk);
    leaf_script.extend_from_slice(&[0xbc, 0x6c, 0x8b, 0x6b, 0x67, 0x75, 0x68, 0x6c, 0x51, 0xa2]);
    let mut leaf_preimage = vec![0xc0, 0xfd];
    leaf_preimage.extend_from_slice(&(leaf_script.len() as u16).to_le_bytes());
    leaf_preimage.extend_from_slice(&leaf_script);
    let leaf_hash = tagged_hash("TapLeaf", &leaf_preimage);
    // BIP341 NUMS: sha256(uncompressed secp256k1 generator).
    let internal_bytes =
        hex::decode("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
            .map_err(|e| e.to_string())?;
    let internal = XOnlyPublicKey::from_byte_array(
        internal_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid NUMS length")?,
    )
    .map_err(|e| e.to_string())?;
    let mut tweak_preimage = internal_bytes.clone();
    tweak_preimage.extend_from_slice(&leaf_hash);
    let tweak = Scalar::from_be_bytes(tagged_hash("TapTweak", &tweak_preimage))
        .map_err(|_| "TapTweak scalar out of range".to_string())?;
    let (output, parity) = internal
        .add_tweak(&Secp256k1::verification_only(), &tweak)
        .map_err(|e| e.to_string())?;
    let output_key = output.serialize();
    let mut control_block = vec![0xc0 | if parity == Parity::Odd { 1 } else { 0 }];
    control_block.extend_from_slice(&internal_bytes);
    Ok(Descriptor {
        script_pubkey: script_pubkey(&output_key),
        leaf_script,
        control_block,
        output_key,
        leaf_hash,
    })
}

pub(crate) fn script_pubkey(program: &[u8]) -> Vec<u8> {
    let mut script = vec![0x52, 0x20];
    script.extend_from_slice(program);
    script
}

pub fn derive(pk: &[u8], network: &str) -> Result<Address, String> {
    let prefix = hrp(network)?;
    let d = descriptor(pk)?;
    let mut words = vec![u5::try_from_u8(2).map_err(|e| e.to_string())?];
    words.extend(d.output_key.to_base32());
    let address = bech32::encode(prefix, words, Variant::Bech32m).map_err(|e| e.to_string())?;
    Ok(Address {
        address,
        script_pubkey_hex: hex::encode(d.script_pubkey),
        leaf_script_hex: hex::encode(d.leaf_script),
        control_block_hex: hex::encode(d.control_block),
        output_key_hex: hex::encode(d.output_key),
        leaf_hash_hex: hex::encode(d.leaf_hash),
    })
}

/// Return the 32-byte witness program (not the scriptPubKey).
/// Accept only canonical lowercase witness-v2 Bech32m for the selected network.
pub fn decode(address: &str, network: &str) -> Result<Vec<u8>, String> {
    let prefix = hrp(network)?;
    if address.len() > 90 || !address.is_ascii() || address.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err("address must be canonical lowercase Bech32m, at most 90 bytes".into());
    }
    let (got_prefix, words, variant) = bech32::decode(address).map_err(|e| e.to_string())?;
    if got_prefix != prefix
        || variant != Variant::Bech32m
        || words.first().map(|v| v.to_u8()) != Some(2)
    {
        return Err("address must be network-matching witness-v2 Bech32m".into());
    }
    let program = Vec::<u8>::from_base32(&words[1..]).map_err(|e| e.to_string())?;
    if program.len() != 32 {
        return Err("witness-v2 program must be 32 bytes".into());
    }
    let canonical = bech32::encode(prefix, words, Variant::Bech32m).map_err(|e| e.to_string())?;
    if canonical != address {
        return Err("noncanonical address".into());
    }
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_other_witness_versions_networks_and_uppercase() {
        let a = derive(&[7; 1952], "regtest").unwrap();
        assert_eq!(
            decode(&a.address, "regtest").unwrap(),
            hex::decode(a.output_key_hex).unwrap()
        );
        assert!(decode(&a.address, "mainnet").is_err());
        assert!(decode(&a.address.to_uppercase(), "regtest").is_err());
        for version in [0, 1, 3, 16] {
            let mut words = vec![u5::try_from_u8(version).unwrap()];
            words.extend([7u8; 32].to_base32());
            let encoded = bech32::encode("tcrt", words, Variant::Bech32m).unwrap();
            assert!(decode(&encoded, "regtest").is_err());
        }
    }
}

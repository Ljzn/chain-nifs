use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// Bounded RFC2104 HMAC: the only keys are the 21-byte salt and 32-byte PRK.
// Explicit pads/output plus SHA256's zeroize Drop avoid retained keyed state.
fn hmac(key: &[u8], parts: &[&[u8]]) -> Result<Zeroizing<[u8; 32]>, String> {
    if key.len() > 64 {
        return Err("HMAC key outside bounded derivation domain".into());
    }
    let mut ipad = Zeroizing::new([0x36u8; 64]);
    let mut opad = Zeroizing::new([0x5cu8; 64]);
    for (i, b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let mut inner = Sha256::new();
    inner.update(&ipad[..]);
    for p in parts {
        inner.update(p);
    }
    let mut inner_hash = Zeroizing::new([0u8; 32]);
    inner.finalize_into(
        (&mut inner_hash[..])
            .try_into()
            .map_err(|_| "invalid digest workspace")?,
    );
    let mut outer = Sha256::new();
    outer.update(&opad[..]);
    outer.update(&inner_hash[..]);
    let mut result = Zeroizing::new([0u8; 32]);
    outer.finalize_into(
        (&mut result[..])
            .try_into()
            .map_err(|_| "invalid digest workspace")?,
    );
    Ok(result)
}
pub fn derive(
    seed64: &[u8],
    genesis: &[u8],
    account: u32,
    spending: Option<(&[u8], u8, u32)>,
) -> Result<Zeroizing<[u8; 32]>, String> {
    if seed64.len() != 64 || genesis.len() != 32 {
        return Err("BIP39 seed must be 64 bytes and genesis must be 32 bytes".into());
    }
    let seed = Zeroizing::new(seed64.to_vec());
    let root = hmac(b"TensorCash/PQ-root/v1", &[&seed])?;
    let mut info = Vec::new();
    match spending {
        Some((policy, branch, index)) => {
            if policy.len() != 32 || branch > 1 {
                return Err("policy id must be 32 bytes; branch must be 0 or 1".into());
            }
            info.extend_from_slice(b"TensorCash/PQ-spend/v1");
            info.extend_from_slice(genesis);
            info.extend_from_slice(&account.to_be_bytes());
            info.extend_from_slice(policy);
            info.push(branch);
            info.extend_from_slice(&index.to_be_bytes());
        }
        None => {
            info.extend_from_slice(b"TensorCash/PQ-identity/v1");
            info.extend_from_slice(genesis);
            info.extend_from_slice(&account.to_be_bytes());
        }
    }
    // HKDF-Expand length32 has exactly one SHA256 block: HMAC(PRK, info || 01).
    hmac(&root[..], &[&info, &[1]])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc5869_case1_extract_and_first_expand_block() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0..13).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let prk = hmac(&salt, &[&ikm]).unwrap();
        assert_eq!(
            hex::encode(&prk[..]),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let t = hmac(&prk[..], &[&info, &[1]]).unwrap();
        assert_eq!(
            hex::encode(&t[..]),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }
}

//! Indexed stealth payment preparation and recovery; no node or UTXO access.
//! Ported from core d4c7f785 wallet/{builder,memo,scanner}.go and stealth.rs.
use crate::transaction::{
    self, point, scalar, Transaction, TxInput, TxOutput, MAX_INPUTS, MAX_OUTPUTS, MAX_RAW_BYTES,
    RING_SIZE, SIGNATURE_BYTES,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use rustler::NifMap;
use sha2::{Digest as ShaDigest, Sha256};
use sha3::Sha3_256;
use zeroize::Zeroizing;

pub use crate::transaction::{Input, Output};
#[derive(NifMap)]
pub struct Payment {
    pub raw_hex: String,
    pub txid: String,
    pub signing_hash_hex: String,
    pub tx_public_hex: String,
    pub fee: u64,
    pub bytes: u64,
}
#[derive(NifMap)]
pub struct Received {
    pub index: u32,
    pub amount: u64,
    pub memo_hex: String,
    pub memo_valid: bool,
    pub secret_hex: String,
    pub blinding_hex: String,
}
#[derive(NifMap)]
pub struct Keys {
    pub spend_secret_hex: String,
    pub view_secret_hex: String,
    pub spend_public_hex: String,
    pub view_public_hex: String,
}

// Best effort cleanup of Rust allocations; BEAM binaries and compiler copies persist.
impl Drop for Received {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_hex.zeroize();
        self.blinding_hex.zeroize();
        self.memo_hex.zeroize();
    }
}
impl Drop for Keys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.spend_secret_hex.zeroize();
        self.view_secret_hex.zeroize();
    }
}

fn array32(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| "expected exactly 32 bytes".into())
}
fn hex32(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 {
        return Err("expected exactly 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).map_err(|_| "invalid hexadecimal encoding")?;
    Ok(out)
}
fn secret(bytes: &[u8]) -> Result<Zeroizing<Scalar>, String> {
    let s = scalar(&array32(bytes)?)?;
    if s == Scalar::ZERO {
        return Err("secret scalar must be nonzero".into());
    }
    Ok(Zeroizing::new(s))
}
fn nonidentity(bytes: &[u8; 32]) -> Result<RistrettoPoint, String> {
    let p = point(bytes)?;
    if p == RistrettoPoint::identity() {
        return Err("identity public key".into());
    }
    Ok(p)
}
fn network_domain(network: &str) -> Result<&'static [u8], String> {
    match network {
        "mainnet" => Ok(b"blocknet_mainnet"),
        "testnet" => Ok(b"blocknet_testnet"),
        _ => Err("network must be mainnet or testnet".into()),
    }
}
fn h3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
fn reduce32(digest: [u8; 32]) -> Scalar {
    // Official SHA256 reductions zero-extend into the LOW half of a wide scalar.
    let mut wide = Zeroizing::new([0u8; 64]);
    wide[..32].copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}
fn indexed_shared(dh: &RistrettoPoint, index: u32) -> Zeroizing<Scalar> {
    let mut h = Sha256::new();
    h.update(b"blocknet_stealth_hs");
    h.update(dh.compress().as_bytes());
    h.update(index.to_le_bytes());
    Zeroizing::new(reduce32(h.finalize().into()))
}
fn blinding(shared: &Scalar, index: u32) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(h3(&[
        b"blocknet_blinding",
        shared.as_bytes(),
        &index.to_le_bytes(),
    ]))
}
fn amount_mask(raw_blind: &[u8; 32], index: u32) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(h3(&[b"blocknet_amount", raw_blind, &index.to_le_bytes()]))
}
fn memo_mask(shared: &Scalar, index: u32, network: &[u8]) -> Zeroizing<[u8; 128]> {
    let seed = Zeroizing::new(h3(&[
        shared.as_bytes(),
        b"memo",
        &index.to_le_bytes(),
        network,
    ]));
    let mut mask = Zeroizing::new([0u8; 128]);
    for i in 0..4u32 {
        let block = Zeroizing::new(h3(&[seed.as_ref(), &i.to_le_bytes()]));
        mask[i as usize * 32..(i as usize + 1) * 32].copy_from_slice(block.as_ref());
    }
    mask
}
fn memo_checksum(payload: &[u8]) -> [u8; 32] {
    h3(&[
        b"blocknet_memo_checksum",
        &(payload.len() as u16).to_le_bytes(),
        payload,
    ])
}
fn encrypt_memo(
    payload: &[u8],
    shared: &Scalar,
    index: u32,
    network: &[u8],
) -> Result<[u8; 128], String> {
    if payload.len() > 124 {
        return Err("memo exceeds 124 bytes".into());
    }
    let mut plain = Zeroizing::new([0u8; 128]);
    plain[0] = 1;
    plain[1] = payload.len() as u8;
    plain[2..4].copy_from_slice(&memo_checksum(payload)[..2]);
    plain[4..4 + payload.len()].copy_from_slice(payload);
    getrandom::getrandom(&mut plain[4 + payload.len()..])
        .map_err(|_| "memo padding entropy unavailable")?;
    let mask = memo_mask(shared, index, network);
    let mut encrypted = [0u8; 128];
    for i in 0..128 {
        encrypted[i] = plain[i] ^ mask[i];
    }
    Ok(encrypted)
}
fn decrypt_memo(
    encrypted: &[u8; 128],
    shared: &Scalar,
    index: u32,
    network: &[u8],
) -> Result<Vec<u8>, String> {
    let mask = memo_mask(shared, index, network);
    let mut plain = Zeroizing::new([0u8; 128]);
    for i in 0..128 {
        plain[i] = encrypted[i] ^ mask[i];
    }
    let len = plain[1] as usize;
    if plain[0] != 1 || len > 124 {
        return Err("invalid received memo envelope".into());
    }
    let payload = &plain[4..4 + len];
    if plain[2..4] != memo_checksum(payload)[..2] {
        return Err("received memo checksum mismatch".into());
    }
    Ok(payload.to_vec())
}
fn random_scalar() -> Result<Zeroizing<Scalar>, String> {
    let mut bytes = Zeroizing::new([0u8; 64]);
    getrandom::getrandom(bytes.as_mut()).map_err(|_| "blinding entropy unavailable")?;
    Ok(Zeroizing::new(Scalar::from_bytes_mod_order_wide(&bytes)))
}

/// Build a version-1 payment from prepared rings using indexed stealth only.
pub fn build(
    view_secret: &[u8],
    network: &str,
    inputs: &[Input],
    outputs: &[Output],
    fee: u64,
) -> Result<Payment, String> {
    let domain = network_domain(network)?;
    let _view = secret(view_secret)?;
    if !(1..=MAX_INPUTS).contains(&inputs.len()) || !(1..=MAX_OUTPUTS).contains(&outputs.len()) {
        return Err("payment requires 1..16 inputs and outputs".into());
    }
    let mut input_total = 0u64;
    let mut output_total = fee;
    for i in inputs {
        if i.amount == 0 {
            return Err("input amount must be positive".into());
        }
        input_total = input_total
            .checked_add(i.amount)
            .ok_or("input amount sum overflow")?;
    }
    for o in outputs {
        if o.amount == 0 {
            return Err("output amount must be positive".into());
        }
        output_total = output_total
            .checked_add(o.amount)
            .ok_or("output amount plus fee overflow")?;
        if o.memo_hex.len() > 248 || o.memo_hex.len() % 2 != 0 {
            return Err("memo must encode at most 124 bytes".into());
        }
    }
    if input_total != output_total {
        return Err("inputs must equal outputs plus fee exactly".into());
    }
    let mut prepared = inputs
        .iter()
        .map(prepare_input)
        .collect::<Result<Vec<_>, _>>()?;
    let mut images = prepared.iter().map(|p| p.wire.image).collect::<Vec<_>>();
    images.sort_unstable();
    if images.windows(2).any(|p| p[0] == p[1]) {
        return Err("duplicate key image".into());
    }
    let mut h = Sha256::new();
    h.update(b"blocknet_deterministic_tx_key");
    h.update(view_secret);
    for i in &images {
        h.update(i);
    }
    let r = Zeroizing::new(reduce32(h.finalize().into()));
    if *r == Scalar::ZERO {
        return Err("derived transaction scalar is zero".into());
    }
    let public = (*r * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let mut wire_outputs = Vec::with_capacity(outputs.len());
    let mut total_blind = Zeroizing::new(Scalar::ZERO);
    for (index, o) in outputs.iter().enumerate() {
        let index = index as u32;
        let spend = nonidentity(&hex32(&o.spend_public_hex)?)?;
        let view = nonidentity(&hex32(&o.view_public_hex)?)?;
        let dh = *r * view;
        let shared = indexed_shared(&dh, index);
        let public = (*shared * RISTRETTO_BASEPOINT_POINT + spend)
            .compress()
            .to_bytes();
        nonidentity(&public)?;
        let raw_blind = blinding(&shared, index);
        let blind = Zeroizing::new(Scalar::from_bytes_mod_order(*raw_blind));
        *total_blind += *blind;
        let commitment = crate::crypto::commitment(o.amount, blind.as_bytes())?;
        let proof = crate::crypto::range_prove(o.amount, blind.as_bytes())?;
        if proof.is_empty() || proof.len() > transaction::MAX_PROOF_BYTES {
            return Err("generated proof exceeds bounds".into());
        }
        let mask = amount_mask(&raw_blind, index);
        let mut amount = o.amount.to_le_bytes();
        for j in 0..8 {
            amount[j] ^= mask[j];
        }
        let payload = Zeroizing::new(hex::decode(&o.memo_hex).map_err(|_| "invalid memo hex")?);
        let memo = encrypt_memo(&payload, &shared, index, domain)?;
        wire_outputs.push(TxOutput {
            public,
            commitment,
            proof,
            amount,
            memo,
        });
    }
    let mut pseudo_blinds = Vec::with_capacity(prepared.len());
    let mut distributed = Zeroizing::new(Scalar::ZERO);
    for _ in 0..prepared.len() - 1 {
        let blind = random_scalar()?;
        *distributed += *blind;
        pseudo_blinds.push(blind);
    }
    pseudo_blinds.push(Zeroizing::new(*total_blind - *distributed));
    let mut tx = Transaction {
        public,
        fee,
        outputs: wire_outputs,
        inputs: Vec::new(),
    };
    // Input count is signed in the prefix: insert wire records before hashing.
    for p in &mut prepared {
        tx.inputs.push(TxInput {
            image: p.wire.image,
            pseudo: [0; 32],
            keys: std::mem::take(&mut p.wire.keys),
            commitments: std::mem::take(&mut p.wire.commitments),
            signature: Vec::new(),
        });
    }
    let signing_hash = tx.signing_hash();
    for ((wire, p), blind) in tx.inputs.iter_mut().zip(&prepared).zip(&pseudo_blinds) {
        wire.pseudo = crate::crypto::commitment(p.amount, blind.as_bytes())?;
        wire.signature = crate::crypto::ring_sign(
            &wire.keys,
            &wire.commitments,
            p.real,
            p.secret.as_ref(),
            p.blinding.as_ref(),
            &wire.pseudo,
            blind.as_bytes(),
            &signing_hash,
        )?;
        if wire.signature.len() != SIGNATURE_BYTES
            || wire.signature[SIGNATURE_BYTES - 64..SIGNATURE_BYTES - 32] != wire.image
            || wire.signature[SIGNATURE_BYTES - 32..] != wire.pseudo
        {
            return Err("generated signature has inconsistent key image or pseudo output".into());
        }
    }
    let raw = tx.serialize();
    if raw.len() > MAX_RAW_BYTES {
        return Err("transaction exceeds 128 KiB".into());
    }
    // Parsing generated wire also enforces canonical fields and outer/inner binding.
    if !transaction::verify(&raw)? {
        return Err("generated payment failed cryptographic verification".into());
    }
    Ok(Payment {
        raw_hex: hex::encode(&raw),
        txid: hex::encode(transaction::hash(&raw)),
        signing_hash_hex: hex::encode(signing_hash),
        tx_public_hex: hex::encode(public),
        fee,
        bytes: raw.len() as u64,
    })
}

/// Verify before recovering owned indexed outputs. Secret fields are intentional wallet results.
pub fn receive(
    raw: &[u8],
    spend_secret: &[u8],
    view_secret: &[u8],
    network: &str,
) -> Result<Vec<Received>, String> {
    let domain = network_domain(network)?;
    let spend = secret(spend_secret)?;
    let view = secret(view_secret)?;
    let tx = transaction::parse(raw)?;
    if !transaction::verify_parsed(&tx)? {
        return Err("transaction failed cryptographic verification".into());
    }
    let dh = *view * nonidentity(&tx.public)?;
    let spend_public = *spend * RISTRETTO_BASEPOINT_POINT;
    let mut found = Vec::new();
    for (index, o) in tx.outputs.iter().enumerate() {
        let index = index as u32;
        let shared = indexed_shared(&dh, index);
        let expected = (*shared * RISTRETTO_BASEPOINT_POINT + spend_public)
            .compress()
            .to_bytes();
        if expected != o.public {
            continue;
        }
        let raw_blind = blinding(&shared, index);
        let blind = Zeroizing::new(Scalar::from_bytes_mod_order(*raw_blind));
        let mask = amount_mask(&raw_blind, index);
        let mut amount_bytes = Zeroizing::new(o.amount);
        for j in 0..8 {
            amount_bytes[j] ^= mask[j];
        }
        let amount = u64::from_le_bytes(*amount_bytes);
        if crate::crypto::commitment(amount, blind.as_bytes())? != o.commitment {
            // A sender can sign inconsistent amount ciphertext. Like the official scanner,
            // skip only that output; retain valid outputs on either side of it. Zero is
            // recoverable when its opening matches, even though our builder sends > 0.
            continue;
        }
        // Like the official scanner, retain owned funds even if the memo is invalid.
        // The network domain affects memo decoding, not ownership or amount recovery.
        let (payload, memo_valid) = match decrypt_memo(&o.memo, &shared, index, domain) {
            Ok(payload) => (payload, true),
            Err(_) => (Vec::new(), false),
        };
        let memo = Zeroizing::new(payload);
        let key = Zeroizing::new(*shared + *spend);
        if *key == Scalar::ZERO {
            continue;
        }
        found.push(Received {
            index,
            amount,
            memo_hex: hex::encode(memo.as_slice()),
            memo_valid,
            secret_hex: hex::encode(key.as_bytes()),
            blinding_hex: hex::encode(&raw_blind[..]),
        });
    }
    Ok(found)
}

/// Exact wallet/mnemonic.go split, followed by ring.rs seeded_key generation.
/// Accepts the official 64-byte wallet seed; does not invent a 32-byte seed mapping.
pub fn derive_keys(seed64: &[u8]) -> Result<Keys, String> {
    if seed64.len() != 64 {
        return Err("official wallet key derivation requires exactly 64 seed bytes".into());
    }
    let spend = Zeroizing::new(crate::crypto::seeded_key(&seed64[..32])?);
    let view = Zeroizing::new(crate::crypto::seeded_key(&seed64[32..])?);
    secret(spend.as_ref())?;
    secret(view.as_ref())?;
    let spend_public = crate::crypto::public_key(spend.as_ref())?;
    let view_public = crate::crypto::public_key(view.as_ref())?;
    Ok(Keys {
        spend_secret_hex: hex::encode(&spend[..]),
        view_secret_hex: hex::encode(&view[..]),
        spend_public_hex: hex::encode(spend_public),
        view_public_hex: hex::encode(view_public),
    })
}

struct PreparedInput {
    secret: Zeroizing<[u8; 32]>,
    blinding: Zeroizing<[u8; 32]>,
    amount: u64,
    real: usize,
    wire: TxInput,
}
fn prepare_input(input: &Input) -> Result<PreparedInput, String> {
    if input.amount == 0 {
        return Err("input amount must be positive".into());
    }
    if input.ring_keys.len() != RING_SIZE
        || input.ring_commitments.len() != RING_SIZE
        || input.real_index as usize >= RING_SIZE
    {
        return Err("input requires a 16-member ring and real_index < 16".into());
    }
    let sk = Zeroizing::new(hex32(&input.secret_hex)?);
    secret(sk.as_ref())?;
    let blind = Zeroizing::new(hex32(&input.blinding_hex)?);
    // Official wallet blindings are raw SHA3 bytes; crypto reduces modulo l.
    let keys = input
        .ring_keys
        .iter()
        .map(|s| hex32(s))
        .collect::<Result<Vec<_>, _>>()?;
    let commitments = input
        .ring_commitments
        .iter()
        .map(|s| hex32(s))
        .collect::<Result<Vec<_>, _>>()?;
    // Wallet construction policy: repeated public keys reduce the effective anonymity set.
    // Compare decoded bytes so alternate hex casing cannot bypass the check. Do not impose
    // commitment uniqueness or change the protocol-level parser/verifier acceptance rules.
    let mut seen = std::collections::HashSet::with_capacity(RING_SIZE);
    for k in &keys {
        nonidentity(k)?;
        if !seen.insert(*k) {
            return Err("duplicate ring public key".into());
        }
    }
    for c in &commitments {
        point(c)?;
    }
    let real = input.real_index as usize;
    if crate::crypto::public_key(sk.as_ref())? != keys[real] {
        return Err("input secret does not match real ring key".into());
    }
    if crate::crypto::commitment(input.amount, blind.as_ref())? != commitments[real] {
        return Err("input opening does not match real ring commitment".into());
    }
    let image = crate::crypto::key_image(sk.as_ref())?;
    Ok(PreparedInput {
        secret: sk,
        blinding: blind,
        amount: input.amount,
        real,
        wire: TxInput {
            image,
            pseudo: [0; 32],
            keys,
            commitments,
            signature: Vec::new(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepared(amount: u64, offset: u64, real: usize) -> Input {
        let mut keys = Vec::new();
        let mut commitments = Vec::new();
        for j in 0..16u64 {
            let sk = Scalar::from(offset + j + 1).to_bytes();
            let blind = Scalar::from(offset + j + 101).to_bytes();
            keys.push(hex::encode(crate::crypto::public_key(&sk).unwrap()));
            commitments.push(hex::encode(
                crate::crypto::commitment(amount, &blind).unwrap(),
            ));
        }
        Input {
            secret_hex: hex::encode(Scalar::from(offset + real as u64 + 1).as_bytes()),
            amount,
            blinding_hex: hex::encode(Scalar::from(offset + real as u64 + 101).as_bytes()),
            ring_keys: keys,
            ring_commitments: commitments,
            real_index: real as u32,
        }
    }
    fn recipient(amount: u64, memo: &[u8]) -> Output {
        Output {
            spend_public_hex: hex::encode(
                crate::crypto::public_key(Scalar::from(901u64).as_bytes()).unwrap(),
            ),
            view_public_hex: hex::encode(
                crate::crypto::public_key(Scalar::from(902u64).as_bytes()).unwrap(),
            ),
            amount,
            memo_hex: hex::encode(memo),
        }
    }
    fn rejected(raw: &[u8]) {
        assert!(!matches!(transaction::verify(raw), Ok(true)));
    }

    #[test]
    fn indexed_payment_recovery_and_mutations() {
        let inputs = [prepared(60, 100, 3), prepared(50, 200, 7)];
        let outputs = [recipient(70, b""), recipient(35, &[0, 255, 42])];
        let sender_view = Scalar::from(800u64).to_bytes();
        let spend = Scalar::from(901u64).to_bytes();
        let view = Scalar::from(902u64).to_bytes();
        let payment = build(&sender_view, "testnet", &inputs, &outputs, 5).unwrap();
        let raw = hex::decode(&payment.raw_hex).unwrap();
        assert_eq!(raw.len() as u64, payment.bytes);
        assert!(transaction::verify(&raw).unwrap());
        let recovered = receive(&raw, &spend, &view, "testnet").unwrap();
        assert_eq!(recovered.len(), 2);
        assert!(recovered.iter().all(|o| o.memo_valid));
        assert_eq!(recovered[0].amount, 70);
        assert_eq!(recovered[0].memo_hex, "");
        assert_eq!(recovered[1].amount, 35);
        assert_eq!(recovered[1].memo_hex, "00ff2a");
        assert_ne!(recovered[0].secret_hex, recovered[1].secret_hex);
        assert_ne!(recovered[0].blinding_hex, recovered[1].blinding_hex);
        let tx = transaction::parse(&raw).unwrap();
        assert_eq!(hex::encode(tx.signing_hash()), payment.signing_hash_hex);
        assert_eq!(hex::encode(transaction::hash(&raw)), payment.txid);
        for (o, got) in tx.outputs.iter().zip(&recovered) {
            assert_eq!(
                crate::crypto::public_key(&hex32(&got.secret_hex).unwrap()).unwrap(),
                o.public
            );
            assert_eq!(
                crate::crypto::commitment(got.amount, &hex32(&got.blinding_hex).unwrap()).unwrap(),
                o.commitment
            );
        }
        // Raw recovered blinding is directly usable for a subsequent spend.
        let mut next = prepared(recovered[0].amount, 300, 4);
        next.secret_hex = recovered[0].secret_hex.clone();
        next.blinding_hex = recovered[0].blinding_hex.clone();
        next.ring_keys[4] = hex::encode(tx.outputs[0].public);
        next.ring_commitments[4] = hex::encode(tx.outputs[0].commitment);
        assert!(prepare_input(&next).is_ok());
        let wrong_network = receive(&raw, &spend, &view, "mainnet").unwrap();
        assert_eq!(wrong_network.len(), 2);
        assert!(wrong_network
            .iter()
            .all(|o| !o.memo_valid && o.memo_hex.is_empty()));
        assert_eq!(wrong_network[0].amount, 70);
        assert!(
            receive(&raw, Scalar::from(903u64).as_bytes(), &view, "testnet")
                .unwrap()
                .is_empty()
        );
        let mut changed = raw.clone();
        changed[49 + 64] ^= 1; // encrypted amount is in the signed prefix
        rejected(&changed);
        assert!(receive(&changed, &spend, &view, "testnet").is_err());
        let mut changed = raw.clone();
        changed.extend_from_slice(&[0]);
        rejected(&changed);
        rejected(&raw[..raw.len() - 1]);
        let mut tx = transaction::parse(&raw).unwrap();
        tx.inputs[0].image = tx.inputs[1].image;
        rejected(&tx.serialize());
        let mut tx = transaction::parse(&raw).unwrap();
        tx.inputs[0].signature[0..32].fill(255);
        rejected(&tx.serialize());
        let mut tx = transaction::parse(&raw).unwrap();
        tx.inputs[0].pseudo = tx.inputs[1].pseudo;
        rejected(&tx.serialize());
        let mut tx = transaction::parse(&raw).unwrap();
        tx.outputs[0].proof[0] ^= 1;
        rejected(&tx.serialize());
    }

    #[test]
    fn rejects_bad_amounts_memos_and_duplicate_images() {
        let view = Scalar::from(42u64).to_bytes();
        assert!(build(
            &view,
            "mainnet",
            &[prepared(0, 10, 0)],
            &[recipient(1, b"")],
            0
        )
        .is_err());
        assert!(build(
            &view,
            "mainnet",
            &[prepared(u64::MAX, 10, 0), prepared(1, 50, 0)],
            &[recipient(1, b"")],
            0
        )
        .is_err());
        assert!(build(
            &view,
            "mainnet",
            &[prepared(1, 10, 0)],
            &[recipient(u64::MAX, b"")],
            1
        )
        .is_err());
        assert!(build(
            &view,
            "mainnet",
            &[prepared(1, 10, 0)],
            &[recipient(1, &[0; 125])],
            0
        )
        .is_err());
        assert!(build(
            &view,
            "mainnet",
            &[prepared(1, 10, 0), prepared(1, 10, 0)],
            &[recipient(2, b"")],
            0
        )
        .is_err());
        assert!(build(
            &view,
            "mainnet",
            &[prepared(1, 10, 0)],
            &[recipient(2, b"")],
            0
        )
        .is_err());
        assert!(build(
            &view,
            "unknown",
            &[prepared(1, 10, 0)],
            &[recipient(1, b"")],
            0
        )
        .is_err());
        let mut input = prepared(1, 10, 0);
        input.ring_keys[0] =
            hex::encode(crate::crypto::public_key(Scalar::from(9000u64).as_bytes()).unwrap());
        assert!(
            matches!(prepare_input(&input), Err(e) if e == "input secret does not match real ring key")
        );
        let mut input = prepared(1, 10, 0);
        input.ring_commitments[0] = input.ring_commitments[1].clone();
        assert!(
            matches!(prepare_input(&input), Err(e) if e == "input opening does not match real ring commitment")
        );
    }

    #[test]
    fn duplicate_decoy_keys_are_rejected_by_wallet_construction() {
        let mut input = prepared(1, 10, 0);
        // Keep real index 0 intact; duplicate decoys only, including alternate hex case.
        input.ring_keys[2] = input.ring_keys[1].to_uppercase();
        assert!(matches!(prepare_input(&input), Err(e) if e == "duplicate ring public key"));
        input.ring_commitments[2] = input.ring_commitments[1].clone();
        assert!(matches!(prepare_input(&input), Err(e) if e == "duplicate ring public key"));
        let mut input = prepared(1, 10, 0);
        input.ring_commitments[2] = input.ring_commitments[1].clone();
        assert!(prepare_input(&input).is_ok());
    }

    #[test]
    fn memo_envelope_and_seed_contract() {
        let shared = Scalar::from(77u64);
        let domain = network_domain("mainnet").unwrap();
        let ciphertext = encrypt_memo(b"", &shared, 2, domain).unwrap();
        assert!(decrypt_memo(&ciphertext, &shared, 2, domain)
            .unwrap()
            .is_empty());
        let mut corrupt = ciphertext;
        corrupt[2] ^= 1;
        assert!(decrypt_memo(&corrupt, &shared, 2, domain).is_err());
        let ciphertext = encrypt_memo(&[42; 124], &shared, 2, domain).unwrap();
        assert_eq!(
            decrypt_memo(&ciphertext, &shared, 2, domain).unwrap(),
            vec![42; 124]
        );
        assert!(derive_keys(&[7; 32]).is_err());
        let mut seed = [7; 64];
        seed[32..].fill(9);
        let keys = derive_keys(&seed).unwrap();
        assert_eq!(
            keys.spend_secret_hex,
            hex::encode(crate::crypto::seeded_key(&[7; 32]).unwrap())
        );
        assert_eq!(
            keys.view_secret_hex,
            hex::encode(crate::crypto::seeded_key(&[9; 32]).unwrap())
        );
    }
}

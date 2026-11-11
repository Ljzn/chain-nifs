//! Version-1 indexed-wallet transaction wire format from core d4c7f785.
//! Verification is cryptographic only: ring members are caller-prepared, not chain checked.
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;

#[derive(rustler::NifMap)]
pub struct Input {
    pub secret_hex: String,
    pub amount: u64,
    pub blinding_hex: String,
    pub ring_keys: Vec<String>,
    pub ring_commitments: Vec<String>,
    pub real_index: u32,
}
#[derive(rustler::NifMap)]
pub struct Output {
    pub spend_public_hex: String,
    pub view_public_hex: String,
    pub amount: u64,
    pub memo_hex: String,
}
pub use crate::wallet::{build, receive};

impl Drop for Input {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_hex.zeroize();
        self.blinding_hex.zeroize();
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.memo_hex.zeroize();
    }
}

pub const MAX_INPUTS: usize = 16;
pub const MAX_OUTPUTS: usize = 16;
pub const MAX_RAW_BYTES: usize = 128 * 1024;
pub const RING_SIZE: usize = 16;
pub const SIGNATURE_BYTES: usize = 96 + 64 * RING_SIZE;
pub const MAX_PROOF_BYTES: usize = 1024;

pub(crate) fn point(bytes: &[u8; 32]) -> Result<RistrettoPoint, String> {
    CompressedRistretto(*bytes)
        .decompress()
        .ok_or_else(|| "invalid Ristretto encoding".into())
}
pub(crate) fn scalar(bytes: &[u8; 32]) -> Result<Scalar, String> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
        .ok_or_else(|| "noncanonical scalar".into())
}
pub(crate) fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}

pub(crate) struct TxOutput {
    pub public: [u8; 32],
    pub commitment: [u8; 32],
    pub amount: [u8; 8],
    pub memo: [u8; 128],
    pub proof: Vec<u8>,
}
pub(crate) struct TxInput {
    pub image: [u8; 32],
    pub pseudo: [u8; 32],
    pub keys: Vec<[u8; 32]>,
    pub commitments: Vec<[u8; 32]>,
    pub signature: Vec<u8>,
}
pub(crate) struct Transaction {
    pub public: [u8; 32],
    pub fee: u64,
    pub outputs: Vec<TxOutput>,
    pub inputs: Vec<TxInput>,
}
impl Transaction {
    pub(crate) fn prefix(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(1);
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.fee.to_le_bytes());
        for o in &self.outputs {
            out.extend_from_slice(&o.public);
            out.extend_from_slice(&o.commitment);
            out.extend_from_slice(&o.amount);
            out.extend_from_slice(&o.memo);
            out.extend_from_slice(&(o.proof.len() as u32).to_le_bytes());
            out.extend_from_slice(&o.proof);
        }
        out
    }
    pub(crate) fn signing_hash(&self) -> [u8; 32] {
        hash(&self.prefix())
    }
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut out = self.prefix();
        for i in &self.inputs {
            out.extend_from_slice(&i.image);
            out.extend_from_slice(&i.pseudo);
            out.extend_from_slice(&(RING_SIZE as u32).to_le_bytes());
            for k in &i.keys {
                out.extend_from_slice(k);
            }
            for c in &i.commitments {
                out.extend_from_slice(c);
            }
            out.extend_from_slice(&(i.signature.len() as u32).to_le_bytes());
            out.extend_from_slice(&i.signature);
        }
        out
    }
}

struct Reader<'a> {
    raw: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self.offset.checked_add(len).ok_or("wire length overflow")?;
        let bytes = self
            .raw
            .get(self.offset..end)
            .ok_or("truncated transaction")?;
        self.offset = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.take(N)?
            .try_into()
            .map_err(|_| "wire field length".into())
    }
    fn u32(&mut self) -> Result<usize, String> {
        Ok(u32::from_le_bytes(self.array()?) as usize)
    }
    fn encoded_point(&mut self, nonidentity: bool) -> Result<[u8; 32], String> {
        let bytes = self.array()?;
        let p = point(&bytes)?;
        if nonidentity && p == RistrettoPoint::identity() {
            return Err("identity public key or key image".into());
        }
        Ok(bytes)
    }
}

pub(crate) fn parse(raw: &[u8]) -> Result<Transaction, String> {
    if raw.len() > MAX_RAW_BYTES {
        return Err("transaction exceeds 128 KiB".into());
    }
    let mut r = Reader { raw, offset: 0 };
    if r.take(1)? != [1] {
        return Err("only transaction version 1 is supported".into());
    }
    let public = r.encoded_point(true)?;
    let ni = r.u32()?;
    let no = r.u32()?;
    if !(1..=MAX_INPUTS).contains(&ni) || !(1..=MAX_OUTPUTS).contains(&no) {
        return Err("transaction requires 1..16 inputs and outputs".into());
    }
    let fee = u64::from_le_bytes(r.array()?);
    let mut outputs = Vec::with_capacity(no);
    for _ in 0..no {
        let public = r.encoded_point(true)?;
        let commitment = r.encoded_point(false)?;
        let amount = r.array()?;
        let memo: [u8; 128] = r.array()?;
        if memo.iter().all(|b| *b == 0) {
            return Err("all-zero encrypted memo is invalid".into());
        }
        let len = r.u32()?;
        if len == 0 || len > MAX_PROOF_BYTES {
            return Err("range proof length outside 1..1024".into());
        }
        let proof = r.take(len)?.to_vec();
        outputs.push(TxOutput {
            public,
            commitment,
            amount,
            memo,
            proof,
        });
    }
    let mut images = HashSet::with_capacity(ni);
    let mut inputs = Vec::with_capacity(ni);
    for _ in 0..ni {
        let image = r.encoded_point(true)?;
        if !images.insert(image) {
            return Err("duplicate key image".into());
        }
        let pseudo = r.encoded_point(false)?;
        if r.u32()? != RING_SIZE {
            return Err("every ring must have 16 members".into());
        }
        let mut keys = Vec::with_capacity(RING_SIZE);
        let mut commitments = Vec::with_capacity(RING_SIZE);
        for _ in 0..RING_SIZE {
            keys.push(r.encoded_point(true)?);
        }
        for _ in 0..RING_SIZE {
            commitments.push(r.encoded_point(false)?);
        }
        if r.u32()? != SIGNATURE_BYTES {
            return Err("invalid RingCT signature length".into());
        }
        let signature = r.take(SIGNATURE_BYTES)?.to_vec();
        // c0 || s[16] || t[16] || inner key image || inner pseudo output.
        for s in signature[..32 + 64 * RING_SIZE].chunks_exact(32) {
            let b: [u8; 32] = s.try_into().map_err(|_| "invalid signature scalar")?;
            scalar(&b)?;
        }
        if signature[SIGNATURE_BYTES - 64..SIGNATURE_BYTES - 32] != image
            || signature[SIGNATURE_BYTES - 32..] != pseudo
        {
            return Err("outer and inner RingCT fields differ".into());
        }
        inputs.push(TxInput {
            image,
            pseudo,
            keys,
            commitments,
            signature,
        });
    }
    if r.offset != raw.len() {
        return Err("trailing transaction bytes".into());
    }
    Ok(Transaction {
        public,
        fee,
        inputs,
        outputs,
    })
}

pub(crate) fn verify_parsed(tx: &Transaction) -> Result<bool, String> {
    let message = tx.signing_hash();
    let mut incoming = RistrettoPoint::identity();
    let mut outgoing = Scalar::from(tx.fee) * RISTRETTO_BASEPOINT_POINT;
    for o in &tx.outputs {
        if !crate::crypto::range_verify(&o.commitment, &o.proof)? {
            return Ok(false);
        }
        outgoing += point(&o.commitment)?;
    }
    for i in &tx.inputs {
        if !crate::crypto::ring_verify(&i.keys, &i.commitments, &message, &i.signature)? {
            return Ok(false);
        }
        incoming += point(&i.pseudo)?;
    }
    Ok(incoming == outgoing)
}

/// Validate bounded canonical wire, all proofs, all RingCT bindings, and commitment balance.
/// Does not establish ring provenance, maturity, fee policy, or unspent status.
pub fn verify(raw: &[u8]) -> Result<bool, String> {
    verify_parsed(&parse(raw)?)
}

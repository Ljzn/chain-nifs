//! Bounded ordinary-TSC transactions for the address module's ML-DSA-65
//! 1-of-1 descriptor. This is a format-specific verifier, not a script VM or
//! chain/UTXO validator: supplied amounts and ownership must be trusted by callers.
use crate::address::{self, Descriptor};
use rustler::NifMap;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const MAX_INPUTS: usize = 64;
pub const MAX_OUTPUTS: usize = 16;
pub const MAX_RAW_BYTES: usize = 512 * 1024;
// Core consensus/amount.h (COIN = 100000000).
const MAX_MONEY: u64 = 2_100_000_000_000_000;
const SIGNATURE_BYTES: usize = 3309;

#[derive(NifMap, Clone, Debug)]
pub struct Input {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub sequence: u32,
}

#[derive(NifMap, Clone, Debug)]
pub struct Output {
    pub address: String,
    pub amount: u64,
}

#[derive(NifMap, Clone, Debug)]
pub struct Payment {
    pub unsigned_hex: String,
    pub raw_hex: String,
    pub txid: String,
    pub wtxid: String,
    pub fee: u64,
    /// Actual serialized weight; when unsigned this excludes future witnesses.
    pub weight: u64,
    pub vsize: u64,
    pub digests: Vec<String>,
}

struct WireInput {
    prevout: [u8; 36],
    amount: u64,
    sequence: u32,
}

struct WireOutput {
    amount: u64,
    script: Vec<u8>,
}

fn compact_size(n: u64, out: &mut Vec<u8>) {
    match n {
        0..=252 => out.push(n as u8),
        253..=0xffff => {
            out.push(253);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x10000..=0xffff_ffff => {
            out.push(254);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(255);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

fn bytes(data: &[u8], out: &mut Vec<u8>) {
    compact_size(data.len() as u64, out);
    out.extend_from_slice(data);
}

fn add_amount(sum: u64, amount: u64) -> Result<u64, String> {
    if amount == 0 || amount > MAX_MONEY {
        return Err("amount must be positive and within MAX_MONEY".into());
    }
    let total = sum.checked_add(amount).ok_or("amount sum overflow")?;
    if total > MAX_MONEY {
        return Err("amount sum exceeds MAX_MONEY".into());
    }
    Ok(total)
}

fn prepare_inputs(inputs: &[Input]) -> Result<(Vec<WireInput>, u64), String> {
    if inputs.is_empty() || inputs.len() > MAX_INPUTS {
        return Err("requires 1..64 inputs".into());
    }
    let mut seen = HashSet::new();
    let mut result = Vec::with_capacity(inputs.len());
    let mut sum = 0;
    for i in inputs {
        if i.txid.len() != 64 {
            return Err("txid must be 64 display-order hex characters".into());
        }
        let mut txid = hex::decode(&i.txid).map_err(|_| "invalid txid hex".to_string())?;
        txid.reverse();
        let mut prevout = [0u8; 36];
        prevout[..32].copy_from_slice(&txid);
        prevout[32..].copy_from_slice(&i.vout.to_le_bytes());
        if prevout[..32].iter().all(|b| *b == 0) && i.vout == u32::MAX {
            return Err("coinbase prevout is not supported".into());
        }
        if !seen.insert(prevout) {
            return Err("duplicate prevout".into());
        }
        sum = add_amount(sum, i.amount)?;
        result.push(WireInput {
            prevout,
            amount: i.amount,
            sequence: i.sequence,
        });
    }
    Ok((result, sum))
}

fn serialize_outputs(outputs: &[WireOutput]) -> Vec<u8> {
    let mut out = Vec::new();
    for o in outputs {
        out.extend_from_slice(&o.amount.to_le_bytes());
        bytes(&o.script, &mut out);
    }
    out
}

fn serialize(
    inputs: &[WireInput],
    outputs: &[WireOutput],
    witness: Option<&[Vec<u8>]>,
    d: &Descriptor,
) -> Vec<u8> {
    let mut out = 2i32.to_le_bytes().to_vec();
    if witness.is_some() {
        out.extend_from_slice(&[0, 1]);
    }
    compact_size(inputs.len() as u64, &mut out);
    for i in inputs {
        out.extend_from_slice(&i.prevout);
        out.push(0); // Empty scriptSig.
        out.extend_from_slice(&i.sequence.to_le_bytes());
    }
    compact_size(outputs.len() as u64, &mut out);
    out.extend_from_slice(&serialize_outputs(outputs));
    if let Some(signatures) = witness {
        for sig in signatures {
            out.push(3);
            bytes(sig, &mut out);
            bytes(&d.leaf_script, &mut out);
            bytes(&d.control_block, &mut out);
        }
    }
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

fn digests(inputs: &[WireInput], outputs: &[WireOutput], d: &Descriptor) -> Vec<[u8; 32]> {
    let mut prevouts = Vec::new();
    let mut amounts = Vec::new();
    let mut scripts = Vec::new();
    let mut sequences = Vec::new();
    for i in inputs {
        prevouts.extend_from_slice(&i.prevout);
        amounts.extend_from_slice(&i.amount.to_le_bytes());
        bytes(&d.script_pubkey, &mut scripts);
        sequences.extend_from_slice(&i.sequence.to_le_bytes());
    }
    let mut prefix = vec![0x00, 0x01]; // Epoch 0, SIGHASH_ALL.
    prefix.extend_from_slice(&2i32.to_le_bytes());
    prefix.extend_from_slice(&0u32.to_le_bytes());
    let serialized_outputs = serialize_outputs(outputs);
    for data in [
        &prevouts,
        &amounts,
        &scripts,
        &sequences,
        &serialized_outputs,
    ] {
        prefix.extend_from_slice(&Sha256::digest(data));
    }
    prefix.push(0x02); // ext_flag=1, no annex.
    (0..inputs.len())
        .map(|index| {
            let mut msg = prefix.clone();
            msg.extend_from_slice(&(index as u32).to_le_bytes());
            msg.extend_from_slice(&d.leaf_hash);
            msg.push(0); // key version.
            msg.extend_from_slice(&u32::MAX.to_le_bytes()); // No OP_CODESEPARATOR.
            address::tagged_hash("TapSighash/ML-DSA", &msg)
        })
        .collect()
}

fn transaction_id(raw: &[u8]) -> String {
    let mut hash = Sha256::digest(Sha256::digest(raw)).to_vec();
    hash.reverse();
    hex::encode(hash)
}

pub fn build(
    pk: &[u8],
    sk: Option<&[u8]>,
    network: &str,
    inputs: &[Input],
    outputs: &[Output],
) -> Result<Payment, String> {
    address::hrp(network)?;
    let d = address::descriptor(pk)?;
    let (wire_inputs, input_sum) = prepare_inputs(inputs)?;
    if outputs.is_empty() || outputs.len() > MAX_OUTPUTS {
        return Err("requires 1..16 outputs".into());
    }
    let mut wire_outputs = Vec::with_capacity(outputs.len());
    let mut output_sum = 0;
    for o in outputs {
        output_sum = add_amount(output_sum, o.amount)?;
        let program = address::decode(&o.address, network)?;
        wire_outputs.push(WireOutput {
            amount: o.amount,
            script: address::script_pubkey(&program),
        });
    }
    let fee = input_sum
        .checked_sub(output_sum)
        .ok_or("outputs exceed supplied input value")?;
    let hashes = digests(&wire_inputs, &wire_outputs, &d);
    let unsigned = serialize(&wire_inputs, &wire_outputs, None, &d);
    let raw = if let Some(secret) = sk {
        let mut signatures = Vec::with_capacity(inputs.len());
        for digest in &hashes {
            let mut signature = crate::crypto::sign_digest(secret, digest)?;
            if signature.len() != SIGNATURE_BYTES {
                return Err("signer returned wrong ML-DSA-65 signature length".into());
            }
            if !crate::crypto::verify_digest(pk, digest, &signature)? {
                return Err("signature does not verify with supplied public key".into());
            }
            signature.push(1);
            signatures.push(signature);
        }
        serialize(&wire_inputs, &wire_outputs, Some(&signatures), &d)
    } else {
        unsigned.clone()
    };
    if raw.len() > MAX_RAW_BYTES {
        return Err("transaction exceeds 512 KiB".into());
    }
    let weight = (unsigned.len() as u64) * 3 + raw.len() as u64;
    Ok(Payment {
        unsigned_hex: hex::encode(&unsigned),
        raw_hex: hex::encode(&raw),
        txid: transaction_id(&unsigned),
        wtxid: transaction_id(&raw),
        fee,
        weight,
        vsize: weight.div_ceil(4),
        digests: hashes.iter().map(hex::encode).collect(),
    })
}

/// Malformed or out-of-scope encodings return Err; descriptor/input or signature
/// mismatches return Ok(false). A canonical unsigned transaction returns false.
/// The network validates the API selection; raw scripts themselves have no HRP.
pub fn verify(raw: &[u8], pk: &[u8], network: &str, inputs: &[Input]) -> Result<bool, String> {
    address::hrp(network)?;
    if raw.len() > MAX_RAW_BYTES {
        return Err("transaction exceeds 512 KiB".into());
    }
    let d = address::descriptor(pk)?;
    let (wire_inputs, input_sum) = prepare_inputs(inputs)?;
    let mut r = Reader { raw, pos: 0 };
    if r.take(4)? != 2i32.to_le_bytes().as_slice() {
        return Err("only transaction version 2 is supported".into());
    }
    let first_count = r.compact()?;
    let (has_witness, input_count) = if first_count == 0 {
        if r.byte()? != 1 {
            return Err("only witness flag 01 is supported; no output extensions".into());
        }
        (true, r.compact()?)
    } else {
        (false, first_count)
    };
    if input_count == 0 || input_count > MAX_INPUTS as u64 {
        return Err("requires 1..64 inputs".into());
    }
    if input_count as usize != wire_inputs.len() {
        return Ok(false);
    }
    let mut matches = true;
    for i in &wire_inputs {
        matches &= r.take(36)? == i.prevout.as_slice();
        if r.compact()? != 0 {
            return Err("scriptSig must be empty".into());
        }
        matches &= r.u32()? == i.sequence;
    }
    let output_count = r.compact()?;
    if output_count == 0 || output_count > MAX_OUTPUTS as u64 {
        return Err("requires 1..16 outputs".into());
    }
    let mut outputs = Vec::with_capacity(output_count as usize);
    let mut output_sum = 0;
    for _ in 0..output_count {
        let amount = r.u64()?;
        output_sum = add_amount(output_sum, amount)?;
        let script = r.vector(34)?;
        if script.len() != 34 || script[..2] != [0x52, 0x20] {
            return Err("only 32-byte witness-v2 output scripts are supported".into());
        }
        outputs.push(WireOutput {
            amount,
            script: script.to_vec(),
        });
    }
    if output_sum > input_sum {
        return Err("outputs exceed supplied input value".into());
    }
    let mut signatures = Vec::with_capacity(wire_inputs.len());
    if has_witness {
        for _ in &wire_inputs {
            if r.compact()? != 3 {
                return Err(
                    "witness must contain exactly signature, leaf, control; no annex".into(),
                );
            }
            let signature = r.vector(SIGNATURE_BYTES + 1)?;
            if signature.len() != SIGNATURE_BYTES + 1 || signature[SIGNATURE_BYTES] != 1 {
                return Err("witness signature must be 3309 bytes plus SIGHASH_ALL 01".into());
            }
            signatures.push(signature);
            matches &= r.vector(d.leaf_script.len())? == d.leaf_script.as_slice();
            matches &= r.vector(d.control_block.len())? == d.control_block.as_slice();
        }
    }
    if r.u32()? != 0 {
        return Err("only locktime 0 is supported".into());
    }
    if r.pos != raw.len() {
        return Err("trailing transaction bytes".into());
    }
    if !matches || !has_witness {
        return Ok(false);
    }
    // Canonical parser plus reserialization prevents accepting alternate framing.
    let owned_signatures: Vec<Vec<u8>> = signatures.iter().map(|s| s.to_vec()).collect();
    if serialize(&wire_inputs, &outputs, Some(&owned_signatures), &d) != raw {
        return Err("noncanonical transaction encoding".into());
    }
    for (digest, signature) in digests(&wire_inputs, &outputs, &d).iter().zip(signatures) {
        if !crate::crypto::verify_digest(pk, digest, &signature[..SIGNATURE_BYTES])? {
            return Ok(false);
        }
    }
    Ok(true)
}

struct Reader<'a> {
    raw: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or("transaction offset overflow")?;
        let result = self.raw.get(self.pos..end).ok_or("truncated transaction")?;
        self.pos = end;
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, String> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    fn compact(&mut self) -> Result<u64, String> {
        let (value, minimum) = match self.byte()? {
            253 => {
                let b = self.take(2)?;
                (u16::from_le_bytes([b[0], b[1]]) as u64, 253)
            }
            254 => (self.u32()? as u64, 0x10000),
            255 => (self.u64()?, 0x1_0000_0000),
            n => return Ok(n as u64),
        };
        if value < minimum {
            return Err("nonminimal CompactSize".into());
        }
        Ok(value)
    }
    fn vector(&mut self, maximum: usize) -> Result<&'a [u8], String> {
        let n = self.compact()?;
        if n > maximum as u64 {
            return Err("transaction item exceeds supported size".into());
        }
        self.take(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_size_boundaries_and_nonminimal_encodings() {
        for value in [
            0,
            252,
            253,
            65535,
            65536,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            u64::MAX,
        ] {
            let mut encoded = Vec::new();
            compact_size(value, &mut encoded);
            let mut r = Reader {
                raw: &encoded,
                pos: 0,
            };
            assert_eq!(r.compact().unwrap(), value);
            assert_eq!(r.pos, encoded.len());
            for end in 0..encoded.len() {
                assert!(Reader {
                    raw: &encoded[..end],
                    pos: 0
                }
                .compact()
                .is_err());
            }
        }
        for encoded in [
            &[253, 252, 0][..],
            &[254, 255, 255, 0, 0][..],
            &[255, 255, 255, 255, 255, 0, 0, 0, 0][..],
        ] {
            assert!(Reader {
                raw: encoded,
                pos: 0
            }
            .compact()
            .is_err());
        }
    }

    #[test]
    fn rejects_duplicate_prevouts_overspend_and_out_of_scope_framing() {
        let pk = [9; 1952];
        let destination = address::derive(&pk, "regtest").unwrap().address;
        let input = Input {
            txid: "12".repeat(32),
            vout: 0,
            amount: 10000,
            sequence: u32::MAX,
        };
        let outputs = [Output {
            address: destination.clone(),
            amount: 9000,
        }];
        assert!(build(
            &pk,
            None,
            "regtest",
            &[input.clone(), input.clone()],
            &outputs
        )
        .is_err());
        assert!(build(
            &pk,
            None,
            "regtest",
            std::slice::from_ref(&input),
            &[Output {
                address: destination,
                amount: 10001
            }]
        )
        .is_err());
        assert!(add_amount(MAX_MONEY, 1).is_err());
        assert!(add_amount(0, 0).is_err());
        let payment = build(&pk, None, "regtest", std::slice::from_ref(&input), &outputs).unwrap();
        let raw = hex::decode(payment.raw_hex).unwrap();
        assert!(!verify(&raw, &pk, "regtest", std::slice::from_ref(&input)).unwrap());
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(verify(&trailing, &pk, "regtest", std::slice::from_ref(&input)).is_err());
        let mut extension_flag = raw.clone();
        extension_flag.splice(4..4, [0, 3]);
        assert!(verify(
            &extension_flag,
            &pk,
            "regtest",
            std::slice::from_ref(&input)
        )
        .is_err());
        let mut nonminimal = raw.clone();
        nonminimal.splice(4..5, [253, 1, 0]);
        assert!(verify(&nonminimal, &pk, "regtest", std::slice::from_ref(&input)).is_err());
        let d = address::descriptor(&pk).unwrap();
        let (ins, _) = prepare_inputs(std::slice::from_ref(&input)).unwrap();
        let outs = [WireOutput {
            amount: 9000,
            script: d.script_pubkey.clone(),
        }];
        // Malformed sighash is rejected before invoking the cryptographic verifier.
        let malformed = serialize(&ins, &outs, Some(&[vec![0; 3310]]), &d);
        assert!(verify(&malformed, &pk, "regtest", &[input]).is_err());
    }

    #[test]
    fn sighash_commits_to_other_inputs_amount_sequence_outputs_and_index() {
        let d = address::descriptor(&[9; 1952]).unwrap();
        let public_inputs = vec![
            Input {
                txid: "11".repeat(32),
                vout: 2,
                amount: 10000,
                sequence: 0xffff_fffd,
            },
            Input {
                txid: "22".repeat(32),
                vout: 3,
                amount: 20000,
                sequence: 0xffff_fffe,
            },
        ];
        let (mut ins, _) = prepare_inputs(&public_inputs).unwrap();
        let mut outs = vec![WireOutput {
            amount: 29000,
            script: d.script_pubkey.clone(),
        }];
        let baseline = digests(&ins, &outs, &d);
        assert_ne!(baseline[0], baseline[1]);
        ins[1].amount += 1;
        assert_ne!(baseline[0], digests(&ins, &outs, &d)[0]);
        ins[1].amount -= 1;
        ins[1].sequence ^= 1;
        assert_ne!(baseline[0], digests(&ins, &outs, &d)[0]);
        ins[1].sequence ^= 1;
        ins[1].prevout[0] ^= 1;
        assert_ne!(baseline[0], digests(&ins, &outs, &d)[0]);
        ins[1].prevout[0] ^= 1;
        outs[0].amount -= 1;
        assert_ne!(baseline[0], digests(&ins, &outs, &d)[0]);
        outs[0].amount += 1;
        outs[0].script[2] ^= 1;
        assert_ne!(baseline[0], digests(&ins, &outs, &d)[0]);
    }
}

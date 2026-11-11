// Wrapper and wire parser are independently authored; upstream/* are exact copies.
#[path = "upstream/commitment.rs"]
mod commitment;
#[path = "upstream/keys.rs"]
mod keys;
#[path = "upstream/rangeproof.rs"]
mod rangeproof;
#[path = "upstream/ring.rs"]
mod ring;
#[path = "upstream/stealth.rs"]
mod stealth;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::io::Read;
fn ok(rc: i32) -> Result<(), String> {
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("official ABI returned {rc}"))
    }
}
fn hx(b: impl AsRef<[u8]>) -> String {
    hex::encode(b)
}
fn bytes(v: &Value, k: &str) -> Result<Vec<u8>, String> {
    hex::decode(v[k].as_str().ok_or(format!("missing {k}"))?).map_err(|e| e.to_string())
}
fn a32(b: &[u8]) -> Result<[u8; 32], String> {
    b.try_into().map_err(|_| "expected 32 bytes".into())
}
fn point(b: &[u8]) -> Result<RistrettoPoint, String> {
    CompressedRistretto(a32(b)?)
        .decompress()
        .ok_or("invalid canonical Ristretto point".into())
}
fn key(seed: [u8; 32]) -> [u8; 64] {
    let mut k = [0; 64];
    assert_eq!(
        ring::blocknet_ristretto_keygen_from_seed(seed.as_ptr(), k.as_mut_ptr()),
        0
    );
    k
}
fn commit(n: u64, b: &[u8]) -> [u8; 32] {
    let mut c = [0; 32];
    assert_eq!(
        commitment::blocknet_pedersen_commit_with_blinding(n, b.as_ptr(), c.as_mut_ptr()),
        0
    );
    c
}
fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p)
    }
    h.finalize().into()
}
fn blind(s: &[u8], i: u32) -> [u8; 32] {
    hash(&[b"blocknet_blinding", s, &i.to_le_bytes()])
}
fn encrypt(n: u64, b: &[u8], i: u32) -> [u8; 8] {
    let m = hash(&[b"blocknet_amount", b, &i.to_le_bytes()]);
    let mut e = n.to_le_bytes();
    for j in 0..8 {
        e[j] ^= m[j]
    }
    e
}
fn memo_mask(s: &[u8], i: u32, network: &str) -> [u8; 128] {
    let seed = hash(&[s, b"memo", &i.to_le_bytes(), network.as_bytes()]);
    let mut m = [0; 128];
    for j in 0u32..4 {
        m[j as usize * 32..(j as usize + 1) * 32]
            .copy_from_slice(&hash(&[&seed, &j.to_le_bytes()]));
    }
    m
}
fn memo_encrypt(payload: &[u8], s: &[u8], i: u32) -> [u8; 128] {
    assert!(payload.len() <= 124);
    let mut p = [0x42; 128];
    p[0] = 1;
    p[1] = payload.len() as u8;
    let c = hash(&[
        b"blocknet_memo_checksum",
        &(payload.len() as u16).to_le_bytes(),
        payload,
    ]);
    p[2..4].copy_from_slice(&c[..2]);
    p[4..4 + payload.len()].copy_from_slice(payload);
    let m = memo_mask(s, i, "blocknet_mainnet");
    for j in 0..128 {
        p[j] ^= m[j]
    }
    p
}
fn ring_case(v: &Value) -> Result<Value, String> {
    let msg = bytes(v, "message_hex")?;
    let sig = bytes(v, "signature_hex")?;
    let parse = |k: &str| -> Result<Vec<u8>, String> {
        let arr = v[k].as_array().ok_or(format!("missing {k}"))?;
        if arr.len() != 16 {
            return Err("ring must contain 16 members".into());
        }
        let mut out = Vec::new();
        for x in arr {
            let b = hex::decode(x.as_str().ok_or("expected hex")?).map_err(|e| e.to_string())?;
            point(&b)?;
            out.extend(b)
        }
        Ok(out)
    };
    let ks = parse("ring_keys")?;
    let cs = parse("ring_commitments")?;
    ok(ring::blocknet_ringct_verify(
        ks.as_ptr(),
        cs.as_ptr(),
        16,
        msg.as_ptr(),
        msg.len(),
        sig.as_ptr(),
        sig.len(),
    ))?;
    Ok(json!({"valid":true}))
}
struct Reader<'a> {
    b: &'a [u8],
    o: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.o.checked_add(n).ok_or("overflow")?;
        let x = self.b.get(self.o..end).ok_or("truncated wire")?;
        self.o = end;
        Ok(x)
    }
    fn u32(&mut self) -> Result<usize, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
}
fn payment(v: &Value) -> Result<Value, String> {
    let raw = bytes(v, "raw_hex")?;
    if raw.len() > 1000000 {
        return Err("oversized wire".into());
    }
    let mut r = Reader { b: &raw, o: 0 };
    if r.take(1)? != [1] {
        return Err("unsupported version".into());
    }
    let txpub = r.take(32)?;
    point(txpub)?;
    let ni = r.u32()?;
    let no = r.u32()?;
    if !(1..=16).contains(&ni) || !(1..=16).contains(&no) {
        return Err("expected 1..16 inputs/outputs".into());
    }
    let fee = u64::from_le_bytes(r.take(8)?.try_into().unwrap());
    let mut sum_out = RistrettoPoint::default();
    let mut recovered = Vec::new();
    for i in 0..no {
        let pk = r.take(32)?;
        point(pk)?;
        let c = r.take(32)?;
        sum_out += point(c)?;
        let encrypted = r.take(8)?;
        let memo = r.take(128)?;
        let np = r.u32()?;
        if np > 1024 {
            return Err("proof too long".into());
        }
        let proof = r.take(np)?;
        ok(rangeproof::blocknet_range_proof_verify(
            c.as_ptr(),
            proof.as_ptr(),
            proof.len(),
        ))?;
        if v.get("receiver").is_some() {
            let rec = &v["receiver"];
            let spend = a32(&bytes(rec, "spend_private_hex")?)?;
            let view = a32(&bytes(rec, "view_private_hex")?)?;
            let mut shared = [0; 32];
            ok(stealth::blocknet_stealth_derive_secret_indexed(
                txpub.as_ptr(),
                view.as_ptr(),
                i as u32,
                shared.as_mut_ptr(),
            ))?;
            let mut private = [0; 32];
            ok(commitment::blocknet_blinding_add(
                spend.as_ptr(),
                shared.as_ptr(),
                private.as_mut_ptr(),
            ))?;
            let mut public = [0; 32];
            ok(stealth::blocknet_scalar_to_pubkey(
                private.as_ptr(),
                public.as_mut_ptr(),
            ))?;
            if public == pk {
                let b = blind(&shared, i as u32);
                let mask = encrypt(0, &b, i as u32);
                let mut amount = [0; 8];
                for j in 0..8 {
                    amount[j] = encrypted[j] ^ mask[j]
                }
                let n = u64::from_le_bytes(amount);
                if commit(n, &b) != c {
                    return Err("recovered amount commitment mismatch".into());
                }
                let network = match v["network"].as_str().unwrap_or("blocknet_mainnet") {
                    "mainnet" | "blocknet_mainnet" => "blocknet_mainnet",
                    "testnet" | "blocknet_testnet" => "blocknet_testnet",
                    _ => return Err("unknown memo network".into()),
                };
                let m = memo_mask(&shared, i as u32, network);
                let mut plain = [0; 128];
                for j in 0..128 {
                    plain[j] = memo[j] ^ m[j]
                }
                let len = plain[1] as usize;
                if plain[0] != 1 || len > 124 {
                    return Err("invalid memo envelope".into());
                }
                let checksum = hash(&[
                    b"blocknet_memo_checksum",
                    &(len as u16).to_le_bytes(),
                    &plain[4..4 + len],
                ]);
                if plain[2..4] != checksum[..2] {
                    return Err("invalid memo checksum".into());
                }
                recovered.push(json!({"index":i,"amount":n,"blinding_raw_hex":hx(b),"one_time_private_hex":hx(private),"memo_hex":hx(&plain[4..4+len])}));
            }
        }
    }
    let signing = hash(&[&raw[..r.o]]);
    let mut sum_in = RistrettoPoint::default();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..ni {
        let ki = r.take(32)?;
        point(ki)?;
        if !seen.insert(ki.to_vec()) {
            return Err("duplicate key image".into());
        }
        let pseudo = r.take(32)?;
        sum_in += point(pseudo)?;
        if r.u32()? != 16 {
            return Err("ring size must be 16".into());
        }
        let ks = r.take(512)?;
        let cs = r.take(512)?;
        for p in ks.chunks(32).chain(cs.chunks(32)) {
            point(p)?;
        }
        let ns = r.u32()?;
        if ns != 1120 {
            return Err("signature size must be 1120".into());
        }
        let sig = r.take(ns)?;
        ok(ring::blocknet_ringct_verify(
            ks.as_ptr(),
            cs.as_ptr(),
            16,
            signing.as_ptr(),
            32,
            sig.as_ptr(),
            sig.len(),
        ))?;
        let mut embedded = [0; 32];
        ok(ring::blocknet_ringct_key_image(
            sig.as_ptr(),
            16,
            embedded.as_mut_ptr(),
        ))?;
        if embedded != ki {
            return Err("key image binding mismatch".into());
        }
        ok(ring::blocknet_ringct_pseudo_output(
            sig.as_ptr(),
            16,
            embedded.as_mut_ptr(),
        ))?;
        if embedded != pseudo {
            return Err("pseudo-output binding mismatch".into());
        }
    }
    if r.o != raw.len() {
        return Err("trailing wire bytes".into());
    }
    let mut fc = [0; 32];
    ok(commitment::blocknet_fee_commitment(fee, fc.as_mut_ptr()))?;
    if sum_in != sum_out + point(&fc)? {
        return Err("commitment balance mismatch".into());
    }
    Ok(
        json!({"valid":true,"signing_hash_hex":hx(signing),"txid_hex":hx(hash(&[&raw])),"inputs":ni,"outputs":no,"fee":fee,"recovered":recovered}),
    )
}
fn generate() -> Value {
    let spend = key([1; 32]);
    let view = key([2; 32]);
    let mut images = Vec::new();
    let mut keys = Vec::new();
    let mut commitments = Vec::new();
    for i in 0u8..16 {
        let k = key([i + 10; 32]);
        let mut ki = [0; 32];
        assert_eq!(
            ring::blocknet_key_image(k[..32].as_ptr(), ki.as_mut_ptr()),
            0
        );
        if i < 2 {
            images.extend(ki)
        }
        keys.push(k);
        commitments.push(commit(100, &[7; 32]));
    }
    let mut tx = [0; 32];
    assert_eq!(
        stealth::blocknet_derive_deterministic_tx_key(
            view.as_ptr(),
            images.as_ptr(),
            2,
            tx.as_mut_ptr()
        ),
        0
    );
    let mut txpub = [0; 32];
    assert_eq!(
        stealth::blocknet_scalar_to_pubkey(tx.as_ptr(), txpub.as_mut_ptr()),
        0
    );
    let mut outputs = Vec::new();
    for i in 0u32..2 {
        let mut s = [0; 32];
        let mut recv = [0; 32];
        assert_eq!(
            stealth::blocknet_stealth_derive_secret_sender_indexed(
                tx.as_ptr(),
                view[32..].as_ptr(),
                i,
                s.as_mut_ptr()
            ),
            0
        );
        assert_eq!(
            stealth::blocknet_stealth_derive_secret_indexed(
                txpub.as_ptr(),
                view.as_ptr(),
                i,
                recv.as_mut_ptr()
            ),
            0
        );
        assert_eq!(s, recv);
        let mut private = [0; 32];
        assert_eq!(
            commitment::blocknet_blinding_add(spend.as_ptr(), s.as_ptr(), private.as_mut_ptr()),
            0
        );
        let mut public = [0; 32];
        assert_eq!(
            stealth::blocknet_scalar_to_pubkey(private.as_ptr(), public.as_mut_ptr()),
            0
        );
        let b = blind(&s, i);
        let c = commit(42, &b);
        let mut proof = [0; 1024];
        let mut n = 0;
        assert_eq!(
            rangeproof::blocknet_range_proof_create(42, b.as_ptr(), proof.as_mut_ptr(), &mut n),
            0
        );
        assert_eq!(
            rangeproof::blocknet_range_proof_verify(c.as_ptr(), proof.as_ptr(), n),
            0
        );
        outputs.push(json!({"index":i,"amount":42,"shared_sender_hex":hx(s),"shared_receiver_hex":hx(recv),"one_time_private_hex":hx(private),"one_time_public_hex":hx(public),"blinding_raw_hex":hx(b),"commitment_hex":hx(c),"encrypted_amount_hex":hx(encrypt(42,&b,i)),"memo_hex":hx(b"Blocknet oracle"),"encrypted_memo_hex":hx(memo_encrypt(b"Blocknet oracle",&s,i)),"range_proof_hex":hx(&proof[..n])}));
    }
    let pseudo = commit(100, &[8; 32]);
    let message = hash(&[b"Blocknet official independent oracle"]);
    let msg = &message;
    let flat: Vec<u8> = keys.iter().flat_map(|k| k[32..].iter().copied()).collect();
    let cs: Vec<u8> = commitments.iter().flatten().copied().collect();
    let mut sig = [0; 1120];
    let mut n = 0;
    assert_eq!(
        ring::blocknet_ringct_sign(
            flat.as_ptr(),
            cs.as_ptr(),
            16,
            0,
            keys[0].as_ptr(),
            [7; 32].as_ptr(),
            pseudo.as_ptr(),
            [8; 32].as_ptr(),
            msg.as_ptr(),
            msg.len(),
            sig.as_mut_ptr(),
            &mut n
        ),
        0
    );
    let case = json!({"message_hex":hx(msg),"ring_keys":keys.iter().map(|k|hx(&k[32..])).collect::<Vec<_>>(),"ring_commitments":commitments.iter().map(hx).collect::<Vec<_>>(),"signature_hex":hx(&sig[..n])});
    assert!(ring_case(&case).is_ok());
    let mut raw = vec![1];
    raw.extend(txpub);
    raw.extend(1u32.to_le_bytes());
    raw.extend(2u32.to_le_bytes());
    raw.extend(16u64.to_le_bytes());
    let mut total_blind = [0u8; 32];
    for o in &outputs {
        for name in [
            "one_time_public_hex",
            "commitment_hex",
            "encrypted_amount_hex",
            "encrypted_memo_hex",
        ] {
            raw.extend(bytes(o, name).unwrap());
        }
        let p = bytes(o, "range_proof_hex").unwrap();
        raw.extend((p.len() as u32).to_le_bytes());
        raw.extend(p);
        let b = bytes(o, "blinding_raw_hex").unwrap();
        let previous = total_blind;
        assert_eq!(
            commitment::blocknet_blinding_add(
                previous.as_ptr(),
                b.as_ptr(),
                total_blind.as_mut_ptr()
            ),
            0
        );
    }
    let signing = hash(&[&raw]);
    let pseudo = commit(100, &total_blind);
    assert_eq!(
        ring::blocknet_ringct_sign(
            flat.as_ptr(),
            cs.as_ptr(),
            16,
            0,
            keys[0].as_ptr(),
            [7; 32].as_ptr(),
            pseudo.as_ptr(),
            total_blind.as_ptr(),
            signing.as_ptr(),
            32,
            sig.as_mut_ptr(),
            &mut n
        ),
        0
    );
    let mut ki = [0; 32];
    assert_eq!(
        ring::blocknet_ringct_key_image(sig.as_ptr(), 16, ki.as_mut_ptr()),
        0
    );
    raw.extend(ki);
    raw.extend(pseudo);
    raw.extend(16u32.to_le_bytes());
    raw.extend(&flat);
    raw.extend(&cs);
    raw.extend((n as u32).to_le_bytes());
    raw.extend(&sig[..n]);
    let expected_received: Vec<Value> = outputs.iter().map(|o| json!({"index":o["index"],"amount":o["amount"],"memo_hex":o["memo_hex"]})).collect();
    let payment_case = json!({"raw_hex":hx(&raw),"expected_received":expected_received,"receiver":{"spend_private_hex":hx(&spend[..32]),"view_private_hex":hx(&view[..32])}});
    assert!(payment(&payment_case).is_ok());
    json!({"schema":"blocknet-official-oracle-v1","upstream_commit":"d4c7f78572e5dd637e7f322ea89573b65912e64c","synthetic_public_seeds_only":true,"network":"blocknet_mainnet","key_vectors":(0u8..4).map(|i|{let k=key([i;32]);json!({"seed_hex":hx([i;32]),"private_hex":hx(&k[..32]),"public_hex":hx(&k[32..])})}).collect::<Vec<_>>(),"stealth":{"wallet_seed64_hex":hx([[1u8;32],[2u8;32]].concat()),"spend_seed_hex":hx([1;32]),"view_seed_hex":hx([2;32]),"spend_private_hex":hx(&spend[..32]),"spend_public_hex":hx(&spend[32..]),"view_private_hex":hx(&view[..32]),"view_public_hex":hx(&view[32..]),"key_images":images.chunks(32).map(hx).collect::<Vec<_>>(),"tx_private_hex":hx(tx),"tx_public_hex":hx(txpub),"outputs":outputs},"cases":[case],"payments":[payment_case]})
}
fn main() {
    let mode = std::env::args().nth(1).unwrap_or("verify".into());
    if mode == "generate" {
        println!("{}", serde_json::to_string_pretty(&generate()).unwrap());
        return;
    }
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let v: Value = serde_json::from_str(&input).unwrap();
    let eval = |f: fn(&Value) -> Result<Value, String>, k: &str| {
        v[k].as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|x| f(x).unwrap_or_else(|e| json!({"valid":false,"error":e})))
            .collect::<Vec<_>>()
    };
    let result = json!({"cases":eval(ring_case,"cases"),"payments":eval(payment,"payments")});
    println!("{}", result);
    if result["cases"]
        .as_array()
        .unwrap()
        .iter()
        .chain(result["payments"].as_array().unwrap())
        .any(|x| x["valid"] != true)
    {
        std::process::exit(1)
    }
}

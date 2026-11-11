//! Safe adaptation of Blocknet core crypto-rs at
//! d4c7f78572e5dd637e7f322ea89573b65912e64c (ring.rs, commitment.rs,
//! rangeproof.rs; stealth.rs reviewed for consistent Ristretto conventions).
//! The RingCT equations, hash domains, transcript and serialization are upstream's.
//! Boundary validation, fallible entropy and the comments below are this adapter's.

#![forbid(unsafe_code)]

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{IsIdentity, MultiscalarMul},
};
use merlin::Transcript;
use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

pub const RING_SIZE: usize = 16;
pub const SIGNATURE_SIZE: usize = 1120;
const RANGE_LABEL: &[u8] = b"Blocknet Range Proof";

fn bytes32(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes.try_into().map_err(|_| "expected 32 bytes".to_owned())
}

/// Parse canonical scalars; zero is allowed for algebraic scalar operations.
pub(crate) fn scalar(bytes: &[u8]) -> Result<Scalar, String> {
    Scalar::from_canonical_bytes(bytes32(bytes)?)
        .into_option()
        .ok_or_else(|| "noncanonical scalar".to_owned())
}

/// Decompression enforces canonical Ristretto encoding. Identity is valid here:
/// zero-value, zero-blind commitments are legitimate algebraic commitments.
pub(crate) fn point(bytes: &[u8]) -> Result<RistrettoPoint, String> {
    CompressedRistretto(bytes32(bytes)?)
        .decompress()
        .ok_or_else(|| "invalid Ristretto point".to_owned())
}

fn nonidentity(bytes: &[u8]) -> Result<RistrettoPoint, String> {
    let p = point(bytes)?;
    if p.is_identity() {
        return Err("identity public key or key image".to_owned());
    }
    Ok(p)
}

fn private(bytes: &[u8]) -> Result<Zeroizing<Scalar>, String> {
    let x = Zeroizing::new(scalar(bytes)?);
    if *x == Scalar::ZERO {
        return Err("zero private key".to_owned());
    }
    Ok(x)
}

// Upstream deliberately reduces hash-derived blindings rather than requiring a
// canonical encoding. Apply the same rule in all commitment/proof operations.
fn blinding(bytes: &[u8]) -> Result<Zeroizing<Scalar>, String> {
    Ok(Zeroizing::new(Scalar::from_bytes_mod_order(bytes32(
        bytes,
    )?)))
}

// Seed a local infallible PRNG only after OS entropy succeeds. No trait method
// hides a fallible OS call or panics on entropy failure. Zeroization is best
// effort: Scalar is Copy and library/compiler temporaries and StdRng state may
// retain copies; Zeroizing does not promise complete memory erasure.
fn fresh_rng() -> Result<StdRng, String> {
    fresh_rng_with_entropy(getrandom::getrandom)
}

// The adapter is private and replaces only the fallible OS boundary in tests.
fn fresh_rng_with_entropy(
    mut entropy: impl FnMut(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Result<StdRng, String> {
    let mut seed = Zeroizing::new([0u8; 32]);
    entropy(&mut seed[..]).map_err(|e| format!("OS entropy failed: {e}"))?;
    Ok(StdRng::from_seed(*seed))
}

fn hash_to_point(data: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(b"blocknet_hash_to_point");
    h.update(data);
    RistrettoPoint::from_uniform_bytes(&h.finalize().into())
}

fn challenge(msg: &[u8], l: &RistrettoPoint, r: &RistrettoPoint, d: &RistrettoPoint) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"blocknet_ringct_c");
    h.update(msg);
    h.update(l.compress().as_bytes());
    h.update(r.compress().as_bytes());
    h.update(d.compress().as_bytes());
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

pub fn public_key(secret: &[u8]) -> Result<[u8; 32], String> {
    let x = private(secret)?;
    Ok((*x * RISTRETTO_BASEPOINT_POINT).compress().to_bytes())
}

/// Return the canonical private scalar derived by upstream seeded key generation.
pub fn seeded_key(seed: &[u8]) -> Result<[u8; 32], String> {
    let seed = Zeroizing::new(bytes32(seed)?);
    let mut h = Sha512::new();
    h.update(b"blocknet_keygen");
    h.update(&seed[..]);
    let wide = Zeroizing::new(<[u8; 64]>::from(h.finalize()));
    let x = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide));
    if *x == Scalar::ZERO {
        return Err("derived zero private key".to_owned());
    }
    Ok(x.to_bytes())
}

pub fn commitment(amount: u64, blind: &[u8]) -> Result<[u8; 32], String> {
    let r = blinding(blind)?;
    Ok(PedersenGens::default()
        .commit(Scalar::from(amount), *r)
        .compress()
        .to_bytes())
}

pub fn key_image(secret: &[u8]) -> Result<[u8; 32], String> {
    let x = private(secret)?;
    let pk = (*x * RISTRETTO_BASEPOINT_POINT).compress();
    let image = *x * hash_to_point(pk.as_bytes());
    if image.is_identity() {
        return Err("identity key image".to_owned());
    }
    Ok(image.compress().to_bytes())
}

pub fn range_prove(amount: u64, blind: &[u8]) -> Result<Vec<u8>, String> {
    range_prove_with_entropy(amount, blind, getrandom::getrandom)
}

fn range_prove_with_entropy(
    amount: u64,
    blind: &[u8],
    entropy: impl FnMut(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Result<Vec<u8>, String> {
    let r = blinding(blind)?;
    let mut rng = fresh_rng_with_entropy(entropy)?;
    let (proof, _) = RangeProof::prove_single_with_rng(
        &BulletproofGens::new(64, 1),
        &PedersenGens::default(),
        &mut Transcript::new(RANGE_LABEL),
        amount,
        &r,
        64,
        &mut rng,
    )
    .map_err(|e| format!("range proof failed: {e}"))?;
    let bytes = proof.to_bytes();
    if bytes.len() > 1024 {
        return Err("range proof exceeds 1024 bytes".to_owned());
    }
    Ok(bytes)
}

pub fn range_verify(commitment: &[u8], proof: &[u8]) -> Result<bool, String> {
    range_verify_with_entropy(commitment, proof, getrandom::getrandom)
}

fn range_verify_with_entropy(
    commitment: &[u8],
    proof: &[u8],
    entropy: impl FnMut(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Result<bool, String> {
    let c = point(commitment)?.compress();
    if proof.len() > 1024 {
        return Err("range proof exceeds 1024 bytes".to_owned());
    }
    let proof = RangeProof::from_bytes(proof).map_err(|e| format!("invalid range proof: {e}"))?;
    // Even a single proof batches verification equations with a random scalar.
    // Keep verifier randomness; do not replace it with a fixed deterministic RNG.
    let mut rng = fresh_rng_with_entropy(entropy)?;
    Ok(proof
        .verify_single_with_rng(
            &BulletproofGens::new(64, 1),
            &PedersenGens::default(),
            &mut Transcript::new(RANGE_LABEL),
            &c,
            64,
            &mut rng,
        )
        .is_ok())
}

fn parse_ring(
    keys: &[[u8; 32]],
    commits: &[[u8; 32]],
    msg: &[u8],
) -> Result<(Vec<RistrettoPoint>, Vec<RistrettoPoint>), String> {
    if keys.len() != RING_SIZE || commits.len() != RING_SIZE {
        return Err("ring must have exactly 16 keys and commitments".to_owned());
    }
    if msg.len() != 32 {
        return Err("message must be exactly 32 bytes".to_owned());
    }
    let keys = keys
        .iter()
        .map(|k| nonidentity(k))
        .collect::<Result<Vec<_>, _>>()?;
    let commits = commits
        .iter()
        .map(|c| point(c))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((keys, commits))
}

// Constant-time multiscalar multiplication also for nonce-dependent signer
// computations, replacing upstream's variable-time evaluation of these equations.
fn pair(a: Scalar, p: RistrettoPoint, b: Scalar, q: RistrettoPoint) -> RistrettoPoint {
    RistrettoPoint::multiscalar_mul([a, b], [p, q])
}

#[allow(clippy::too_many_arguments)]
pub fn ring_sign(
    keys: &[[u8; 32]],
    commits: &[[u8; 32]],
    index: usize,
    secret: &[u8],
    input_blind: &[u8],
    pseudo: &[u8],
    pseudo_blind: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, String> {
    let (pks, cs) = parse_ring(keys, commits, msg)?;
    if index >= RING_SIZE {
        return Err("secret index outside ring".to_owned());
    }
    let x = private(secret)?;
    let r_input = blinding(input_blind)?;
    let r_pseudo = blinding(pseudo_blind)?;
    let z = Zeroizing::new(*r_pseudo - *r_input);
    let c_pseudo = point(pseudo)?;
    let b = PedersenGens::default().B_blinding;
    if *x * RISTRETTO_BASEPOINT_POINT != pks[index] {
        return Err("secret does not match real public key".to_owned());
    }
    let diffs: Vec<_> = cs.iter().map(|c| c_pseudo - c).collect();
    // Reject inconsistent openings before consuming entropy or creating a proof.
    if diffs[index] != *z * b {
        return Err("real and pseudo commitments do not match blinding difference".to_owned());
    }
    let hp = hash_to_point(&keys[index]);
    let image = *x * hp;
    if image.is_identity() {
        return Err("identity key image".to_owned());
    }
    let mut rng = fresh_rng()?;
    let alpha = Zeroizing::new(Scalar::random(&mut rng));
    let alpha_z = Zeroizing::new(Scalar::random(&mut rng));
    let mut s = Zeroizing::new(
        (0..RING_SIZE)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>(),
    );
    let mut t = Zeroizing::new(
        (0..RING_SIZE)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<_>>(),
    );
    let mut c = [Scalar::ZERO; RING_SIZE];
    // Seed the challenge after the real member with nonce commitments
    // L = alpha*G, R = alpha*Hp(P), D = alpha_z*B_blinding.
    let mut next = (index + 1) % RING_SIZE;
    c[next] = challenge(
        msg,
        &(*alpha * RISTRETTO_BASEPOINT_POINT),
        &(*alpha * hp),
        &(*alpha_z * b),
    );
    // Each simulated member contributes s*G+c*P, s*Hp(P)+c*I, and
    // t*B_blinding+c*(C_pseudo-C_i), in exactly that hash order.
    for _ in 0..RING_SIZE - 1 {
        let hp_i = hash_to_point(&keys[next]);
        let l = pair(s[next], RISTRETTO_BASEPOINT_POINT, c[next], pks[next]);
        let r = pair(s[next], hp_i, c[next], image);
        let d = pair(t[next], b, c[next], diffs[next]);
        let after = (next + 1) % RING_SIZE;
        c[after] = challenge(msg, &l, &r, &d);
        next = after;
    }
    // The real responses cancel the final challenge and close both proofs.
    s[index] = *alpha - c[index] * *x;
    t[index] = *alpha_z - c[index] * *z;
    // Wire format: c0 || s[16] || t[16] || image || pseudo commitment.
    let mut sig = Vec::with_capacity(SIGNATURE_SIZE);
    sig.extend_from_slice(c[0].as_bytes());
    for value in s.iter().chain(t.iter()) {
        sig.extend_from_slice(value.as_bytes());
    }
    sig.extend_from_slice(image.compress().as_bytes());
    sig.extend_from_slice(c_pseudo.compress().as_bytes());
    if !ring_verify(keys, commits, msg, &sig)? {
        return Err("generated signature failed self-verification".to_owned());
    }
    Ok(sig)
}

pub fn ring_verify(
    keys: &[[u8; 32]],
    commits: &[[u8; 32]],
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, String> {
    let (pks, cs) = parse_ring(keys, commits, msg)?;
    if sig.len() != SIGNATURE_SIZE {
        return Err("signature must be exactly 1120 bytes".to_owned());
    }
    // Validate every encoding before any signature-dependent group arithmetic.
    let c0 = scalar(&sig[..32])?;
    let s = (0..RING_SIZE)
        .map(|i| scalar(&sig[32 + i * 32..64 + i * 32]))
        .collect::<Result<Vec<_>, _>>()?;
    let t = (0..RING_SIZE)
        .map(|i| scalar(&sig[544 + i * 32..576 + i * 32]))
        .collect::<Result<Vec<_>, _>>()?;
    let image = nonidentity(&sig[1056..1088])?;
    let pseudo = point(&sig[1088..1120])?;
    let b = PedersenGens::default().B_blinding;
    let mut c = c0;
    for i in 0..RING_SIZE {
        let hp = hash_to_point(&keys[i]);
        let l = pair(s[i], RISTRETTO_BASEPOINT_POINT, c, pks[i]);
        let r = pair(s[i], hp, c, image);
        let d = pair(t[i], b, c, pseudo - cs[i]);
        c = challenge(msg, &l, &r, &d);
    }
    Ok(c == c0)
}

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod tests;

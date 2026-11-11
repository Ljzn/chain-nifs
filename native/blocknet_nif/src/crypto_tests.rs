use super::*;

type RingBytes = [[u8; 32]; 16];
fn ring() -> (RingBytes, RingBytes, RingBytes) {
    let secrets = std::array::from_fn(|i| Scalar::from(i as u64 + 1).to_bytes());
    let keys = std::array::from_fn(|i| public_key(&secrets[i]).unwrap());
    let commits =
        std::array::from_fn(|i| commitment(42, &Scalar::from(i as u64 + 20).to_bytes()).unwrap());
    (secrets, keys, commits)
}

#[test]
fn ring_roundtrip_and_wrong_message() {
    let (secrets, keys, commits) = ring();
    let index = 7;
    let input = Scalar::from(27u64).to_bytes();
    let blind = Scalar::from(99u64).to_bytes();
    let pseudo = commitment(42, &blind).unwrap();
    let msg = [3; 32];
    let sig = ring_sign(
        &keys,
        &commits,
        index,
        &secrets[index],
        &input,
        &pseudo,
        &blind,
        &msg,
    )
    .unwrap();
    assert_eq!(sig.len(), 1120);
    assert_eq!(&sig[1056..1088], &key_image(&secrets[index]).unwrap());
    assert!(ring_verify(&keys, &commits, &msg, &sig).unwrap());
    assert!(!ring_verify(&keys, &commits, &[4; 32], &sig).unwrap());
    let mut changed = commits;
    changed[index] = commitment(43, &input).unwrap();
    assert!(!ring_verify(&keys, &changed, &msg, &sig).unwrap());
    let mut malformed = sig.clone();
    malformed[..32].fill(255);
    assert!(ring_verify(&keys, &commits, &msg, &malformed).is_err());
    malformed = sig.clone();
    malformed[1056..1088].fill(0);
    assert!(ring_verify(&keys, &commits, &msg, &malformed).is_err());
    assert!(ring_verify(&keys, &commits, &msg, &sig[..1119]).is_err());
}

#[test]
fn inconsistent_openings_and_secret_rejected_before_signing() {
    let (secrets, keys, commits) = ring();
    let input = Scalar::from(20u64).to_bytes();
    let blind = Scalar::from(99u64).to_bytes();
    let pseudo = commitment(42, &blind).unwrap();
    assert!(ring_sign(
        &keys,
        &commits,
        0,
        &secrets[0],
        &[0; 32],
        &pseudo,
        &blind,
        &[1; 32]
    )
    .is_err());
    let wrong_amount = commitment(43, &blind).unwrap();
    assert!(ring_sign(
        &keys,
        &commits,
        0,
        &secrets[0],
        &input,
        &wrong_amount,
        &blind,
        &[1; 32]
    )
    .is_err());
    assert!(ring_sign(
        &keys,
        &commits,
        0,
        &secrets[1],
        &input,
        &pseudo,
        &blind,
        &[1; 32]
    )
    .is_err());
    assert!(ring_sign(
        &keys,
        &commits,
        16,
        &secrets[0],
        &input,
        &pseudo,
        &blind,
        &[1; 32]
    )
    .is_err());
    assert!(ring_sign(
        &keys[..15],
        &commits,
        0,
        &secrets[0],
        &input,
        &pseudo,
        &blind,
        &[1; 32]
    )
    .is_err());
    assert!(ring_sign(
        &keys,
        &commits,
        0,
        &secrets[0],
        &input,
        &pseudo,
        &blind,
        &[1; 31]
    )
    .is_err());
    let mut invalid = keys;
    invalid[2] = [255; 32];
    assert!(ring_sign(
        &invalid,
        &commits,
        0,
        &secrets[0],
        &input,
        &pseudo,
        &blind,
        &[1; 32]
    )
    .is_err());
    invalid[2] = [0; 32];
    assert!(ring_sign(
        &invalid,
        &commits,
        0,
        &secrets[0],
        &input,
        &pseudo,
        &blind,
        &[1; 32]
    )
    .is_err());
}

#[test]
fn scalar_point_and_blinding_boundaries() {
    assert!(public_key(&[0; 32]).is_err());
    assert!(public_key(&[255; 32]).is_err());
    assert!(key_image(&[0; 32]).is_err());
    assert!(public_key(&[1; 31]).is_err());
    assert!(seeded_key(&[1; 31]).is_err());
    assert!(point(&[255; 32]).is_err());
    assert!(point(&[0; 32]).unwrap().is_identity());
    assert_eq!(commitment(0, &[0; 32]).unwrap(), [0; 32]);
    let reduced = Scalar::from_bytes_mod_order([255; 32]).to_bytes();
    assert_eq!(
        commitment(42, &[255; 32]).unwrap(),
        commitment(42, &reduced).unwrap()
    );
    let mut h = Sha512::new();
    h.update(b"blocknet_keygen");
    h.update([7; 32]);
    let expected = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    assert_eq!(seeded_key(&[7; 32]).unwrap(), expected.to_bytes());
}

#[test]
fn range_proof_roundtrip_and_bounds() {
    let blind = [255; 32];
    let proof = range_prove(42, &blind).unwrap();
    assert!(proof.len() <= 1024);
    assert!(range_verify(&commitment(42, &blind).unwrap(), &proof).unwrap());
    assert!(!range_verify(&commitment(43, &blind).unwrap(), &proof).unwrap());
    assert!(range_verify(&[255; 32], &proof).is_err());
    assert!(range_verify(&commitment(42, &blind).unwrap(), &[0; 1025]).is_err());
    assert!(range_verify(&commitment(42, &blind).unwrap(), &[]).is_err());
}

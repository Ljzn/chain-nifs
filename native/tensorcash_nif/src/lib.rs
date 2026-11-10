mod address;
mod crypto;
mod decode;
mod derivation;
#[cfg(test)]
mod oracle_tests;
mod transaction;
use rustler::{Binary, Env, OwnedBinary};
use std::panic::{catch_unwind, AssertUnwindSafe};
fn boundary<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f))
        .unwrap_or_else(|_| Err("native panic; restart the BEAM before retrying".into()))
}
fn binary<'a>(env: Env<'a>, bytes: &[u8]) -> Result<Binary<'a>, String> {
    let mut out = OwnedBinary::new(bytes.len()).ok_or("binary allocation failed")?;
    out.as_mut_slice().copy_from_slice(bytes);
    Ok(out.release(env))
}
#[rustler::nif(schedule = "DirtyCpu")]
fn public_key<'a>(env: Env<'a>, seed: Binary<'a>) -> Result<Binary<'a>, String> {
    boundary(|| binary(env, &crypto::keypair(seed.as_slice())?.public_key))
}
#[rustler::nif(schedule = "DirtyCpu")]
fn sign<'a>(env: Env<'a>, seed: Binary<'a>, digest: Binary<'a>) -> Result<Binary<'a>, String> {
    boundary(|| {
        if digest.len() != 32 {
            return Err("digest must be 32 bytes".into());
        }
        let key = crypto::keypair(seed.as_slice())?;
        let sig = crypto::sign_digest(&key.secret_key, digest.as_slice())?;
        if !crypto::verify_digest(&key.public_key, digest.as_slice(), &sig)? {
            return Err("signature self-check failed".into());
        }
        binary(env, &sig)
    })
}
#[rustler::nif(schedule = "DirtyCpu")]
fn verify(pk: Binary<'_>, digest: Binary<'_>, sig: Binary<'_>) -> Result<bool, String> {
    boundary(|| crypto::verify_digest(pk.as_slice(), digest.as_slice(), sig.as_slice()))
}
#[rustler::nif(schedule = "DirtyCpu")]
fn spending_seed<'a>(
    env: Env<'a>,
    seed64: Binary<'a>,
    genesis: Binary<'a>,
    account: u32,
    policy: Binary<'a>,
    branch: u8,
    index: u32,
) -> Result<Binary<'a>, String> {
    boundary(|| {
        binary(
            env,
            &derivation::derive(
                seed64.as_slice(),
                genesis.as_slice(),
                account,
                Some((policy.as_slice(), branch, index)),
            )?[..],
        )
    })
}
#[rustler::nif(schedule = "DirtyCpu")]
fn identity_seed<'a>(
    env: Env<'a>,
    seed64: Binary<'a>,
    genesis: Binary<'a>,
    account: u32,
) -> Result<Binary<'a>, String> {
    boundary(|| {
        binary(
            env,
            &derivation::derive(seed64.as_slice(), genesis.as_slice(), account, None)?[..],
        )
    })
}
#[rustler::nif(schedule = "DirtyCpu")]
fn derive_address(pk: Binary<'_>, network: Binary<'_>) -> Result<address::Address, String> {
    boundary(|| address::derive(pk.as_slice(), &decode::network(network)?))
}
#[rustler::nif(schedule = "DirtyCpu")]
fn build_payment(
    seed: Binary<'_>,
    network: Binary<'_>,
    inputs: rustler::Term<'_>,
    outputs: rustler::Term<'_>,
) -> Result<transaction::Payment, String> {
    boundary(|| {
        let inputs = decode::inputs(inputs)?;
        let outputs = decode::outputs(outputs)?;
        let network = decode::network(network)?;
        let key = crypto::keypair(seed.as_slice())?;
        transaction::build(
            &key.public_key,
            Some(&key.secret_key),
            &network,
            &inputs,
            &outputs,
        )
    })
}
#[rustler::nif(schedule = "DirtyCpu")]
fn unsigned_payment(
    pk: Binary<'_>,
    network: Binary<'_>,
    inputs: rustler::Term<'_>,
    outputs: rustler::Term<'_>,
) -> Result<transaction::Payment, String> {
    boundary(|| {
        transaction::build(
            pk.as_slice(),
            None,
            &decode::network(network)?,
            &decode::inputs(inputs)?,
            &decode::outputs(outputs)?,
        )
    })
}
#[rustler::nif(schedule = "DirtyCpu")]
fn verify_payment(
    raw: Binary<'_>,
    pk: Binary<'_>,
    network: Binary<'_>,
    inputs: rustler::Term<'_>,
) -> Result<bool, String> {
    boundary(|| {
        if raw.len() > transaction::MAX_RAW_BYTES {
            return Err("raw transaction exceeds prototype limit".into());
        }
        transaction::verify(
            raw.as_slice(),
            pk.as_slice(),
            &decode::network(network)?,
            &decode::inputs(inputs)?,
        )
    })
}
rustler::init!("Elixir.TensorCashNif.Native");

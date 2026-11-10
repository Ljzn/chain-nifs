mod decode;
mod model;

use model::Artifact;
use noid_core::cpu::ensure_production_hardware;
use noid_gkr::wallet_authorization::{
    prove_paged_spend_authorization_for_version, verify_paged_spend_authorization_for_version,
};
use noid_gkr::{OwnerAuthWitness, WalletAuthorizationBundle};
use noid_poseidon2b::primitives::{derive_address as upstream_address, SpendSecret};
use noid_tx::OwnerAuthorizationVersion;
use rayon::ThreadPoolBuilder;
use rustler::{Binary, Env, Term};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;
use zeroize::Zeroizing;

// A single shared gate also covers direct calls bypassing the Elixir wrapper.
static PROOF_GATE: Mutex<()> = Mutex::new(());

fn boundary<T>(work: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(|| {
        ensure_production_hardware().map_err(|_| "unsupported proof CPU")?;
        work()
    }))
    .unwrap_or_else(|_| Err("native panic; restart the BEAM before retrying".into()))
}

fn secret(bytes: &[u8]) -> Result<SpendSecret, String> {
    let mut copy = Zeroizing::new([0u8; 32]);
    if bytes.len() != copy.len() {
        return Err("secret must be 32 bytes".into());
    }
    copy.copy_from_slice(bytes);
    Ok(SpendSecret::from_bytes(*copy))
}

fn version(value: u8) -> Result<OwnerAuthorizationVersion, String> {
    if value != 4 {
        return Err("only owner authorization V4 is supported".into());
    }
    Ok(OwnerAuthorizationVersion::V4)
}

// build_scoped uses std::thread::scope: both workers are joined even on unwind.
// No unmanaged native thread can outlive a NIF call / library unload.
fn proof_work<T: Send>(work: impl FnOnce() -> Result<T, String> + Send) -> Result<T, String> {
    ThreadPoolBuilder::new()
        .num_threads(2)
        .thread_name(|i| format!("noid-proof-{i}"))
        .build_scoped(|thread| thread.run(), |pool| pool.install(work))
        .map_err(|_| "proof worker initialization failed")?
}

#[rustler::nif(schedule = "DirtyCpu")]
fn derive_address(bytes: Binary<'_>) -> Result<String, String> {
    boundary(|| Ok(upstream_address(&secret(bytes.as_slice())?).to_bech32()))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn build_transaction<'a>(env: Env<'a>, request: Term<'a>) -> Result<Artifact<'a>, String> {
    boundary(|| model::artifact(env, &model::build(decode::request(request)?)?, 0))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn authorize_transaction<'a>(
    env: Env<'a>,
    raw: Binary<'a>,
    bytes: Binary<'a>,
    requested_version: u8,
) -> Result<Artifact<'a>, String> {
    boundary(|| {
        let version = version(requested_version)?;
        let mut intent = model::decode(raw.as_slice(), true)?;
        let key = secret(bytes.as_slice())?;
        if upstream_address(&key) != intent.pages[0].body.input_owner {
            return Err("secret does not match transaction owner".into());
        }
        let _gate = PROOF_GATE.try_lock().map_err(|_| "busy")?;
        intent.authorization_bytes = proof_work(|| {
            let bundle = prove_paged_spend_authorization_for_version(
                &intent.pages,
                OwnerAuthWitness::new(key),
                version,
            )
            .map_err(|_| "authorization proof failed")?;
            verify_paged_spend_authorization_for_version(&intent.pages, &bundle, version)
                .map_err(|_| "generated authorization failed verification")?;
            bundle
                .to_bytes()
                .map_err(|_| "authorization encoding failed".into())
        })?;
        model::artifact(env, &intent, requested_version)
    })
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify_transaction<'a>(
    env: Env<'a>,
    raw: Binary<'a>,
    requested_version: u8,
) -> Result<Artifact<'a>, String> {
    boundary(|| {
        let version = version(requested_version)?;
        let intent = model::decode(raw.as_slice(), false)?;
        let _gate = PROOF_GATE.try_lock().map_err(|_| "busy")?;
        let bundle = WalletAuthorizationBundle::from_bytes(&intent.authorization_bytes)
            .map_err(|_| "invalid authorization encoding")?;
        proof_work(|| {
            verify_paged_spend_authorization_for_version(&intent.pages, &bundle, version)
                .map_err(|_| "invalid authorization proof".into())
        })?;
        model::artifact(env, &intent, requested_version)
    })
}

// A diagnostic only: querying this does not reserve the proof slot.
#[rustler::nif]
fn proof_busy() -> bool {
    PROOF_GATE.try_lock().is_err()
}

rustler::init!("Elixir.Parano1dNif.Native");

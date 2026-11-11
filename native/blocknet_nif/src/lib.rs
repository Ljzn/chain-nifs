mod crypto;
mod decode;
mod transaction;
mod wallet;
use rustler::{Binary, Encoder, Env, OwnedBinary, Term};
use std::panic::{catch_unwind, AssertUnwindSafe};
mod atoms {
    rustler::atoms! {ok,error}
}
fn guarded<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| Err("native operation panicked".into()))
}
fn result<'a, T: Encoder>(env: Env<'a>, r: Result<T, String>) -> Term<'a> {
    match r {
        Ok(v) => (atoms::ok(), v).encode(env),
        Err(e) => (atoms::error(), e).encode(env),
    }
}
fn bytes<'a>(env: Env<'a>, r: Result<impl AsRef<[u8]>, String>) -> Term<'a> {
    match r {
        Ok(v) => match OwnedBinary::new(v.as_ref().len()) {
            Some(mut out) => {
                out.as_mut_slice().copy_from_slice(v.as_ref());
                (atoms::ok(), out.release(env)).encode(env)
            }
            None => (atoms::error(), "binary allocation failed").encode(env),
        },
        Err(e) => (atoms::error(), e).encode(env),
    }
}
fn fixed(b: Binary<'_>, n: usize) -> Result<(), String> {
    if b.len() == n {
        Ok(())
    } else {
        Err("invalid binary length".into())
    }
}
fn rings(t: Term<'_>) -> Result<Vec<[u8; 32]>, String> {
    decode::ring(t)?
        .iter()
        .map(|s| {
            let mut b = [0; 32];
            hex::decode_to_slice(s, &mut b).map_err(|_| "invalid ring hex")?;
            Ok(b)
        })
        .collect()
}
#[rustler::nif(schedule = "DirtyCpu")]
fn seeded_secret<'a>(env: Env<'a>, seed: Binary<'a>) -> Term<'a> {
    bytes(
        env,
        guarded(|| {
            fixed(seed, 32)?;
            crypto::seeded_key(seed.as_slice())
        }),
    )
}
#[rustler::nif(schedule = "DirtyCpu")]
fn public_key<'a>(env: Env<'a>, secret: Binary<'a>) -> Term<'a> {
    bytes(
        env,
        guarded(|| {
            fixed(secret, 32)?;
            crypto::public_key(secret.as_slice())
        }),
    )
}
#[rustler::nif(schedule = "DirtyCpu")]
fn key_image<'a>(env: Env<'a>, secret: Binary<'a>) -> Term<'a> {
    bytes(
        env,
        guarded(|| {
            fixed(secret, 32)?;
            crypto::key_image(secret.as_slice())
        }),
    )
}
#[rustler::nif(schedule = "DirtyCpu")]
fn derive_keys<'a>(env: Env<'a>, seed: Binary<'a>) -> Term<'a> {
    result(
        env,
        guarded(|| {
            fixed(seed, 64)?;
            wallet::derive_keys(seed.as_slice())
        }),
    )
}
#[rustler::nif(schedule = "DirtyCpu")]
fn commitment<'a>(env: Env<'a>, amount: u64, blind: Binary<'a>) -> Term<'a> {
    bytes(
        env,
        guarded(|| {
            fixed(blind, 32)?;
            crypto::commitment(amount, blind.as_slice())
        }),
    )
}
#[rustler::nif(schedule = "DirtyCpu")]
fn range_prove<'a>(env: Env<'a>, amount: u64, blind: Binary<'a>) -> Term<'a> {
    bytes(
        env,
        guarded(|| {
            fixed(blind, 32)?;
            crypto::range_prove(amount, blind.as_slice())
        }),
    )
}
#[rustler::nif(schedule = "DirtyCpu")]
fn range_verify<'a>(env: Env<'a>, commit: Binary<'a>, proof: Binary<'a>) -> Term<'a> {
    result(
        env,
        guarded(|| {
            fixed(commit, 32)?;
            if proof.len() > 1024 {
                return Err("range proof exceeds limit".into());
            }
            crypto::range_verify(commit.as_slice(), proof.as_slice())
        }),
    )
}
#[rustler::nif(schedule = "DirtyCpu")]
#[allow(clippy::too_many_arguments)]
fn ring_sign<'a>(
    env: Env<'a>,
    keys: Term<'a>,
    commits: Term<'a>,
    index: u32,
    secret: Binary<'a>,
    blind: Binary<'a>,
    pseudo: Binary<'a>,
    pseudo_blind: Binary<'a>,
    message: Binary<'a>,
) -> Term<'a> {
    bytes(
        env,
        guarded(|| {
            for b in [secret, blind, pseudo, pseudo_blind, message] {
                fixed(b, 32)?;
            }
            if index >= 16 {
                return Err("ring index must be 0..15".into());
            }
            crypto::ring_sign(
                &rings(keys)?,
                &rings(commits)?,
                index as usize,
                secret.as_slice(),
                blind.as_slice(),
                pseudo.as_slice(),
                pseudo_blind.as_slice(),
                message.as_slice(),
            )
        }),
    )
}
#[rustler::nif(schedule = "DirtyCpu")]
fn ring_verify<'a>(
    env: Env<'a>,
    keys: Term<'a>,
    commits: Term<'a>,
    message: Binary<'a>,
    signature: Binary<'a>,
) -> Term<'a> {
    result(
        env,
        guarded(|| {
            fixed(message, 32)?;
            fixed(signature, 1120)?;
            crypto::ring_verify(
                &rings(keys)?,
                &rings(commits)?,
                message.as_slice(),
                signature.as_slice(),
            )
        }),
    )
}
#[rustler::nif(schedule = "DirtyCpu")]
fn build_payment<'a>(
    env: Env<'a>,
    view: Binary<'a>,
    network: Binary<'a>,
    inputs: Term<'a>,
    outputs: Term<'a>,
    fee: u64,
) -> Term<'a> {
    result(
        env,
        guarded(|| {
            fixed(view, 32)?;
            transaction::build(
                view.as_slice(),
                &decode::network(network)?,
                &decode::inputs(inputs)?,
                &decode::outputs(outputs)?,
                fee,
            )
        }),
    )
}
#[rustler::nif(schedule = "DirtyCpu")]
fn verify_payment<'a>(env: Env<'a>, raw: Binary<'a>) -> Term<'a> {
    result(
        env,
        guarded(|| {
            if raw.len() > 131_072 {
                return Err("payment exceeds prototype limit".into());
            }
            transaction::verify(raw.as_slice())
        }),
    )
}
#[rustler::nif(schedule = "DirtyCpu")]
fn receive_payment<'a>(
    env: Env<'a>,
    raw: Binary<'a>,
    spend: Binary<'a>,
    view: Binary<'a>,
    network: Binary<'a>,
) -> Term<'a> {
    result(
        env,
        guarded(|| {
            fixed(spend, 32)?;
            fixed(view, 32)?;
            if raw.len() > 131_072 {
                return Err("payment exceeds prototype limit".into());
            }
            transaction::receive(
                raw.as_slice(),
                spend.as_slice(),
                view.as_slice(),
                &decode::network(network)?,
            )
        }),
    )
}
rustler::init!("Elixir.BlocknetNif.Native");

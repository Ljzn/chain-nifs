use crate::transaction::{Input, Output};
use rustler::{Atom, Binary, Term};
mod keys {
    rustler::atoms! { secret_hex, amount, blinding_hex, ring_keys, ring_commitments, real_index, spend_public_hex, view_public_hex, memo_hex }
}
fn field<'a>(map: Term<'a>, key: Atom) -> Result<Term<'a>, String> {
    map.map_get(key)
        .map_err(|_| "missing required field or invalid map".into())
}
fn text(term: Term<'_>, min: usize, max: usize) -> Result<String, String> {
    let b: Binary = term.decode().map_err(|_| "expected binary field")?;
    if !(min..=max).contains(&b.len()) {
        return Err("binary field outside size limit".into());
    }
    std::str::from_utf8(b.as_slice())
        .map(str::to_owned)
        .map_err(|_| "invalid UTF-8".into())
}
pub fn list<T>(
    mut tail: Term<'_>,
    max: usize,
    mut item: impl FnMut(Term<'_>) -> Result<T, String>,
) -> Result<Vec<T>, String> {
    let mut values = Vec::new();
    while !tail.is_empty_list() {
        if values.len() >= max {
            return Err("entry count exceeds prototype limit".into());
        }
        let (head, next) = tail.list_get_cell().map_err(|_| "expected proper list")?;
        values.push(item(head)?);
        tail = next;
    }
    if values.is_empty() {
        return Err("entries cannot be empty".into());
    }
    Ok(values)
}
pub fn ring(term: Term<'_>) -> Result<Vec<String>, String> {
    let r = list(term, 16, |t| text(t, 64, 64))?;
    if r.len() != 16 {
        return Err("ring must have 16 members".into());
    }
    Ok(r)
}
pub fn inputs(t: Term<'_>) -> Result<Vec<Input>, String> {
    list(t, 16, |t| {
        Ok(Input {
            secret_hex: text(field(t, keys::secret_hex())?, 64, 64)?,
            amount: field(t, keys::amount())?
                .decode()
                .map_err(|_| "invalid amount")?,
            blinding_hex: text(field(t, keys::blinding_hex())?, 64, 64)?,
            ring_keys: ring(field(t, keys::ring_keys())?)?,
            ring_commitments: ring(field(t, keys::ring_commitments())?)?,
            real_index: field(t, keys::real_index())?
                .decode()
                .map_err(|_| "invalid real index")?,
        })
    })
}
pub fn outputs(t: Term<'_>) -> Result<Vec<Output>, String> {
    list(t, 16, |t| {
        Ok(Output {
            spend_public_hex: text(field(t, keys::spend_public_hex())?, 64, 64)?,
            view_public_hex: text(field(t, keys::view_public_hex())?, 64, 64)?,
            amount: field(t, keys::amount())?
                .decode()
                .map_err(|_| "invalid amount")?,
            memo_hex: text(field(t, keys::memo_hex())?, 0, 248)?,
        })
    })
}
pub fn network(b: Binary<'_>) -> Result<String, String> {
    if b.len() != 7 {
        return Err("network must be mainnet or testnet".into());
    }
    match b.as_slice() {
        b"mainnet" => Ok("mainnet".into()),
        b"testnet" => Ok("testnet".into()),
        _ => Err("network must be mainnet or testnet".into()),
    }
}

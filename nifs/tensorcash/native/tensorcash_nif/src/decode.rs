use crate::transaction::{Input, Output, MAX_INPUTS, MAX_OUTPUTS};
use rustler::{Atom, Binary, Term};
mod keys {
    rustler::atoms! { txid, vout, amount, sequence, address }
}
fn field<'a>(map: Term<'a>, key: Atom) -> Result<Term<'a>, String> {
    map.map_get(key)
        .map_err(|_| "missing transaction field or invalid map".into())
}
fn text(term: Term<'_>, min: usize, max: usize) -> Result<String, String> {
    let b: Binary = term.decode().map_err(|_| "expected binary field")?;
    if !(min..=max).contains(&b.len()) {
        return Err("binary field exceeds size limit".into());
    }
    std::str::from_utf8(b.as_slice())
        .map(str::to_owned)
        .map_err(|_| "invalid UTF-8".into())
}
fn list<T>(
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
pub fn inputs(term: Term<'_>) -> Result<Vec<Input>, String> {
    list(term, MAX_INPUTS, |t| {
        Ok(Input {
            txid: text(field(t, keys::txid())?, 64, 64)?,
            vout: field(t, keys::vout())?
                .decode()
                .map_err(|_| "invalid vout")?,
            amount: field(t, keys::amount())?
                .decode()
                .map_err(|_| "invalid amount")?,
            sequence: field(t, keys::sequence())?
                .decode()
                .map_err(|_| "invalid sequence")?,
        })
    })
}
pub fn outputs(term: Term<'_>) -> Result<Vec<Output>, String> {
    list(term, MAX_OUTPUTS, |t| {
        Ok(Output {
            address: text(field(t, keys::address())?, 8, 90)?,
            amount: field(t, keys::amount())?
                .decode()
                .map_err(|_| "invalid amount")?,
        })
    })
}
pub fn network(b: Binary<'_>) -> Result<String, String> {
    if b.len() != 7 {
        return Err("unsupported network".into());
    }
    let s = std::str::from_utf8(b.as_slice()).map_err(|_| "unsupported network")?;
    match s {
        "mainnet" | "testnet" | "regtest" => Ok(s.into()),
        _ => Err("unsupported network".into()),
    }
}

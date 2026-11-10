use crate::model::{Input, Output, Request, MAX_ADDRESS_BYTES, MAX_INPUTS, MAX_OUTPUTS};
use rustler::{Atom, Binary, Term};

rustler::atoms! { owner, epoch_anchor, fee, inputs, outputs, slot_index, amount, creation_id }

fn field<'a>(term: Term<'a>, key: Atom) -> Result<Term<'a>, String> {
    term.map_get(key)
        .map_err(|_| "missing payment field or invalid map".into())
}

fn address(term: Term<'_>) -> Result<String, String> {
    let bytes: Binary<'_> = term.decode().map_err(|_| "address must be binary")?;
    if !(3..=MAX_ADDRESS_BYTES).contains(&bytes.len()) {
        return Err("address exceeds size limit".into());
    }
    std::str::from_utf8(bytes.as_slice())
        .map(str::to_owned)
        .map_err(|_| "invalid address UTF-8".into())
}

// Inspect no more than max + 1 cells, without Rustler Vec/String pre-allocation.
// list_get_cell also rejects improper tails without ListIterator panic behavior.
fn bounded_list<T>(
    mut tail: Term<'_>,
    max: usize,
    mut decode: impl FnMut(Term<'_>) -> Result<T, String>,
) -> Result<Vec<T>, String> {
    let mut items = Vec::new();
    while !tail.is_empty_list() {
        if items.len() >= max {
            return Err("payment record count exceeds prototype limit".into());
        }
        let (head, next) = tail
            .list_get_cell()
            .map_err(|_| "payment records must be a proper list")?;
        items.push(decode(head)?);
        tail = next;
    }
    if items.is_empty() {
        return Err("payment records cannot be empty".into());
    }
    Ok(items)
}

fn input(term: Term<'_>) -> Result<Input, String> {
    Ok(Input {
        slot_index: field(term, slot_index())?
            .decode()
            .map_err(|_| "invalid input slot")?,
        amount: field(term, amount())?
            .decode()
            .map_err(|_| "invalid input amount")?,
        creation_id: field(term, creation_id())?
            .decode()
            .map_err(|_| "invalid creation id")?,
    })
}

fn output(term: Term<'_>) -> Result<Output, String> {
    Ok(Output {
        slot_index: field(term, slot_index())?
            .decode()
            .map_err(|_| "invalid output slot")?,
        amount: field(term, amount())?
            .decode()
            .map_err(|_| "invalid output amount")?,
        owner: address(field(term, owner())?)?,
    })
}

pub fn request(term: Term<'_>) -> Result<Request<'_>, String> {
    let epoch_anchor: Binary<'_> = field(term, epoch_anchor())?
        .decode()
        .map_err(|_| "invalid epoch anchor")?;
    if epoch_anchor.len() != 32 {
        return Err("epoch anchor must be 32 bytes".into());
    }
    Ok(Request {
        owner: address(field(term, owner())?)?,
        epoch_anchor,
        fee: field(term, fee())?.decode().map_err(|_| "invalid fee")?,
        inputs: bounded_list(field(term, inputs())?, MAX_INPUTS, input)?,
        outputs: bounded_list(field(term, outputs())?, MAX_OUTPUTS, output)?,
    })
}

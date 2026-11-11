use noid_poseidon2b::primitives::Address;
use noid_tx::{
    output_bitmap_bit, validate_paged_spend, PagedSpendIntent, TxBody, TxInput, TxOutput, TxPage,
    PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT, TX_INPUTS, TX_OUTPUTS,
};
use rustler::{Binary, Env, NifMap, OwnedBinary};

pub const MAX_INPUTS: usize = 64;
pub const MAX_OUTPUTS: usize = 2;
pub const MAX_PAGES: usize = MAX_INPUTS / TX_INPUTS;
pub const MAX_ADDRESS_BYTES: usize = 100;
pub const PAGE_BYTES: usize = 323;
pub const MAX_UNSIGNED_BYTES: usize = 7 + MAX_PAGES * PAGE_BYTES;

#[derive(NifMap)]
pub struct Limits {
    pub max_inputs: usize,
    pub max_outputs: usize,
    pub max_pages: usize,
    pub page_bytes: usize,
    pub max_address_bytes: usize,
    pub max_unsigned_bytes: usize,
    pub max_raw_bytes: usize,
}

pub fn limits() -> Limits {
    Limits {
        max_inputs: MAX_INPUTS,
        max_outputs: MAX_OUTPUTS,
        max_pages: MAX_PAGES,
        page_bytes: PAGE_BYTES,
        max_address_bytes: MAX_ADDRESS_BYTES,
        max_unsigned_bytes: MAX_UNSIGNED_BYTES,
        max_raw_bytes: MAX_RAW_BYTES,
    }
}
pub const MAX_RAW_BYTES: usize = MAX_UNSIGNED_BYTES + 256 * 1024;

#[derive(NifMap, Clone)]
pub struct Input {
    pub slot_index: u32,
    pub amount: u64,
    pub creation_id: u64,
}

#[derive(NifMap, Clone)]
pub struct Output {
    pub slot_index: u32,
    pub amount: u64,
    pub owner: String,
}

pub struct Request<'a> {
    pub owner: String,
    pub epoch_anchor: Binary<'a>,
    pub fee: u64,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

#[derive(NifMap)]
pub struct Artifact<'a> {
    pub raw_transaction: Binary<'a>,
    pub txid: String,
    pub owner: String,
    pub epoch_anchor: Binary<'a>,
    pub fee: u64,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub page_count: usize,
    pub authorization_bytes: usize,
    pub authorization_version: u8,
}

pub fn parse_address(value: &str) -> Result<Address, String> {
    if value.len() > MAX_ADDRESS_BYTES {
        return Err("invalid address".into());
    }
    let address = Address::parse(value).map_err(|_| "invalid address")?;
    if address.to_bech32() != value {
        return Err("address must use canonical lowercase Bech32m".into());
    }
    Ok(address)
}

pub fn build(request: Request<'_>) -> Result<PagedSpendIntent, String> {
    if !(1..=MAX_INPUTS).contains(&request.inputs.len())
        || !(1..=MAX_OUTPUTS).contains(&request.outputs.len())
    {
        return Err("prototype requires 1..64 inputs and 1..2 outputs".into());
    }
    let epoch_anchor: [u8; 32] = request
        .epoch_anchor
        .as_slice()
        .try_into()
        .map_err(|_| "epoch anchor must be 32 bytes")?;
    let owner = parse_address(&request.owner)?;
    let outputs: Vec<TxOutput> = request
        .outputs
        .iter()
        .map(|o| {
            Ok(TxOutput {
                slot_index: o.slot_index,
                amount: o.amount,
                owner: parse_address(&o.owner)?,
            })
        })
        .collect::<Result<_, String>>()?;
    let page_count = request
        .inputs
        .len()
        .div_ceil(TX_INPUTS)
        .max(outputs.len().div_ceil(TX_OUTPUTS));
    let mut pages = Vec::with_capacity(page_count);
    for index in 0..page_count {
        let mut body = TxBody {
            epoch_anchor,
            fee: if index == 0 { request.fee } else { 0 },
            input_owner: owner,
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: [TxOutput::dummy(); TX_OUTPUTS],
            validity_bitmap: 0,
            is_coinbase: false,
        };
        for (i, input) in request
            .inputs
            .iter()
            .skip(index * TX_INPUTS)
            .take(TX_INPUTS)
            .enumerate()
        {
            body.inputs[i] = TxInput {
                slot_index: input.slot_index,
                amount: input.amount,
                creation_id: input.creation_id,
            };
            body.validity_bitmap |= 1 << i;
        }
        for (i, output) in outputs
            .iter()
            .skip(index * TX_OUTPUTS)
            .take(TX_OUTPUTS)
            .enumerate()
        {
            body.outputs[i] = *output;
            body.validity_bitmap |= output_bitmap_bit(i);
        }
        if index == 0 {
            body.validity_bitmap |= PAGED_SPEND_START_BIT;
        }
        if index + 1 == page_count {
            body.validity_bitmap |= PAGED_SPEND_END_BIT;
        }
        pages.push(TxPage::new(body).map_err(|_| "invalid payment page")?);
    }
    let intent = PagedSpendIntent::new(pages, Vec::new())
        .map_err(|_| "invalid payment: check balance, slots and records")?;
    check_payment(&intent)?;
    Ok(intent)
}

pub fn check_payment(intent: &PagedSpendIntent) -> Result<(), String> {
    let facts = validate_paged_spend(&intent.pages).map_err(|_| "invalid payment")?;
    if intent.pages.len() > MAX_PAGES
        || !(1..=MAX_INPUTS).contains(&(facts.live_inputs as usize))
        || !(1..=MAX_OUTPUTS).contains(&(facts.live_outputs as usize))
    {
        return Err("payment exceeds prototype limits".into());
    }
    if intent
        .pages
        .iter()
        .any(|p| p.body.is_coinbase || p.body.validity_bitmap & 0xF000 != 0)
    {
        return Err("only ordinary payments are supported".into());
    }
    Ok(())
}

pub fn decode(raw: &[u8], unsigned: bool) -> Result<PagedSpendIntent, String> {
    let limit = if unsigned {
        MAX_UNSIGNED_BYTES
    } else {
        MAX_RAW_BYTES
    };
    if raw.len() > limit {
        return Err("transaction exceeds prototype size limit".into());
    }
    // Reject page counts before upstream allocates or parses any pages.
    if raw.len() < 3 || raw[0] != 0xA3 {
        return Err("invalid transaction encoding".into());
    }
    let pages = u16::from_le_bytes([raw[1], raw[2]]) as usize;
    if !(1..=MAX_PAGES).contains(&pages) {
        return Err("payment exceeds prototype page limit".into());
    }
    let intent = PagedSpendIntent::from_bytes(raw).map_err(|_| "invalid transaction encoding")?;
    check_payment(&intent)?;
    if unsigned && !intent.authorization_bytes.is_empty() {
        return Err("transaction is already authorized".into());
    }
    if !unsigned && intent.authorization_bytes.is_empty() {
        return Err("missing authorization".into());
    }
    Ok(intent)
}

fn binary<'a>(env: Env<'a>, value: &[u8]) -> Result<Binary<'a>, String> {
    let mut result = OwnedBinary::new(value.len()).ok_or("binary allocation failed")?;
    result.as_mut_slice().copy_from_slice(value);
    Ok(result.release(env))
}

pub fn artifact<'a>(
    env: Env<'a>,
    intent: &PagedSpendIntent,
    version: u8,
) -> Result<Artifact<'a>, String> {
    let facts = validate_paged_spend(&intent.pages).map_err(|_| "invalid payment")?;
    let raw = intent
        .to_bytes()
        .map_err(|_| "transaction encoding failed")?;
    let inputs = intent
        .pages
        .iter()
        .flat_map(|p| {
            p.body.live_inputs().map(|(_, v)| Input {
                slot_index: v.slot_index,
                amount: v.amount,
                creation_id: v.creation_id,
            })
        })
        .collect();
    let outputs = intent
        .pages
        .iter()
        .flat_map(|p| {
            p.body.live_outputs().map(|(_, v)| Output {
                slot_index: v.slot_index,
                amount: v.amount,
                owner: v.owner.to_bech32(),
            })
        })
        .collect();
    Ok(Artifact {
        raw_transaction: binary(env, &raw)?,
        txid: hex::encode(facts.logical_txid.0),
        owner: facts.input_owner.to_bech32(),
        epoch_anchor: binary(env, &facts.epoch_anchor)?,
        fee: facts.fee,
        inputs,
        outputs,
        page_count: intent.pages.len(),
        authorization_bytes: intent.authorization_bytes.len(),
        authorization_version: version,
    })
}

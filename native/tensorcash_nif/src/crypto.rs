use std::sync::Once;
use zeroize::Zeroizing;
pub const PUBLIC_KEY_BYTES: usize = 1952;
pub const SECRET_KEY_BYTES: usize = 4032;
pub const SIGNATURE_BYTES: usize = 3309;
static INIT: Once = Once::new();
extern "C" {
    fn OQS_init();
    fn tensorcash_keypair_seed(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;
    fn tensorcash_sign(
        sig: *mut u8,
        siglen: *mut usize,
        msg: *const u8,
        sk: *const u8,
        rnd: *const u8,
    ) -> i32;
    fn OQS_SIG_ml_dsa_65_verify(
        msg: *const u8,
        msglen: usize,
        sig: *const u8,
        siglen: usize,
        pk: *const u8,
    ) -> i32;
}
fn init() {
    INIT.call_once(|| {
        // SAFETY: initializes pinned liboqs once before concurrent use; OpenSSL is disabled.
        unsafe { OQS_init() };
    });
}
pub struct Keypair {
    pub public_key: Vec<u8>,
    pub secret_key: Zeroizing<Vec<u8>>,
}
pub fn keypair(seed: &[u8]) -> Result<Keypair, String> {
    if seed.len() != 32 {
        return Err("seed must be 32 bytes".into());
    }
    init();
    let seed = Zeroizing::new(<[u8; 32]>::try_from(seed).map_err(|_| "seed must be 32 bytes")?);
    let mut public_key = vec![0; PUBLIC_KEY_BYTES];
    let mut secret_key = Zeroizing::new(vec![0; SECRET_KEY_BYTES]);
    // SAFETY: fixed-size initialized writable buffers, exact seed length, no aliases.
    let status = unsafe {
        tensorcash_keypair_seed(
            public_key.as_mut_ptr(),
            secret_key.as_mut_ptr(),
            seed.as_ptr(),
        )
    };
    if status != 0 {
        return Err("native key generation failed".into());
    }
    Ok(Keypair {
        public_key,
        secret_key,
    })
}
pub fn sign_digest(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    let mut rnd = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut rnd[..]).map_err(|_| "system randomness unavailable")?;
    sign_with_randomness(sk, msg, &rnd[..])
}
// Only the fixed-seed keygen above supplies SKs in production. No public raw-SK NIF.
// Explicit-rnd entry is Rust-internal and used for FIPS/official deterministic vectors.
pub(crate) fn sign_with_randomness(sk: &[u8], msg: &[u8], rnd: &[u8]) -> Result<Vec<u8>, String> {
    if sk.len() != SECRET_KEY_BYTES || msg.len() != 32 || rnd.len() != 32 {
        return Err("invalid signing buffer lengths".into());
    }
    init();
    let mut signature = vec![0; SIGNATURE_BYTES];
    let mut len = SIGNATURE_BYTES;
    // SAFETY: fixed validated lengths, caller holds a valid expanded SK produced by keypair.
    // The pinned reference call uses the external Pure-MLDSA prefix {0,0}, not external-mu.
    let status = unsafe {
        tensorcash_sign(
            signature.as_mut_ptr(),
            &mut len,
            msg.as_ptr(),
            sk.as_ptr(),
            rnd.as_ptr(),
        )
    };
    if status != 0 || len != SIGNATURE_BYTES {
        return Err("native signing failed".into());
    }
    Ok(signature)
}
pub fn verify_digest(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, String> {
    if pk.len() != PUBLIC_KEY_BYTES || msg.len() != 32 || sig.len() != SIGNATURE_BYTES {
        return Err("expected public key 1952, digest 32, signature 3309 bytes".into());
    }
    init();
    // SAFETY: all input buffers remain borrowed for the call; exact key/signature lengths.
    Ok(unsafe {
        OQS_SIG_ml_dsa_65_verify(
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
            pk.as_ptr(),
        )
    } == 0)
}

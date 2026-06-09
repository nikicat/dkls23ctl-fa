pub mod keygen;
pub mod reshare;
pub mod sign;

use sl_dkls23::setup::NoVerifyingKey;

/// Verifying keys for parties 0..n. We rely on iroh's transport encryption
/// and authentication, so dkls23-level message signing is disabled, exactly
/// like in the upstream examples.
pub fn no_vks(n: usize) -> Vec<NoVerifyingKey> {
    (0..n).map(NoVerifyingKey::new).collect()
}

/// A fresh random seed for a protocol run.
pub fn seed() -> [u8; 32] {
    rand::random()
}

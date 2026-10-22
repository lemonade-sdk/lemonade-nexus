//! ECIES encapsulation to the storage public key (design B2).
//!
//! The crate returns only the shared point. Key derivation and the AEAD run
//! in C++ with the existing HKDF-SHA256 and XChaCha20-Poly1305 primitives.
//!
//! No upstream audit covers this module.

use curve25519_dalek::ristretto::RistrettoPoint;
use frost_ristretto255::Ristretto255Sha512;
use rand_core::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::plan::decode_point;
use crate::Result;

/// Pick a random nonzero `r` and return `R = r·G` and the compressed
/// shared point `r·S`. `r` is destroyed before return. The shared point is
/// secret.
pub fn encapsulate(storage_public_key: &[u8; 32]) -> Result<([u8; 32], Zeroizing<[u8; 32]>)> {
    let key = decode_point(storage_public_key)?;
    let r = Zeroizing::new(frost_core::random_nonzero::<Ristretto255Sha512, _>(
        &mut OsRng,
    ));
    let ephemeral = RistrettoPoint::mul_base(&r).compress().to_bytes();
    // By reference, so no extra copy of r is made.
    #[allow(clippy::op_ref)]
    let mut shared = key * &*r;
    let out = Zeroizing::new(shared.compress().to_bytes());
    shared.zeroize();
    Ok((ephemeral, out))
}

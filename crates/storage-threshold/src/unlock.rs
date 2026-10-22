//! Decryption partials with DLEQ proofs, and their combination (design B2).
//!
//! A holder answers an unlock request for the ephemeral point `R` with the
//! partial `P_i = s_i·R` and a Chaum-Pedersen proof that
//! `log_G(Y_i) = log_R(P_i)`. The requester verifies `t` partials against the
//! plan and interpolates `s·R = Σ λ_i·P_i`.
//!
//! No upstream audit covers this module. The proof is
//! `elastic_elgamal::LogEqualityProof` (not audited either). The merlin
//! transcript binds the proof to the domain tag, network, epoch, plan digest,
//! request nonce, storage public key, holder, and `R`.

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use elastic_elgamal::group::Ristretto;
use elastic_elgamal::{LogEqualityProof, PublicKey, SecretKey};
use merlin::Transcript;
use rand_core::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::keys::{PeerMessages, Share};
use crate::plan::{decode_point, interpolate, Plan};
use crate::{HolderId, Result, StorageError, DOMAIN};

/// Length of a partial: the 32-byte point `s_i·R`, then the 64-byte proof.
pub const PARTIAL_LEN: usize = 96;

/// The request fields every partial is bound to. The requester and each
/// holder must use identical values.
///
/// `plan_digest` is the digest of the finalized holder plan that the caller
/// defines. The crate also binds `S` and `Y_i` from the plan bytes, so a
/// wrong digest cannot pair a proof with another key.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnlockContext {
    /// The network identity.
    pub network_id: [u8; 32],
    /// The epoch of the unlock request.
    pub epoch: u64,
    /// Digest of the finalized holder plan.
    pub plan_digest: [u8; 32],
    /// The unlock request nonce.
    pub request_nonce: [u8; 32],
}

/// The transcript of one partial. merlin length-prefixes every message, so
/// the field boundaries are unambiguous.
fn transcript(
    context: &UnlockContext,
    storage_public_key: &[u8; 32],
    holder: HolderId,
    ephemeral: &[u8; 32],
) -> Transcript {
    let mut t = Transcript::new(DOMAIN);
    t.append_message(b"purpose", b"unlock-partial");
    t.append_message(b"network", &context.network_id);
    t.append_message(b"epoch", &context.epoch.to_le_bytes());
    t.append_message(b"plan", &context.plan_digest);
    t.append_message(b"nonce", &context.request_nonce);
    t.append_message(b"S", storage_public_key);
    t.append_message(b"holder", &holder.to_le_bytes());
    t.append_message(b"R", ephemeral);
    t
}

/// Holder side: compute `s_i·R` and its proof.
///
/// Fails with [`StorageError::ShareMismatch`] when `share` is not the
/// holder's current share in `plan`, and with
/// [`StorageError::InvalidArgument`] when `R` is not a canonical, non-identity
/// Ristretto encoding.
pub fn create_partial(
    share: &Share,
    plan: &Plan,
    context: &UnlockContext,
    ephemeral: &[u8; 32],
) -> Result<[u8; PARTIAL_LEN]> {
    share.check_in_plan(plan)?;
    let base = decode_point(ephemeral)?;
    let log_base =
        PublicKey::<Ristretto>::from_bytes(ephemeral).map_err(|_| StorageError::InvalidArgument)?;
    let scalar = share.secret_scalar();
    let scalar_bytes = Zeroizing::new(scalar.to_bytes());
    let secret =
        SecretKey::<Ristretto>::from_bytes(&scalar_bytes[..]).ok_or(StorageError::Crypto)?;
    // By reference, so no extra copy of the secret scalar is made.
    #[allow(clippy::op_ref)]
    let partial = base * &*scalar;
    let proof = LogEqualityProof::new(
        &log_base,
        &secret,
        (share.verifying_share(), partial),
        &mut transcript(
            context,
            &plan.storage_public_key_bytes(),
            share.holder(),
            ephemeral,
        ),
        &mut OsRng,
    );
    let mut out = [0u8; PARTIAL_LEN];
    out[..32].copy_from_slice(&partial.compress().to_bytes());
    out[32..].copy_from_slice(&proof.to_bytes());
    Ok(out)
}

/// Requester side: verify one partial from `holder` and return `s_i·R`.
///
/// Fails with [`StorageError::Proof`] when the holder is not in the plan, the
/// point or proof does not decode, or the proof does not verify.
pub fn verify_partial(
    plan: &Plan,
    context: &UnlockContext,
    ephemeral: &[u8; 32],
    holder: HolderId,
    partial: &[u8],
) -> Result<RistrettoPoint> {
    if partial.len() != PARTIAL_LEN {
        return Err(StorageError::InvalidArgument);
    }
    let log_base =
        PublicKey::<Ristretto>::from_bytes(ephemeral).map_err(|_| StorageError::InvalidArgument)?;
    let commitment = plan.verifying_share(holder).ok_or(StorageError::Proof)?;
    let mut point_bytes = [0u8; 32];
    point_bytes.copy_from_slice(&partial[..32]);
    let point = decode_point(&point_bytes).map_err(|_| StorageError::Proof)?;
    let proof =
        LogEqualityProof::<Ristretto>::from_bytes(&partial[32..]).ok_or(StorageError::Proof)?;
    proof
        .verify(
            &log_base,
            (commitment, point),
            &mut transcript(context, &plan.storage_public_key_bytes(), holder, ephemeral),
        )
        .map_err(|_| StorageError::Proof)?;
    Ok(point)
}

/// Requester side: verify every partial and combine them into the
/// compressed `s·R`. The result is the ECIES shared secret and is secret.
///
/// Needs at least `t` partials from distinct holders of the plan. Any
/// partial that fails verification fails the call; the caller can drop it
/// after [`verify_partial`] and retry with the rest.
pub fn combine(
    plan: &Plan,
    context: &UnlockContext,
    ephemeral: &[u8; 32],
    partials: &PeerMessages,
) -> Result<Zeroizing<[u8; 32]>> {
    decode_point(ephemeral)?;
    if partials.len() < usize::from(plan.threshold()) {
        return Err(StorageError::BelowThreshold);
    }
    let mut points = BTreeMap::new();
    for (holder, bytes) in partials {
        points.insert(
            *holder,
            verify_partial(plan, context, ephemeral, *holder, bytes)?,
        );
    }
    let mut shared = interpolate(&points, None)?;
    let out = Zeroizing::new(shared.compress().to_bytes());
    shared.zeroize();
    Ok(out)
}

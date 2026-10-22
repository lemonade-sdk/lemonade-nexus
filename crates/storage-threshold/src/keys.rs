//! Key generation, share refresh, and holder enrollment.
//!
//! Every protocol step is one frost-ristretto255 call. This module adds the
//! design rules around those calls:
//!
//! - The first key needs `5 ≤ n ≤ 50` holders. A rotation (a new key
//!   generation that replaces `S`) and a refresh need `3 ≤ n ≤ 50`, so the
//!   holders can re-share after losses (design B4, B5). Every plan uses
//!   `t = ceil(0.65 × n)`.
//! - A refresh keeps `t` and `S`. It fails with
//!   [`StorageError::ThresholdChange`] when the new holder count needs a
//!   different `t`; the caller then rotates the key with a new key generation
//!   (design B5, Option A).
//! - A refresh needs at least `t` participants from the old plan, and an
//!   enrollment needs at least `t` helpers (design B5).
//! - A repaired share and every refreshed share are checked against the
//!   public share commitments of the plan, because frost does not check them.
//!
//! Messages carry no session binding. The caller must move them only inside
//! authenticated envelopes bound to the network, epoch, and session, as for
//! the FROST epoch key generation. Round 2 packages, repair deltas, and repair
//! sigmas are secret and must travel only over an encrypted pairwise channel.

use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::Scalar;
use frost::keys::{
    dkg, refresh, repairable, KeyPackage, PublicKeyPackage, SecretShare,
    VerifiableSecretSharingCommitment, VerifyingShare,
};
use frost::{Identifier, Ristretto255Sha512};
use frost_ristretto255 as frost;
use rand_core::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::params::{creation_threshold, is_plan_threshold, plan_threshold};
use crate::plan::{holder_id, identifier, Plan};
use crate::{HolderId, Result, StorageError};

/// Upper bound on one protocol message or serialized share.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

/// Peer messages keyed by holder: the sender for inputs.
pub type PeerMessages<'a> = BTreeMap<HolderId, &'a [u8]>;

/// Messages for other holders, keyed by recipient. The bytes are secret.
pub type SecretMessages = BTreeMap<HolderId, Zeroizing<Vec<u8>>>;

/// One holder's share of the storage secret. Zeroized on drop.
pub struct Share {
    holder: HolderId,
    inner: KeyPackage,
}

impl Drop for Share {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl Share {
    pub(crate) fn from_key_package(inner: KeyPackage) -> Result<Self> {
        // Wrap first so that every error path below still zeroizes.
        let mut share = Share { holder: 0, inner };
        share.holder = holder_id(share.inner.identifier()).ok_or(StorageError::InvalidArgument)?;
        if !is_plan_threshold(*share.inner.min_signers()) {
            return Err(StorageError::HolderCount);
        }
        let expected = RistrettoPoint::mul_base(&share.secret_scalar());
        if share.verifying_share() != expected {
            return Err(StorageError::Crypto);
        }
        Ok(share)
    }

    /// The holder identifier.
    pub fn holder(&self) -> HolderId {
        self.holder
    }

    /// The threshold of the plan this share was made for.
    pub fn threshold(&self) -> u16 {
        *self.inner.min_signers()
    }

    /// The public share commitment `Y_i = s_i·G`.
    pub fn verifying_share(&self) -> RistrettoPoint {
        self.inner.verifying_share().to_element()
    }

    /// The storage public key `S`.
    pub fn storage_public_key(&self) -> RistrettoPoint {
        self.inner.verifying_key().to_element()
    }

    pub(crate) fn secret_scalar(&self) -> Zeroizing<Scalar> {
        Zeroizing::new(self.inner.signing_share().to_scalar())
    }

    /// Serialize the share for sealed storage. The bytes are secret.
    pub fn serialize(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.inner.serialize()?))
    }

    /// Parse a share serialized by [`Share::serialize`]. Checks that the
    /// stored commitment matches the secret and that the threshold is one a
    /// plan can have.
    pub fn deserialize(bytes: &[u8]) -> Result<Share> {
        if bytes.is_empty() || bytes.len() > MAX_MESSAGE_BYTES {
            return Err(StorageError::InvalidArgument);
        }
        let inner = KeyPackage::deserialize(bytes).map_err(|_| StorageError::Serialization)?;
        Share::from_key_package(inner)
    }

    /// Check that this share is the current share of its holder in `plan`.
    pub fn check_in_plan(&self, plan: &Plan) -> Result<()> {
        if plan.threshold() != self.threshold()
            || plan.storage_public_key() != self.storage_public_key()
            || plan.verifying_share(self.holder) != Some(self.verifying_share())
        {
            return Err(StorageError::ShareMismatch);
        }
        Ok(())
    }
}

// --- Key generation ---------------------------------------------------------

/// Secret state between key generation part 1 and part 2.
pub struct DkgRound1 {
    secret: dkg::round1::SecretPackage,
}

impl Drop for DkgRound1 {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Secret state between key generation part 2 and part 3.
pub struct DkgRound2 {
    secret: dkg::round2::SecretPackage,
}

impl Drop for DkgRound2 {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Key generation part 1 of the first storage key, for `holder` among
/// `holder_count` holders (`5 ≤ holder_count ≤ 50`). Returns the state and
/// the round 1 package to broadcast.
pub fn dkg_part1(holder: HolderId, holder_count: u16) -> Result<(DkgRound1, Vec<u8>)> {
    dkg_part1_with(holder, holder_count, creation_threshold(holder_count as usize)?)
}

/// Key generation part 1 of a key rotation, for `holder` among
/// `holder_count` holders (`3 ≤ holder_count ≤ 50`). A rotation replaces an
/// existing key, so it may run with fewer holders than the first key after
/// holders are lost. Parts 2 and 3 are the same as for the first key.
pub fn dkg_rotation_part1(holder: HolderId, holder_count: u16) -> Result<(DkgRound1, Vec<u8>)> {
    dkg_part1_with(holder, holder_count, plan_threshold(holder_count as usize)?)
}

fn dkg_part1_with(
    holder: HolderId,
    holder_count: u16,
    threshold: u16,
) -> Result<(DkgRound1, Vec<u8>)> {
    let (secret, package) = dkg::part1(identifier(holder)?, holder_count, threshold, OsRng)?;
    let state = DkgRound1 { secret };
    let bytes = package.serialize()?;
    Ok((state, bytes))
}

/// Key generation part 2. `round1` holds the round 1 package of every other
/// holder, keyed by sender. Returns the state and one secret round 2 package
/// per recipient.
pub fn dkg_part2(state: DkgRound1, round1: &PeerMessages) -> Result<(DkgRound2, SecretMessages)> {
    let packages = parse_messages(round1, dkg::round1::Package::deserialize)?;
    let (secret, outgoing) = dkg::part2(state.secret.clone(), &packages)?;
    drop(state);
    let next = DkgRound2 { secret };
    Ok((next, serialize_outgoing(outgoing, |p| p.serialize())?))
}

/// Key generation part 3. `round1` is the same map given to part 2;
/// `round2` holds the packages addressed to this holder, keyed by sender.
/// Returns the share and the new plan.
pub fn dkg_part3(
    state: DkgRound2,
    round1: &PeerMessages,
    round2: &PeerMessages,
) -> Result<(Share, Plan)> {
    let r1 = parse_messages(round1, dkg::round1::Package::deserialize)?;
    let r2 = parse_messages(round2, dkg::round2::Package::deserialize)?;
    let (key_package, public_key_package) = dkg::part3(&state.secret, &r1, &r2)?;
    drop(state);
    finish(key_package, public_key_package, None)
}

// --- Share refresh ----------------------------------------------------------

/// Secret state between refresh part 1 and part 2.
pub struct RefreshRound1 {
    threshold: u16,
    secret: dkg::round1::SecretPackage,
}

impl Drop for RefreshRound1 {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Secret state between refresh part 2 and part 3.
pub struct RefreshRound2 {
    holder: HolderId,
    holder_count: u16,
    threshold: u16,
    secret: dkg::round2::SecretPackage,
}

impl Drop for RefreshRound2 {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Refresh part 1 for the holder of `current`, among `new_holder_count`
/// holders. The new holder set may drop old holders and include holders
/// enrolled with [`repair_part3`].
///
/// Fails with [`StorageError::ThresholdChange`] when `new_holder_count`
/// needs a threshold other than the current one.
pub fn refresh_part1(current: &Share, new_holder_count: u16) -> Result<(RefreshRound1, Vec<u8>)> {
    let threshold = plan_threshold(new_holder_count as usize)?;
    if threshold != current.threshold() {
        return Err(StorageError::ThresholdChange);
    }
    let (secret, package) = refresh::refresh_dkg_part1(
        identifier(current.holder())?,
        new_holder_count,
        threshold,
        OsRng,
    )?;
    let state = RefreshRound1 { threshold, secret };
    let bytes = package.serialize()?;
    Ok((state, bytes))
}

/// Refresh part 2. `round1` holds the refresh round 1 package of every other
/// participant, keyed by sender.
pub fn refresh_part2(
    state: RefreshRound1,
    round1: &PeerMessages,
) -> Result<(RefreshRound2, SecretMessages)> {
    let packages = parse_messages(round1, dkg::round1::Package::deserialize)?;
    let holder = holder_id(state.secret.identifier()).ok_or(StorageError::InvalidArgument)?;
    let holder_count = *state.secret.max_signers();
    let threshold = state.threshold;
    let (secret, outgoing) = refresh::refresh_dkg_part2(state.secret.clone(), &packages)?;
    drop(state);
    let next = RefreshRound2 {
        holder,
        holder_count,
        threshold,
        secret,
    };
    Ok((next, serialize_outgoing(outgoing, |p| p.serialize())?))
}

/// Refresh part 3. `round1` is the same map given to part 2; `round2` holds
/// the packages addressed to this holder, keyed by sender. `current` is this
/// holder's share under `old_plan`, or its share from [`repair_part3`].
///
/// Returns the refreshed share and the new plan. `S` does not change. The
/// new plan lists only the refresh participants, so a removed holder's share
/// no longer matches any commitment. Keep `current` until the new plan is
/// finalized, then destroy it.
pub fn refresh_part3(
    state: RefreshRound2,
    round1: &PeerMessages,
    round2: &PeerMessages,
    current: &Share,
    old_plan: &Plan,
) -> Result<(Share, Plan)> {
    let t = state.threshold;
    if current.holder() != state.holder {
        return Err(StorageError::InvalidArgument);
    }
    if current.threshold() != t || old_plan.threshold() != t {
        return Err(StorageError::ShareMismatch);
    }
    let r1 = parse_messages(round1, dkg::round1::Package::deserialize)?;
    // frost checks the commitment length in part 2 only. A longer commitment
    // here would raise the polynomial degree and so the effective threshold.
    if r1
        .values()
        .any(|p| p.commitment().coefficients().len() != usize::from(t) - 1)
    {
        return Err(StorageError::Crypto);
    }
    let r2 = parse_messages(round2, dkg::round2::Package::deserialize)?;

    let mut participants: BTreeSet<HolderId> = round1.keys().copied().collect();
    participants.insert(state.holder);
    if participants.len() != usize::from(state.holder_count) {
        return Err(StorageError::InvalidArgument);
    }
    let old_holders = participants
        .iter()
        .filter(|h| old_plan.contains(**h))
        .count();
    if old_holders < usize::from(t) {
        return Err(StorageError::BelowThreshold);
    }

    // frost needs an old commitment for every participant. An enrolled
    // holder has none in the old plan; interpolate it.
    let mut old_shares: BTreeMap<Identifier, VerifyingShare> =
        old_plan.package().verifying_shares().clone();
    let enrolled: Vec<HolderId> = participants
        .iter()
        .copied()
        .filter(|h| !old_plan.contains(*h))
        .collect();
    if !enrolled.is_empty() {
        old_plan.validate()?;
        for holder in enrolled {
            let commitment = old_plan.interpolate_share(holder)?;
            old_shares.insert(identifier(holder)?, VerifyingShare::new(commitment));
        }
    }
    let own = old_shares
        .get(&identifier(state.holder)?)
        .map(|s| s.to_element());
    if own != Some(current.verifying_share())
        || current.storage_public_key() != old_plan.storage_public_key()
    {
        return Err(StorageError::ShareMismatch);
    }
    let old_package = PublicKeyPackage::new(old_shares, *old_plan.package().verifying_key());

    let (key_package, public_key_package) =
        refresh::refresh_dkg_shares(&state.secret, &r1, &r2, old_package, current.inner.clone())?;
    let holder_count = state.holder_count;
    drop(state);
    let (share, plan) = finish(key_package, public_key_package, Some(old_plan))?;
    if plan.holder_count() != holder_count {
        return Err(StorageError::Crypto);
    }
    Ok((share, plan))
}

// --- Holder enrollment (share repair) ---------------------------------------

/// Enrollment step 1, run by each helper. `helpers` lists every helper,
/// this one included; it needs at least `t` holders of `plan`. Returns one
/// secret delta per helper (this one included), keyed by recipient.
pub fn repair_part1(
    helper: &Share,
    plan: &Plan,
    helpers: &[HolderId],
    new_holder: HolderId,
) -> Result<BTreeMap<HolderId, Zeroizing<[u8; 32]>>> {
    helper.check_in_plan(plan)?;
    if new_holder == 0 || plan.contains(new_holder) {
        return Err(StorageError::InvalidArgument);
    }
    let set: BTreeSet<HolderId> = helpers.iter().copied().collect();
    if set.len() != helpers.len()
        || !set.contains(&helper.holder())
        || set.iter().any(|h| !plan.contains(*h))
    {
        return Err(StorageError::InvalidArgument);
    }
    if set.len() < usize::from(plan.threshold()) {
        return Err(StorageError::BelowThreshold);
    }
    let ids = set
        .iter()
        .map(|h| identifier(*h))
        .collect::<Result<Vec<_>>>()?;

    // Only the identifier and the signing share are read by step 1.
    let mut own = SecretShare::new(
        identifier(helper.holder())?,
        *helper.inner.signing_share(),
        VerifiableSecretSharingCommitment::new(Vec::new()),
    );
    let deltas = repairable::repair_share_step_1::<Ristretto255Sha512, _>(
        &ids,
        &own,
        &mut OsRng,
        identifier(new_holder)?,
    );
    own.zeroize();
    let mut deltas = deltas?;

    let mut out = BTreeMap::new();
    for (id, delta) in deltas.iter_mut() {
        let recipient = holder_id(id).ok_or(StorageError::InvalidArgument)?;
        out.insert(recipient, Zeroizing::new(delta.to_bytes()));
        delta.zeroize();
    }
    Ok(out)
}

/// Enrollment step 2, run by each helper. `deltas` holds the delta from
/// every helper (this one included), keyed by sender. Returns the secret
/// sigma for the new holder.
pub fn repair_part2(helper: &Share, deltas: &PeerMessages) -> Result<Zeroizing<[u8; 32]>> {
    if deltas.len() < usize::from(helper.threshold()) {
        return Err(StorageError::BelowThreshold);
    }
    let scalars = parse_scalars(deltas)?;
    let sigma = Zeroizing::new(repairable::repair_share_step_2(&scalars));
    Ok(Zeroizing::new(sigma.to_bytes()))
}

/// Enrollment step 3, run by the new holder. `sigmas` holds the sigma from
/// every helper, keyed by sender. Checks the result against the commitment
/// interpolated from `plan` and returns the new holder's share.
///
/// The share is not usable for decryption until a refresh that includes the
/// new holder produces a plan that lists it.
pub fn repair_part3(plan: &Plan, new_holder: HolderId, sigmas: &PeerMessages) -> Result<Share> {
    if new_holder == 0 || plan.contains(new_holder) {
        return Err(StorageError::InvalidArgument);
    }
    if sigmas.keys().any(|h| !plan.contains(*h)) {
        return Err(StorageError::InvalidArgument);
    }
    if sigmas.len() < usize::from(plan.threshold()) {
        return Err(StorageError::BelowThreshold);
    }
    plan.validate()?;
    let expected = plan.interpolate_share(new_holder)?;
    let scalars = parse_scalars(sigmas)?;
    let mut repaired = repairable::repair_share_step_3(
        &scalars,
        identifier(new_holder)?,
        &VerifiableSecretSharingCommitment::new(Vec::new()),
    );
    let key_package = KeyPackage::new(
        identifier(new_holder)?,
        *repaired.signing_share(),
        VerifyingShare::new(expected),
        *plan.package().verifying_key(),
        plan.threshold(),
    );
    repaired.zeroize();
    // from_key_package checks s·G against the interpolated commitment. With
    // fewer than t honest helpers the repaired share is off the polynomial.
    Share::from_key_package(key_package)
}

// --- Helpers ----------------------------------------------------------------

/// Common checks on the output of key generation or refresh.
fn finish(
    key_package: KeyPackage,
    public_key_package: PublicKeyPackage,
    old_plan: Option<&Plan>,
) -> Result<(Share, Plan)> {
    let share = Share::from_key_package(key_package)?;
    let plan = Plan::from_package(public_key_package)?;
    if let Some(old) = old_plan {
        if plan.storage_public_key() != old.storage_public_key() {
            return Err(StorageError::Crypto);
        }
    }
    share
        .check_in_plan(&plan)
        .map_err(|_| StorageError::Crypto)?;
    plan.validate()?;
    Ok((share, plan))
}

fn parse_messages<T>(
    messages: &PeerMessages,
    parse: impl Fn(&[u8]) -> std::result::Result<T, frost::Error>,
) -> Result<BTreeMap<Identifier, T>> {
    let mut out = BTreeMap::new();
    for (holder, bytes) in messages {
        if bytes.is_empty() || bytes.len() > MAX_MESSAGE_BYTES {
            return Err(StorageError::InvalidArgument);
        }
        let value = parse(bytes).map_err(|_| StorageError::Serialization)?;
        out.insert(identifier(*holder)?, value);
    }
    Ok(out)
}

fn serialize_outgoing<T>(
    outgoing: BTreeMap<Identifier, T>,
    serialize: impl Fn(&T) -> std::result::Result<Vec<u8>, frost::Error>,
) -> Result<SecretMessages> {
    let mut out = BTreeMap::new();
    for (id, package) in &outgoing {
        let recipient = holder_id(id).ok_or(StorageError::InvalidArgument)?;
        out.insert(recipient, Zeroizing::new(serialize(package)?));
    }
    Ok(out)
}

fn parse_scalars(messages: &PeerMessages) -> Result<Zeroizing<Vec<Scalar>>> {
    let mut scalars = Zeroizing::new(Vec::with_capacity(messages.len()));
    for bytes in messages.values() {
        let mut array = Zeroizing::new([0u8; 32]);
        if bytes.len() != array.len() {
            return Err(StorageError::InvalidArgument);
        }
        array.copy_from_slice(bytes);
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(*array))
            .ok_or(StorageError::Serialization)?;
        scalars.push(scalar);
    }
    Ok(scalars)
}

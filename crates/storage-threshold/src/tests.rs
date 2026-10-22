//! Protocol tests over the Rust API (design "Tests Required", storage key).

use std::collections::BTreeMap;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use rand_core::{OsRng, RngCore};

use crate::keys::{self, PeerMessages, Share};
use crate::params::{threshold_for, MAX_HOLDERS, MIN_HOLDERS};
use crate::plan::{interpolate, Plan};
use crate::unlock::{self, UnlockContext, PARTIAL_LEN};
use crate::wrap::encapsulate;
use crate::{HolderId, StorageError};

struct Group {
    shares: BTreeMap<HolderId, Share>,
    plan: Plan,
}

fn view<'a>(map: &'a BTreeMap<HolderId, Vec<u8>>, skip: Option<HolderId>) -> PeerMessages<'a> {
    map.iter()
        .filter(|(h, _)| Some(**h) != skip)
        .map(|(h, b)| (*h, b.as_slice()))
        .collect()
}

fn run_dkg(ids: &[HolderId]) -> Group {
    let n = ids.len() as u16;
    let mut round1 = BTreeMap::new();
    let mut packages = BTreeMap::new();
    for &id in ids {
        let (state, package) = keys::dkg_part1(id, n).expect("part1");
        round1.insert(id, state);
        packages.insert(id, package);
    }
    let mut round2 = BTreeMap::new();
    let mut inbox: BTreeMap<HolderId, BTreeMap<HolderId, Vec<u8>>> = BTreeMap::new();
    for (id, state) in round1 {
        let (next, outgoing) = keys::dkg_part2(state, &view(&packages, Some(id))).expect("part2");
        for (recipient, bytes) in outgoing {
            inbox
                .entry(recipient)
                .or_default()
                .insert(id, bytes.to_vec());
        }
        round2.insert(id, next);
    }
    let mut shares = BTreeMap::new();
    let mut plan_bytes = None;
    let mut plan = None;
    for (id, state) in round2 {
        let (share, p) =
            keys::dkg_part3(state, &view(&packages, Some(id)), &view(&inbox[&id], None))
                .expect("part3");
        let bytes = p.serialize().unwrap();
        // Every holder derives the same plan.
        if let Some(previous) = &plan_bytes {
            assert_eq!(previous, &bytes);
        }
        plan_bytes = Some(bytes);
        plan = Some(p);
        shares.insert(id, share);
    }
    Group {
        shares,
        plan: plan.unwrap(),
    }
}

/// Refresh among `participants`. Each must have a share in `current`.
fn run_refresh(
    current: &BTreeMap<HolderId, &Share>,
    old_plan: &Plan,
    participants: &[HolderId],
) -> Result<Group, StorageError> {
    let n = participants.len() as u16;
    let mut round1 = BTreeMap::new();
    let mut packages = BTreeMap::new();
    for id in participants {
        let (state, package) = keys::refresh_part1(current[id], n)?;
        round1.insert(*id, state);
        packages.insert(*id, package);
    }
    let mut round2 = BTreeMap::new();
    let mut inbox: BTreeMap<HolderId, BTreeMap<HolderId, Vec<u8>>> = BTreeMap::new();
    for (id, state) in round1 {
        let (next, outgoing) = keys::refresh_part2(state, &view(&packages, Some(id)))?;
        for (recipient, bytes) in outgoing {
            inbox
                .entry(recipient)
                .or_default()
                .insert(id, bytes.to_vec());
        }
        round2.insert(id, next);
    }
    let mut shares = BTreeMap::new();
    let mut plan: Option<Plan> = None;
    for (id, state) in round2 {
        let (share, p) = keys::refresh_part3(
            state,
            &view(&packages, Some(id)),
            &view(&inbox[&id], None),
            current[&id],
            old_plan,
        )?;
        if let Some(previous) = &plan {
            assert_eq!(previous.serialize().unwrap(), p.serialize().unwrap());
        }
        plan = Some(p);
        shares.insert(id, share);
    }
    Ok(Group {
        shares,
        plan: plan.unwrap(),
    })
}

fn all_shares(group: &Group) -> BTreeMap<HolderId, &Share> {
    group.shares.iter().map(|(h, s)| (*h, s)).collect()
}

fn enroll(
    group: &Group,
    helpers: &[HolderId],
    new_holder: HolderId,
) -> Result<Share, StorageError> {
    let mut inbox: BTreeMap<HolderId, BTreeMap<HolderId, Vec<u8>>> = BTreeMap::new();
    for h in helpers {
        let deltas = keys::repair_part1(&group.shares[h], &group.plan, helpers, new_holder)?;
        for (recipient, delta) in deltas {
            inbox
                .entry(recipient)
                .or_default()
                .insert(*h, delta.to_vec());
        }
    }
    let mut sigmas = BTreeMap::new();
    for h in helpers {
        let sigma = keys::repair_part2(&group.shares[h], &view(&inbox[h], None))?;
        sigmas.insert(*h, sigma.to_vec());
    }
    keys::repair_part3(&group.plan, new_holder, &view(&sigmas, None))
}

fn context() -> UnlockContext {
    let mut c = UnlockContext {
        network_id: [0; 32],
        epoch: 7,
        plan_digest: [0; 32],
        request_nonce: [0; 32],
    };
    OsRng.fill_bytes(&mut c.network_id);
    OsRng.fill_bytes(&mut c.plan_digest);
    OsRng.fill_bytes(&mut c.request_nonce);
    c
}

fn partials(
    group: &Group,
    holders: &[HolderId],
    ctx: &UnlockContext,
    ephemeral: &[u8; 32],
) -> BTreeMap<HolderId, Vec<u8>> {
    holders
        .iter()
        .map(|h| {
            let p = unlock::create_partial(&group.shares[h], &group.plan, ctx, ephemeral)
                .expect("partial");
            (*h, p.to_vec())
        })
        .collect()
}

fn ids(range: std::ops::RangeInclusive<HolderId>) -> Vec<HolderId> {
    range.collect()
}

fn raw_partial(share: &Share, ephemeral: &[u8; 32]) -> RistrettoPoint {
    crate::plan::decode_point(ephemeral).unwrap() * *share.secret_scalar()
}

// --- Valid paths -------------------------------------------------------------

#[test]
fn key_generation_wrap_and_unlock() {
    for n in [5u16, 7, 10] {
        let group = run_dkg(&ids(1..=n));
        let t = threshold_for(n).unwrap();
        assert_eq!(group.plan.threshold(), t);
        assert_eq!(group.plan.holder_count(), n);
        group.plan.validate().unwrap();

        let (ephemeral, shared) = encapsulate(&group.plan.storage_public_key_bytes()).unwrap();
        let ctx = context();
        // Exactly t holders, from either end of the set.
        let low: Vec<_> = ids(1..=t);
        let high: Vec<_> = ids(n - t + 1..=n);
        for set in [low, high, ids(1..=n)] {
            let p = partials(&group, &set, &ctx, &ephemeral);
            let combined = unlock::combine(&group.plan, &ctx, &ephemeral, &view(&p, None)).unwrap();
            assert_eq!(*combined, *shared, "n = {n}, set = {set:?}");
        }
    }
}

#[test]
fn non_contiguous_identifiers() {
    let group = run_dkg(&[3, 9, 17, 200, 65535]);
    let (ephemeral, shared) = encapsulate(&group.plan.storage_public_key_bytes()).unwrap();
    let ctx = context();
    let p = partials(&group, &[9, 200, 65535, 3], &ctx, &ephemeral);
    let combined = unlock::combine(&group.plan, &ctx, &ephemeral, &view(&p, None)).unwrap();
    assert_eq!(*combined, *shared);
}

#[test]
fn share_and_plan_round_trip() {
    let group = run_dkg(&ids(1..=5));
    let bytes = group.shares[&2].serialize().unwrap();
    let restored = Share::deserialize(&bytes).unwrap();
    assert_eq!(restored.holder(), 2);
    restored.check_in_plan(&group.plan).unwrap();

    let plan_bytes = group.plan.serialize().unwrap();
    let plan = Plan::deserialize(&plan_bytes).unwrap();
    plan.validate().unwrap();
    assert_eq!(plan.storage_public_key(), group.plan.storage_public_key());
}

// --- Rejections: partials ----------------------------------------------------

#[test]
fn fewer_than_t_partials() {
    let group = run_dkg(&ids(1..=7));
    let t = group.plan.threshold();
    let (ephemeral, _) = encapsulate(&group.plan.storage_public_key_bytes()).unwrap();
    let ctx = context();
    let p = partials(&group, &ids(1..=t - 1), &ctx, &ephemeral);
    assert_eq!(
        unlock::combine(&group.plan, &ctx, &ephemeral, &view(&p, None)),
        Err(StorageError::BelowThreshold)
    );
    assert_eq!(
        unlock::combine(&group.plan, &ctx, &ephemeral, &PeerMessages::new()),
        Err(StorageError::BelowThreshold)
    );
}

#[test]
fn invalid_dleq_partial() {
    let group = run_dkg(&ids(1..=5));
    let (ephemeral, _) = encapsulate(&group.plan.storage_public_key_bytes()).unwrap();
    let ctx = context();
    let good = partials(&group, &ids(1..=5), &ctx, &ephemeral);

    // A flipped bit in the proof, in the point, or a proof presented for
    // another holder.
    let mut proof_bit = good.clone();
    proof_bit.get_mut(&1).unwrap()[40] ^= 1;
    let mut point_bit = good.clone();
    point_bit.get_mut(&1).unwrap()[0] ^= 1;
    let mut swapped = good.clone();
    let one = swapped[&1].clone();
    swapped.insert(2, one);
    for bad in [proof_bit, point_bit, swapped] {
        assert_eq!(
            unlock::combine(&group.plan, &ctx, &ephemeral, &view(&bad, None)),
            Err(StorageError::Proof)
        );
    }

    // A correct point with a proof made by another holder's share.
    let forged_point = raw_partial(&group.shares[&3], &ephemeral);
    let mut forged = good[&1].clone();
    forged[..32].copy_from_slice(&forged_point.compress().to_bytes());
    assert_eq!(
        unlock::verify_partial(&group.plan, &ctx, &ephemeral, 1, &forged),
        Err(StorageError::Proof)
    );

    // An unknown holder, a short partial.
    assert_eq!(
        unlock::verify_partial(&group.plan, &ctx, &ephemeral, 6, &good[&1]),
        Err(StorageError::Proof)
    );
    assert_eq!(
        unlock::verify_partial(
            &group.plan,
            &ctx,
            &ephemeral,
            1,
            &good[&1][..PARTIAL_LEN - 1]
        ),
        Err(StorageError::InvalidArgument)
    );
}

#[test]
fn partial_for_a_different_r() {
    let group = run_dkg(&ids(1..=5));
    let (ephemeral, _) = encapsulate(&group.plan.storage_public_key_bytes()).unwrap();
    let (other, _) = encapsulate(&group.plan.storage_public_key_bytes()).unwrap();
    let ctx = context();
    let mut p = partials(&group, &ids(1..=4), &ctx, &ephemeral);
    let wrong = partials(&group, &[1], &ctx, &other);
    p.insert(1, wrong[&1].clone());
    assert_eq!(
        unlock::combine(&group.plan, &ctx, &ephemeral, &view(&p, None)),
        Err(StorageError::Proof)
    );
}

#[test]
fn proof_bound_to_request_context() {
    let group = run_dkg(&ids(1..=5));
    let (ephemeral, _) = encapsulate(&group.plan.storage_public_key_bytes()).unwrap();
    let ctx = context();
    let p = partials(&group, &[1], &ctx, &ephemeral);
    let mut variants = Vec::new();
    let mut c = ctx;
    c.request_nonce[0] ^= 1;
    variants.push(c);
    let mut c = ctx;
    c.epoch += 1;
    variants.push(c);
    let mut c = ctx;
    c.network_id[31] ^= 1;
    variants.push(c);
    let mut c = ctx;
    c.plan_digest[5] ^= 1;
    variants.push(c);
    for other in variants {
        assert_eq!(
            unlock::verify_partial(&group.plan, &other, &ephemeral, 1, &p[&1]),
            Err(StorageError::Proof)
        );
    }
    unlock::verify_partial(&group.plan, &ctx, &ephemeral, 1, &p[&1]).unwrap();
}

#[test]
fn malformed_points_rejected() {
    let group = run_dkg(&ids(1..=5));
    let ctx = context();
    let identity = RistrettoPoint::identity().compress().to_bytes();
    let non_canonical = [0xffu8; 32];
    for bad in [identity, non_canonical] {
        assert_eq!(
            encapsulate(&bad).unwrap_err(),
            StorageError::InvalidArgument
        );
        assert_eq!(
            unlock::create_partial(&group.shares[&1], &group.plan, &ctx, &bad).unwrap_err(),
            StorageError::InvalidArgument
        );
        assert_eq!(
            unlock::combine(&group.plan, &ctx, &bad, &PeerMessages::new()),
            Err(StorageError::InvalidArgument)
        );
    }
}

#[test]
fn encapsulation_is_randomized() {
    let group = run_dkg(&ids(1..=5));
    let s = group.plan.storage_public_key_bytes();
    let (r1, k1) = encapsulate(&s).unwrap();
    let (r2, k2) = encapsulate(&s).unwrap();
    assert_ne!(r1, r2);
    assert_ne!(*k1, *k2);
}

// --- Refresh -----------------------------------------------------------------

#[test]
fn refresh_keeps_key_and_retires_old_shares() {
    let group = run_dkg(&ids(1..=7));
    let refreshed = run_refresh(&all_shares(&group), &group.plan, &ids(1..=7)).unwrap();
    assert_eq!(
        refreshed.plan.storage_public_key(),
        group.plan.storage_public_key()
    );
    assert_eq!(refreshed.plan.threshold(), 5);
    assert_ne!(
        refreshed.plan.serialize().unwrap(),
        group.plan.serialize().unwrap()
    );

    let (ephemeral, shared) = encapsulate(&group.plan.storage_public_key_bytes()).unwrap();
    let ctx = context();
    let p = partials(&refreshed, &ids(3..=7), &ctx, &ephemeral);
    let combined = unlock::combine(&refreshed.plan, &ctx, &ephemeral, &view(&p, None)).unwrap();
    assert_eq!(*combined, *shared);

    // A pre-refresh share cannot make a partial for the new plan.
    assert_eq!(
        unlock::create_partial(&group.shares[&1], &refreshed.plan, &ctx, &ephemeral).unwrap_err(),
        StorageError::ShareMismatch
    );
    // A pre-refresh partial does not verify against the new plan.
    let stale = partials(&group, &[1], &ctx, &ephemeral);
    let mut mixed = partials(&refreshed, &ids(2..=5), &ctx, &ephemeral);
    mixed.insert(1, stale[&1].clone());
    assert_eq!(
        unlock::combine(&refreshed.plan, &ctx, &ephemeral, &view(&mixed, None)),
        Err(StorageError::Proof)
    );
    // Even without proofs, a pre-refresh share mixed with post-refresh shares
    // interpolates to the wrong point.
    let mut points = BTreeMap::new();
    points.insert(1, raw_partial(&group.shares[&1], &ephemeral));
    for h in 2..=5 {
        points.insert(h, raw_partial(&refreshed.shares[&h], &ephemeral));
    }
    assert_ne!(
        interpolate(&points, None).unwrap().compress().to_bytes(),
        *shared
    );
}

#[test]
fn refresh_removes_a_holder() {
    // 6 holders (t = 4) to 5 holders (t = 4): same threshold, so refresh.
    let group = run_dkg(&ids(1..=6));
    let refreshed = run_refresh(&all_shares(&group), &group.plan, &ids(1..=5)).unwrap();
    assert!(!refreshed.plan.contains(6));
    assert_eq!(
        refreshed.plan.storage_public_key(),
        group.plan.storage_public_key()
    );

    let (ephemeral, shared) = encapsulate(&group.plan.storage_public_key_bytes()).unwrap();
    let ctx = context();
    let removed = &group.shares[&6];
    assert_eq!(
        removed.check_in_plan(&refreshed.plan),
        Err(StorageError::ShareMismatch)
    );
    let old = partials(&group, &[6], &ctx, &ephemeral);
    assert_eq!(
        unlock::verify_partial(&refreshed.plan, &ctx, &ephemeral, 6, &old[&6]),
        Err(StorageError::Proof)
    );
    // The removed holder's share plus t - 1 current shares is wrong.
    let mut points = BTreeMap::new();
    points.insert(6, raw_partial(removed, &ephemeral));
    for h in 1..=3 {
        points.insert(h, raw_partial(&refreshed.shares[&h], &ephemeral));
    }
    assert_ne!(
        interpolate(&points, None).unwrap().compress().to_bytes(),
        *shared
    );
    // The current holders still unlock.
    let p = partials(&refreshed, &ids(2..=5), &ctx, &ephemeral);
    assert_eq!(
        *unlock::combine(&refreshed.plan, &ctx, &ephemeral, &view(&p, None)).unwrap(),
        *shared
    );
}

#[test]
fn threshold_change_requires_rotation() {
    let seven = run_dkg(&ids(1..=7));
    // 7 holders (t = 5) to 6 holders (t = 4).
    assert_eq!(
        keys::refresh_part1(&seven.shares[&1], 6).err(),
        Some(StorageError::ThresholdChange)
    );
    // 7 to 8 holders (t = 6).
    assert_eq!(
        keys::refresh_part1(&seven.shares[&1], 8).err(),
        Some(StorageError::ThresholdChange)
    );
    let five = run_dkg(&ids(1..=5));
    // 5 to 4 holders is below the minimum plan size.
    assert_eq!(
        keys::refresh_part1(&five.shares[&1], 4).err(),
        Some(StorageError::HolderCount)
    );
    assert_eq!(
        keys::refresh_part1(&five.shares[&1], MAX_HOLDERS + 1).err(),
        Some(StorageError::HolderCount)
    );
}

#[test]
fn refresh_with_fewer_than_t_old_holders() {
    // Plan of 6 (t = 4). Enroll 7 and 8 with valid helpers, then try a
    // refresh among {1, 2, 3, 7, 8}: only 3 old holders contribute.
    let group = run_dkg(&ids(1..=6));
    let seven = enroll(&group, &[1, 2, 3, 4], 7).unwrap();
    let eight = enroll(&group, &[3, 4, 5, 6], 8).unwrap();
    let mut current = all_shares(&group);
    current.insert(7, &seven);
    current.insert(8, &eight);
    assert_eq!(
        run_refresh(&current, &group.plan, &[1, 2, 3, 7, 8]).err(),
        Some(StorageError::BelowThreshold)
    );
    // With 4 old holders the same enrollment completes.
    let refreshed = run_refresh(&current, &group.plan, &[1, 2, 3, 4, 7]).unwrap();
    assert!(refreshed.plan.contains(7));
}

#[test]
fn refresh_with_missing_participant_package() {
    let group = run_dkg(&ids(1..=5));
    let mut round1 = BTreeMap::new();
    let mut packages = BTreeMap::new();
    for id in 1..=5u16 {
        let (state, package) = keys::refresh_part1(&group.shares[&id], 5).unwrap();
        round1.insert(id, state);
        packages.insert(id, package);
    }
    let state = round1.remove(&1).unwrap();
    // Holder 1 sees only three of the four other packages.
    let mut partial_view = view(&packages, Some(1));
    partial_view.remove(&5);
    assert_eq!(
        keys::refresh_part2(state, &partial_view).err(),
        Some(StorageError::InvalidArgument)
    );
}

// --- Enrollment --------------------------------------------------------------

#[test]
fn enrollment_replaces_a_lost_holder() {
    // Holder 5 is lost; holder 6 joins. 5 holders stay, t = 4.
    let group = run_dkg(&ids(1..=5));
    let six = enroll(&group, &[1, 2, 3, 4], 6).unwrap();
    // Not usable before the refresh lists it.
    let ctx = context();
    let (ephemeral, shared) = encapsulate(&group.plan.storage_public_key_bytes()).unwrap();
    assert_eq!(
        unlock::create_partial(&six, &group.plan, &ctx, &ephemeral).unwrap_err(),
        StorageError::ShareMismatch
    );

    let mut current = all_shares(&group);
    current.insert(6, &six);
    let refreshed = run_refresh(&current, &group.plan, &[1, 2, 3, 4, 6]).unwrap();
    assert!(refreshed.plan.contains(6));
    assert!(!refreshed.plan.contains(5));
    let p = partials(&refreshed, &[2, 3, 4, 6], &ctx, &ephemeral);
    assert_eq!(
        *unlock::combine(&refreshed.plan, &ctx, &ephemeral, &view(&p, None)).unwrap(),
        *shared
    );
    assert_eq!(
        group.shares[&5].check_in_plan(&refreshed.plan),
        Err(StorageError::ShareMismatch)
    );
}

#[test]
fn enrollment_with_fewer_than_t_helpers() {
    let group = run_dkg(&ids(1..=5));
    // The API refuses t - 1 helpers.
    assert_eq!(
        keys::repair_part1(&group.shares[&1], &group.plan, &[1, 2, 3], 6).err(),
        Some(StorageError::BelowThreshold)
    );

    // Run the repair math with 3 helpers directly through frost, which does
    // not check the count, and hand the sigmas to step 3.
    use frost_ristretto255::keys::{repairable, SecretShare, VerifiableSecretSharingCommitment};
    use frost_ristretto255::{Identifier, Ristretto255Sha512};
    let helpers: Vec<Identifier> = [1u16, 2, 3]
        .iter()
        .map(|h| Identifier::try_from(*h).unwrap())
        .collect();
    let new_id = Identifier::try_from(6u16).unwrap();
    let mut deltas: BTreeMap<HolderId, Vec<curve25519_dalek::Scalar>> = BTreeMap::new();
    for h in [1u16, 2, 3] {
        let share = &group.shares[&h];
        let ss = SecretShare::new(
            Identifier::try_from(h).unwrap(),
            frost_ristretto255::keys::SigningShare::new(*share.secret_scalar()),
            VerifiableSecretSharingCommitment::new(Vec::new()),
        );
        let out = repairable::repair_share_step_1::<Ristretto255Sha512, _>(
            &helpers, &ss, &mut OsRng, new_id,
        )
        .unwrap();
        for (id, d) in out {
            let recipient = crate::plan::holder_id(&id).unwrap();
            deltas.entry(recipient).or_default().push(d);
        }
    }
    let mut sigmas = BTreeMap::new();
    for h in [1u16, 2, 3] {
        sigmas.insert(
            h,
            repairable::repair_share_step_2(&deltas[&h])
                .to_bytes()
                .to_vec(),
        );
    }
    assert_eq!(
        keys::repair_part3(&group.plan, 6, &view(&sigmas, None)).err(),
        Some(StorageError::BelowThreshold)
    );
    // Padding to t with a made-up sigma does not pass the commitment check.
    sigmas.insert(
        4,
        curve25519_dalek::Scalar::from(12345u64).to_bytes().to_vec(),
    );
    assert_eq!(
        keys::repair_part3(&group.plan, 6, &view(&sigmas, None)).err(),
        Some(StorageError::Crypto)
    );
}

#[test]
fn enrollment_with_a_tampered_sigma() {
    let group = run_dkg(&ids(1..=5));
    let helpers = [1u16, 2, 3, 4];
    let mut inbox: BTreeMap<HolderId, BTreeMap<HolderId, Vec<u8>>> = BTreeMap::new();
    for h in &helpers {
        for (recipient, delta) in
            keys::repair_part1(&group.shares[h], &group.plan, &helpers, 6).unwrap()
        {
            inbox
                .entry(recipient)
                .or_default()
                .insert(*h, delta.to_vec());
        }
    }
    let mut sigmas = BTreeMap::new();
    for h in &helpers {
        let sigma = keys::repair_part2(&group.shares[h], &view(&inbox[h], None)).unwrap();
        sigmas.insert(*h, sigma.to_vec());
    }
    let mut tampered = sigmas.clone();
    tampered.get_mut(&2).unwrap()[0] ^= 1;
    assert_eq!(
        keys::repair_part3(&group.plan, 6, &view(&tampered, None)).err(),
        Some(StorageError::Crypto)
    );
    keys::repair_part3(&group.plan, 6, &view(&sigmas, None)).unwrap();
    // An existing identifier or a helper outside the plan is refused.
    assert_eq!(
        keys::repair_part1(&group.shares[&1], &group.plan, &helpers, 5).err(),
        Some(StorageError::InvalidArgument)
    );
    assert_eq!(
        keys::repair_part1(&group.shares[&1], &group.plan, &[1, 2, 3, 9], 6).err(),
        Some(StorageError::InvalidArgument)
    );
}

// --- Plans and shares --------------------------------------------------------

#[test]
fn inconsistent_plan_fails_validation() {
    let group = run_dkg(&ids(1..=5));
    let other = run_dkg(&ids(1..=5));
    // Splice holder 5's commitment from another key into the plan.
    let mut shares = group.plan.package().verifying_shares().clone();
    let id5 = frost_ristretto255::Identifier::try_from(5u16).unwrap();
    shares.insert(id5, other.plan.package().verifying_shares()[&id5]);
    let spliced = Plan::from_package(frost_ristretto255::keys::PublicKeyPackage::new(
        shares,
        *group.plan.package().verifying_key(),
    ))
    .unwrap();
    assert_eq!(spliced.validate(), Err(StorageError::Crypto));
    // A plan with the wrong storage public key fails too.
    let wrong_key = Plan::from_package(frost_ristretto255::keys::PublicKeyPackage::new(
        group.plan.package().verifying_shares().clone(),
        *other.plan.package().verifying_key(),
    ))
    .unwrap();
    assert_eq!(wrong_key.validate(), Err(StorageError::Crypto));
}

#[test]
fn malformed_share_and_plan_bytes() {
    let group = run_dkg(&ids(1..=5));
    assert_eq!(
        Share::deserialize(&[]).err(),
        Some(StorageError::InvalidArgument)
    );
    assert_eq!(
        Plan::deserialize(&[]).err(),
        Some(StorageError::InvalidArgument)
    );
    assert_eq!(
        Plan::deserialize(&[1, 2, 3]).err(),
        Some(StorageError::Serialization)
    );
    // Flip a bit of the signing share so it no longer matches the stored
    // commitment.
    let mut bytes = group.shares[&1].serialize().unwrap().to_vec();
    let secret = group.shares[&1].secret_scalar().to_bytes();
    let at = bytes
        .windows(32)
        .position(|w| w == secret)
        .expect("signing share in encoding");
    bytes[at] ^= 1;
    assert_eq!(Share::deserialize(&bytes).err(), Some(StorageError::Crypto));
}

// --- Holder-count sweep ------------------------------------------------------

#[test]
fn key_generation_rejects_out_of_range_counts() {
    for n in 0..MIN_HOLDERS {
        assert_eq!(
            keys::dkg_part1(1, n).err(),
            Some(StorageError::HolderCount),
            "n = {n}"
        );
    }
    assert_eq!(
        keys::dkg_part1(1, MAX_HOLDERS + 1).err(),
        Some(StorageError::HolderCount)
    );
    assert_eq!(
        keys::dkg_part1(0, 5).err(),
        Some(StorageError::InvalidArgument)
    );
}

/// Test-only shares from the frost trusted dealer. The crate never deals
/// shares; this only makes the every-count sweep fast.
fn dealer_group(n: u16) -> Group {
    use frost_ristretto255::keys::{generate_with_dealer, IdentifierList, KeyPackage};
    let t = threshold_for(n).unwrap();
    let (secret_shares, package) =
        generate_with_dealer(n, t, IdentifierList::Default, OsRng).unwrap();
    let shares = secret_shares
        .into_values()
        .map(|s| {
            let share = Share::from_key_package(KeyPackage::try_from(s).unwrap()).unwrap();
            (share.holder(), share)
        })
        .collect();
    Group {
        shares,
        plan: Plan::from_package(package).unwrap(),
    }
}

/// Unlock with exactly `t` partials succeeds and with `t − 1` fails.
fn check_exact_threshold(group: &Group, n: u16) {
    let t = threshold_for(n).unwrap();
    assert_eq!(group.plan.threshold(), t);
    group.plan.validate().unwrap();
    let (ephemeral, shared) = encapsulate(&group.plan.storage_public_key_bytes()).unwrap();
    let ctx = context();
    // Holders spread across the set: every other holder first.
    let mut order: Vec<HolderId> = (1..=n).step_by(2).collect();
    order.extend((2..=n).step_by(2));
    let chosen = &order[..t as usize];
    let p = partials(group, chosen, &ctx, &ephemeral);
    assert_eq!(
        *unlock::combine(&group.plan, &ctx, &ephemeral, &view(&p, None)).unwrap(),
        *shared,
        "n = {n}"
    );
    let mut short = p.clone();
    short.remove(&chosen[0]);
    assert_eq!(
        unlock::combine(&group.plan, &ctx, &ephemeral, &view(&short, None)),
        Err(StorageError::BelowThreshold),
        "n = {n}"
    );
}

/// Every permitted holder count, with dealer shares.
#[test]
fn every_holder_count_exact_threshold() {
    for n in MIN_HOLDERS..=MAX_HOLDERS {
        check_exact_threshold(&dealer_group(n), n);
    }
}

/// Key generation at the boundary sizes, the 50-holder cap included.
#[test]
fn key_generation_boundary_counts_exact_threshold() {
    for n in [5u16, 6, 7, 10, 20, 31, 50] {
        check_exact_threshold(&run_dkg(&ids(1..=n)), n);
    }
}

/// Key generation at every permitted holder count. More than a minute; run with
/// `cargo test --locked -- --ignored`.
#[test]
#[ignore]
fn key_generation_every_holder_count_exact_threshold() {
    for n in MIN_HOLDERS..=MAX_HOLDERS {
        check_exact_threshold(&run_dkg(&ids(1..=n)), n);
    }
}

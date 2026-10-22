//! The holder plan: the public part of one storage key.
//!
//! A plan is a frost `PublicKeyPackage`: the storage public key `S` and the
//! public share commitment `Y_i = s_i·G` of every holder. The threshold is
//! not stored. It is always `ceil(0.65 × n)` of the plan's holder count.
//!
//! No upstream audit covers this module. It holds the plan checks and the
//! Lagrange interpolation in the exponent, built from
//! `frost_core::compute_lagrange_coefficient` and a dalek multiscalar
//! multiplication.

use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use frost_core::compute_lagrange_coefficient;
use frost_ristretto255::keys::PublicKeyPackage;
use frost_ristretto255::{Identifier, Ristretto255Sha512};

use crate::params::plan_threshold;
use crate::{HolderId, Result, StorageError};

/// Upper bound on a serialized plan. A 50-holder plan is about 3.3 KiB.
pub const MAX_PLAN_BYTES: usize = 16 * 1024;

/// A parsed holder plan whose size and threshold follow the design rules.
#[derive(Clone)]
pub struct Plan {
    package: PublicKeyPackage,
    threshold: u16,
    shares: BTreeMap<HolderId, RistrettoPoint>,
    storage_public_key: RistrettoPoint,
}

impl Plan {
    /// Wrap a frost public key package. Checks the holder count and that
    /// every identifier is a nonzero `u16`. Does not check consistency; see
    /// [`Plan::validate`].
    pub(crate) fn from_package(package: PublicKeyPackage) -> Result<Self> {
        let threshold = plan_threshold(package.verifying_shares().len())?;
        let mut shares = BTreeMap::new();
        for (id, share) in package.verifying_shares() {
            let holder = holder_id(id).ok_or(StorageError::InvalidArgument)?;
            shares.insert(holder, share.to_element());
        }
        let storage_public_key = package.verifying_key().to_element();
        Ok(Plan {
            package,
            threshold,
            shares,
            storage_public_key,
        })
    }

    /// Parse a serialized plan. Does not check consistency; see
    /// [`Plan::validate`].
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PLAN_BYTES {
            return Err(StorageError::InvalidArgument);
        }
        let package =
            PublicKeyPackage::deserialize(bytes).map_err(|_| StorageError::Serialization)?;
        Plan::from_package(package)
    }

    /// The canonical serialization (frost encoding, holders in identifier order).
    pub fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.package.serialize()?)
    }

    /// The number of shares needed to decrypt.
    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    /// The number of holders.
    pub fn holder_count(&self) -> u16 {
        // from_package bounds the count by MAX_HOLDERS.
        self.shares.len() as u16
    }

    /// Holder identifiers in ascending order.
    pub fn holder_ids(&self) -> impl Iterator<Item = HolderId> + '_ {
        self.shares.keys().copied()
    }

    /// Whether `holder` is in the plan.
    pub fn contains(&self, holder: HolderId) -> bool {
        self.shares.contains_key(&holder)
    }

    /// The public share commitment `Y_i` of `holder`.
    pub fn verifying_share(&self, holder: HolderId) -> Option<RistrettoPoint> {
        self.shares.get(&holder).copied()
    }

    /// The storage public key `S`.
    pub fn storage_public_key(&self) -> RistrettoPoint {
        self.storage_public_key
    }

    /// The canonical 32-byte encoding of `S`.
    pub fn storage_public_key_bytes(&self) -> [u8; 32] {
        self.storage_public_key.compress().to_bytes()
    }

    pub(crate) fn package(&self) -> &PublicKeyPackage {
        &self.package
    }

    /// Check that every share commitment lies on one polynomial of degree
    /// `t − 1` whose constant term is `S`.
    ///
    /// Interpolates `S` and every remaining `Y_j` from the first `t` holders.
    /// A plan made by an honest key generation, refresh, or enrollment always
    /// passes. Interpolating a new holder's commitment depends on this check.
    pub fn validate(&self) -> Result<()> {
        let base = self.base_points();
        if interpolate(&base, None)? != self.storage_public_key {
            return Err(StorageError::Crypto);
        }
        for (holder, share) in self.shares.iter().skip(self.threshold as usize) {
            if interpolate(&base, Some(*holder))? != *share {
                return Err(StorageError::Crypto);
            }
        }
        Ok(())
    }

    /// The commitment `f(x)·G` for an identifier `x` not in the plan,
    /// interpolated from the first `t` holders. Call [`Plan::validate`] first.
    pub(crate) fn interpolate_share(&self, holder: HolderId) -> Result<RistrettoPoint> {
        if holder == 0 || self.contains(holder) {
            return Err(StorageError::InvalidArgument);
        }
        interpolate(&self.base_points(), Some(holder))
    }

    fn base_points(&self) -> BTreeMap<HolderId, RistrettoPoint> {
        self.shares
            .iter()
            .take(self.threshold as usize)
            .map(|(h, p)| (*h, *p))
            .collect()
    }
}

/// `Σ λ_i(x)·P_i` over the holders in `points`, with `x = 0` for `None`.
///
/// `λ_i(x)` comes from `frost_core::compute_lagrange_coefficient`. The sum
/// uses the constant-time dalek multiscalar multiplication, because the
/// result is secret when the points are decryption partials.
pub(crate) fn interpolate(
    points: &BTreeMap<HolderId, RistrettoPoint>,
    x: Option<HolderId>,
) -> Result<RistrettoPoint> {
    let ids = points
        .keys()
        .map(|h| identifier(*h))
        .collect::<Result<BTreeSet<Identifier>>>()?;
    let x = x.map(identifier).transpose()?;
    let mut coefficients = Vec::with_capacity(points.len());
    for holder in points.keys() {
        coefficients.push(compute_lagrange_coefficient::<Ristretto255Sha512>(
            &ids,
            x,
            identifier(*holder)?,
        )?);
    }
    Ok(RistrettoPoint::multiscalar_mul(
        coefficients.iter(),
        points.values(),
    ))
}

/// The frost identifier of a holder. Zero is invalid.
pub(crate) fn identifier(holder: HolderId) -> Result<Identifier> {
    Identifier::try_from(holder).map_err(|_| StorageError::InvalidArgument)
}

/// The holder index of a frost identifier, if it is a nonzero `u16`.
pub(crate) fn holder_id(id: &Identifier) -> Option<HolderId> {
    let bytes = id.to_scalar().to_bytes();
    if bytes[2..].iter().any(|b| *b != 0) {
        return None;
    }
    let value = u16::from_le_bytes([bytes[0], bytes[1]]);
    (value != 0).then_some(value)
}

/// Decode a canonical Ristretto encoding. Rejects non-canonical encodings
/// and the identity.
pub(crate) fn decode_point(bytes: &[u8; 32]) -> Result<RistrettoPoint> {
    let point = CompressedRistretto(*bytes)
        .decompress()
        .ok_or(StorageError::InvalidArgument)?;
    if point == RistrettoPoint::identity() {
        return Err(StorageError::InvalidArgument);
    }
    Ok(point)
}

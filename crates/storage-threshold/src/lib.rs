//! Threshold storage key for Lemonade Nexus (design Part B, Phase 4).
//!
//! The storage secret `s` is shared among at most 50 holders with threshold
//! `t = ceil(0.65 × n)`. It is never assembled. A server wraps its data key
//! (DEK) to the storage public key `S = s·G` with ECIES. To unwrap, it sends
//! the ephemeral point `R` to the holders. Each holder returns `s_i·R` with a
//! Chaum-Pedersen (DLEQ) proof. The server verifies `t` partials and combines
//! them into `s·R = r·S`.
//!
//! The storage key is a separate key role with the domain-separation tag
//! [`DOMAIN`]. It never signs and never authorizes.
//!
//! # Library use
//!
//! | Step | Library call |
//! |---|---|
//! | Key generation | `frost_ristretto255::keys::dkg::part1..3` (audited) |
//! | Share refresh, holder removal | `frost_ristretto255::keys::refresh::refresh_dkg_*` (not audited) |
//! | Holder enrollment | `frost_ristretto255::keys::repairable::repair_share_step_*` (not audited) |
//! | Lagrange coefficients | `frost_core::compute_lagrange_coefficient` (audited with key generation) |
//! | DLEQ proof | `elastic_elgamal::LogEqualityProof` (not audited) |
//! | Point arithmetic | `curve25519-dalek` 4.1.3 |
//!
//! Code written in this crate (no upstream audit) is limited to the modules
//! [`plan`] (holder-plan checks and interpolation in the exponent),
//! [`unlock`] (transcript, partial wrapper, combiner), [`wrap`] (ECIES
//! encapsulation), the input checks in [`keys`], and the C ABI in [`ffi`].

pub mod ffi;
pub mod keys;
pub mod params;
pub mod plan;
pub mod unlock;
pub mod wrap;

use frost_ristretto255 as frost;

/// Domain-separation tag of the storage key role.
pub const DOMAIN: &[u8] = b"LEMONADE-NEXUS-STORAGE-V1";

/// A holder identifier: the 1-based index assigned by the holder plan.
pub type HolderId = u16;

/// Errors of the storage-threshold operations. Each maps to one C status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// Malformed input: zero or duplicate identifier, bad length, bad point.
    InvalidArgument,
    /// A library protocol step rejected its input, or a check failed.
    Crypto,
    /// Byte encoding or decoding failed.
    Serialization,
    /// Fewer than `t` distinct contributors (partials, helpers, or old holders).
    BelowThreshold,
    /// The new holder count needs a different threshold. Rotate the key.
    ThresholdChange,
    /// The holder count is outside the permitted range.
    HolderCount,
    /// A partial failed DLEQ verification, or its holder is not in the plan.
    Proof,
    /// The share does not belong to the plan (stale, removed, or another key).
    ShareMismatch,
}

impl StorageError {
    /// The C status code of this error.
    pub fn code(self) -> i32 {
        match self {
            StorageError::InvalidArgument => ffi::STORAGE_ERR_INVALID_ARGUMENT,
            StorageError::Crypto => ffi::STORAGE_ERR_CRYPTO,
            StorageError::Serialization => ffi::STORAGE_ERR_SERIALIZATION,
            StorageError::BelowThreshold => ffi::STORAGE_ERR_BELOW_THRESHOLD,
            StorageError::ThresholdChange => ffi::STORAGE_ERR_THRESHOLD_CHANGE,
            StorageError::HolderCount => ffi::STORAGE_ERR_HOLDER_COUNT,
            StorageError::Proof => ffi::STORAGE_ERR_PROOF,
            StorageError::ShareMismatch => ffi::STORAGE_ERR_SHARE_MISMATCH,
        }
    }
}

impl From<frost::Error> for StorageError {
    fn from(e: frost::Error) -> Self {
        match e {
            frost::Error::SerializationError | frost::Error::DeserializationError => {
                StorageError::Serialization
            }
            frost::Error::DuplicatedIdentifier
            | frost::Error::IncorrectNumberOfPackages
            | frost::Error::IncorrectNumberOfIdentifiers
            | frost::Error::IncorrectPackage
            | frost::Error::PackageNotFound
            | frost::Error::UnknownIdentifier => StorageError::InvalidArgument,
            _ => StorageError::Crypto,
        }
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, StorageError>;

#[cfg(test)]
mod tests;

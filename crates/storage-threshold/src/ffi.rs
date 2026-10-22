//! C ABI for the storage-threshold crate. See `include/storage_threshold.h`.
//!
//! Every entry point catches panics and returns `STORAGE_ERR_PANIC`.
//! Out-parameters are written only on success. Secret material stays behind
//! opaque handles, except where the protocol must move it: round 2 packages,
//! repair deltas and sigmas, serialized shares, and the ECIES shared point.
//! Rust-allocated buffers are zeroized when freed.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use zeroize::{Zeroize, Zeroizing};

use crate::keys::{self, DkgRound1, DkgRound2, PeerMessages, RefreshRound1, RefreshRound2, Share};
use crate::params::{threshold_for, MAX_HOLDERS};
use crate::plan::Plan;
use crate::unlock::{self, UnlockContext, PARTIAL_LEN};
use crate::{wrap, HolderId, Result, StorageError};

/// Success.
pub const STORAGE_OK: i32 = 0;
/// Null pointer, zero or duplicate identifier, bad length, or bad point.
pub const STORAGE_ERR_INVALID_ARGUMENT: i32 = -1;
/// A protocol step rejected its input, or a consistency check failed.
pub const STORAGE_ERR_CRYPTO: i32 = -2;
/// Byte encoding or decoding failed.
pub const STORAGE_ERR_SERIALIZATION: i32 = -3;
/// Fewer than `t` distinct contributors.
pub const STORAGE_ERR_BELOW_THRESHOLD: i32 = -4;
/// The new holder count needs another threshold. Rotate the key.
pub const STORAGE_ERR_THRESHOLD_CHANGE: i32 = -5;
/// Holder count outside 5..=50.
pub const STORAGE_ERR_HOLDER_COUNT: i32 = -6;
/// A partial failed verification, or its holder is not in the plan.
pub const STORAGE_ERR_PROOF: i32 = -7;
/// The share does not belong to the plan.
pub const STORAGE_ERR_SHARE_MISMATCH: i32 = -8;
/// A Rust panic was caught at the boundary.
pub const STORAGE_ERR_PANIC: i32 = -10;

/// Rust-allocated output buffer. Free only with `storage_buffer_free`.
#[repr(C)]
pub struct StorageBuffer {
    pub data: *mut u8,
    pub len: usize,
}

/// Caller-supplied (holder, bytes) input pair.
#[repr(C)]
pub struct StoragePeerBytes {
    pub identifier: u16,
    pub data: *const u8,
    pub len: usize,
}

/// Rust-allocated (holder, buffer) output pair. Free the whole array only
/// with `storage_peer_buffers_free`.
#[repr(C)]
pub struct StoragePeerBuffer {
    pub identifier: u16,
    pub buffer: StorageBuffer,
}

/// C name of the request binding fields.
pub type StorageUnlockContext = UnlockContext;
/// Opaque share handle.
pub type StorageShare = Share;
/// Opaque key generation state after part 1.
pub type StorageDkgRound1State = DkgRound1;
/// Opaque key generation state after part 2.
pub type StorageDkgRound2State = DkgRound2;
/// Opaque refresh state after part 1.
pub type StorageRefreshRound1State = RefreshRound1;
/// Opaque refresh state after part 2.
pub type StorageRefreshRound2State = RefreshRound2;

fn guard<F: FnOnce() -> Result<()>>(f: F) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => STORAGE_OK,
        Ok(Err(e)) => e.code(),
        Err(_) => STORAGE_ERR_PANIC,
    }
}

impl StorageBuffer {
    fn from_vec(v: Vec<u8>) -> Self {
        let boxed = v.into_boxed_slice();
        let len = boxed.len();
        let data = Box::into_raw(boxed) as *mut u8;
        StorageBuffer { data, len }
    }
}

unsafe fn free_buffer_contents(buffer: &mut StorageBuffer) {
    if buffer.data.is_null() {
        return;
    }
    let slice = std::ptr::slice_from_raw_parts_mut(buffer.data, buffer.len);
    (*slice).zeroize();
    drop(Box::from_raw(slice));
    buffer.data = std::ptr::null_mut();
    buffer.len = 0;
}

fn non_null<T>(p: *const T) -> Result<()> {
    if p.is_null() {
        Err(StorageError::InvalidArgument)
    } else {
        Ok(())
    }
}

unsafe fn bytes<'a>(data: *const u8, len: usize) -> Result<&'a [u8]> {
    if data.is_null() || len == 0 {
        return Err(StorageError::InvalidArgument);
    }
    Ok(std::slice::from_raw_parts(data, len))
}

unsafe fn array32<'a>(data: *const u8) -> Result<&'a [u8; 32]> {
    non_null(data)?;
    Ok(&*(data as *const [u8; 32]))
}

unsafe fn plan_from(data: *const u8, len: usize) -> Result<Plan> {
    Plan::deserialize(bytes(data, len)?)
}

/// Parse a caller list into a map keyed by holder. Rejects identifier 0,
/// null data, duplicates, and more than `MAX_HOLDERS` entries.
unsafe fn peer_map<'a>(ptr: *const StoragePeerBytes, count: usize) -> Result<PeerMessages<'a>> {
    if count > usize::from(MAX_HOLDERS) || (count > 0 && ptr.is_null()) {
        return Err(StorageError::InvalidArgument);
    }
    let mut out = BTreeMap::new();
    for i in 0..count {
        let entry = &*ptr.add(i);
        if entry.identifier == 0 {
            return Err(StorageError::InvalidArgument);
        }
        let data = bytes(entry.data, entry.len)?;
        if out.insert(entry.identifier, data).is_some() {
            return Err(StorageError::InvalidArgument);
        }
    }
    Ok(out)
}

/// Move per-recipient messages into a heap array for the caller.
fn peer_buffers<B: AsRef<[u8]>>(entries: BTreeMap<HolderId, B>) -> (*mut StoragePeerBuffer, usize) {
    let boxed: Box<[StoragePeerBuffer]> = entries
        .into_iter()
        .map(|(identifier, b)| StoragePeerBuffer {
            identifier,
            buffer: StorageBuffer::from_vec(b.as_ref().to_vec()),
        })
        .collect();
    let count = boxed.len();
    (Box::into_raw(boxed) as *mut StoragePeerBuffer, count)
}

unsafe fn take<T>(state: *mut T) -> Result<Box<T>> {
    non_null(state)?;
    Ok(Box::from_raw(state))
}

// --- Parameters -------------------------------------------------------------

/// Write `ceil(0.65 × holder_count)` for `1 ≤ holder_count ≤ 50`.
///
/// # Safety
/// `out_threshold` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn storage_threshold_for(holder_count: u16, out_threshold: *mut u16) -> i32 {
    guard(|| {
        non_null(out_threshold)?;
        *out_threshold = threshold_for(holder_count).ok_or(StorageError::HolderCount)?;
        Ok(())
    })
}

// --- Key generation ---------------------------------------------------------

/// Key generation part 1.
///
/// # Safety
/// Out pointers must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn storage_dkg_part1(
    identifier: u16,
    holder_count: u16,
    out_state: *mut *mut StorageDkgRound1State,
    out_package: *mut StorageBuffer,
) -> i32 {
    guard(|| {
        non_null(out_state)?;
        non_null(out_package)?;
        let (state, package) = keys::dkg_part1(identifier, holder_count)?;
        *out_state = Box::into_raw(Box::new(state));
        *out_package = StorageBuffer::from_vec(package);
        Ok(())
    })
}

/// Key generation part 2. Consumes `state` on every return path.
///
/// # Safety
/// `round1` must point to `round1_count` valid entries. Out pointers must be
/// valid and writable.
#[no_mangle]
pub unsafe extern "C" fn storage_dkg_part2(
    state: *mut StorageDkgRound1State,
    round1: *const StoragePeerBytes,
    round1_count: usize,
    out_state: *mut *mut StorageDkgRound2State,
    out_packages: *mut *mut StoragePeerBuffer,
    out_count: *mut usize,
) -> i32 {
    guard(|| {
        let state = take(state)?;
        non_null(out_state)?;
        non_null(out_packages)?;
        non_null(out_count)?;
        let r1 = peer_map(round1, round1_count)?;
        let (next, outgoing) = keys::dkg_part2(*state, &r1)?;
        let (array, count) = peer_buffers(outgoing);
        *out_state = Box::into_raw(Box::new(next));
        *out_packages = array;
        *out_count = count;
        Ok(())
    })
}

/// Key generation part 3. Consumes `state` on every return path.
///
/// # Safety
/// Lists must point to valid entries. `out_storage_public_key` must point to
/// 32 writable bytes. Out pointers must be valid and writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn storage_dkg_part3(
    state: *mut StorageDkgRound2State,
    round1: *const StoragePeerBytes,
    round1_count: usize,
    round2: *const StoragePeerBytes,
    round2_count: usize,
    out_share: *mut *mut StorageShare,
    out_storage_public_key: *mut u8,
    out_plan: *mut StorageBuffer,
) -> i32 {
    guard(|| {
        let state = take(state)?;
        non_null(out_share)?;
        non_null(out_storage_public_key)?;
        non_null(out_plan)?;
        let r1 = peer_map(round1, round1_count)?;
        let r2 = peer_map(round2, round2_count)?;
        let (share, plan) = keys::dkg_part3(*state, &r1, &r2)?;
        let plan_bytes = plan.serialize()?;
        let key = plan.storage_public_key_bytes();
        *out_share = Box::into_raw(Box::new(share));
        std::ptr::copy_nonoverlapping(key.as_ptr(), out_storage_public_key, 32);
        *out_plan = StorageBuffer::from_vec(plan_bytes);
        Ok(())
    })
}

// --- Share refresh ----------------------------------------------------------

/// Refresh part 1 for the holder of `current` among `new_holder_count`
/// holders.
///
/// # Safety
/// `current` must be a live handle. Out pointers must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn storage_refresh_part1(
    current: *const StorageShare,
    new_holder_count: u16,
    out_state: *mut *mut StorageRefreshRound1State,
    out_package: *mut StorageBuffer,
) -> i32 {
    guard(|| {
        non_null(current)?;
        non_null(out_state)?;
        non_null(out_package)?;
        let (state, package) = keys::refresh_part1(&*current, new_holder_count)?;
        *out_state = Box::into_raw(Box::new(state));
        *out_package = StorageBuffer::from_vec(package);
        Ok(())
    })
}

/// Refresh part 2. Consumes `state` on every return path.
///
/// # Safety
/// `round1` must point to `round1_count` valid entries. Out pointers must be
/// valid and writable.
#[no_mangle]
pub unsafe extern "C" fn storage_refresh_part2(
    state: *mut StorageRefreshRound1State,
    round1: *const StoragePeerBytes,
    round1_count: usize,
    out_state: *mut *mut StorageRefreshRound2State,
    out_packages: *mut *mut StoragePeerBuffer,
    out_count: *mut usize,
) -> i32 {
    guard(|| {
        let state = take(state)?;
        non_null(out_state)?;
        non_null(out_packages)?;
        non_null(out_count)?;
        let r1 = peer_map(round1, round1_count)?;
        let (next, outgoing) = keys::refresh_part2(*state, &r1)?;
        let (array, count) = peer_buffers(outgoing);
        *out_state = Box::into_raw(Box::new(next));
        *out_packages = array;
        *out_count = count;
        Ok(())
    })
}

/// Refresh part 3. Consumes `state` on every return path. Does not consume
/// `current`.
///
/// # Safety
/// Lists must point to valid entries. `current` must be a live handle.
/// `old_plan` must point to `old_plan_len` readable bytes. Out pointers must
/// be valid and writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn storage_refresh_part3(
    state: *mut StorageRefreshRound2State,
    round1: *const StoragePeerBytes,
    round1_count: usize,
    round2: *const StoragePeerBytes,
    round2_count: usize,
    current: *const StorageShare,
    old_plan: *const u8,
    old_plan_len: usize,
    out_share: *mut *mut StorageShare,
    out_plan: *mut StorageBuffer,
) -> i32 {
    guard(|| {
        let state = take(state)?;
        non_null(current)?;
        non_null(out_share)?;
        non_null(out_plan)?;
        let r1 = peer_map(round1, round1_count)?;
        let r2 = peer_map(round2, round2_count)?;
        let old = plan_from(old_plan, old_plan_len)?;
        let (share, plan) = keys::refresh_part3(*state, &r1, &r2, &*current, &old)?;
        let plan_bytes = plan.serialize()?;
        *out_share = Box::into_raw(Box::new(share));
        *out_plan = StorageBuffer::from_vec(plan_bytes);
        Ok(())
    })
}

// --- Holder enrollment ------------------------------------------------------

/// Enrollment step 1, run by each helper.
///
/// # Safety
/// `helper` must be a live handle. `plan` must point to `plan_len` readable
/// bytes. `helpers` must point to `helper_count` identifiers. Out pointers
/// must be valid and writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn storage_repair_part1(
    helper: *const StorageShare,
    plan: *const u8,
    plan_len: usize,
    helpers: *const u16,
    helper_count: usize,
    new_identifier: u16,
    out_deltas: *mut *mut StoragePeerBuffer,
    out_count: *mut usize,
) -> i32 {
    guard(|| {
        non_null(helper)?;
        non_null(helpers)?;
        non_null(out_deltas)?;
        non_null(out_count)?;
        if helper_count == 0 || helper_count > usize::from(MAX_HOLDERS) {
            return Err(StorageError::InvalidArgument);
        }
        let plan = plan_from(plan, plan_len)?;
        let list = std::slice::from_raw_parts(helpers, helper_count);
        let deltas = keys::repair_part1(&*helper, &plan, list, new_identifier)?;
        let (array, count) = peer_buffers(deltas);
        *out_deltas = array;
        *out_count = count;
        Ok(())
    })
}

/// Enrollment step 2, run by each helper.
///
/// # Safety
/// `helper` must be a live handle. `deltas` must point to `delta_count`
/// valid entries. `out_sigma` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn storage_repair_part2(
    helper: *const StorageShare,
    deltas: *const StoragePeerBytes,
    delta_count: usize,
    out_sigma: *mut u8,
) -> i32 {
    guard(|| {
        non_null(helper)?;
        non_null(out_sigma)?;
        let map = peer_map(deltas, delta_count)?;
        let sigma = keys::repair_part2(&*helper, &map)?;
        std::ptr::copy_nonoverlapping(sigma.as_ptr(), out_sigma, 32);
        Ok(())
    })
}

/// Enrollment step 3, run by the new holder.
///
/// # Safety
/// `plan` must point to `plan_len` readable bytes. `sigmas` must point to
/// `sigma_count` valid entries. `out_share` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn storage_repair_part3(
    plan: *const u8,
    plan_len: usize,
    new_identifier: u16,
    sigmas: *const StoragePeerBytes,
    sigma_count: usize,
    out_share: *mut *mut StorageShare,
) -> i32 {
    guard(|| {
        non_null(out_share)?;
        let plan = plan_from(plan, plan_len)?;
        let map = peer_map(sigmas, sigma_count)?;
        let share = keys::repair_part3(&plan, new_identifier, &map)?;
        *out_share = Box::into_raw(Box::new(share));
        Ok(())
    })
}

// --- Partials, combination, encapsulation -----------------------------------

/// Holder side: write the 96-byte partial for `ephemeral_point`.
///
/// # Safety
/// `share` must be a live handle. `plan` must point to `plan_len` readable
/// bytes. `context` must be valid. `ephemeral_point` must point to 32
/// readable bytes and `out_partial` to 96 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn storage_partial_create(
    share: *const StorageShare,
    plan: *const u8,
    plan_len: usize,
    context: *const StorageUnlockContext,
    ephemeral_point: *const u8,
    out_partial: *mut u8,
) -> i32 {
    guard(|| {
        non_null(share)?;
        non_null(context)?;
        non_null(out_partial)?;
        let plan = plan_from(plan, plan_len)?;
        let partial = unlock::create_partial(&*share, &plan, &*context, array32(ephemeral_point)?)?;
        std::ptr::copy_nonoverlapping(partial.as_ptr(), out_partial, PARTIAL_LEN);
        Ok(())
    })
}

/// Requester side: verify one partial from `holder`.
///
/// # Safety
/// `plan` must point to `plan_len` readable bytes. `context` must be valid.
/// `ephemeral_point` must point to 32 readable bytes and `partial` to
/// `partial_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn storage_partial_verify(
    plan: *const u8,
    plan_len: usize,
    context: *const StorageUnlockContext,
    ephemeral_point: *const u8,
    holder: u16,
    partial: *const u8,
    partial_len: usize,
) -> i32 {
    guard(|| {
        non_null(context)?;
        let plan = plan_from(plan, plan_len)?;
        let partial = bytes(partial, partial_len)?;
        unlock::verify_partial(&plan, &*context, array32(ephemeral_point)?, holder, partial)?;
        Ok(())
    })
}

/// Requester side: verify every partial and write the compressed shared
/// point `s·R` (secret) to `out_shared_point`.
///
/// # Safety
/// `plan` must point to `plan_len` readable bytes. `context` must be valid.
/// `ephemeral_point` must point to 32 readable bytes. `partials` must point
/// to `partial_count` valid entries. `out_shared_point` must point to 32
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn storage_combine(
    plan: *const u8,
    plan_len: usize,
    context: *const StorageUnlockContext,
    ephemeral_point: *const u8,
    partials: *const StoragePeerBytes,
    partial_count: usize,
    out_shared_point: *mut u8,
) -> i32 {
    guard(|| {
        non_null(context)?;
        non_null(out_shared_point)?;
        let plan = plan_from(plan, plan_len)?;
        let map = peer_map(partials, partial_count)?;
        let shared = unlock::combine(&plan, &*context, array32(ephemeral_point)?, &map)?;
        std::ptr::copy_nonoverlapping(shared.as_ptr(), out_shared_point, 32);
        Ok(())
    })
}

/// Write a fresh `R = r·G` and the compressed shared point `r·S` (secret).
///
/// # Safety
/// `storage_public_key` must point to 32 readable bytes. The out pointers
/// must each point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn storage_encapsulate(
    storage_public_key: *const u8,
    out_ephemeral_point: *mut u8,
    out_shared_point: *mut u8,
) -> i32 {
    guard(|| {
        non_null(out_ephemeral_point)?;
        non_null(out_shared_point)?;
        let (ephemeral, shared) = wrap::encapsulate(array32(storage_public_key)?)?;
        std::ptr::copy_nonoverlapping(ephemeral.as_ptr(), out_ephemeral_point, 32);
        std::ptr::copy_nonoverlapping(shared.as_ptr(), out_shared_point, 32);
        Ok(())
    })
}

// --- Plans ------------------------------------------------------------------

/// Parse and fully check a plan: size, threshold, identifiers, and that
/// every commitment lies on one polynomial of degree `t − 1` with constant
/// term `S`. Writes the holder count, threshold, and `S`.
///
/// # Safety
/// `plan` must point to `plan_len` readable bytes. Out pointers must be
/// valid; `out_storage_public_key` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn storage_plan_validate(
    plan: *const u8,
    plan_len: usize,
    out_holder_count: *mut u16,
    out_threshold: *mut u16,
    out_storage_public_key: *mut u8,
) -> i32 {
    guard(|| {
        non_null(out_holder_count)?;
        non_null(out_threshold)?;
        non_null(out_storage_public_key)?;
        let plan = plan_from(plan, plan_len)?;
        plan.validate()?;
        let key = plan.storage_public_key_bytes();
        *out_holder_count = plan.holder_count();
        *out_threshold = plan.threshold();
        std::ptr::copy_nonoverlapping(key.as_ptr(), out_storage_public_key, 32);
        Ok(())
    })
}

/// Write the plan's holder identifiers in ascending order. `capacity` must
/// be at least the holder count; 50 always suffices.
///
/// # Safety
/// `plan` must point to `plan_len` readable bytes. `out_holders` must point
/// to `capacity` writable identifiers. `out_count` must be writable.
#[no_mangle]
pub unsafe extern "C" fn storage_plan_holders(
    plan: *const u8,
    plan_len: usize,
    out_holders: *mut u16,
    capacity: usize,
    out_count: *mut usize,
) -> i32 {
    guard(|| {
        non_null(out_holders)?;
        non_null(out_count)?;
        let plan = plan_from(plan, plan_len)?;
        let ids: Vec<HolderId> = plan.holder_ids().collect();
        if ids.len() > capacity {
            return Err(StorageError::InvalidArgument);
        }
        std::ptr::copy_nonoverlapping(ids.as_ptr(), out_holders, ids.len());
        *out_count = ids.len();
        Ok(())
    })
}

/// Write the public share commitment `Y_i` of `holder`.
///
/// # Safety
/// `plan` must point to `plan_len` readable bytes. `out_commitment` must
/// point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn storage_plan_commitment(
    plan: *const u8,
    plan_len: usize,
    holder: u16,
    out_commitment: *mut u8,
) -> i32 {
    guard(|| {
        non_null(out_commitment)?;
        let plan = plan_from(plan, plan_len)?;
        let point = plan
            .verifying_share(holder)
            .ok_or(StorageError::InvalidArgument)?;
        let encoded = point.compress().to_bytes();
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), out_commitment, 32);
        Ok(())
    })
}

// --- Shares -----------------------------------------------------------------

/// Write the holder identifier, threshold, and `S` of a share.
///
/// # Safety
/// `share` must be a live handle. Out pointers must be valid;
/// `out_storage_public_key` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn storage_share_info(
    share: *const StorageShare,
    out_identifier: *mut u16,
    out_threshold: *mut u16,
    out_storage_public_key: *mut u8,
) -> i32 {
    guard(|| {
        non_null(share)?;
        non_null(out_identifier)?;
        non_null(out_threshold)?;
        non_null(out_storage_public_key)?;
        let share = &*share;
        let key = share.storage_public_key().compress().to_bytes();
        *out_identifier = share.holder();
        *out_threshold = share.threshold();
        std::ptr::copy_nonoverlapping(key.as_ptr(), out_storage_public_key, 32);
        Ok(())
    })
}

/// Serialize a share for sealed storage. The buffer holds the secret.
///
/// # Safety
/// `share` must be a live handle. `out_share` must be writable.
#[no_mangle]
pub unsafe extern "C" fn storage_share_serialize(
    share: *const StorageShare,
    out_share: *mut StorageBuffer,
) -> i32 {
    guard(|| {
        non_null(share)?;
        non_null(out_share)?;
        let serialized: Zeroizing<Vec<u8>> = (*share).serialize()?;
        *out_share = StorageBuffer::from_vec(serialized.to_vec());
        Ok(())
    })
}

/// Parse a share written by `storage_share_serialize`.
///
/// # Safety
/// `data` must point to `len` readable bytes. `out_share` must be writable.
#[no_mangle]
pub unsafe extern "C" fn storage_share_deserialize(
    data: *const u8,
    len: usize,
    out_share: *mut *mut StorageShare,
) -> i32 {
    guard(|| {
        non_null(out_share)?;
        let share = Share::deserialize(bytes(data, len)?)?;
        *out_share = Box::into_raw(Box::new(share));
        Ok(())
    })
}

// --- Release ----------------------------------------------------------------

/// Zeroize and free the bytes of a buffer, then null its fields. NULL is a
/// no-op.
///
/// # Safety
/// `buffer` must be null or point to a buffer written by this library.
#[no_mangle]
pub unsafe extern "C" fn storage_buffer_free(buffer: *mut StorageBuffer) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(b) = buffer.as_mut() {
            free_buffer_contents(b);
        }
    }));
}

/// Zeroize and free an array of peer buffers. Pass the exact pointer and
/// count the call returned. NULL is a no-op.
///
/// # Safety
/// `buffers` must be null or an array returned by this library with `count`
/// entries.
#[no_mangle]
pub unsafe extern "C" fn storage_peer_buffers_free(buffers: *mut StoragePeerBuffer, count: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if buffers.is_null() {
            return;
        }
        let slice = std::ptr::slice_from_raw_parts_mut(buffers, count);
        for entry in (*slice).iter_mut() {
            free_buffer_contents(&mut entry.buffer);
        }
        drop(Box::from_raw(slice));
    }));
}

macro_rules! handle_free {
    ($(#[$doc:meta])* $name:ident, $ty:ty) => {
        $(#[$doc])*
        ///
        /// # Safety
        /// The pointer must be null or a live handle from this library.
        #[no_mangle]
        pub unsafe extern "C" fn $name(handle: *mut $ty) {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                if !handle.is_null() {
                    drop(Box::from_raw(handle));
                }
            }));
        }
    };
}

handle_free!(
    /// Free an unused key generation part 1 state and zeroize it.
    storage_dkg_round1_state_free,
    StorageDkgRound1State
);
handle_free!(
    /// Free an unused key generation part 2 state and zeroize it.
    storage_dkg_round2_state_free,
    StorageDkgRound2State
);
handle_free!(
    /// Free an unused refresh part 1 state and zeroize it.
    storage_refresh_round1_state_free,
    StorageRefreshRound1State
);
handle_free!(
    /// Free an unused refresh part 2 state and zeroize it.
    storage_refresh_round2_state_free,
    StorageRefreshRound2State
);
handle_free!(
    /// Free a share and zeroize it.
    storage_share_free,
    StorageShare
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::{null, null_mut};

    unsafe fn take_vec(b: &mut StorageBuffer) -> Vec<u8> {
        let v = std::slice::from_raw_parts(b.data, b.len).to_vec();
        storage_buffer_free(b);
        v
    }

    fn peers(map: &BTreeMap<u16, Vec<u8>>, skip: u16) -> Vec<StoragePeerBytes> {
        map.iter()
            .filter(|(h, _)| **h != skip)
            .map(|(h, b)| StoragePeerBytes {
                identifier: *h,
                data: b.as_ptr(),
                len: b.len(),
            })
            .collect()
    }

    struct Holder {
        share: *mut StorageShare,
    }

    unsafe fn ffi_dkg(n: u16) -> (Vec<Holder>, Vec<u8>, [u8; 32]) {
        let mut states1 = Vec::new();
        let mut packages = BTreeMap::new();
        for id in 1..=n {
            let mut state = null_mut();
            let mut buf = StorageBuffer {
                data: null_mut(),
                len: 0,
            };
            assert_eq!(storage_dkg_part1(id, n, &mut state, &mut buf), STORAGE_OK);
            packages.insert(id, take_vec(&mut buf));
            states1.push(state);
        }
        let mut states2 = Vec::new();
        let mut inbox: BTreeMap<u16, BTreeMap<u16, Vec<u8>>> = BTreeMap::new();
        for (i, state) in states1.into_iter().enumerate() {
            let id = i as u16 + 1;
            let input = peers(&packages, id);
            let mut next = null_mut();
            let mut out = null_mut();
            let mut count = 0;
            assert_eq!(
                storage_dkg_part2(
                    state,
                    input.as_ptr(),
                    input.len(),
                    &mut next,
                    &mut out,
                    &mut count
                ),
                STORAGE_OK
            );
            for e in std::slice::from_raw_parts(out, count) {
                let bytes = std::slice::from_raw_parts(e.buffer.data, e.buffer.len).to_vec();
                inbox.entry(e.identifier).or_default().insert(id, bytes);
            }
            storage_peer_buffers_free(out, count);
            states2.push(next);
        }
        let mut holders = Vec::new();
        let mut plan = Vec::new();
        let mut key = [0u8; 32];
        for (i, state) in states2.into_iter().enumerate() {
            let id = i as u16 + 1;
            let r1 = peers(&packages, id);
            let r2 = peers(&inbox[&id], 0);
            let mut share = null_mut();
            let mut buf = StorageBuffer {
                data: null_mut(),
                len: 0,
            };
            assert_eq!(
                storage_dkg_part3(
                    state,
                    r1.as_ptr(),
                    r1.len(),
                    r2.as_ptr(),
                    r2.len(),
                    &mut share,
                    key.as_mut_ptr(),
                    &mut buf
                ),
                STORAGE_OK
            );
            plan = take_vec(&mut buf);
            holders.push(Holder { share });
        }
        (holders, plan, key)
    }

    #[test]
    fn ffi_end_to_end() {
        unsafe {
            let (holders, plan, key) = ffi_dkg(5);
            let mut count = 0u16;
            let mut t = 0u16;
            let mut key2 = [0u8; 32];
            assert_eq!(
                storage_plan_validate(
                    plan.as_ptr(),
                    plan.len(),
                    &mut count,
                    &mut t,
                    key2.as_mut_ptr()
                ),
                STORAGE_OK
            );
            assert_eq!((count, t), (5, 4));
            assert_eq!(key, key2);

            let mut ephemeral = [0u8; 32];
            let mut shared = [0u8; 32];
            assert_eq!(
                storage_encapsulate(key.as_ptr(), ephemeral.as_mut_ptr(), shared.as_mut_ptr()),
                STORAGE_OK
            );
            let ctx = UnlockContext {
                network_id: [1; 32],
                epoch: 3,
                plan_digest: [2; 32],
                request_nonce: [3; 32],
            };
            let mut partials = BTreeMap::new();
            for (i, h) in holders.iter().enumerate().take(4) {
                let mut p = [0u8; PARTIAL_LEN];
                assert_eq!(
                    storage_partial_create(
                        h.share,
                        plan.as_ptr(),
                        plan.len(),
                        &ctx,
                        ephemeral.as_ptr(),
                        p.as_mut_ptr()
                    ),
                    STORAGE_OK
                );
                assert_eq!(
                    storage_partial_verify(
                        plan.as_ptr(),
                        plan.len(),
                        &ctx,
                        ephemeral.as_ptr(),
                        i as u16 + 1,
                        p.as_ptr(),
                        p.len()
                    ),
                    STORAGE_OK
                );
                partials.insert(i as u16 + 1, p.to_vec());
            }
            let list = peers(&partials, 0);
            let mut combined = [0u8; 32];
            assert_eq!(
                storage_combine(
                    plan.as_ptr(),
                    plan.len(),
                    &ctx,
                    ephemeral.as_ptr(),
                    list.as_ptr(),
                    list.len(),
                    combined.as_mut_ptr()
                ),
                STORAGE_OK
            );
            assert_eq!(combined, shared);
            assert_eq!(
                storage_combine(
                    plan.as_ptr(),
                    plan.len(),
                    &ctx,
                    ephemeral.as_ptr(),
                    list.as_ptr(),
                    3,
                    combined.as_mut_ptr()
                ),
                STORAGE_ERR_BELOW_THRESHOLD
            );

            // Share serialization round trip.
            let mut buf = StorageBuffer {
                data: null_mut(),
                len: 0,
            };
            assert_eq!(
                storage_share_serialize(holders[0].share, &mut buf),
                STORAGE_OK
            );
            let mut restored = null_mut();
            assert_eq!(
                storage_share_deserialize(buf.data, buf.len, &mut restored),
                STORAGE_OK
            );
            storage_buffer_free(&mut buf);
            assert!(buf.data.is_null());
            let (mut id, mut th, mut k) = (0u16, 0u16, [0u8; 32]);
            assert_eq!(
                storage_share_info(restored, &mut id, &mut th, k.as_mut_ptr()),
                STORAGE_OK
            );
            assert_eq!((id, th, k), (1, 4, key));
            storage_share_free(restored);

            for h in holders {
                storage_share_free(h.share);
            }
        }
    }

    #[test]
    fn ffi_rejects_bad_arguments() {
        unsafe {
            let mut t = 0u16;
            assert_eq!(storage_threshold_for(0, &mut t), STORAGE_ERR_HOLDER_COUNT);
            assert_eq!(storage_threshold_for(51, &mut t), STORAGE_ERR_HOLDER_COUNT);
            assert_eq!(storage_threshold_for(20, &mut t), STORAGE_OK);
            assert_eq!(t, 13);
            assert_eq!(
                storage_threshold_for(20, null_mut()),
                STORAGE_ERR_INVALID_ARGUMENT
            );

            let mut state = null_mut();
            let mut buf = StorageBuffer {
                data: null_mut(),
                len: 0,
            };
            assert_eq!(
                storage_dkg_part1(1, 4, &mut state, &mut buf),
                STORAGE_ERR_HOLDER_COUNT
            );
            assert_eq!(
                storage_dkg_part1(0, 5, &mut state, &mut buf),
                STORAGE_ERR_INVALID_ARGUMENT
            );
            assert!(state.is_null() && buf.data.is_null());

            // Duplicate and zero identifiers in a peer list.
            assert_eq!(storage_dkg_part1(1, 5, &mut state, &mut buf), STORAGE_OK);
            let package = take_vec(&mut buf);
            let dup = [
                StoragePeerBytes {
                    identifier: 2,
                    data: package.as_ptr(),
                    len: package.len(),
                },
                StoragePeerBytes {
                    identifier: 2,
                    data: package.as_ptr(),
                    len: package.len(),
                },
            ];
            let (mut next, mut out, mut count) = (null_mut(), null_mut(), 0usize);
            assert_eq!(
                storage_dkg_part2(
                    state,
                    dup.as_ptr(),
                    dup.len(),
                    &mut next,
                    &mut out,
                    &mut count
                ),
                STORAGE_ERR_INVALID_ARGUMENT
            );
            assert!(next.is_null());

            // Null plan and null context.
            let ctx = UnlockContext {
                network_id: [0; 32],
                epoch: 0,
                plan_digest: [0; 32],
                request_nonce: [0; 32],
            };
            let r = [0u8; 32];
            let p = [0u8; PARTIAL_LEN];
            assert_eq!(
                storage_partial_verify(null(), 0, &ctx, r.as_ptr(), 1, p.as_ptr(), p.len()),
                STORAGE_ERR_INVALID_ARGUMENT
            );
            assert_eq!(
                storage_partial_verify(
                    p.as_ptr(),
                    p.len(),
                    null(),
                    r.as_ptr(),
                    1,
                    p.as_ptr(),
                    p.len()
                ),
                STORAGE_ERR_INVALID_ARGUMENT
            );

            // Free functions accept NULL.
            storage_buffer_free(null_mut());
            storage_peer_buffers_free(null_mut(), 0);
            storage_share_free(null_mut());
            storage_dkg_round1_state_free(null_mut());
            storage_dkg_round2_state_free(null_mut());
            storage_refresh_round1_state_free(null_mut());
            storage_refresh_round2_state_free(null_mut());
        }
    }
}

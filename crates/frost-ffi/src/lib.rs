//! C FFI for FROST(Ed25519, SHA-512) threshold signatures.
//!
//! Wraps frost-ed25519 2.2.0 (Zcash Foundation) for per-epoch dealerless DKG
//! and threshold signing. Secret material lives only behind opaque handles in
//! Rust memory and is zeroized when a handle is freed or consumed. Signing
//! nonces are single-use: `frost_sign` consumes the nonce handle, so a nonce
//! cannot sign twice through this API. All randomness comes from `OsRng`; a
//! caller-supplied RNG would be a nonce-reuse footgun.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use frost_ed25519 as frost;

use frost::keys::dkg;
use frost::Identifier;
use rand_core::OsRng;
use zeroize::Zeroize;

/// Success.
pub const FROST_OK: i32 = 0;
/// Null pointer, zero identifier, or duplicate identifier.
pub const FROST_ERR_INVALID_ARGUMENT: i32 = -1;
/// The FROST protocol rejected the operation (bad share, wrong counts, ...).
pub const FROST_ERR_CRYPTO: i32 = -2;
/// Byte encoding or decoding failed.
pub const FROST_ERR_SERIALIZATION: i32 = -3;
/// A Rust panic was caught at the FFI boundary.
pub const FROST_ERR_PANIC: i32 = -10;

/// Rust-allocated output buffer. Free only with `frost_buffer_free`.
#[repr(C)]
pub struct FrostBuffer {
    pub data: *mut u8,
    pub len: usize,
}

/// Caller-supplied (identifier, serialized package) input pair.
#[repr(C)]
pub struct FrostPeerBytes {
    pub identifier: u16,
    pub data: *const u8,
    pub len: usize,
}

/// Rust-allocated (identifier, buffer) output pair.
/// Free the whole array only with `frost_peer_buffers_free`.
#[repr(C)]
pub struct FrostPeerBuffer {
    pub identifier: u16,
    pub buffer: FrostBuffer,
}

/// Opaque DKG round 1 secret state. The secret never crosses the FFI.
pub struct FrostDkgRound1State {
    identifier: u16,
    secret: dkg::round1::SecretPackage,
}

impl Drop for FrostDkgRound1State {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Opaque DKG round 2 secret state. The secret never crosses the FFI.
pub struct FrostDkgRound2State {
    identifier: u16,
    secret: dkg::round2::SecretPackage,
}

impl Drop for FrostDkgRound2State {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Opaque key share. The signing share never crosses the FFI.
pub struct FrostKeyPackage {
    identifier: u16,
    inner: frost::keys::KeyPackage,
}

impl Drop for FrostKeyPackage {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// Opaque single-use signing nonces. Never persisted, never serialized.
pub struct FrostSigningNonces {
    inner: frost::round1::SigningNonces,
}

impl Drop for FrostSigningNonces {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// Catch panics at the FFI boundary. Unwinding into C is undefined behavior.
fn ffi_guard<F: FnOnce() -> i32>(f: F) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(FROST_ERR_PANIC)
}

fn map_err(e: frost::Error) -> i32 {
    match e {
        frost::Error::SerializationError | frost::Error::DeserializationError => {
            FROST_ERR_SERIALIZATION
        }
        _ => FROST_ERR_CRYPTO,
    }
}

impl FrostBuffer {
    fn from_vec(v: Vec<u8>) -> Self {
        let boxed = v.into_boxed_slice();
        let len = boxed.len();
        let data = Box::into_raw(boxed) as *mut u8;
        FrostBuffer { data, len }
    }
}

/// Zeroize and free the bytes owned by a buffer, then null it out.
unsafe fn free_buffer_contents(buffer: &mut FrostBuffer) {
    if buffer.data.is_null() {
        return;
    }
    let slice = std::ptr::slice_from_raw_parts_mut(buffer.data, buffer.len);
    (*slice).zeroize();
    drop(Box::from_raw(slice));
    buffer.data = std::ptr::null_mut();
    buffer.len = 0;
}

/// Peer packages keyed by identifier, plus the reverse u16 map.
type PeerMaps<T> = (BTreeMap<Identifier, T>, BTreeMap<Identifier, u16>);

/// Parse a caller-supplied peer list into a package map plus a reverse
/// identifier map. Rejects identifier 0, null data, and duplicates.
unsafe fn parse_peer_list<T>(
    ptr: *const FrostPeerBytes,
    count: usize,
    parse: impl Fn(&[u8]) -> Result<T, i32>,
) -> Result<PeerMaps<T>, i32> {
    if count > 0 && ptr.is_null() {
        return Err(FROST_ERR_INVALID_ARGUMENT);
    }
    let mut packages = BTreeMap::new();
    let mut ids = BTreeMap::new();
    for i in 0..count {
        let entry = &*ptr.add(i);
        if entry.identifier == 0 || entry.data.is_null() {
            return Err(FROST_ERR_INVALID_ARGUMENT);
        }
        let id =
            Identifier::try_from(entry.identifier).map_err(|_| FROST_ERR_INVALID_ARGUMENT)?;
        if ids.insert(id, entry.identifier).is_some() {
            return Err(FROST_ERR_INVALID_ARGUMENT);
        }
        let bytes = std::slice::from_raw_parts(entry.data, entry.len);
        packages.insert(id, parse(bytes)?);
    }
    Ok((packages, ids))
}

/// Move serialized per-recipient packages into a heap array for the caller.
fn peer_buffers_into_raw(entries: Vec<(u16, Vec<u8>)>) -> (*mut FrostPeerBuffer, usize) {
    let boxed: Box<[FrostPeerBuffer]> = entries
        .into_iter()
        .map(|(identifier, bytes)| FrostPeerBuffer {
            identifier,
            buffer: FrostBuffer::from_vec(bytes),
        })
        .collect();
    let count = boxed.len();
    (Box::into_raw(boxed) as *mut FrostPeerBuffer, count)
}

/// Run DKG part 1 for one participant.
///
/// On success, writes an opaque round 1 state and the serialized round 1
/// package to broadcast to every other participant.
///
/// # Safety
/// `out_state` and `out_round1_package` must be valid writable pointers.
#[no_mangle]
pub unsafe extern "C" fn frost_dkg_part1(
    identifier: u16,
    max_signers: u16,
    min_signers: u16,
    out_state: *mut *mut FrostDkgRound1State,
    out_round1_package: *mut FrostBuffer,
) -> i32 {
    ffi_guard(|| {
        if identifier == 0 || out_state.is_null() || out_round1_package.is_null() {
            return FROST_ERR_INVALID_ARGUMENT;
        }
        let id = match Identifier::try_from(identifier) {
            Ok(id) => id,
            Err(_) => return FROST_ERR_INVALID_ARGUMENT,
        };
        let (secret, package) = match dkg::part1(id, max_signers, min_signers, OsRng) {
            Ok(r) => r,
            Err(e) => return map_err(e),
        };
        let bytes = match package.serialize() {
            Ok(b) => b,
            Err(_) => return FROST_ERR_SERIALIZATION,
        };
        *out_state = Box::into_raw(Box::new(FrostDkgRound1State { identifier, secret }));
        *out_round1_package = FrostBuffer::from_vec(bytes);
        FROST_OK
    })
}

/// Run DKG part 2. `round1_packages` holds the round 1 package of every OTHER
/// participant, keyed by sender identifier.
///
/// The call consumes `state` on every return path, success and failure alike.
/// The state pointer is invalid after the call returns. This prevents reuse of
/// round 1 secrets.
///
/// On success, writes an opaque round 2 state and one package per recipient.
/// Each output identifier names the RECIPIENT that package must be sent to.
///
/// # Safety
/// `round1_packages` must point to `round1_count` valid entries. Out pointers
/// must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn frost_dkg_part2(
    state: *mut FrostDkgRound1State,
    round1_packages: *const FrostPeerBytes,
    round1_count: usize,
    out_state: *mut *mut FrostDkgRound2State,
    out_round2_packages: *mut *mut FrostPeerBuffer,
    out_count: *mut usize,
) -> i32 {
    ffi_guard(|| {
        if state.is_null() {
            return FROST_ERR_INVALID_ARGUMENT;
        }
        // Consume the state on every path from here on.
        let st = Box::from_raw(state);
        if out_state.is_null() || out_round2_packages.is_null() || out_count.is_null() {
            return FROST_ERR_INVALID_ARGUMENT;
        }
        let (packages, id_map) = match parse_peer_list(round1_packages, round1_count, |b| {
            dkg::round1::Package::deserialize(b).map_err(map_err)
        }) {
            Ok(r) => r,
            Err(rc) => return rc,
        };
        let identifier = st.identifier;
        let secret = st.secret.clone();
        // Wipe the handle copy before the protocol step.
        drop(st);
        let (round2_secret, round2_map) = match dkg::part2(secret, &packages) {
            Ok(r) => r,
            Err(e) => return map_err(e),
        };
        // Hold the new secret in a zeroizing handle before any fallible step.
        let new_state = Box::new(FrostDkgRound2State {
            identifier,
            secret: round2_secret,
        });
        let mut entries = Vec::with_capacity(round2_map.len());
        for (id, package) in &round2_map {
            let recipient = match id_map.get(id) {
                Some(r) => *r,
                None => return FROST_ERR_CRYPTO,
            };
            let bytes = match package.serialize() {
                Ok(b) => b,
                Err(_) => return FROST_ERR_SERIALIZATION,
            };
            entries.push((recipient, bytes));
        }
        let (buffers, count) = peer_buffers_into_raw(entries);
        *out_state = Box::into_raw(new_state);
        *out_round2_packages = buffers;
        *out_count = count;
        FROST_OK
    })
}

/// Run DKG part 3. `round1_packages` must be the same list given to part 2.
/// `round2_packages` holds the packages addressed to this participant, keyed
/// by SENDER identifier.
///
/// The call consumes `state` on every return path, success and failure alike.
/// The state pointer is invalid after the call returns.
///
/// On success, writes the opaque key package, the 32-byte group public key
/// (a plain Ed25519 verifying key), and the serialized public key package
/// needed later by `frost_aggregate`.
///
/// # Safety
/// Package lists must point to valid entries. `out_group_public_key` must
/// point to 32 writable bytes. Out pointers must be valid and writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn frost_dkg_part3(
    state: *mut FrostDkgRound2State,
    round1_packages: *const FrostPeerBytes,
    round1_count: usize,
    round2_packages: *const FrostPeerBytes,
    round2_count: usize,
    out_key_package: *mut *mut FrostKeyPackage,
    out_group_public_key: *mut u8,
    out_public_key_package: *mut FrostBuffer,
) -> i32 {
    ffi_guard(|| {
        if state.is_null() {
            return FROST_ERR_INVALID_ARGUMENT;
        }
        // Consume the state on every path from here on.
        let st = Box::from_raw(state);
        if out_key_package.is_null()
            || out_group_public_key.is_null()
            || out_public_key_package.is_null()
        {
            return FROST_ERR_INVALID_ARGUMENT;
        }
        let (r1, _) = match parse_peer_list(round1_packages, round1_count, |b| {
            dkg::round1::Package::deserialize(b).map_err(map_err)
        }) {
            Ok(r) => r,
            Err(rc) => return rc,
        };
        let (r2, _) = match parse_peer_list(round2_packages, round2_count, |b| {
            dkg::round2::Package::deserialize(b).map_err(map_err)
        }) {
            Ok(r) => r,
            Err(rc) => return rc,
        };
        let (key_package, public_key_package) = match dkg::part3(&st.secret, &r1, &r2) {
            Ok(r) => r,
            Err(e) => return map_err(e),
        };
        let identifier = st.identifier;
        drop(st);
        let group_pk = match public_key_package.verifying_key().serialize() {
            Ok(b) if b.len() == 32 => b,
            _ => return FROST_ERR_SERIALIZATION,
        };
        let pkp_bytes = match public_key_package.serialize() {
            Ok(b) => b,
            Err(_) => return FROST_ERR_SERIALIZATION,
        };
        *out_key_package = Box::into_raw(Box::new(FrostKeyPackage {
            identifier,
            inner: key_package,
        }));
        std::ptr::copy_nonoverlapping(group_pk.as_ptr(), out_group_public_key, 32);
        *out_public_key_package = FrostBuffer::from_vec(pkp_bytes);
        FROST_OK
    })
}

/// Generate fresh signing nonces and their commitments for one signing run.
///
/// The nonces stay behind the opaque handle and are never serialized. The
/// serialized commitments go to the coordinator.
///
/// # Safety
/// `key_package` must be a live handle. Out pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn frost_signing_commit(
    key_package: *const FrostKeyPackage,
    out_nonces: *mut *mut FrostSigningNonces,
    out_commitments: *mut FrostBuffer,
) -> i32 {
    ffi_guard(|| {
        if key_package.is_null() || out_nonces.is_null() || out_commitments.is_null() {
            return FROST_ERR_INVALID_ARGUMENT;
        }
        let kp = &*key_package;
        let (nonces, commitments) = frost::round1::commit(kp.inner.signing_share(), &mut OsRng);
        let bytes = match commitments.serialize() {
            Ok(b) => b,
            Err(_) => return FROST_ERR_SERIALIZATION,
        };
        *out_nonces = Box::into_raw(Box::new(FrostSigningNonces { inner: nonces }));
        *out_commitments = FrostBuffer::from_vec(bytes);
        FROST_OK
    })
}

/// Produce this participant's signature share. `commitments` holds the
/// commitments of ALL selected signers (this one included), keyed by signer
/// identifier.
///
/// The call consumes `nonces` on every return path, success and failure
/// alike. The nonce pointer is invalid after the call returns. A nonce signs
/// at most once; there is no way to reuse it through this API.
///
/// # Safety
/// `message` must point to `message_len` readable bytes. `commitments` must
/// point to `commitments_count` valid entries. Out pointer must be writable.
#[no_mangle]
pub unsafe extern "C" fn frost_sign(
    key_package: *const FrostKeyPackage,
    nonces: *mut FrostSigningNonces,
    message: *const u8,
    message_len: usize,
    commitments: *const FrostPeerBytes,
    commitments_count: usize,
    out_signature_share: *mut FrostBuffer,
) -> i32 {
    ffi_guard(|| {
        if nonces.is_null() {
            return FROST_ERR_INVALID_ARGUMENT;
        }
        // Consume the nonces on every path from here on.
        let n = Box::from_raw(nonces);
        if key_package.is_null() || message.is_null() || out_signature_share.is_null() {
            return FROST_ERR_INVALID_ARGUMENT;
        }
        let (commitment_map, _) = match parse_peer_list(commitments, commitments_count, |b| {
            frost::round1::SigningCommitments::deserialize(b).map_err(map_err)
        }) {
            Ok(r) => r,
            Err(rc) => return rc,
        };
        let msg = std::slice::from_raw_parts(message, message_len);
        let signing_package = frost::SigningPackage::new(commitment_map, msg);
        let kp = &*key_package;
        let share = match frost::round2::sign(&signing_package, &n.inner, &kp.inner) {
            Ok(s) => s,
            Err(e) => return map_err(e),
        };
        *out_signature_share = FrostBuffer::from_vec(share.serialize());
        FROST_OK
    })
}

/// Aggregate signature shares into one plain Ed25519 signature.
///
/// `commitments` and `signature_shares` must cover the same signer set that
/// produced the shares. `public_key_package` is the serialized output of
/// `frost_dkg_part3`. Every share is verified; a bad share fails the call.
///
/// # Safety
/// All lists and byte spans must be readable at the given lengths.
/// `out_signature` must point to 64 writable bytes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn frost_aggregate(
    message: *const u8,
    message_len: usize,
    commitments: *const FrostPeerBytes,
    commitments_count: usize,
    signature_shares: *const FrostPeerBytes,
    shares_count: usize,
    public_key_package: *const u8,
    public_key_package_len: usize,
    out_signature: *mut u8,
) -> i32 {
    ffi_guard(|| {
        if message.is_null() || public_key_package.is_null() || out_signature.is_null() {
            return FROST_ERR_INVALID_ARGUMENT;
        }
        let pkp_bytes = std::slice::from_raw_parts(public_key_package, public_key_package_len);
        let pubkeys = match frost::keys::PublicKeyPackage::deserialize(pkp_bytes) {
            Ok(p) => p,
            Err(e) => return map_err(e),
        };
        let (commitment_map, _) = match parse_peer_list(commitments, commitments_count, |b| {
            frost::round1::SigningCommitments::deserialize(b).map_err(map_err)
        }) {
            Ok(r) => r,
            Err(rc) => return rc,
        };
        let (share_map, _) = match parse_peer_list(signature_shares, shares_count, |b| {
            frost::round2::SignatureShare::deserialize(b).map_err(map_err)
        }) {
            Ok(r) => r,
            Err(rc) => return rc,
        };
        let msg = std::slice::from_raw_parts(message, message_len);
        let signing_package = frost::SigningPackage::new(commitment_map, msg);
        let signature = match frost::aggregate(&signing_package, &share_map, &pubkeys) {
            Ok(s) => s,
            Err(e) => return map_err(e),
        };
        let bytes = match signature.serialize() {
            Ok(b) if b.len() == 64 => b,
            _ => return FROST_ERR_SERIALIZATION,
        };
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_signature, 64);
        FROST_OK
    })
}

/// Verify a 64-byte signature under a 32-byte group public key. The check is
/// plain Ed25519 verification.
///
/// # Safety
/// `group_public_key` must point to 32 readable bytes, `signature` to 64,
/// and `message` to `message_len`.
#[no_mangle]
pub unsafe extern "C" fn frost_verify(
    group_public_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
) -> i32 {
    ffi_guard(|| {
        if group_public_key.is_null() || message.is_null() || signature.is_null() {
            return FROST_ERR_INVALID_ARGUMENT;
        }
        let vk_bytes = std::slice::from_raw_parts(group_public_key, 32);
        let vk = match frost::VerifyingKey::deserialize(vk_bytes) {
            Ok(v) => v,
            Err(_) => return FROST_ERR_SERIALIZATION,
        };
        let sig_bytes = std::slice::from_raw_parts(signature, 64);
        let sig = match frost::Signature::deserialize(sig_bytes) {
            Ok(s) => s,
            Err(_) => return FROST_ERR_SERIALIZATION,
        };
        let msg = std::slice::from_raw_parts(message, message_len);
        match vk.verify(msg, &sig) {
            Ok(()) => FROST_OK,
            Err(e) => map_err(e),
        }
    })
}

/// Read the participant identifier out of a key package handle.
///
/// # Safety
/// `key_package` must be a live handle. `out_identifier` must be writable.
#[no_mangle]
pub unsafe extern "C" fn frost_key_package_identifier(
    key_package: *const FrostKeyPackage,
    out_identifier: *mut u16,
) -> i32 {
    ffi_guard(|| {
        if key_package.is_null() || out_identifier.is_null() {
            return FROST_ERR_INVALID_ARGUMENT;
        }
        *out_identifier = (*key_package).identifier;
        FROST_OK
    })
}

/// Zeroize and free the bytes owned by a buffer. Nulls the struct fields so a
/// second call is a no-op. Null pointer is a no-op.
///
/// # Safety
/// `buffer` must be null or a buffer written by this library.
#[no_mangle]
pub unsafe extern "C" fn frost_buffer_free(buffer: *mut FrostBuffer) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(b) = buffer.as_mut() {
            free_buffer_contents(b);
        }
    }));
}

/// Zeroize and free an array returned by `frost_dkg_part2`. `count` must be
/// the count the call returned. Null pointer is a no-op.
///
/// # Safety
/// `buffers` must be null or the exact pointer written by `frost_dkg_part2`,
/// paired with its exact count.
#[no_mangle]
pub unsafe extern "C" fn frost_peer_buffers_free(buffers: *mut FrostPeerBuffer, count: usize) {
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

/// Drop an unused round 1 state. The secret inside is zeroized.
///
/// # Safety
/// `state` must be null or a live handle. It is invalid afterwards.
#[no_mangle]
pub unsafe extern "C" fn frost_dkg_round1_state_free(state: *mut FrostDkgRound1State) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !state.is_null() {
            drop(Box::from_raw(state));
        }
    }));
}

/// Drop an unused round 2 state. The secret inside is zeroized.
///
/// # Safety
/// `state` must be null or a live handle. It is invalid afterwards.
#[no_mangle]
pub unsafe extern "C" fn frost_dkg_round2_state_free(state: *mut FrostDkgRound2State) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !state.is_null() {
            drop(Box::from_raw(state));
        }
    }));
}

/// Drop a key package. The signing share inside is zeroized.
///
/// # Safety
/// `key_package` must be null or a live handle. It is invalid afterwards.
#[no_mangle]
pub unsafe extern "C" fn frost_key_package_free(key_package: *mut FrostKeyPackage) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !key_package.is_null() {
            drop(Box::from_raw(key_package));
        }
    }));
}

/// Drop unused signing nonces. The nonces are zeroized.
///
/// # Safety
/// `nonces` must be null or a live handle. It is invalid afterwards.
#[no_mangle]
pub unsafe extern "C" fn frost_signing_nonces_free(nonces: *mut FrostSigningNonces) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !nonces.is_null() {
            drop(Box::from_raw(nonces));
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::null_mut;

    struct Node {
        id: u16,
        key_package: *mut FrostKeyPackage,
        group_pk: [u8; 32],
        public_key_package: Vec<u8>,
    }

    type PeerVec = Vec<(u16, Vec<u8>)>;

    unsafe fn buf_to_vec(b: &FrostBuffer) -> Vec<u8> {
        std::slice::from_raw_parts(b.data, b.len).to_vec()
    }

    fn peer_list(entries: &[(u16, Vec<u8>)], skip: Option<u16>) -> Vec<FrostPeerBytes> {
        entries
            .iter()
            .filter(|(id, _)| Some(*id) != skip)
            .map(|(id, bytes)| FrostPeerBytes {
                identifier: *id,
                data: bytes.as_ptr(),
                len: bytes.len(),
            })
            .collect()
    }

    /// Full dealerless DKG through the C API. Returns one node per
    /// participant, each holding its own key package handle.
    unsafe fn run_dkg(n: u16, t: u16) -> Vec<Node> {
        // Part 1: every participant broadcasts a round 1 package.
        let mut states1 = Vec::new();
        let mut r1: Vec<(u16, Vec<u8>)> = Vec::new();
        for id in 1..=n {
            let mut state: *mut FrostDkgRound1State = null_mut();
            let mut buf = FrostBuffer {
                data: null_mut(),
                len: 0,
            };
            assert_eq!(frost_dkg_part1(id, n, t, &mut state, &mut buf), FROST_OK);
            r1.push((id, buf_to_vec(&buf)));
            frost_buffer_free(&mut buf);
            states1.push((id, state));
        }

        // Part 2: every participant sends one package to every other one.
        let mut states2 = Vec::new();
        let mut r2: Vec<((u16, u16), Vec<u8>)> = Vec::new(); // (sender, recipient)
        for (id, state) in states1 {
            let others = peer_list(&r1, Some(id));
            let mut state2: *mut FrostDkgRound2State = null_mut();
            let mut out: *mut FrostPeerBuffer = null_mut();
            let mut count: usize = 0;
            assert_eq!(
                frost_dkg_part2(state, others.as_ptr(), others.len(), &mut state2, &mut out, &mut count),
                FROST_OK
            );
            assert_eq!(count, (n - 1) as usize);
            for pb in std::slice::from_raw_parts(out, count) {
                if id == 1 && pb.identifier == 2 {
                    eprintln!("sizes: n={} t={} round1_package={} round2_package={}",
                        n, t, r1[0].1.len(), pb.buffer.len);
                }
                r2.push(((id, pb.identifier), buf_to_vec(&pb.buffer)));
            }
            frost_peer_buffers_free(out, count);
            states2.push((id, state2));
        }

        // Part 3: every participant derives its key package.
        let mut nodes = Vec::new();
        for (id, state2) in states2 {
            let r1_list = peer_list(&r1, Some(id));
            let addressed: Vec<(u16, Vec<u8>)> = r2
                .iter()
                .filter(|((_, to), _)| *to == id)
                .map(|((from, _), bytes)| (*from, bytes.clone()))
                .collect();
            let r2_list = peer_list(&addressed, None);
            let mut kp: *mut FrostKeyPackage = null_mut();
            let mut group_pk = [0u8; 32];
            let mut pkp = FrostBuffer {
                data: null_mut(),
                len: 0,
            };
            assert_eq!(
                frost_dkg_part3(
                    state2,
                    r1_list.as_ptr(),
                    r1_list.len(),
                    r2_list.as_ptr(),
                    r2_list.len(),
                    &mut kp,
                    group_pk.as_mut_ptr(),
                    &mut pkp,
                ),
                FROST_OK
            );
            let public_key_package = buf_to_vec(&pkp);
            if id == 1 {
                eprintln!("sizes: n={} public_key_package={}", n, public_key_package.len());
            }
            frost_buffer_free(&mut pkp);
            nodes.push(Node {
                id,
                key_package: kp,
                group_pk,
                public_key_package,
            });
        }
        nodes
    }

    unsafe fn free_nodes(nodes: Vec<Node>) {
        for node in nodes {
            frost_key_package_free(node.key_package);
        }
    }

    /// Rounds 1 and 2 of signing for the given signers. Returns the
    /// commitment list and the signature share list.
    unsafe fn commit_and_sign(
        nodes: &[Node],
        signer_ids: &[u16],
        msg: &[u8],
    ) -> (PeerVec, PeerVec) {
        let mut nonce_handles = Vec::new();
        let mut commitments: Vec<(u16, Vec<u8>)> = Vec::new();
        for id in signer_ids {
            let node = nodes.iter().find(|n| n.id == *id).unwrap();
            let mut nonces: *mut FrostSigningNonces = null_mut();
            let mut buf = FrostBuffer {
                data: null_mut(),
                len: 0,
            };
            assert_eq!(
                frost_signing_commit(node.key_package, &mut nonces, &mut buf),
                FROST_OK
            );
            commitments.push((*id, buf_to_vec(&buf)));
            frost_buffer_free(&mut buf);
            nonce_handles.push((*id, nonces));
        }

        let commitment_list = peer_list(&commitments, None);
        let mut shares: Vec<(u16, Vec<u8>)> = Vec::new();
        for (id, nonces) in nonce_handles {
            let node = nodes.iter().find(|n| n.id == id).unwrap();
            let mut buf = FrostBuffer {
                data: null_mut(),
                len: 0,
            };
            // frost_sign consumes the nonce handle. The pointer is dead after
            // this call; only the returned share leaves the signer.
            assert_eq!(
                frost_sign(
                    node.key_package,
                    nonces,
                    msg.as_ptr(),
                    msg.len(),
                    commitment_list.as_ptr(),
                    commitment_list.len(),
                    &mut buf,
                ),
                FROST_OK
            );
            shares.push((id, buf_to_vec(&buf)));
            frost_buffer_free(&mut buf);
        }
        (commitments, shares)
    }

    unsafe fn aggregate(
        msg: &[u8],
        commitments: &[(u16, Vec<u8>)],
        shares: &[(u16, Vec<u8>)],
        public_key_package: &[u8],
    ) -> Result<[u8; 64], i32> {
        let commitment_list = peer_list(commitments, None);
        let share_list = peer_list(shares, None);
        let mut sig = [0u8; 64];
        let rc = frost_aggregate(
            msg.as_ptr(),
            msg.len(),
            commitment_list.as_ptr(),
            commitment_list.len(),
            share_list.as_ptr(),
            share_list.len(),
            public_key_package.as_ptr(),
            public_key_package.len(),
            sig.as_mut_ptr(),
        );
        if rc == FROST_OK {
            Ok(sig)
        } else {
            Err(rc)
        }
    }

    #[test]
    fn dkg_and_threshold_sign_end_to_end() {
        unsafe {
            let nodes = run_dkg(5, 5);
            let group_pk = nodes[0].group_pk;
            for node in &nodes {
                assert_eq!(node.group_pk, group_pk);
                assert_eq!(node.public_key_package, nodes[0].public_key_package);
                let mut id = 0u16;
                assert_eq!(frost_key_package_identifier(node.key_package, &mut id), FROST_OK);
                assert_eq!(id, node.id);
            }

            let msg = b"lemonade nexus epoch handoff";
            let (commitments, shares) = commit_and_sign(&nodes, &[1, 2, 3, 4, 5], msg);
            eprintln!(
                "sizes: commitments={} signature_share={} public_key_package={}",
                commitments[0].1.len(),
                shares[0].1.len(),
                nodes[0].public_key_package.len()
            );
            let sig = aggregate(msg, &commitments, &shares, &nodes[0].public_key_package)
                .expect("aggregate");

            assert_eq!(
                frost_verify(group_pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()),
                FROST_OK
            );
            // Wrong message must fail verification.
            let bad = b"lemonade nexus epoch handofF";
            assert_eq!(
                frost_verify(group_pk.as_ptr(), bad.as_ptr(), bad.len(), sig.as_ptr()),
                FROST_ERR_CRYPTO
            );

            // The aggregate signature is a plain Ed25519 signature.
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_pk).unwrap();
            let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig);
            vk.verify_strict(msg, &dalek_sig).expect("plain Ed25519 verify");

            free_nodes(nodes);
        }
    }

    #[test]
    fn seven_of_five_threshold() {
        unsafe {
            let nodes_a = run_dkg(7, 5);
            let nodes_b = run_dkg(7, 5);
            // Fresh DKG must give a fresh group key.
            assert_ne!(nodes_a[0].group_pk, nodes_b[0].group_pk);

            let msg = b"threshold five of seven";
            let signers = [2, 3, 5, 6, 7];
            let (commitments, shares) = commit_and_sign(&nodes_a, &signers, msg);
            let sig = aggregate(msg, &commitments, &shares, &nodes_a[0].public_key_package)
                .expect("aggregate with exactly t signers");
            assert_eq!(
                frost_verify(nodes_a[0].group_pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()),
                FROST_OK
            );

            free_nodes(nodes_a);
            free_nodes(nodes_b);
        }
    }

    #[test]
    fn below_threshold_fails() {
        unsafe {
            let nodes = run_dkg(5, 5);
            let msg = b"not enough signers";
            let (commitments, shares) = commit_and_sign(&nodes, &[1, 2, 3, 4, 5], msg);
            // Drop one signer at aggregation time.
            let rc = aggregate(msg, &commitments[..4], &shares[..4], &nodes[0].public_key_package)
                .unwrap_err();
            assert!(rc < 0);
            free_nodes(nodes);
        }
    }

    #[test]
    fn tampered_share_rejected() {
        unsafe {
            let nodes = run_dkg(5, 5);
            let msg = b"tamper detection";
            let (commitments, mut shares) = commit_and_sign(&nodes, &[1, 2, 3, 4, 5], msg);
            // Flip the low byte of one scalar. The encoding stays canonical,
            // so aggregate must identify the share as invalid.
            shares[2].1[0] ^= 0x01;
            let rc = aggregate(msg, &commitments, &shares, &nodes[0].public_key_package)
                .unwrap_err();
            assert_eq!(rc, FROST_ERR_CRYPTO);
            free_nodes(nodes);
        }
    }

    #[test]
    fn wrong_identifier_rejected() {
        unsafe {
            // Identifier 0 is invalid.
            let mut state: *mut FrostDkgRound1State = null_mut();
            let mut buf = FrostBuffer {
                data: null_mut(),
                len: 0,
            };
            assert_eq!(
                frost_dkg_part1(0, 3, 2, &mut state, &mut buf),
                FROST_ERR_INVALID_ARGUMENT
            );
            assert!(state.is_null());
            assert!(buf.data.is_null());

            // Duplicate identifiers in a package list are rejected.
            let mut buf1 = FrostBuffer {
                data: null_mut(),
                len: 0,
            };
            let mut buf2 = FrostBuffer {
                data: null_mut(),
                len: 0,
            };
            let mut s1: *mut FrostDkgRound1State = null_mut();
            let mut s2: *mut FrostDkgRound2State = null_mut();
            assert_eq!(frost_dkg_part1(1, 3, 2, &mut s1, &mut buf1), FROST_OK);
            let mut s_other: *mut FrostDkgRound1State = null_mut();
            assert_eq!(frost_dkg_part1(2, 3, 2, &mut s_other, &mut buf2), FROST_OK);
            let pkg2 = buf_to_vec(&buf2);
            let dup = [
                FrostPeerBytes {
                    identifier: 2,
                    data: pkg2.as_ptr(),
                    len: pkg2.len(),
                },
                FrostPeerBytes {
                    identifier: 2,
                    data: pkg2.as_ptr(),
                    len: pkg2.len(),
                },
            ];
            let mut out: *mut FrostPeerBuffer = null_mut();
            let mut count = 0usize;
            assert_eq!(
                frost_dkg_part2(s1, dup.as_ptr(), dup.len(), &mut s2, &mut out, &mut count),
                FROST_ERR_INVALID_ARGUMENT
            );
            // s1 is consumed even on failure. Do not free it again.
            assert!(s2.is_null());
            assert!(out.is_null());

            // Identifier 0 inside a package list is rejected too.
            let mut s3: *mut FrostDkgRound1State = null_mut();
            let mut buf3 = FrostBuffer {
                data: null_mut(),
                len: 0,
            };
            assert_eq!(frost_dkg_part1(3, 3, 2, &mut s3, &mut buf3), FROST_OK);
            let zero = [FrostPeerBytes {
                identifier: 0,
                data: pkg2.as_ptr(),
                len: pkg2.len(),
            }];
            assert_eq!(
                frost_dkg_part2(s3, zero.as_ptr(), zero.len(), &mut s2, &mut out, &mut count),
                FROST_ERR_INVALID_ARGUMENT
            );

            frost_dkg_round1_state_free(s_other);
            frost_buffer_free(&mut buf1);
            frost_buffer_free(&mut buf2);
            frost_buffer_free(&mut buf3);
        }
    }

    #[test]
    fn nonce_single_use() {
        unsafe {
            let nodes = run_dkg(3, 2);
            // frost_sign consumes the nonce handle on every return path, so a
            // second sign with the same pointer is impossible by construction.
            // Two commit calls must give fresh, distinct nonces.
            let mut n1: *mut FrostSigningNonces = null_mut();
            let mut n2: *mut FrostSigningNonces = null_mut();
            let mut c1 = FrostBuffer {
                data: null_mut(),
                len: 0,
            };
            let mut c2 = FrostBuffer {
                data: null_mut(),
                len: 0,
            };
            assert_eq!(frost_signing_commit(nodes[0].key_package, &mut n1, &mut c1), FROST_OK);
            assert_eq!(frost_signing_commit(nodes[0].key_package, &mut n2, &mut c2), FROST_OK);
            assert_ne!(buf_to_vec(&c1), buf_to_vec(&c2));
            frost_signing_nonces_free(n1);
            frost_signing_nonces_free(n2);
            frost_buffer_free(&mut c1);
            frost_buffer_free(&mut c2);
            free_nodes(nodes);
        }
    }

    #[test]
    fn buffer_free_roundtrip() {
        unsafe {
            // Success path: allocate, free, second free is a no-op.
            let mut state: *mut FrostDkgRound1State = null_mut();
            let mut buf = FrostBuffer {
                data: null_mut(),
                len: 0,
            };
            assert_eq!(frost_dkg_part1(1, 3, 2, &mut state, &mut buf), FROST_OK);
            eprintln!("sizes: round1_package={}", buf.len);
            assert!(!buf.data.is_null());
            frost_buffer_free(&mut buf);
            assert!(buf.data.is_null());
            assert_eq!(buf.len, 0);
            frost_buffer_free(&mut buf);
            frost_buffer_free(null_mut());

            // Unused handles free cleanly.
            frost_dkg_round1_state_free(state);
            frost_dkg_round1_state_free(null_mut());
            frost_dkg_round2_state_free(null_mut());
            frost_key_package_free(null_mut());
            frost_signing_nonces_free(null_mut());
            frost_peer_buffers_free(null_mut(), 0);

            // Error path: out-params stay untouched.
            let sentinel = 0xA5A5usize as *mut FrostDkgRound1State;
            let mut untouched_state = sentinel;
            let mut untouched_buf = FrostBuffer {
                data: null_mut(),
                len: 7,
            };
            assert_eq!(
                frost_dkg_part1(0, 3, 2, &mut untouched_state, &mut untouched_buf),
                FROST_ERR_INVALID_ARGUMENT
            );
            assert_eq!(untouched_state, sentinel);
            assert_eq!(untouched_buf.len, 7);
        }
    }
}

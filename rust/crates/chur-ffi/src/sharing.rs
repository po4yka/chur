//! Phase 4 collection-sharing identity C ABI.

use chur_core::{ChurStatus, Error, Id, ensure};
use chur_crypto::Key;
use chur_format::codec::{Reader, Writer};
use chur_sync_protocol::{
    collection_membership::{CollectionMembershipRecord, RecipientVerification},
    grant::{CollectionGrant, PermissionProfile},
    identity::fingerprint,
    membership::{EnrollmentRecord, RevocationRecord},
    operation::Operation,
    state::MembershipState,
};

use crate::api::{Status, borrow_bytes, borrow_bytes_mut, borrow_large, write_out};
use crate::panic::guard_status_for;
use crate::registry::{self, Entry, Handle, Kind};

const RECORD_VERSION_V1: u16 = 1;
const BUNDLE_BYTES_MAX: u32 = 16_777_216;
const BUNDLE_RECORDS_MAX: usize = 4_096;
const ISSUERS_MAX: usize = 257;

struct DecodedIssuer {
    membership: Vec<chur_catalog::sharing_service::IssuerMembershipRecord>,
    operations: Vec<Operation>,
}

fn permission_profile(value: u8) -> Result<PermissionProfile, Error> {
    match value {
        0x01 => Ok(PermissionProfile::Read),
        0x03 => Ok(PermissionProfile::Contribute),
        0x07 => Ok(PermissionProfile::ManageMembers),
        _ => Err(Error::new(
            ChurStatus::UnsupportedVersion,
            "sharing permission profile is not supported",
        )),
    }
}

/// Idempotently provisions or returns the ordinary local sharing identity.
///
/// # Safety
///
/// `destination` covers `capacity` writable bytes and `bytes_written` points
/// to one writable, aligned `size_t` for this call.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 6.9 fixes this exported symbol"
)]
pub unsafe extern "C" fn chur_sharing_identity(
    session: Handle,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: the caller guarantees the writable out-parameter above.
        let _ = unsafe { write_out(bytes_written, 0usize) };
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let encoded = {
            let mut session = registry::lock(session);
            let vault_id = session.vault_id();
            let root = session.root_secret()?.duplicate();
            let (enrollment, operation) = chur_catalog::sync_receive::provision_local_identity(
                session.catalog()?,
                &root,
                vault_id,
            )?;
            let display = fingerprint(
                enrollment.vault_id(),
                enrollment.device_id(),
                enrollment.signing_public_key(),
                enrollment.hpke_public_key(),
            );
            let mut writer = Writer::new();
            writer
                .u16(RECORD_VERSION_V1)
                .id(enrollment.vault_id())
                .id(enrollment.device_id())
                .fixed(enrollment.signing_public_key())
                .fixed(enrollment.hpke_public_key());
            writer.variable(display.as_bytes())?;
            writer.variable(&enrollment.encode())?;
            writer.variable(&operation.encode())?;
            writer.finish()
        };
        // SAFETY: the caller guarantees the destination range above.
        let buffer = unsafe { borrow_bytes_mut(destination, capacity)? };
        ensure!(
            encoded.len() <= buffer.len(),
            ResourceLimitExceeded,
            "the destination buffer is smaller than the sharing identity record"
        );
        buffer[..encoded.len()].copy_from_slice(&encoded);
        // SAFETY: the caller guarantees the writable out-parameter above.
        unsafe { write_out(bytes_written, encoded.len()) }
    })
}

/// Returns the default collection and its current and historical recipient devices.
///
/// # Safety
///
/// `destination` covers `capacity` writable bytes and `bytes_written` points
/// to one writable, aligned `size_t` for this call.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 6.14 fixes this exported symbol"
)]
pub unsafe extern "C" fn chur_sharing_overview(
    session: Handle,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: the caller guarantees the writable out-parameter above.
        unsafe { write_out(bytes_written, 0usize)? };
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let encoded = {
            let mut session = registry::lock(session);
            let collection_id = chur_media::keys::ensure_default_collection(&mut session)?;
            let state = chur_catalog::sharing::load(session.catalog_ref()?, &collection_id)?;
            let mut writer = Writer::new();
            writer.u16(RECORD_VERSION_V1).id(&collection_id);
            let members = state
                .as_ref()
                .map_or_else(Vec::new, |state| state.members().collect::<Vec<_>>());
            ensure!(
                members.len() <= BUNDLE_RECORDS_MAX,
                ResourceLimitExceeded,
                "the sharing overview exceeds the member limit"
            );
            writer.u32(u32::try_from(members.len()).map_err(|_| {
                Error::new(
                    ChurStatus::ResourceLimitExceeded,
                    "the sharing overview count exceeds u32",
                )
            })?);
            for (vault_id, device_id, member) in members {
                let display = fingerprint(
                    vault_id,
                    device_id,
                    member.signing_public_key(),
                    member.hpke_public_key(),
                );
                let verified = state
                    .as_ref()
                    .and_then(|state| state.recipient_verification(vault_id, device_id));
                writer
                    .id(vault_id)
                    .id(device_id)
                    .u8(member.permissions() as u8)
                    .u8(u8::from(member.is_active()))
                    .u8(u8::from(verified == Some(RecipientVerification::Verified)));
                writer.variable(display.as_bytes())?;
            }
            writer.finish()
        };
        // SAFETY: the caller guarantees the writable destination range above.
        let buffer = unsafe { borrow_bytes_mut(destination, capacity)? };
        ensure!(
            encoded.len() <= buffer.len(),
            ResourceLimitExceeded,
            "the destination buffer is smaller than the sharing overview"
        );
        buffer[..encoded.len()].copy_from_slice(&encoded);
        // SAFETY: the caller guarantees the writable out-parameter above.
        unsafe { write_out(bytes_written, encoded.len()) }
    })
}

/// Authenticates a self-signed initial enrollment before showing its identity.
///
/// # Safety
///
/// `enrollment` covers `enrollment_length` readable bytes, `destination`
/// covers `capacity` writable bytes, and `bytes_written` is writable.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 6.14 fixes this exported symbol"
)]
pub unsafe extern "C" fn chur_sharing_inspect_enrollment(
    enrollment: *const u8,
    enrollment_length: u32,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    guard_status_for(0, || {
        // SAFETY: the caller guarantees the writable out-parameter above.
        unsafe { write_out(bytes_written, 0usize)? };
        ensure!(
            enrollment_length as usize == EnrollmentRecord::LEN,
            InvalidInput,
            "a recipient enrollment has an invalid length"
        );
        // SAFETY: the caller guarantees the readable input range above.
        let record =
            EnrollmentRecord::decode(unsafe { borrow_bytes(enrollment, enrollment_length)? })?;
        MembershipState::bootstrap(&record)?;
        let display = fingerprint(
            record.vault_id(),
            record.device_id(),
            record.signing_public_key(),
            record.hpke_public_key(),
        );
        let mut writer = Writer::new();
        writer
            .u16(RECORD_VERSION_V1)
            .id(record.vault_id())
            .id(record.device_id());
        writer.variable(display.as_bytes())?;
        let encoded = writer.finish();
        // SAFETY: the caller guarantees the writable destination range above.
        let buffer = unsafe { borrow_bytes_mut(destination, capacity)? };
        ensure!(
            encoded.len() <= buffer.len(),
            ResourceLimitExceeded,
            "the destination buffer is smaller than the recipient preview"
        );
        buffer[..encoded.len()].copy_from_slice(&encoded);
        // SAFETY: the caller guarantees the writable out-parameter above.
        unsafe { write_out(bytes_written, encoded.len()) }
    })
}

/// Prepares one recipient membership and HPKE collection-key grant.
///
/// # Safety
///
/// Fixed and variable input pointers cover their declared readable ranges.
/// `destination` covers `capacity` writable bytes and `bytes_written` points
/// to one writable, aligned `size_t` for this call.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 6.10 fixes this exported symbol"
)]
pub unsafe extern "C" fn chur_sharing_prepare(
    session: Handle,
    collection_id: *const u8,
    recipient_enrollment: *const u8,
    recipient_enrollment_length: u32,
    permissions: u8,
    fingerprint_verified: u8,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: the caller guarantees the writable out-parameter above.
        let _ = unsafe { write_out(bytes_written, 0usize) };
        // SAFETY: the caller guarantees the fixed input range above.
        let collection_id = Id::from_slice(unsafe { borrow_bytes(collection_id, 16)? })?;
        // SAFETY: the caller guarantees the variable input range above.
        let enrollment = EnrollmentRecord::decode(unsafe {
            borrow_bytes(recipient_enrollment, recipient_enrollment_length)?
        })?;
        let permissions = permission_profile(permissions)?;
        let fingerprint_verified = match fingerprint_verified {
            0 => false,
            1 => true,
            _ => {
                return Err(Error::new(
                    ChurStatus::InvalidInput,
                    "fingerprint verification must be zero or one",
                ));
            }
        };
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let encoded = {
            let mut session = registry::lock(session);
            let source_vault_id = session.vault_id();
            let root = session.root_secret()?.duplicate();
            let prepared = chur_catalog::sharing_service::prepare_share(
                session.catalog()?,
                &root,
                source_vault_id,
                collection_id,
                &enrollment,
                permissions,
                fingerprint_verified,
            )?;
            encode_prepared_share(&prepared)?
        };
        // SAFETY: the caller guarantees the destination range above.
        let buffer = unsafe { borrow_bytes_mut(destination, capacity)? };
        ensure!(
            encoded.len() <= buffer.len(),
            ResourceLimitExceeded,
            "the destination buffer is smaller than the prepared share record"
        );
        buffer[..encoded.len()].copy_from_slice(&encoded);
        // SAFETY: the caller guarantees the writable out-parameter above.
        unsafe { write_out(bytes_written, encoded.len()) }
    })
}

/// Prepares a grant for one device in an authenticated recipient vault.
///
/// # Safety
///
/// Fixed and variable input pointers cover their declared readable ranges.
/// `destination` covers `capacity` writable bytes and `bytes_written` points
/// to one writable, aligned `size_t` for this call.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 6.13 fixes this exported symbol"
)]
pub unsafe extern "C" fn chur_sharing_prepare_device(
    session: Handle,
    collection_id: *const u8,
    recipient_evidence: *const u8,
    recipient_evidence_length: u32,
    recipient_device_id: *const u8,
    permissions: u8,
    fingerprint_verified: u8,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: the caller guarantees the writable out-parameter above.
        let _ = unsafe { write_out(bytes_written, 0usize) };
        ensure!(
            recipient_evidence_length <= BUNDLE_BYTES_MAX,
            ResourceLimitExceeded,
            "recipient evidence exceeds the ABI limit"
        );
        // SAFETY: the caller guarantees the fixed input range above.
        let collection_id = Id::from_slice(unsafe { borrow_bytes(collection_id, 16)? })?;
        // SAFETY: the caller guarantees the fixed input range above.
        let recipient_device_id =
            Id::from_slice(unsafe { borrow_bytes(recipient_device_id, 16)? })?;
        // FFI_CONTRACT.md section 6.13 admits 16 MiB of evidence, so the
        // `ensure!` above is the operative bound; `borrow_bytes` would refuse
        // anything over its own 64 KiB argument bound first, which makes the
        // documented ceiling unreachable. Section 6.8's `chur_sync_stage` has
        // the same shape.
        // SAFETY: the caller guarantees the variable input range above.
        let evidence = decode_recipient_evidence(unsafe {
            borrow_large(recipient_evidence, recipient_evidence_length)?
        })?;
        let permissions = permission_profile(permissions)?;
        let fingerprint_verified = match fingerprint_verified {
            0 => false,
            1 => true,
            _ => {
                return Err(Error::new(
                    ChurStatus::InvalidInput,
                    "fingerprint verification must be zero or one",
                ));
            }
        };
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let encoded = {
            let mut session = registry::lock(session);
            let source_vault_id = session.vault_id();
            let root = session.root_secret()?.duplicate();
            let prepared = chur_catalog::sharing_service::prepare_share_for_device(
                session.catalog()?,
                &root,
                source_vault_id,
                collection_id,
                chur_catalog::sharing_service::IssuerEvidence {
                    membership: &evidence.membership,
                    operations: &evidence.operations,
                },
                recipient_device_id,
                permissions,
                fingerprint_verified,
            )?;
            encode_prepared_share(&prepared)?
        };
        // SAFETY: the caller guarantees the destination range above.
        let buffer = unsafe { borrow_bytes_mut(destination, capacity)? };
        ensure!(
            encoded.len() <= buffer.len(),
            ResourceLimitExceeded,
            "the destination buffer is smaller than the prepared share record"
        );
        buffer[..encoded.len()].copy_from_slice(&encoded);
        // SAFETY: the caller guarantees the writable out-parameter above.
        unsafe { write_out(bytes_written, encoded.len()) }
    })
}

/// Revokes one recipient and prepares the forward-only collection rotation.
///
/// # Safety
///
/// Each identifier points to 16 readable bytes. `destination` covers
/// `capacity` writable bytes and `bytes_written` points to one writable,
/// aligned `size_t` for this call.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 6.12 fixes this exported symbol"
)]
pub unsafe extern "C" fn chur_sharing_revoke(
    session: Handle,
    collection_id: *const u8,
    recipient_vault_id: *const u8,
    recipient_device_id: *const u8,
    accepted_at_ms: u64,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: the caller guarantees the writable out-parameter above.
        unsafe { write_out(bytes_written, 0usize)? };
        ensure!(
            capacity >= BUNDLE_BYTES_MAX as usize,
            ResourceLimitExceeded,
            "the revocation destination must cover the ABI response bound"
        );
        // SAFETY: the caller guarantees the destination range above.
        let buffer = unsafe { borrow_bytes_mut(destination, capacity)? };
        // SAFETY: the caller guarantees the fixed input ranges above.
        let collection_id = Id::from_slice(unsafe { borrow_bytes(collection_id, 16)? })?;
        // SAFETY: the caller guarantees the fixed input ranges above.
        let recipient_vault_id = Id::from_slice(unsafe { borrow_bytes(recipient_vault_id, 16)? })?;
        // SAFETY: the caller guarantees the fixed input ranges above.
        let recipient_device_id =
            Id::from_slice(unsafe { borrow_bytes(recipient_device_id, 16)? })?;
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let encoded = {
            let mut session = registry::lock(session);
            let source_vault_id = session.vault_id();
            let root = session.root_secret()?.duplicate();
            let prepared = chur_catalog::sharing_service::prepare_share_revocation(
                session.catalog()?,
                &root,
                source_vault_id,
                collection_id,
                recipient_vault_id,
                recipient_device_id,
                accepted_at_ms,
                BUNDLE_RECORDS_MAX,
            )?;
            ensure!(
                prepared.rotation_operations().len() <= BUNDLE_RECORDS_MAX
                    && prepared.grants().len() <= BUNDLE_RECORDS_MAX,
                ResourceLimitExceeded,
                "the prepared revocation exceeds the ABI record limit"
            );
            let rotation_count =
                u32::try_from(prepared.rotation_operations().len()).map_err(|_| {
                    Error::new(
                        ChurStatus::ResourceLimitExceeded,
                        "the rotation operation count exceeds u32",
                    )
                })?;
            let grant_count = u32::try_from(prepared.grants().len()).map_err(|_| {
                Error::new(
                    ChurStatus::ResourceLimitExceeded,
                    "the current grant count exceeds u32",
                )
            })?;
            let mut writer = Writer::new();
            writer.u16(RECORD_VERSION_V1);
            writer.variable(&prepared.membership().encode())?;
            writer.variable(&prepared.membership_operation().encode())?;
            writer.u32(rotation_count);
            for operation in prepared.rotation_operations() {
                writer.variable(&operation.encode())?;
            }
            writer.u32(grant_count);
            for (grant, operation) in prepared.grants() {
                writer.variable(&grant.encode())?;
                writer.variable(&operation.encode())?;
            }
            writer.u8(u8::from(prepared.rotation_complete()));
            writer.finish()
        };
        ensure!(
            encoded.len() <= BUNDLE_BYTES_MAX as usize,
            ResourceLimitExceeded,
            "the prepared revocation exceeds the ABI byte limit"
        );
        buffer[..encoded.len()].copy_from_slice(&encoded);
        // SAFETY: the caller guarantees the writable out-parameter above.
        unsafe { write_out(bytes_written, encoded.len()) }
    })
}

/// Authenticates and installs one recipient share bundle.
///
/// # Safety
///
/// `bundle` covers `bundle_length` readable bytes for this call.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "FFI_CONTRACT.md section 6.11 fixes this exported symbol"
)]
pub unsafe extern "C" fn chur_sharing_accept(
    session: Handle,
    bundle: *const u8,
    bundle_length: u32,
) -> Status {
    guard_status_for(session, || {
        ensure!(
            bundle_length <= BUNDLE_BYTES_MAX,
            ResourceLimitExceeded,
            "the sharing acceptance bundle exceeds the ABI limit"
        );
        // FFI_CONTRACT.md section 6.11 admits a 16 MiB bundle, so the `ensure!`
        // above is the operative bound; `borrow_bytes` would refuse anything
        // over its own 64 KiB argument bound first, which makes the documented
        // ceiling unreachable. Section 6.8's `chur_sync_stage` has the same
        // shape.
        // SAFETY: the caller guarantees the readable input range above.
        let bytes = unsafe { borrow_large(bundle, bundle_length)? };
        let (issuers, membership, grant, grant_operation) = decode_accept_bundle(bytes)?;
        let evidence = issuers
            .iter()
            .map(|issuer| chur_catalog::sharing_service::IssuerEvidence {
                membership: &issuer.membership,
                operations: &issuer.operations,
            })
            .collect::<Vec<_>>();
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let mut session = registry::lock(session);
        let root = session.root_secret()?.duplicate();
        chur_catalog::sharing_service::accept_share(
            session.catalog()?,
            &root,
            &evidence,
            &membership,
            &grant,
            &grant_operation,
        )?;
        Ok(())
    })
}

type DecodedAcceptBundle = (
    Vec<DecodedIssuer>,
    Vec<(CollectionMembershipRecord, Operation)>,
    CollectionGrant,
    Operation,
);

fn decode_accept_bundle(bytes: &[u8]) -> Result<DecodedAcceptBundle, Error> {
    let mut reader = Reader::new(bytes, ChurStatus::NonCanonicalEncoding);
    ensure!(
        reader.u16()? == RECORD_VERSION_V1,
        UnsupportedVersion,
        "sharing acceptance bundle version is not supported"
    );
    let issuer_count = bounded_count(&mut reader, ISSUERS_MAX, "sharing issuer count")?;
    let mut issuers = Vec::with_capacity(issuer_count);
    for _ in 0..issuer_count {
        issuers.push(decode_issuer(&mut reader)?);
    }
    let membership_count = bounded_count(
        &mut reader,
        BUNDLE_RECORDS_MAX,
        "collection membership count",
    )?;
    let mut membership = Vec::with_capacity(membership_count);
    for _ in 0..membership_count {
        let record = CollectionMembershipRecord::decode(
            reader.variable(CollectionMembershipRecord::LEN as u32)?,
        )?;
        let operation = Operation::decode(reader.variable(BUNDLE_BYTES_MAX)?)?;
        membership.push((record, operation));
    }
    let grant = CollectionGrant::decode(reader.variable(CollectionGrant::LEN as u32)?)?;
    let grant_operation = Operation::decode(reader.variable(BUNDLE_BYTES_MAX)?)?;
    reader.finish()?;
    Ok((issuers, membership, grant, grant_operation))
}

/// Accepts one page of shared collection operations and returns verified download work.
///
/// # Safety
///
/// Input pointers cover their lengths. `destination` covers `capacity` writable
/// bytes and `bytes_written` is a writable aligned `size_t`.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "the exported C ABI validates bounded caller buffers"
)]
pub unsafe extern "C" fn chur_sharing_receive(
    session: Handle,
    bundle: *const u8,
    bundle_length: u32,
    operations: *const u8,
    operations_length: u32,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: the caller owns this writable out-parameter.
        unsafe { write_out(bytes_written, 0usize)? };
        ensure!(
            bundle_length <= BUNDLE_BYTES_MAX && operations_length <= BUNDLE_BYTES_MAX,
            ResourceLimitExceeded,
            "shared operation page exceeds the ABI bound"
        );
        // SAFETY: the caller guarantees both readable ranges.
        let (issuers, membership, grant, grant_operation) =
            decode_accept_bundle(unsafe { borrow_large(bundle, bundle_length)? })?;
        // SAFETY: the caller guarantees the readable page range.
        let mut reader = Reader::new(
            unsafe { borrow_large(operations, operations_length)? },
            ChurStatus::NonCanonicalEncoding,
        );
        let count = bounded_count(
            &mut reader,
            BUNDLE_RECORDS_MAX,
            "collection operation count",
        )?;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            records.push(
                chur_sync_protocol::collection_operation::CollectionOperation::decode(
                    reader.variable(BUNDLE_BYTES_MAX)?,
                )?,
            );
        }
        reader.finish()?;
        let evidence = issuers
            .iter()
            .map(|issuer| chur_catalog::sharing_service::IssuerEvidence {
                membership: &issuer.membership,
                operations: &issuer.operations,
            })
            .collect::<Vec<_>>();
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let mut session = registry::lock(session);
        let vault_id = session.vault_id();
        let root = session.root_secret()?.duplicate();
        let plan = chur_catalog::sharing_receive::receive(
            session.catalog()?,
            &root,
            vault_id,
            &evidence,
            &membership,
            &grant,
            &grant_operation,
            &records,
        )?;
        crate::product::finish_pending_deletions(&mut session, crate::api::now_ms())?;
        // The ABI plan is bounded, while a whole vault can contain more
        // objects. Activated rows leave the pending projection, so the next
        // sync returns the following page without a separate cursor.
        let download_count = plan.objects.len().min(BUNDLE_RECORDS_MAX);
        let mut writer = Writer::new();
        writer
            .u16(RECORD_VERSION_V1)
            .id(&plan.source_vault_id)
            .id(&plan.collection_id)
            .id(&plan.selector)
            .u32(u32::try_from(plan.pending_operations).map_err(|_| {
                Error::new(
                    ChurStatus::ResourceLimitExceeded,
                    "pending operation count exceeds u32",
                )
            })?)
            .u32(u32::try_from(download_count).map_err(|_| {
                Error::new(
                    ChurStatus::ResourceLimitExceeded,
                    "shared object count exceeds u32",
                )
            })?);
        for object in plan.objects.iter().take(download_count) {
            writer
                .id(&object.object_id)
                .id(&object.store_id)
                .u64(object.container_length);
        }
        let encoded = writer.finish();
        // SAFETY: the caller guarantees the writable destination range.
        let output = unsafe { borrow_bytes_mut(destination, capacity)? };
        ensure!(
            encoded.len() <= output.len(),
            ResourceLimitExceeded,
            "shared download plan does not fit the destination"
        );
        output[..encoded.len()].copy_from_slice(&encoded);
        // SAFETY: the caller guarantees this writable out-parameter.
        unsafe { write_out(bytes_written, encoded.len()) }
    })
}

/// Reads the durable staging offset for a currently authenticated shared object.
///
/// # Safety
///
/// The identifier pointers cover 16 bytes and `out_offset` is writable and aligned.
#[unsafe(no_mangle)]
#[expect(unsafe_code, reason = "the exported C ABI validates caller pointers")]
pub unsafe extern "C" fn chur_sharing_download_offset(
    session: Handle,
    collection_id: *const u8,
    object_id: *const u8,
    out_offset: *mut u64,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: the caller guarantees a writable out-parameter.
        unsafe { write_out(out_offset, 0u64)? };
        // SAFETY: both identifiers cover 16 readable bytes.
        let collection_id = Id::from_slice(unsafe { borrow_bytes(collection_id, 16)? })?;
        let object_id = Id::from_slice(unsafe { borrow_bytes(object_id, 16)? })?;
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let mut session = registry::lock(session);
        let vault_id = session.vault_id();
        let root = session.root_secret()?.duplicate();
        let object = chur_catalog::sharing_receive::pending_object_for_collection(
            session.catalog()?,
            &root,
            vault_id,
            collection_id,
            object_id,
        )?;
        let expected = chur_media::sync_download::Expectation::new(
            object.object_id,
            object.stream_id,
            object.container_length,
            object.container_commitment,
        )?;
        let offset = chur_media::sync_download::staged_offset(
            session.root_dir(),
            &session.object_store_id(),
            &object_id,
            &expected,
        )?;
        // SAFETY: the caller guarantees a writable out-parameter.
        unsafe { write_out(out_offset, offset) }
    })
}

/// Appends one ciphertext range whose destination was signed by the source.
///
/// # Safety
///
/// The identifier pointers cover 16 bytes and `bytes` covers `length` bytes.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "the exported C ABI validates bounded caller buffers"
)]
pub unsafe extern "C" fn chur_sharing_download_append(
    session: Handle,
    collection_id: *const u8,
    object_id: *const u8,
    offset: u64,
    bytes: *const u8,
    length: u32,
) -> Status {
    guard_status_for(session, || {
        ensure!(
            length <= 1_048_576,
            ResourceLimitExceeded,
            "shared range exceeds one MiB"
        );
        // SAFETY: each identifier and range is caller-owned and readable.
        let collection_id = Id::from_slice(unsafe { borrow_bytes(collection_id, 16)? })?;
        let object_id = Id::from_slice(unsafe { borrow_bytes(object_id, 16)? })?;
        let bytes = unsafe { borrow_large(bytes, length)? };
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let mut session = registry::lock(session);
        let vault_id = session.vault_id();
        let root = session.root_secret()?.duplicate();
        let object = chur_catalog::sharing_receive::pending_object_for_collection(
            session.catalog()?,
            &root,
            vault_id,
            collection_id,
            object_id,
        )?;
        let expected = chur_media::sync_download::Expectation::new(
            object.object_id,
            object.stream_id,
            object.container_length,
            object.container_commitment,
        )?;
        chur_media::sync_download::append_range(
            session.root_dir(),
            &session.object_store_id(),
            &object_id,
            offset,
            bytes,
            &expected,
        )
    })
}

/// Verifies every ciphertext record and activates one shared object.
///
/// # Safety
///
/// The identifier pointers each cover 16 readable bytes.
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "the exported C ABI validates caller identifiers"
)]
pub unsafe extern "C" fn chur_sharing_download_finish(
    session: Handle,
    collection_id: *const u8,
    object_id: *const u8,
    now_ms: u64,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: both identifiers are caller-owned and readable.
        let collection_id = Id::from_slice(unsafe { borrow_bytes(collection_id, 16)? })?;
        let object_id = Id::from_slice(unsafe { borrow_bytes(object_id, 16)? })?;
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let mut session = registry::lock(session);
        let vault_id = session.vault_id();
        let root = session.root_secret()?.duplicate();
        let object = chur_catalog::sharing_receive::pending_object_for_collection(
            session.catalog()?,
            &root,
            vault_id,
            collection_id,
            object_id,
        )?;
        chur_media::sync_download::activate_shared(&mut session, &object, now_ms)
    })
}

fn decode_recipient_evidence(bytes: &[u8]) -> Result<DecodedIssuer, Error> {
    let mut reader = Reader::new(bytes, ChurStatus::NonCanonicalEncoding);
    ensure!(
        reader.u16()? == RECORD_VERSION_V1,
        UnsupportedVersion,
        "recipient evidence version is not supported"
    );
    let evidence = decode_issuer(&mut reader)?;
    reader.finish()?;
    Ok(evidence)
}

fn decode_issuer(reader: &mut Reader<'_>) -> Result<DecodedIssuer, Error> {
    let membership_count = bounded_count(reader, BUNDLE_RECORDS_MAX, "issuer membership count")?;
    let mut membership = Vec::with_capacity(membership_count);
    for _ in 0..membership_count {
        let bytes = reader.variable(EnrollmentRecord::LEN as u32)?;
        let record = match bytes.len() {
            EnrollmentRecord::LEN => {
                chur_catalog::sharing_service::IssuerMembershipRecord::Enrollment(
                    EnrollmentRecord::decode(bytes)?,
                )
            }
            RevocationRecord::LEN => {
                chur_catalog::sharing_service::IssuerMembershipRecord::Revocation(
                    RevocationRecord::decode(bytes)?,
                )
            }
            _ => {
                return Err(Error::new(
                    ChurStatus::NonCanonicalEncoding,
                    "issuer membership record has another length",
                ));
            }
        };
        membership.push(record);
    }
    let operation_count = bounded_count(reader, BUNDLE_RECORDS_MAX, "issuer operation count")?;
    let mut operations = Vec::with_capacity(operation_count);
    for _ in 0..operation_count {
        operations.push(Operation::decode(reader.variable(BUNDLE_BYTES_MAX)?)?);
    }
    Ok(DecodedIssuer {
        membership,
        operations,
    })
}

fn encode_prepared_share(
    prepared: &chur_catalog::sharing_service::PreparedShare,
) -> Result<Vec<u8>, Error> {
    let mut writer = Writer::new();
    writer.u16(RECORD_VERSION_V1);
    writer.variable(&prepared.membership().encode())?;
    writer.variable(&prepared.membership_operation().encode())?;
    writer.variable(&prepared.grant().encode())?;
    writer.variable(&prepared.grant_operation().encode())?;
    Ok(writer.finish())
}

fn bounded_count(
    reader: &mut Reader<'_>,
    maximum: usize,
    context: &'static str,
) -> Result<usize, Error> {
    let count = usize::try_from(reader.u32()?).map_err(|_| {
        Error::new(
            ChurStatus::ResourceLimitExceeded,
            "sharing record count exceeds the address space",
        )
    })?;
    if count > maximum {
        return Err(Error::new(ChurStatus::ResourceLimitExceeded, context));
    }
    Ok(count)
}

/// Requests an object key through an authenticated disposable recipient key.
///
/// # Safety
/// Input and output pointers cover their declared lengths; `bytes_written` is writable.
#[unsafe(no_mangle)]
#[expect(unsafe_code, reason = "the C ABI borrows caller-owned buffers")]
pub unsafe extern "C" fn chur_object_key_request(
    session: Handle,
    input: *const u8,
    input_length: u32,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    // SAFETY: the caller guarantees all declared buffers and the out-parameter.
    unsafe {
        object_key_call(
            session,
            input,
            input_length,
            destination,
            capacity,
            bytes_written,
            227,
            |db, root, vault_id, input| {
                let mut reader = Reader::new(input, ChurStatus::NonCanonicalEncoding);
                let collection = reader.id()?;
                let object = reader.id()?;
                reader.finish()?;
                let request =
                    chur_catalog::object_grants::request(db, root, vault_id, collection, object)?;
                match chur_catalog::object_grants::pending_envelope(db, &collection, &object) {
                    Ok(_) => Ok(vec![0]),
                    Err(error) if error.status() == ChurStatus::NotFound => {
                        let mut bytes = vec![1];
                        bytes.extend_from_slice(&request.encode());
                        Ok(bytes)
                    }
                    Err(error) => Err(error),
                }
            },
        )
    }
}

/// Issues an object key through an authenticated disposable recipient key.
///
/// # Safety
/// Input and output pointers cover their declared lengths; `bytes_written` is writable.
#[unsafe(no_mangle)]
#[expect(unsafe_code, reason = "the C ABI borrows caller-owned buffers")]
pub unsafe extern "C" fn chur_object_key_issue(
    session: Handle,
    input: *const u8,
    input_length: u32,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    // SAFETY: the caller guarantees all declared buffers and the out-parameter.
    unsafe {
        object_key_call(
            session,
            input,
            input_length,
            destination,
            capacity,
            bytes_written,
            346,
            |db, root, vault_id, input| {
                let prekey = chur_sync_protocol::object_grant::ObjectPrekey::decode(input)?;
                Ok(chur_catalog::object_grants::issue(db, root, vault_id, &prekey)?.encode())
            },
        )
    }
}

/// Accepts an object key through an authenticated disposable recipient key.
///
/// # Safety
/// Input and output pointers cover their declared lengths; `bytes_written` is writable.
#[unsafe(no_mangle)]
#[expect(unsafe_code, reason = "the C ABI borrows caller-owned buffers")]
pub unsafe extern "C" fn chur_object_key_accept(
    session: Handle,
    input: *const u8,
    input_length: u32,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    // SAFETY: the caller guarantees all declared buffers and the out-parameter.
    unsafe {
        object_key_call(
            session,
            input,
            input_length,
            destination,
            capacity,
            bytes_written,
            0,
            |db, root, vault_id, input| {
                let mut reader = Reader::new(input, ChurStatus::NonCanonicalEncoding);
                let package = reader.variable(BUNDLE_BYTES_MAX)?;
                let issuers = if package.is_empty() {
                    Vec::new()
                } else {
                    decode_accept_bundle(package)?.0
                };
                let grant = chur_sync_protocol::object_grant::ObjectKeyGrant::decode(
                    reader.variable(1024)?,
                )?;
                reader.finish()?;
                let evidence = issuers
                    .iter()
                    .map(|issuer| chur_catalog::sharing_service::IssuerEvidence {
                        membership: &issuer.membership,
                        operations: &issuer.operations,
                    })
                    .collect::<Vec<_>>();
                chur_catalog::object_grants::accept(db, root, vault_id, &evidence, &grant)?;
                Ok(Vec::new())
            },
        )
    }
}

#[expect(
    unsafe_code,
    reason = "the shared ABI implementation checks caller-owned buffers"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "shared buffer ABI and an internal checked operation"
)]
unsafe fn object_key_call(
    session: Handle,
    input: *const u8,
    input_length: u32,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
    required: usize,
    run: impl FnOnce(&mut chur_catalog::db::CatalogDb, &Key, Id, &[u8]) -> Result<Vec<u8>, Error>,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: caller owns the out-parameter and all declared ranges.
        unsafe { write_out(bytes_written, 0usize)? };
        ensure!(
            input_length <= BUNDLE_BYTES_MAX,
            ResourceLimitExceeded,
            "object key input exceeds the ABI bound"
        );
        // SAFETY: the input covers input_length bytes.
        let input = unsafe { borrow_large(input, input_length)? };
        // Check output capacity before any destructive key acceptance.
        ensure!(
            capacity >= required,
            ResourceLimitExceeded,
            "object key output is too small"
        );
        // SAFETY: caller declares this destination range writable.
        let output = unsafe { borrow_bytes_mut(destination, capacity)? };
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let encoded = {
            let mut session = registry::lock(session);
            let vault_id = session.vault_id();
            let root = session.root_secret()?.duplicate();
            run(session.catalog()?, &root, vault_id, input)?
        };
        ensure!(
            encoded.len() <= output.len(),
            ResourceLimitExceeded,
            "object key output does not fit"
        );
        output[..encoded.len()].copy_from_slice(&encoded);
        // SAFETY: caller owns the writable out-parameter.
        unsafe { write_out(bytes_written, encoded.len()) }
    })
}

/// Lists locally authored collection operations, including permanent deletion.
///
/// # Safety
/// The output buffer covers capacity bytes and bytes_written is writable.
#[unsafe(no_mangle)]
#[expect(unsafe_code, reason = "the C ABI writes caller-owned buffers")]
pub unsafe extern "C" fn chur_sharing_outbound(
    session: Handle,
    after_cursor: u64,
    destination: *mut u8,
    capacity: usize,
    bytes_written: *mut usize,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: caller owns the output parameter.
        unsafe { write_out(bytes_written, 0usize)? };
        let entry = registry::get(session, Kind::Session)?;
        let Entry::Session { session, .. } = entry.as_ref() else {
            return Err(Error::new(
                ChurStatus::InvalidInput,
                "the handle is of another type",
            ));
        };
        let encoded = {
            let session = registry::lock(session);
            let root = session.root_secret()?.duplicate();
            let db = session.catalog_ref()?;
            let membership = chur_catalog::sync_membership::load(db)?.ok_or_else(|| {
                Error::new(ChurStatus::RecoveryRequired, "outbox membership is absent")
            })?;
            let (device_id, _) = chur_catalog::sync_keys::local_identity(db, &root, &membership)?
                .ok_or_else(|| {
                Error::new(
                    ChurStatus::RecoveryRequired,
                    "outbox signing identity is absent",
                )
            })?;
            let records = chur_catalog::sharing_log::outbound_after(
                db,
                &session.vault_id(),
                &device_id,
                after_cursor,
            )?;
            let mut writer = Writer::new();
            writer.u16(1).u32(u32::try_from(records.len()).map_err(|_| {
                Error::new(
                    ChurStatus::ResourceLimitExceeded,
                    "outbox page is too large",
                )
            })?);
            for record in records {
                writer.u64(record.cursor).id(&record.collection_id);
                writer.variable(&record.record)?;
            }
            writer.finish()
        };
        // SAFETY: caller declares this range writable.
        let output = unsafe { borrow_bytes_mut(destination, capacity)? };
        ensure!(
            encoded.len() <= output.len(),
            ResourceLimitExceeded,
            "outbox output does not fit"
        );
        output[..encoded.len()].copy_from_slice(&encoded);
        // SAFETY: caller owns this output parameter.
        unsafe { write_out(bytes_written, encoded.len()) }
    })
}

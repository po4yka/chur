//! Durable user-approved enrollment of a restored own-vault device.

use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::{Key, Nonce, random};
use chur_format::codec::{Reader, Writer};
use chur_sync_protocol::checkpoint::Checkpoint;
use chur_sync_protocol::device_pairing::{
    APPROVAL_MAX, AUTHORITY_RECORDS_MAX, PairingApproval, PairingRequest,
};
use chur_sync_protocol::identity::{DeviceIdentity, DeviceIdentityEnvelope};
use chur_sync_protocol::membership::{EnrollmentRecord, RevocationRecord};
use chur_sync_protocol::operation::Operation;
use chur_sync_protocol::operation_log::ApplyOutcome;
use chur_sync_protocol::payload::{OperationPayload, PayloadBody};
use chur_sync_protocol::peer_auth::PeerCredential;
use chur_sync_protocol::state::{DeviceStatus, MembershipState};
use chur_sync_protocol::{KeyDirectory, KeyDomain};
use rusqlite::{OptionalExtension, params};
use zeroize::Zeroizing;

use crate::db::{as_sqlite_integer, map_sqlite};
use crate::{CatalogDb, own_sync, sharing_publication, sync_keys, sync_log, sync_membership};

/// Durable public enrollment records and an encrypted credential response.
pub struct PreparedPair {
    /// Signed bootstrap checkpoint.
    pub checkpoint: Vec<u8>,
    /// Signed new-device enrollment.
    pub enrollment: Vec<u8>,
    /// Root-encrypted enrollment operation for transport upload.
    pub operation: Vec<u8>,
    /// Signed HPKE approval code for the new device.
    pub approval: Vec<u8>,
}

/// Credentials released only after native authority and HPKE verification.
pub struct PairCredentials {
    /// New ordinary device identifier.
    pub device_id: Id,
    /// Signed enrollment to verify during bootstrap.
    pub enrollment: Vec<u8>,
    /// Signed checkpoint that all downloaded prefixes must satisfy.
    pub checkpoint: Vec<u8>,
}

/// One member from the authenticated current vault membership.
pub struct PairedDevice {
    /// Public device identifier.
    pub device_id: Id,
    /// Fingerprint of the member's current enrolled public keys.
    pub fingerprint: String,
    /// Whether the member can still author operations.
    pub active: bool,
    /// Whether this is the local ordinary signer.
    pub current: bool,
    /// Whether this device retained a locally authored revocation for transport retry.
    pub retry_available: bool,
}

/// Durable revocation records for idempotent transport retries.
pub struct PreparedRevocation {
    /// Signed current checkpoint.
    pub checkpoint: Vec<u8>,
    /// Signed membership revocation.
    pub revocation: Vec<u8>,
    /// Root-encrypted revocation operation.
    pub operation: Vec<u8>,
}

/// Issues a checkpoint for current signed membership after enrollment or revocation
/// transport completes. The prior bootstrap checkpoint remains in the approval.
pub fn current_checkpoint(
    db: &mut CatalogDb,
    root: &Key,
    vault: Id,
    now_ms: u64,
) -> Result<Vec<u8>> {
    let membership = local_membership(db, vault)?;
    let (issuer, identity) =
        sync_keys::local_identity(db, root, &membership)?.ok_or_else(|| {
            Error::new(
                ChurStatus::RecoveryRequired,
                "checkpoint needs an ordinary identity",
            )
        })?;
    let mut log = sync_log::load(db, &membership)?;
    Ok(log
        .issue_own_checkpoint(db, &membership, &issuer, identity.signing_key(), now_ms)?
        .encode())
}

/// Lists authenticated public membership for an ordinary local device.
pub fn overview(db: &CatalogDb, root: &Key, vault: Id) -> Result<Vec<PairedDevice>> {
    let membership = local_membership(db, vault)?;
    let (current, _) = sync_keys::local_identity(db, root, &membership)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "device management needs an ordinary identity",
        )
    })?;
    sync_log::device_ids(db)?
        .into_iter()
        .map(|device_id| {
            let member = membership.device(&device_id).ok_or_else(|| {
                Error::new(
                    ChurStatus::CatalogCorrupt,
                    "stored device is absent from membership",
                )
            })?;
            let retry_available: bool = db
                .connection()
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM device_pairing_revocations WHERE device_id = ?1)",
                    [device_id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    map_sqlite(error, "revocation retry availability could not be read")
                })?;
            Ok(PairedDevice {
                device_id,
                fingerprint: chur_sync_protocol::identity::fingerprint(
                    &vault,
                    &device_id,
                    member.signing_public_key(),
                    member.hpke_public_key(),
                ),
                active: member.status() == DeviceStatus::Active,
                current: device_id == current,
                retry_available,
            })
        })
        .collect()
}

/// Revokes a peer at its latest accepted branch. The local signer cannot revoke
/// itself. The signed operation and retry artifacts commit together.
pub fn prepare_revoke(
    db: &mut CatalogDb,
    root: &Key,
    vault: Id,
    target: Id,
    now_ms: u64,
) -> Result<PreparedRevocation> {
    let membership = local_membership(db, vault)?;
    let (issuer, identity) =
        sync_keys::local_identity(db, root, &membership)?.ok_or_else(|| {
            Error::new(
                ChurStatus::RecoveryRequired,
                "device revocation needs an ordinary identity",
            )
        })?;
    ensure!(
        target != issuer,
        InvalidInput,
        "the local device cannot revoke itself"
    );
    let cached: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = db.connection().query_row(
        "SELECT checkpoint, revocation, operation FROM device_pairing_revocations WHERE device_id = ?1",
        [target.as_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional().map_err(|error| map_sqlite(error, "revocation retry state could not be read"))?;
    if let Some((checkpoint, revocation, operation)) = cached {
        ensure!(
            !membership.is_active(&target),
            CatalogCorrupt,
            "cached revocation has an active target"
        );
        return Ok(PreparedRevocation {
            checkpoint,
            revocation,
            operation,
        });
    }
    ensure!(
        membership.is_active(&target),
        InvalidInput,
        "revocation target is absent or already revoked"
    );
    let mut log = sync_log::load(db, &membership)?;
    let head = log.head(&target).unwrap_or((0, [0; 32]));
    let checkpoint =
        log.issue_own_checkpoint(db, &membership, &issuer, identity.signing_key(), now_ms)?;
    let revocation = RevocationRecord::new(
        vault,
        target,
        head.0,
        head.1,
        membership.generation().checked_add(1).ok_or_else(|| {
            Error::new(
                ChurStatus::ResourceLimitExceeded,
                "membership generation is exhausted",
            )
        })?,
        issuer,
        *membership.commitment(),
    )?
    .sign(identity.signing_key());
    let domain = KeyDomain::root(root, &vault)?;
    let payload = OperationPayload::new(vault, 0, PayloadBody::RevokeDevice(revocation.clone()))?;
    let operation = log.author(
        random::id()?,
        vault,
        issuer,
        *domain.selector(),
        domain.operation_key(),
        Nonce::random()?,
        &payload.encode(),
        identity.signing_key(),
        &membership,
    )?;
    let prepared = PreparedRevocation {
        checkpoint: checkpoint.encode(),
        revocation: revocation.encode(),
        operation: operation.encode(),
    };
    ensure!(log.accept_with(db, &operation, &membership, |tx| {
        sync_membership::project_revocation(tx, &membership, &revocation, &issuer)?;
        tx.execute("INSERT INTO device_pairing_revocations(device_id, checkpoint, revocation, operation) VALUES (?1, ?2, ?3, ?4)",
            params![target.as_bytes().as_slice(), &prepared.checkpoint, &prepared.revocation, &prepared.operation])
            .map_err(|error| map_sqlite(error, "revocation retry state could not be committed"))?;
        Ok(())
    })? == ApplyOutcome::Applied, InternalFailure, "fresh peer revocation was not applied");
    Ok(prepared)
}

/// Generates one pending ordinary identity in the encrypted restored catalog.
/// Repeated calls return the same public request. The recovery signer stays active.
pub fn prepare_request(db: &mut CatalogDb, root: &Key, vault: Id) -> Result<PairingRequest> {
    let membership = local_membership(db, vault)?;
    sync_keys::portable_identity_envelope(db, root, &membership)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "pairing requires a restored recovery identity",
        )
    })?;
    let stored: Option<Vec<u8>> = db
        .connection()
        .query_row(
            "SELECT request FROM device_pairing_pending WHERE only_row = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "pending pairing request could not be read"))?;
    if let Some(bytes) = stored {
        let request = PairingRequest::decode(&bytes)?;
        request.verify_root(root)?;
        return Ok(request);
    }
    let identity = DeviceIdentity::generate()?;
    let request = PairingRequest::new(root, vault, random::id()?, random::id()?, &identity)?;
    let envelope = DeviceIdentityEnvelope::seal_for_local(
        root,
        vault,
        *request.device_id(),
        1,
        Nonce::random()?,
        &identity,
    )?;
    db.transaction(|tx| {
        tx.execute(
            "INSERT INTO device_pairing_pending VALUES (1, ?1, ?2, NULL, NULL, 0)",
            params![request.encode(), envelope.encode()],
        )
        .map_err(|error| map_sqlite(error, "pending pairing identity could not be stored"))?;
        Ok(())
    })?;
    Ok(request)
}

/// Approves a fingerprint-verified request using the current ordinary signer.
/// The membership operation and stable encrypted response commit together.
pub fn approve(
    db: &mut CatalogDb,
    root: &Key,
    vault: Id,
    request: &PairingRequest,
    now_ms: u64,
) -> Result<PreparedPair> {
    ensure!(
        request.vault_id() == &vault,
        InvalidInput,
        "pairing request belongs to another vault"
    );
    request.verify_root(root)?;
    let membership = local_membership(db, vault)?;
    let (issuer_device, identity) =
        sync_keys::local_identity(db, root, &membership)?.ok_or_else(|| {
            Error::new(
                ChurStatus::RecoveryRequired,
                "pairing approval needs an ordinary identity",
            )
        })?;
    let cached = db.connection().query_row(
        "SELECT request, checkpoint, enrollment, operation, approval FROM device_pairing_approvals WHERE request_id = ?1",
        [request.request_id().as_bytes().as_slice()], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?)),
    ).optional().map_err(|error| map_sqlite(error, "pairing approval cache could not be read"))?;
    if let Some((previous, checkpoint, enrollment, operation, approval)) = cached {
        ensure!(
            previous == request.encode(),
            Conflict,
            "pairing request was reused for another approval"
        );
        ensure!(
            membership.is_active(request.device_id()),
            AuthenticationFailed,
            "approved device is no longer active"
        );
        return Ok(PreparedPair {
            checkpoint,
            enrollment,
            operation,
            approval,
        });
    }
    ensure!(
        membership.device(request.device_id()).is_none(),
        Conflict,
        "pairing device is already enrolled"
    );
    // Fail before publishing or checkpointing; accept_enrollment stays authoritative.
    ensure!(
        membership.active_device_ids().count() < chur_core::limits::sync::ACTIVE_DEVICES_MAX,
        ResourceLimitExceeded,
        "vault already has the maximum number of active devices"
    );
    // Publish inherited local objects before the checkpoint. Otherwise the new
    // source replica could independently author a second creation for one ID.
    for collection in own_sync::collection_ids(db)? {
        let mut after = [0; 16];
        loop {
            let candidates = sharing_publication::candidates(db, &collection, &after)?;
            if candidates.is_empty() {
                break;
            }
            for candidate in candidates {
                after = *candidate.object_id.as_bytes();
                own_sync::publish(db, root, vault, collection, &[candidate])?;
            }
        }
    }
    let mut log = sync_log::load(db, &membership)?;
    let checkpoint = log.issue_own_checkpoint(
        db,
        &membership,
        &issuer_device,
        identity.signing_key(),
        now_ms,
    )?;
    let head = log
        .head(&issuer_device)
        .ok_or_else(|| Error::new(ChurStatus::CatalogCorrupt, "pairing issuer has no head"))?;
    let enrollment = EnrollmentRecord::new(
        vault,
        *request.device_id(),
        *request.signing_public_key(),
        *request.hpke_public_key(),
        head.0.checked_add(1).ok_or_else(|| {
            Error::new(
                ChurStatus::ResourceLimitExceeded,
                "pairing issuer sequence is exhausted",
            )
        })?,
        issuer_device,
        membership.generation().checked_add(1).ok_or_else(|| {
            Error::new(
                ChurStatus::ResourceLimitExceeded,
                "pairing membership is exhausted",
            )
        })?,
        *membership.commitment(),
        checkpoint.commitment(),
    )?
    .sign(identity.signing_key());
    let domain = KeyDomain::root(root, &vault)?;
    let payload = OperationPayload::new(vault, 0, PayloadBody::AddDevice(enrollment.clone()))?;
    let operation = log.author(
        random::id()?,
        vault,
        issuer_device,
        *domain.selector(),
        domain.operation_key(),
        Nonce::random()?,
        &payload.encode(),
        identity.signing_key(),
        &membership,
    )?;
    payload.validate_for_operation(&operation, &vault, 0)?;
    let credentials = encode_credentials(
        request,
        &checkpoint.encode(),
        &enrollment.encode(),
        &operation.encode(),
    )?;
    let approval = PairingApproval::seal(
        request,
        issuer_device,
        authority_records(db)?,
        &identity,
        &credentials,
    )?
    .encode()?;
    let prepared = PreparedPair {
        checkpoint: checkpoint.encode(),
        enrollment: enrollment.encode(),
        operation: operation.encode(),
        approval,
    };
    ensure!(
        log.accept_with(db, &operation, &membership, |tx| {
            sync_membership::project_enrollment(
                tx,
                &membership,
                &enrollment,
                &issuer_device,
                operation.device_sequence(),
            )?;
            tx.execute(
                "INSERT INTO device_pairing_approvals VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    request.request_id().as_bytes().as_slice(),
                    request.encode(),
                    &prepared.checkpoint,
                    &prepared.enrollment,
                    &prepared.operation,
                    &prepared.approval
                ],
            )
            .map_err(|error| map_sqlite(error, "pairing approval could not be stored"))?;
            Ok(())
        })? == ApplyOutcome::Applied,
        InternalFailure,
        "pairing enrollment was not applied"
    );
    Ok(prepared)
}

/// Verifies authority, exact request and encrypted credentials before network use.
/// A retained pending response makes a failed transport setup safely retryable.
pub fn accept_start(
    db: &mut CatalogDb,
    root: &Key,
    vault: Id,
    encoded: &[u8],
) -> Result<PairCredentials> {
    let (request, envelope, previous, credentials, finalized) = pending(db)?;
    ensure!(
        request.vault_id() == &vault,
        AuthenticationFailed,
        "pairing target belongs to another vault"
    );
    request.verify_root(root)?;
    if let Some(previous) = previous.as_ref() {
        ensure!(
            previous == encoded,
            Conflict,
            "another pairing approval is pending"
        );
    }
    if finalized {
        let membership = local_membership(db, vault)?;
        ensure!(
            membership.is_active(request.device_id()),
            AuthenticationFailed,
            "paired device is revoked"
        );
        return decode_credentials(
            &request,
            credentials.as_deref().ok_or_else(|| {
                Error::new(
                    ChurStatus::CatalogCorrupt,
                    "finalized pairing has no credentials",
                )
            })?,
        )
        .map(|(credentials, _)| credentials);
    }
    let envelope = DeviceIdentityEnvelope::decode(envelope.as_deref().ok_or_else(|| {
        Error::new(
            ChurStatus::CatalogCorrupt,
            "pairing private identity is absent",
        )
    })?)?;
    let identity = envelope.open_for_local(root)?;
    let approval = PairingApproval::decode(encoded)?;
    approval.verify_request(&request)?;
    let authority = validate_authority(db, approval.authority_records())?;
    let issuer = authority
        .device(approval.issuer_device_id())
        .ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "pairing issuer is unknown",
            )
        })?;
    ensure!(
        issuer.status() == DeviceStatus::Active,
        AuthenticationFailed,
        "pairing issuer is revoked"
    );
    let current = local_membership(db, vault)?;
    ensure!(
        current
            .device(approval.issuer_device_id())
            .is_none_or(|member| member.status() == DeviceStatus::Active),
        AuthenticationFailed,
        "pairing issuer was revoked locally"
    );
    let plaintext = approval.open(&identity, issuer.signing_public_key())?;
    let (credentials, operation) = decode_credentials(&request, &plaintext)?;
    let enrollment = EnrollmentRecord::decode(&credentials.enrollment)?;
    let checkpoint = Checkpoint::decode(&credentials.checkpoint)?;
    validate_bootstrap(
        &request,
        &approval,
        &authority,
        &enrollment,
        &checkpoint,
        &operation,
        root,
    )?;
    if previous.is_none() {
        let log = sync_log::load(db, &current)?;
        for device in sync_log::device_ids(db)? {
            // A revoked device's signed cutoff pins its history, and the approver's checkpoint need not name it.
            // The approver's authority may revoke a device that a stale restored membership still lists.
            if !current.is_active(&device) || !authority.is_active(&device) {
                continue;
            }
            for trusted in [log.head(&device), log.floor(&device)]
                .into_iter()
                .flatten()
            {
                ensure!(
                    checkpoint
                        .heads()
                        .iter()
                        .any(|head| head.device_id() == &device
                            && (head.device_sequence() > trusted.0
                                || (head.device_sequence() == trusted.0
                                    && head.operation_digest() == &trusted.1))),
                    SyncHeadRollback,
                    "pairing approval precedes trusted local history"
                );
            }
        }
    }
    db.transaction(|tx| {
        // A restored signer is recovery-only. Its checkpoint is remote evidence
        // once approval starts; ownership must not block newer signed evidence.
        tx.execute("UPDATE sync_checkpoints SET own = 0", []).map_err(|error| map_sqlite(error, "recovered checkpoint ownership could not be retired"))?;
        tx.execute("UPDATE sync_state SET latest_own_checkpoint_commitment = NULL", []).map_err(|error| map_sqlite(error, "recovered checkpoint ownership could not be removed"))?;
        tx.execute("UPDATE device_pairing_pending SET approval = ?1, credentials = ?2 WHERE only_row = 1 AND finalized = 0",
            params![encoded, plaintext.as_slice()]).map_err(|error| map_sqlite(error, "validated pairing credentials could not be stored"))?;
        Ok(())
    })?;
    Ok(credentials)
}

/// Revalidates an unfinished approval after a local lock or process restart.
/// No transport endpoint or credential is recovered; only signed pairing evidence is retained.
pub fn resume(db: &mut CatalogDb, root: &Key, vault: Id) -> Result<Option<PairCredentials>> {
    let approval: Option<Vec<u8>> = db
        .connection()
        .query_row(
            "SELECT approval FROM device_pairing_pending WHERE only_row = 1 AND finalized = 0",
            [],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "pending peer approval could not be read"))?
        .flatten();
    approval
        .map(|bytes| accept_start(db, root, vault, &bytes))
        .transpose()
}

/// Loads the enrolled signer and the active device keys for one direct peer session.
/// An ordinary device trusts its current membership. A restored recovery-only device
/// with a verified pending approval signs with its approved identity and trusts the
/// newer of its local membership and the approval authority.
pub fn peer_credential(db: &mut CatalogDb, root: &Key, vault: Id) -> Result<PeerCredential> {
    let membership = local_membership(db, vault)?;
    let Some((request, envelope, approval)) = approved_pending(db, root, &membership)? else {
        // A restored recovery identity cannot sign until pairing is approved.
        ensure!(
            !sync_keys::is_recovery_only(db, root, &membership)?,
            RecoveryRequired,
            "direct sync needs an ordinary or approved device identity"
        );
        let (device, identity) =
            sync_keys::local_identity(db, root, &membership)?.ok_or_else(|| {
                Error::new(
                    ChurStatus::RecoveryRequired,
                    "direct sync needs an ordinary or approved device identity",
                )
            })?;
        return Ok(PeerCredential::new(
            vault,
            device,
            identity,
            active_keys(&membership),
        ));
    };
    ensure!(
        request.vault_id() == &vault,
        AuthenticationFailed,
        "pairing target belongs to another vault"
    );
    let identity = DeviceIdentityEnvelope::decode(&envelope)?.open_for_local(root)?;
    ensure!(
        identity.signing_public_key() == *request.signing_public_key(),
        CatalogCorrupt,
        "pending pairing identity differs from its request"
    );
    let trusted = trusted_membership(db, membership, &approval)?;
    Ok(PeerCredential::new(
        vault,
        *request.device_id(),
        identity,
        active_keys(&trusted),
    ))
}

/// The membership that a direct peer session trusts at this moment.
///
/// # Errors
///
/// Fails when the local membership is absent or the pending approval does not verify.
pub fn peer_membership(db: &CatalogDb, root: &Key, vault: Id) -> Result<MembershipState> {
    let membership = local_membership(db, vault)?;
    match approved_pending(db, root, &membership)? {
        Some((_, _, approval)) => trusted_membership(db, membership, &approval),
        None => Ok(membership),
    }
}

/// Confirms that an authenticated peer device is active in the membership trusted now.
/// Call it before each served or accepted frame: a device can be revoked after the
/// handshake, while the session credential still holds the earlier key list.
///
/// # Errors
///
/// Returns [`ChurStatus::AuthenticationFailed`] for a revoked or unknown device.
pub fn verify_peer(db: &CatalogDb, root: &Key, vault: Id, device: &Id) -> Result<()> {
    ensure!(
        peer_membership(db, root, vault)?.is_active(device),
        AuthenticationFailed,
        "peer device is revoked or unknown"
    );
    Ok(())
}

/// A pending request, its sealed identity envelope, and its verified approval.
type ApprovedPending = (PairingRequest, Vec<u8>, Vec<u8>);
/// The unfinished approved pairing of a restored recovery-only device. An ordinary
/// identity never signs as a pending request, whatever the pending row holds.
fn approved_pending(
    db: &CatalogDb,
    root: &Key,
    membership: &MembershipState,
) -> Result<Option<ApprovedPending>> {
    if !sync_keys::is_recovery_only(db, root, membership)? {
        return Ok(None);
    }
    match pending(db) {
        Ok((request, Some(envelope), Some(approval), Some(_), false)) => {
            Ok(Some((request, envelope, approval)))
        }
        Ok(_) => Ok(None),
        Err(error) if error.status() == ChurStatus::RecoveryRequired => Ok(None),
        Err(error) => Err(error),
    }
}

/// The newer of the local membership and a verified approval authority. The authority
/// extends the local membership when it is newer. When it is an older prefix, the local
/// membership wins, so a device that was revoked later is not trusted again.
fn trusted_membership(
    db: &CatalogDb,
    local: MembershipState,
    approval: &[u8],
) -> Result<MembershipState> {
    let authority = validate_authority(db, PairingApproval::decode(approval)?.authority_records())?;
    Ok(if authority.generation() > local.generation() {
        authority
    } else {
        local
    })
}

fn active_keys(membership: &MembershipState) -> Vec<(Id, [u8; 32])> {
    membership
        .active_device_ids()
        .filter_map(|device| {
            membership
                .device(device)
                .map(|member| (*device, *member.signing_public_key()))
        })
        .collect()
}

/// Installs the fresh ordinary identity only after downloaded signed prefixes
/// satisfy the enrollment and checkpoint. Private recovery and pending copies
/// are removed in the first fresh ordinary operation's catalog transaction.
pub fn finalize(db: &mut CatalogDb, root: &Key, vault: Id, now_ms: u64) -> Result<Id> {
    let (request, envelope, approval, credentials, finalized) = pending(db)?;
    let membership = local_membership(db, vault)?;
    let member = membership.device(request.device_id()).ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "pairing enrollment has not been downloaded",
        )
    })?;
    ensure!(
        request.vault_id() == &vault
            && member.status() == DeviceStatus::Active
            && member.signing_public_key() == request.signing_public_key()
            && member.hpke_public_key() == request.hpke_public_key(),
        AuthenticationFailed,
        "paired device is not the current active enrolled identity"
    );
    if finalized {
        return Ok(*request.device_id());
    }
    let approval =
        PairingApproval::decode(approval.as_deref().ok_or_else(|| {
            Error::new(ChurStatus::RecoveryRequired, "pairing approval is absent")
        })?)?;
    let authority = validate_authority(db, approval.authority_records())?;
    ensure!(
        membership.is_active(approval.issuer_device_id()),
        AuthenticationFailed,
        "pairing approver is revoked"
    );
    let credentials = credentials
        .ok_or_else(|| Error::new(ChurStatus::CatalogCorrupt, "pairing credentials are absent"))?;
    let (credentials, enrollment_operation) = decode_credentials(&request, &credentials)?;
    let enrollment = EnrollmentRecord::decode(&credentials.enrollment)?;
    let checkpoint = Checkpoint::decode(&credentials.checkpoint)?;
    validate_bootstrap(
        &request,
        &approval,
        &authority,
        &enrollment,
        &checkpoint,
        &enrollment_operation,
        root,
    )?;
    let mut log = sync_log::load(db, &membership)?;
    let recorded = sync_log::record_at(
        db,
        enrollment_operation.device_id(),
        enrollment_operation.device_sequence(),
    )?
    .ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "pairing enrollment operation has not been downloaded",
        )
    })?;
    ensure!(
        recorded == enrollment_operation.encode(),
        AuthenticationFailed,
        "downloaded pairing enrollment differs"
    );
    for head in checkpoint.heads() {
        // Delivery never returns an operation above a revocation cutoff, and its head creates no floor.
        if sync_log::above_revocation_cutoff(&membership, head.device_id(), head.device_sequence())
        {
            continue;
        }
        let record = sync_log::record_at(db, head.device_id(), head.device_sequence())?
            .ok_or_else(|| {
                Error::new(
                    ChurStatus::RecoveryRequired,
                    "pairing checkpoint prefix is incomplete",
                )
            })?;
        ensure!(
            Operation::decode(&record)?.digest() == *head.operation_digest(),
            SyncHeadRollback,
            "pairing checkpoint prefix differs"
        );
    }
    // The downloaded log has validated every stored checkpoint. Keep a newer
    // source checkpoint instead of replacing its floor evidence with approval.
    let existing: Option<Vec<u8>> = db
        .connection()
        .query_row(
            "SELECT record FROM sync_checkpoints WHERE issuer_device_id = ?1",
            [checkpoint.issuer_device_id().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| map_sqlite(error, "pairing checkpoint evidence could not be read"))?;
    let checkpoint = if let Some(existing) = existing {
        let existing = Checkpoint::decode(&existing)?;
        if sync_log::checkpoint_covers(&existing, &checkpoint, &membership) {
            existing
        } else {
            ensure!(
                sync_log::checkpoint_covers(&checkpoint, &existing, &membership),
                SyncHeadRollback,
                "pairing checkpoint conflicts with newer evidence"
            );
            checkpoint
        }
    } else {
        checkpoint
    };
    let envelope = DeviceIdentityEnvelope::decode(envelope.as_deref().ok_or_else(|| {
        Error::new(
            ChurStatus::CatalogCorrupt,
            "pending pairing identity is absent",
        )
    })?)?;
    let identity = envelope.open_for_local(root)?;
    let domain = KeyDomain::root(root, &vault)?;
    let ready_payload = OperationPayload::new(vault, 0, PayloadBody::DeviceReady)?;
    let ready = log.author(
        random::id()?,
        vault,
        *request.device_id(),
        *domain.selector(),
        domain.operation_key(),
        Nonce::random()?,
        &ready_payload.encode(),
        identity.signing_key(),
        &membership,
    )?;
    ensure!(
        ready.device_sequence() == 1,
        Conflict,
        "new pairing identity already authored operations"
    );
    ensure!(log.accept_with(db, &ready, &membership, |tx| {
        tx.execute("DELETE FROM sync_identity_envelopes", []).map_err(|error| map_sqlite(error, "recovery identities could not be removed"))?;
        sync_keys::project_local_identity(tx, &envelope)?;
        tx.execute("UPDATE sync_checkpoints SET own = 0", []).map_err(|error| map_sqlite(error, "restored own checkpoints could not be retired"))?;
        tx.execute("UPDATE sync_state SET latest_own_checkpoint_commitment = NULL", []).map_err(|error| map_sqlite(error, "restored checkpoint ownership could not be removed"))?;
        tx.execute("INSERT INTO sync_checkpoints(issuer_device_id, commitment, record, accepted_at_ms, own) VALUES (?1, ?2, ?3, ?4, 0)
            ON CONFLICT(issuer_device_id) DO UPDATE SET commitment = excluded.commitment, record = excluded.record, accepted_at_ms = excluded.accepted_at_ms, own = 0",
            params![checkpoint.issuer_device_id().as_bytes().as_slice(), checkpoint.commitment().as_slice(), checkpoint.encode(),
                as_sqlite_integer(now_ms, "pairing completion time is too large")?]).map_err(|error| map_sqlite(error, "pairing freshness checkpoint could not be stored"))?;
        for head in checkpoint.heads() {
            tx.execute("UPDATE sync_heads SET floor_sequence = ?1, floor_digest = ?2 WHERE device_id = ?3 AND (floor_sequence IS NULL OR floor_sequence <= ?1)",
                params![as_sqlite_integer(head.device_sequence(), "pairing floor is too large")?, head.operation_digest().as_slice(), head.device_id().as_bytes().as_slice()])
                .map_err(|error| map_sqlite(error, "pairing freshness floor could not be stored"))?;
        }
        tx.execute("UPDATE device_pairing_pending SET identity_envelope = NULL, finalized = 1 WHERE only_row = 1", [])
            .map_err(|error| map_sqlite(error, "pending pairing private copy could not be removed"))?;
        Ok(())
    })? == ApplyOutcome::Applied, InternalFailure, "fresh pairing identity was not installed");
    Ok(*request.device_id())
}

fn local_membership(db: &CatalogDb, vault: Id) -> Result<MembershipState> {
    let membership = sync_membership::load(db)?
        .ok_or_else(|| Error::new(ChurStatus::RecoveryRequired, "pairing membership is absent"))?;
    ensure!(
        membership.vault_id() == &vault,
        AuthenticationFailed,
        "pairing membership belongs to another vault"
    );
    Ok(membership)
}

type PendingPair = (
    PairingRequest,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    bool,
);
fn pending(db: &CatalogDb) -> Result<PendingPair> {
    let row = db.connection().query_row("SELECT request, identity_envelope, approval, credentials, finalized FROM device_pairing_pending WHERE only_row = 1", [],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?, row.get::<_, Option<Vec<u8>>>(2)?, row.get::<_, Option<Vec<u8>>>(3)?, row.get::<_, bool>(4)?)))
        .optional().map_err(|error| map_sqlite(error, "pending pairing state could not be read"))?
        .ok_or_else(|| Error::new(ChurStatus::RecoveryRequired, "pairing request has not been prepared"))?;
    Ok((PairingRequest::decode(&row.0)?, row.1, row.2, row.3, row.4))
}

fn authority_records(db: &CatalogDb) -> Result<Vec<Vec<u8>>> {
    let mut statement = db.connection().prepare("SELECT record_kind, record FROM sync_membership_records ORDER BY membership_generation LIMIT ?1")
        .map_err(|error| map_sqlite(error, "pairing authority proof could not be prepared"))?;
    let rows = statement
        .query_map([(AUTHORITY_RECORDS_MAX + 1) as i64], |row| {
            Ok((row.get::<_, u8>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|error| map_sqlite(error, "pairing authority proof could not be read"))?;
    let mut records = Vec::new();
    for row in rows {
        let (kind, record) =
            row.map_err(|error| map_sqlite(error, "pairing authority row failed"))?;
        let mut bytes = vec![kind];
        bytes.extend_from_slice(&record);
        records.push(bytes);
    }
    ensure!(
        records.len() <= AUTHORITY_RECORDS_MAX,
        ResourceLimitExceeded,
        "pairing authority proof exceeds its bound"
    );
    Ok(records)
}

fn validate_authority(db: &CatalogDb, records: &[Vec<u8>]) -> Result<MembershipState> {
    let current = sync_membership::load(db)?.ok_or_else(|| {
        Error::new(
            ChurStatus::RecoveryRequired,
            "pairing trust anchor is absent",
        )
    })?;
    let mut state: Option<MembershipState> = None;
    let mut anchored = false;
    for record in records {
        let (&kind, bytes) = record.split_first().ok_or_else(|| {
            Error::new(ChurStatus::InvalidInput, "empty pairing authority record")
        })?;
        match kind {
            1 => {
                let enrollment = EnrollmentRecord::decode(bytes)?;
                if let Some(state) = state.as_mut() {
                    state.accept_enrollment(
                        &enrollment,
                        enrollment.issuer_device_id(),
                        enrollment.created_sequence(),
                    )?;
                } else {
                    state = Some(MembershipState::bootstrap(&enrollment)?);
                }
            }
            2 => {
                let revocation = RevocationRecord::decode(bytes)?;
                state
                    .as_mut()
                    .ok_or_else(|| {
                        Error::new(
                            ChurStatus::AuthenticationFailed,
                            "pairing authority starts with revocation",
                        )
                    })?
                    .accept_revocation(&revocation, revocation.issuer_device_id())?;
            }
            _ => {
                return Err(Error::new(
                    ChurStatus::InvalidInput,
                    "pairing authority kind differs",
                ));
            }
        }
        if let Some(state) = state.as_ref() {
            ensure!(
                state.vault_id() == current.vault_id(),
                AuthenticationFailed,
                "pairing authority belongs to another vault"
            );
            if state.generation() <= current.generation() {
                let known: Vec<u8> = db.connection().query_row("SELECT commitment FROM sync_membership_records WHERE membership_generation = ?1",
                    [as_sqlite_integer(state.generation(), "pairing generation is too large")?], |row| row.get(0))
                    .map_err(|error| map_sqlite(error, "pairing trust anchor could not be read"))?;
                ensure!(
                    known == state.commitment().as_slice(),
                    AuthenticationFailed,
                    "pairing authority does not extend trusted membership"
                );
                anchored = true;
            }
        }
    }
    ensure!(
        anchored,
        AuthenticationFailed,
        "pairing authority has no trusted anchor"
    );
    state.ok_or_else(|| {
        Error::new(
            ChurStatus::AuthenticationFailed,
            "pairing authority proof is empty",
        )
    })
}

fn encode_credentials(
    request: &PairingRequest,
    checkpoint: &[u8],
    enrollment: &[u8],
    operation: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut writer = Writer::new();
    writer
        .u16(2)
        .fixed(&request.digest())
        .id(request.device_id());
    writer
        .variable(checkpoint)?
        .variable(enrollment)?
        .variable(operation)?;
    Ok(Zeroizing::new(writer.finish()))
}
fn decode_credentials(
    request: &PairingRequest,
    bytes: &[u8],
) -> Result<(PairCredentials, Operation)> {
    let mut reader = Reader::new(bytes, ChurStatus::InvalidInput);
    ensure!(
        reader.u16()? == 2
            && reader.fixed::<32>()? == request.digest()
            && reader.id()? == *request.device_id(),
        AuthenticationFailed,
        "pairing credentials do not match their request"
    );
    let checkpoint = reader.variable(APPROVAL_MAX as u32)?.to_vec();
    let enrollment = reader.variable(APPROVAL_MAX as u32)?.to_vec();
    let operation = Operation::decode(reader.variable(APPROVAL_MAX as u32)?)?;
    reader.finish()?;
    Ok((
        PairCredentials {
            device_id: *request.device_id(),
            enrollment,
            checkpoint,
        },
        operation,
    ))
}
fn validate_bootstrap(
    request: &PairingRequest,
    approval: &PairingApproval,
    authority: &MembershipState,
    enrollment: &EnrollmentRecord,
    checkpoint: &Checkpoint,
    operation: &Operation,
    root: &Key,
) -> Result<()> {
    let issuer = authority
        .device(approval.issuer_device_id())
        .ok_or_else(|| Error::new(ChurStatus::AuthenticationFailed, "pairing issuer is absent"))?;
    approval.verify(issuer.signing_public_key())?;
    checkpoint.verify_signature(issuer.signing_public_key())?;
    let head = checkpoint
        .heads()
        .iter()
        .find(|head| head.device_id() == approval.issuer_device_id())
        .ok_or_else(|| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "pairing checkpoint lacks its issuer",
            )
        })?;
    ensure!(
        checkpoint.vault_id() == request.vault_id()
            && checkpoint.issuer_device_id() == approval.issuer_device_id()
            && checkpoint.membership_generation() == authority.generation()
            && checkpoint.membership_commitment() == authority.commitment()
            && enrollment.vault_id() == request.vault_id()
            && enrollment.device_id() == request.device_id()
            && enrollment.signing_public_key() == request.signing_public_key()
            && enrollment.hpke_public_key() == request.hpke_public_key()
            && enrollment.issuer_device_id() == approval.issuer_device_id()
            && enrollment.bootstrap_checkpoint_commitment() == &checkpoint.commitment()
            && enrollment.membership_generation() == authority.generation().saturating_add(1)
            && enrollment.previous_membership_commitment() == authority.commitment()
            && enrollment.created_sequence() == head.device_sequence().saturating_add(1)
            && operation.device_id() == approval.issuer_device_id()
            && operation.device_sequence() == enrollment.created_sequence()
            && operation.previous_operation_hash() == head.operation_digest(),
        AuthenticationFailed,
        "pairing bootstrap records do not bind the approved identity and freshness floor"
    );
    enrollment.verify_signature(issuer.signing_public_key())?;
    operation.verify_signature(issuer.signing_public_key())?;
    let keys = KeyDirectory::new(root, request.vault_id())?;
    let payload = OperationPayload::open_for_operation(operation, &keys)?;
    ensure!(
        matches!(payload.body(), PayloadBody::AddDevice(record) if record.encode() == enrollment.encode()),
        AuthenticationFailed,
        "pairing outer operation does not contain its enrollment"
    );
    Ok(())
}

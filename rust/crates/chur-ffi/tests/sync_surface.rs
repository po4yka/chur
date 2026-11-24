//! Locked staging and unlocked processing through the real C ABI.

#![allow(clippy::expect_used)]
#![expect(unsafe_code, reason = "the test drives the C ABI pointer contract")]

use chur_catalog::sync_receive;
use chur_ffi::api::{chur_runtime_close, chur_runtime_open, chur_session_close, chur_vault_unlock};
use chur_ffi::records::{ChurRuntimeConfigV1, ChurUnlockRequestV1};
use chur_ffi::sync::{
    ChurSyncReportV1, chur_sync_fork_acknowledge, chur_sync_fork_state, chur_sync_process,
    chur_sync_stage,
};
use chur_sync_protocol::KeyDomain;
use chur_sync_protocol::identity::DeviceIdentity;
use chur_sync_protocol::membership::EnrollmentRecord;
use chur_sync_protocol::operation::Operation;
use chur_sync_protocol::payload::{OperationPayload, PayloadBody};

const PASSWORD: &[u8] = b"correct horse battery staple";

#[test]
fn locked_stage_is_validated_and_removed_after_unlock() {
    let path = std::env::temp_dir().join(format!(
        "chur-ffi-sync-{}",
        chur_crypto::random::id().expect("random id").to_hex()
    ));
    let root = chur_catalog::paths::VaultRoot::new(&path);
    let mut session = chur_catalog::vault::create(&root, PASSWORD, 1)
        .expect("create")
        .activate()
        .expect("activate");
    let identity = DeviceIdentity::generate().expect("identity");
    let vault_id = session.vault_id();
    let device_id = chur_crypto::random::id().expect("device id");
    let enrollment = EnrollmentRecord::initial(
        vault_id,
        device_id,
        identity.signing_public_key(),
        identity.hpke_public_key(),
    )
    .expect("enrollment")
    .sign(identity.signing_key());
    let root_secret = chur_crypto::Key::new(*session.root_secret().expect("root").expose());
    let (_, _, operation) = sync_receive::provision_initial_membership(
        session.catalog().expect("catalog"),
        &root_secret,
        identity.signing_key(),
        &enrollment,
    )
    .expect("provision sync");
    drop(session);

    let path_bytes = path.to_str().expect("UTF-8 path").as_bytes();
    let config = ChurRuntimeConfigV1 {
        root_path: path_bytes.as_ptr(),
        root_path_length: path_bytes.len() as u32,
    };
    let mut runtime = 0;
    assert_eq!(unsafe { chur_runtime_open(&config, &mut runtime) }, 0);
    let bytes = operation.encode();
    assert_eq!(
        unsafe {
            chur_sync_stage(
                runtime,
                vault_id.as_bytes().as_ptr(),
                1,
                2,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        },
        0
    );
    let mut page = Vec::new();
    page.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    page.extend_from_slice(&bytes);
    page.extend_from_slice(&3u32.to_be_bytes());
    page.extend_from_slice(&[1, 2, 3]);
    let mut malformed = page.clone();
    malformed.pop();
    assert_eq!(
        unsafe {
            chur_sync_stage(
                runtime,
                vault_id.as_bytes().as_ptr(),
                3,
                2,
                malformed.as_ptr(),
                malformed.len() as u32,
            )
        },
        chur_core::ChurStatus::InvalidInput as i32
    );
    for _ in 0..2 {
        assert_eq!(
            unsafe {
                chur_sync_stage(
                    runtime,
                    vault_id.as_bytes().as_ptr(),
                    3,
                    2,
                    page.as_ptr(),
                    page.len() as u32,
                )
            },
            0
        );
    }
    let unlock = ChurUnlockRequestV1 {
        factor: 1,
        reserved: [0; 3],
        secret: PASSWORD.as_ptr(),
        secret_length: PASSWORD.len() as u32,
    };
    let mut session = 0;
    assert_eq!(
        unsafe { chur_vault_unlock(runtime, &unlock, &mut session) },
        0
    );
    let mut report = ChurSyncReportV1 {
        applied: 0,
        duplicates: 0,
        pending: 0,
        rejected: 0,
        first_rejection: 0,
        reserved: [9; 4],
    };

    assert_eq!(unsafe { chur_sync_process(session, 2, &mut report) }, 0);
    assert_eq!(report.duplicates, 1);
    assert_eq!(report.rejected, 1);
    assert_eq!(report.pending, 0);
    assert_eq!(report.reserved, [0; 4]);
    assert_eq!(unsafe { chur_session_close(session) }, 0);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, 0);
    std::fs::remove_dir_all(path).expect("cleanup");
}

/// `ROLLBACK_PROTECTION.md` §4 through §6.24: the fork state outlives the pass
/// that found it and a restart, and acknowledging it leaves the chain frozen.
#[test]
fn a_fork_state_survives_a_restart_and_acknowledging_it_keeps_the_chain_frozen() {
    let path = std::env::temp_dir().join(format!(
        "chur-ffi-sync-fork-{}",
        chur_crypto::random::id().expect("random id").to_hex()
    ));
    let root = chur_catalog::paths::VaultRoot::new(&path);
    let mut session = chur_catalog::vault::create(&root, PASSWORD, 1)
        .expect("create")
        .activate()
        .expect("activate");
    let identity = DeviceIdentity::generate().expect("identity");
    let vault_id = session.vault_id();
    let device_id = chur_crypto::random::id().expect("device id");
    let enrollment = EnrollmentRecord::initial(
        vault_id,
        device_id,
        identity.signing_public_key(),
        identity.hpke_public_key(),
    )
    .expect("enrollment")
    .sign(identity.signing_key());
    let root_secret = chur_crypto::Key::new(*session.root_secret().expect("root").expose());
    let catalog = session.catalog().expect("catalog");
    let (_, _, accepted) = sync_receive::provision_initial_membership(
        catalog,
        &root_secret,
        identity.signing_key(),
        &enrollment,
    )
    .expect("provision sync");
    // A second signed record at the sequence the device already used, in a
    // collection this vault holds the key of, as the chur-catalog fork case.
    let collection_id = chur_crypto::random::id().expect("collection id");
    let collection_key = chur_crypto::Key::new([31; 32]);
    let envelope = chur_format::envelope::CollectionKeyEnvelope::seal(
        &root_secret,
        vault_id,
        collection_id,
        1,
        1,
        chur_crypto::Nonce::new([32; 24]),
        &collection_key,
    )
    .expect("envelope");
    chur_catalog::store::put_collection_with_envelope(
        catalog,
        &chur_catalog::model::Collection {
            collection_id,
            current_epoch: 1,
            policy_type: chur_catalog::model::COLLECTION_POLICY_VAULT_DEFAULT,
            created_revision: 1,
            status: chur_catalog::model::COLLECTION_STATUS_ACTIVE,
        },
        1,
        &envelope.encode(),
    )
    .expect("collection");
    let domain = KeyDomain::collection(&collection_key, &collection_id, 1).expect("domain");
    let payload = OperationPayload::new(
        collection_id,
        1,
        PayloadBody::CreateAlbum {
            album_id: chur_crypto::random::id().expect("album id"),
            name: "fork".to_owned(),
        },
    )
    .expect("payload")
    .encode();
    let fork = Operation::seal(
        chur_crypto::random::id().expect("operation id"),
        vault_id,
        device_id,
        1,
        [0; 32],
        Vec::new(),
        *domain.selector(),
        domain.operation_key(),
        chur_crypto::Nonce::new([21; 24]),
        &payload,
    )
    .expect("fork")
    .sign(identity.signing_key());
    drop(session);

    let path_bytes = path.to_str().expect("UTF-8 path").as_bytes();
    let config = ChurRuntimeConfigV1 {
        root_path: path_bytes.as_ptr(),
        root_path_length: path_bytes.len() as u32,
    };
    let unlock = ChurUnlockRequestV1 {
        factor: 1,
        reserved: [0; 3],
        secret: PASSWORD.as_ptr(),
        secret_length: PASSWORD.len() as u32,
    };
    let open = || {
        let mut runtime = 0;
        assert_eq!(unsafe { chur_runtime_open(&config, &mut runtime) }, 0);
        let mut session = 0;
        assert_eq!(
            unsafe { chur_vault_unlock(runtime, &unlock, &mut session) },
            0
        );
        (runtime, session)
    };
    let close = |(runtime, session): (u64, u64)| {
        assert_eq!(unsafe { chur_session_close(session) }, 0);
        assert_eq!(unsafe { chur_runtime_close(runtime) }, 0);
    };
    let pass = |runtime: u64, session: u64, record: &[u8]| {
        let staged = unsafe {
            chur_sync_stage(
                runtime,
                vault_id.as_bytes().as_ptr(),
                1,
                2,
                record.as_ptr(),
                record.len() as u32,
            )
        };
        assert_eq!(staged, 0);
        let mut report = ChurSyncReportV1 {
            applied: 0,
            duplicates: 0,
            pending: 0,
            rejected: 0,
            first_rejection: 0,
            reserved: [0; 4],
        };
        assert_eq!(unsafe { chur_sync_process(session, 2, &mut report) }, 0);
        report.first_rejection
    };
    let state = |session: u64| {
        let (mut detected, mut acknowledged) = (9, 9);
        assert_eq!(
            unsafe { chur_sync_fork_state(session, &mut detected, &mut acknowledged) },
            0
        );
        (detected, acknowledged)
    };
    let fork_status = chur_core::ChurStatus::SyncChainFork.as_i32();

    let (runtime, session) = open();
    assert_eq!(state(session), (0, 0));
    assert_eq!(pass(runtime, session, &fork.encode()), fork_status);
    assert_eq!(state(session), (1, 0));
    close((runtime, session));

    // The pass reported the fork once; after a restart the state still says so.
    let (runtime, session) = open();
    assert_eq!(state(session), (1, 0));
    assert_eq!(chur_sync_fork_acknowledge(session), 0);
    assert_eq!(state(session), (0, 1));
    // The record the chain already accepted is a duplicate on a live chain;
    // on a frozen one it is refused as the fork it belongs to.
    assert_eq!(pass(runtime, session, &accepted.encode()), fork_status);
    assert_eq!(state(session), (0, 1));
    close((runtime, session));
    std::fs::remove_dir_all(path).expect("cleanup");
}

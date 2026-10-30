//! Sharing identity provisioning through the real C ABI.

#![allow(clippy::expect_used)]
#![expect(unsafe_code, reason = "the test drives the C ABI pointer contract")]

use chur_ffi::api::{chur_runtime_close, chur_runtime_open, chur_session_close, chur_vault_unlock};
use chur_ffi::records::{ChurRuntimeConfigV1, ChurUnlockRequestV1};
use chur_ffi::sharing::{
    chur_object_key_accept, chur_object_key_issue, chur_object_key_request, chur_sharing_accept,
    chur_sharing_download_append, chur_sharing_download_finish, chur_sharing_download_offset,
    chur_sharing_identity, chur_sharing_inspect_enrollment, chur_sharing_overview,
    chur_sharing_prepare, chur_sharing_prepare_device, chur_sharing_receive, chur_sharing_revoke,
};
use chur_ffi::sharing_publish::{chur_sharing_author, chur_sharing_publication};
use chur_format::codec::{Reader, Writer};
use chur_format::constants::MediaClass;
use chur_format::envelope::CollectionKeyEnvelope;
use chur_media::import::{CanonicalMedia, SourceCapability, import_bytes};
use chur_sync_protocol::{
    collection_membership::{CollectionMembershipAction, CollectionMembershipRecord},
    grant::{CollectionGrant, PermissionProfile},
    identity::fingerprint,
    membership::EnrollmentRecord,
    operation::Operation,
};
use sha2::{Digest, Sha256};

const PASSWORD: &[u8] = b"correct horse battery staple";

#[test]
fn identity_provisioning_is_private_atomic_and_idempotent() {
    let path = std::env::temp_dir().join(format!(
        "chur-ffi-sharing-{}",
        chur_crypto::random::id().expect("random id").to_hex()
    ));
    let root = chur_catalog::paths::VaultRoot::new(&path);
    drop(
        chur_catalog::vault::create(&root, PASSWORD, 1)
            .expect("create")
            .activate()
            .expect("activate"),
    );
    let mut direct = chur_catalog::vault::unlock_with_password(&root, PASSWORD, 1).expect("unlock");
    let source_vault_id = direct.vault_id();
    let root_key = chur_crypto::Key::new(*direct.root_secret().expect("root").expose());
    let collection_id = chur_crypto::random::id().expect("collection");
    let collection_key = chur_crypto::Key::new([31; 32]);
    let envelope = CollectionKeyEnvelope::seal(
        &root_key,
        source_vault_id,
        collection_id,
        1,
        1,
        chur_crypto::Nonce::new([32; 24]),
        &collection_key,
    )
    .expect("collection envelope");
    chur_catalog::store::put_collection_with_envelope(
        direct.catalog().expect("catalog"),
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
    let plaintext = zeroize::Zeroizing::new(vec![7u8; 4096]);
    let shared_object_id = import_bytes(
        &mut direct,
        SourceCapability {
            requested_object_id: None,
            seekable: true,
            known_length: Some(plaintext.len() as u64),
            content_type_hint: "image/jpeg".to_owned(),
            original_filename: Some("shared.jpg".to_owned()),
            capture_time_ms: Some(1),
        },
        CanonicalMedia {
            media_class: MediaClass::Image,
            width: 10,
            height: 10,
            duration_ms: 0,
        },
        "image/jpeg",
        &plaintext,
        1,
    )
    .expect("import before share");
    let shared_stream =
        chur_catalog::store::streams(direct.catalog_ref().expect("catalog"), &shared_object_id)
            .expect("streams")
            .into_iter()
            .find(|stream| stream.stream_kind == chur_format::constants::StreamKind::Original)
            .expect("original stream");
    let ciphertext =
        std::fs::read(root.container(&direct.object_store_id(), &shared_stream.container_path_id))
            .expect("source ciphertext");
    drop(direct);
    let path_bytes = path.to_str().expect("UTF-8 path").as_bytes();
    let config = ChurRuntimeConfigV1 {
        root_path: path_bytes.as_ptr(),
        root_path_length: path_bytes.len() as u32,
    };
    let mut runtime = 0;
    assert_eq!(unsafe { chur_runtime_open(&config, &mut runtime) }, 0);
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

    let mut bytes = vec![0u8; 4096];
    let mut written = 0;
    assert_eq!(
        unsafe { chur_sharing_identity(session, bytes.as_mut_ptr(), bytes.len(), &mut written) },
        0
    );
    bytes.truncate(written);
    let mut reader = Reader::new(&bytes, chur_core::ChurStatus::NonCanonicalEncoding);
    assert_eq!(reader.u16().expect("version"), 1);
    let vault_id = reader.id().expect("vault");
    let device_id = reader.id().expect("device");
    let signing = reader.fixed::<32>().expect("signing key");
    let hpke = reader.fixed::<32>().expect("HPKE key");
    let display = reader.variable(49).expect("fingerprint");
    let enrollment = EnrollmentRecord::decode(reader.variable(270).expect("enrollment"))
        .expect("valid enrollment");
    let operation = Operation::decode(reader.variable(16_777_216).expect("operation"))
        .expect("valid operation");
    reader.finish().expect("complete record");
    assert_eq!(enrollment.vault_id(), &vault_id);
    assert_eq!(enrollment.device_id(), &device_id);
    assert_eq!(enrollment.signing_public_key(), &signing);
    assert_eq!(enrollment.hpke_public_key(), &hpke);
    assert_eq!(
        display,
        fingerprint(&vault_id, &device_id, &signing, &hpke).as_bytes()
    );
    assert_eq!(operation.device_id(), &device_id);
    assert_eq!(operation.device_sequence(), 1);

    let mut overview = vec![0u8; 512 * 1024];
    assert_eq!(
        unsafe {
            chur_sharing_overview(session, overview.as_mut_ptr(), overview.len(), &mut written)
        },
        0
    );
    let mut overview_reader = Reader::new(
        &overview[..written],
        chur_core::ChurStatus::NonCanonicalEncoding,
    );
    assert_eq!(overview_reader.u16().expect("overview version"), 1);
    assert_eq!(
        overview_reader.id().expect("default collection"),
        collection_id
    );
    assert_eq!(overview_reader.u32().expect("empty members"), 0);
    overview_reader.finish().expect("complete empty overview");

    let recipient_path = std::env::temp_dir().join(format!(
        "chur-ffi-sharing-recipient-{}",
        chur_crypto::random::id().expect("random id").to_hex()
    ));
    let recipient_root = chur_catalog::paths::VaultRoot::new(&recipient_path);
    drop(
        chur_catalog::vault::create(&recipient_root, PASSWORD, 1)
            .expect("create recipient")
            .activate()
            .expect("activate recipient"),
    );
    let recipient_path_bytes = recipient_path.to_str().expect("UTF-8 path").as_bytes();
    let recipient_config = ChurRuntimeConfigV1 {
        root_path: recipient_path_bytes.as_ptr(),
        root_path_length: recipient_path_bytes.len() as u32,
    };
    let mut recipient_runtime = 0;
    assert_eq!(
        unsafe { chur_runtime_open(&recipient_config, &mut recipient_runtime) },
        0
    );
    let mut recipient_session = 0;
    assert_eq!(
        unsafe { chur_vault_unlock(recipient_runtime, &unlock, &mut recipient_session) },
        0
    );
    let mut recipient_identity = vec![0u8; 4096];
    let mut recipient_identity_length = 0;
    assert_eq!(
        unsafe {
            chur_sharing_identity(
                recipient_session,
                recipient_identity.as_mut_ptr(),
                recipient_identity.len(),
                &mut recipient_identity_length,
            )
        },
        0
    );
    recipient_identity.truncate(recipient_identity_length);
    let mut recipient_reader = Reader::new(
        &recipient_identity,
        chur_core::ChurStatus::NonCanonicalEncoding,
    );
    assert_eq!(recipient_reader.u16().expect("version"), 1);
    let recipient_vault_id = recipient_reader.id().expect("recipient vault");
    let recipient_device_id = recipient_reader.id().expect("recipient device");
    recipient_reader.slice(64).expect("recipient public keys");
    recipient_reader
        .variable(49)
        .expect("recipient fingerprint");
    let recipient_enrollment = recipient_reader
        .variable(EnrollmentRecord::LEN as u32)
        .expect("recipient enrollment")
        .to_vec();
    let mut preview = [0u8; 128];
    assert_eq!(
        unsafe {
            chur_sharing_inspect_enrollment(
                recipient_enrollment.as_ptr(),
                recipient_enrollment.len() as u32,
                preview.as_mut_ptr(),
                preview.len(),
                &mut written,
            )
        },
        0
    );
    let mut preview_reader = Reader::new(
        &preview[..written],
        chur_core::ChurStatus::NonCanonicalEncoding,
    );
    assert_eq!(preview_reader.u16().expect("preview version"), 1);
    assert_eq!(
        preview_reader.id().expect("preview vault"),
        recipient_vault_id
    );
    assert_eq!(
        preview_reader.id().expect("preview device"),
        recipient_device_id
    );
    assert_eq!(
        preview_reader
            .variable(49)
            .expect("preview fingerprint")
            .len(),
        49
    );
    preview_reader.finish().expect("complete preview");
    let mut forged = recipient_enrollment.clone();
    *forged.last_mut().expect("signature byte") ^= 1;
    assert_eq!(
        unsafe {
            chur_sharing_inspect_enrollment(
                forged.as_ptr(),
                forged.len() as u32,
                preview.as_mut_ptr(),
                preview.len(),
                &mut written,
            )
        },
        chur_core::ChurStatus::AuthenticationFailed.as_i32()
    );
    assert_eq!(written, 0);
    let recipient_initial_operation = recipient_reader
        .variable(16_777_216)
        .expect("recipient initial operation")
        .to_vec();
    recipient_reader
        .finish()
        .expect("recipient identity record");
    let mut short = [0xa5];
    written = usize::MAX;
    assert_eq!(
        unsafe {
            chur_sharing_prepare(
                session,
                collection_id.as_bytes().as_ptr(),
                recipient_enrollment.as_ptr(),
                recipient_enrollment.len() as u32,
                PermissionProfile::Contribute as u8,
                1,
                short.as_mut_ptr(),
                short.len(),
                &mut written,
            )
        },
        chur_core::ChurStatus::ResourceLimitExceeded.as_i32()
    );
    assert_eq!(written, 0);
    assert_eq!(short, [0xa5]);

    let mut share = vec![0u8; 4096];
    assert_eq!(
        unsafe {
            chur_sharing_prepare(
                session,
                collection_id.as_bytes().as_ptr(),
                recipient_enrollment.as_ptr(),
                recipient_enrollment.len() as u32,
                PermissionProfile::Contribute as u8,
                1,
                share.as_mut_ptr(),
                share.len(),
                &mut written,
            )
        },
        0
    );
    share.truncate(written);
    let mut reader = Reader::new(&share, chur_core::ChurStatus::NonCanonicalEncoding);
    assert_eq!(reader.u16().expect("share version"), 1);
    let membership = CollectionMembershipRecord::decode(
        reader
            .variable(CollectionMembershipRecord::LEN as u32)
            .expect("membership"),
    )
    .expect("valid membership");
    let membership_operation =
        Operation::decode(reader.variable(16_777_216).expect("membership operation"))
            .expect("valid membership operation");
    let grant =
        CollectionGrant::decode(reader.variable(CollectionGrant::LEN as u32).expect("grant"))
            .expect("valid grant");
    let grant_operation = Operation::decode(reader.variable(16_777_216).expect("grant operation"))
        .expect("valid grant operation");
    reader.finish().expect("complete share record");
    assert_eq!(membership.collection_id(), &collection_id);
    assert_eq!(
        membership.recipient_identity_vault_id(),
        &recipient_vault_id
    );
    assert_eq!(membership.recipient_device_id(), &recipient_device_id);
    assert_eq!(grant.collection_id(), &collection_id);
    assert_eq!(grant.recipient_identity_vault_id(), &recipient_vault_id);
    assert_eq!(grant.recipient_device_id(), &recipient_device_id);
    assert!(grant.permissions() == PermissionProfile::Contribute);
    assert!(membership_operation.device_sequence() < grant_operation.device_sequence());

    assert_eq!(
        unsafe {
            chur_sharing_overview(session, overview.as_mut_ptr(), overview.len(), &mut written)
        },
        0
    );
    let mut overview_reader = Reader::new(
        &overview[..written],
        chur_core::ChurStatus::NonCanonicalEncoding,
    );
    assert_eq!(overview_reader.u16().expect("overview version"), 1);
    assert_eq!(
        overview_reader.id().expect("default collection"),
        collection_id
    );
    assert_eq!(overview_reader.u32().expect("member count"), 1);
    assert_eq!(
        overview_reader.id().expect("member vault"),
        recipient_vault_id
    );
    assert_eq!(
        overview_reader.id().expect("member device"),
        recipient_device_id
    );
    assert_eq!(
        overview_reader.u8().expect("permission"),
        PermissionProfile::Contribute as u8
    );
    assert_eq!(overview_reader.u8().expect("active"), 1);
    assert_eq!(overview_reader.u8().expect("verified"), 1);
    assert_eq!(
        overview_reader
            .variable(49)
            .expect("member fingerprint")
            .len(),
        49
    );
    overview_reader.finish().expect("complete overview");

    let mut recipient_evidence = Writer::new();
    recipient_evidence.u16(1).u32(1);
    recipient_evidence
        .variable(&recipient_enrollment)
        .expect("recipient membership");
    recipient_evidence.u32(1);
    recipient_evidence
        .variable(&recipient_initial_operation)
        .expect("recipient operation");
    let recipient_evidence = recipient_evidence.finish();
    let mut device_share = vec![0u8; 4096];
    let mut device_share_written = 0;
    assert_eq!(
        unsafe {
            chur_sharing_prepare_device(
                session,
                collection_id.as_bytes().as_ptr(),
                recipient_evidence.as_ptr(),
                recipient_evidence.len() as u32,
                recipient_device_id.as_bytes().as_ptr(),
                PermissionProfile::Contribute as u8,
                1,
                device_share.as_mut_ptr(),
                device_share.len(),
                &mut device_share_written,
            )
        },
        0
    );
    assert_eq!(&device_share[..device_share_written], share.as_slice());

    let mut bundle = Writer::new();
    bundle.u16(1).u32(1).u32(1);
    bundle
        .variable(&enrollment.encode())
        .expect("issuer enrollment");
    bundle.u32(3);
    bundle
        .variable(&operation.encode())
        .expect("issuer operation");
    bundle
        .variable(&membership_operation.encode())
        .expect("membership operation");
    bundle
        .variable(&grant_operation.encode())
        .expect("grant operation");
    bundle.u32(1);
    bundle
        .variable(&membership.encode())
        .expect("membership record");
    bundle
        .variable(&membership_operation.encode())
        .expect("membership operation");
    bundle.variable(&grant.encode()).expect("grant");
    bundle
        .variable(&grant_operation.encode())
        .expect("grant operation");
    let bundle = bundle.finish();
    assert_eq!(
        unsafe { chur_sharing_accept(recipient_session, bundle.as_ptr(), 1) },
        chur_core::ChurStatus::NonCanonicalEncoding.as_i32()
    );
    assert_eq!(
        unsafe { chur_sharing_accept(recipient_session, bundle.as_ptr(), bundle.len() as u32,) },
        0
    );

    // The original existed before the grant. Author it only after its complete
    // ciphertext is available, then deliver the signed content to the second vault.
    let mut publication = vec![0u8; 8192];
    let zero = [0u8; 16];
    assert_eq!(
        unsafe {
            chur_sharing_publication(
                session,
                collection_id.as_bytes().as_ptr(),
                zero.as_ptr(),
                publication.as_mut_ptr(),
                publication.len(),
                &mut written,
            )
        },
        0
    );
    let mut publication_reader = Reader::new(
        &publication[..written],
        chur_core::ChurStatus::NonCanonicalEncoding,
    );
    assert_eq!(publication_reader.u16().expect("version"), 1);
    assert_eq!(publication_reader.u32().expect("count"), 1);
    assert!(
        publication_reader
            .variable(1_048_576)
            .expect("unsigned create")
            .is_empty()
    );
    assert!(
        publication_reader
            .variable(1_048_576)
            .expect("unsigned commit")
            .is_empty()
    );
    assert_eq!(publication_reader.id().expect("object"), shared_object_id);
    let remote_store_id = publication_reader.id().expect("store");
    assert_eq!(
        publication_reader.u64().expect("length"),
        ciphertext.len() as u64
    );
    let full_sha256: [u8; 32] = Sha256::digest(&ciphertext).into();
    assert_eq!(publication_reader.fixed::<32>().expect("hash"), full_sha256);
    publication_reader.finish().expect("publication page");

    assert_eq!(
        unsafe {
            chur_sharing_author(
                session,
                collection_id.as_bytes().as_ptr(),
                shared_object_id.as_bytes().as_ptr(),
                remote_store_id.as_bytes().as_ptr(),
                ciphertext.len() as u64,
                full_sha256.as_ptr(),
                publication.as_mut_ptr(),
                publication.len(),
                &mut written,
            )
        },
        0
    );
    let mut authored = Reader::new(
        &publication[..written],
        chur_core::ChurStatus::NonCanonicalEncoding,
    );
    assert_eq!(authored.u16().expect("version"), 1);
    assert_eq!(authored.u32().expect("count"), 1);
    let create = authored.variable(1_048_576).expect("create").to_vec();
    let commit = authored.variable(1_048_576).expect("commit").to_vec();
    let mut response = vec![0u8; 8192];
    let receive = |records: &[&[u8]], response: &mut Vec<u8>| {
        let mut page = Writer::new();
        page.u32(records.len() as u32);
        for record in records {
            page.variable(record).expect("record");
        }
        let page = page.finish();
        let mut length = 0;
        let status = unsafe {
            chur_sharing_receive(
                recipient_session,
                bundle.as_ptr(),
                bundle.len() as u32,
                page.as_ptr(),
                page.len() as u32,
                response.as_mut_ptr(),
                response.len(),
                &mut length,
            )
        };
        (status, length)
    };
    let (status, pending_length) = receive(&[&commit], &mut response);
    assert_eq!(status, 0, "out-of-order commit remains pending");
    let mut pending = Reader::new(
        &response[..pending_length],
        chur_core::ChurStatus::NonCanonicalEncoding,
    );
    assert_eq!(pending.u16().expect("version"), 1);
    pending.slice(48).expect("source, collection, selector");
    assert_eq!(pending.u32().expect("pending count"), 1);
    let (status, plan_length) = receive(&[&create, &commit], &mut response);
    assert_eq!(status, 0, "signed source content applies");
    let mut plan = Reader::new(
        &response[..plan_length],
        chur_core::ChurStatus::NonCanonicalEncoding,
    );
    assert_eq!(plan.u16().expect("version"), 1);
    plan.slice(48).expect("source, collection, selector");
    assert_eq!(plan.u32().expect("pending count"), 0);
    assert_eq!(plan.u32().expect("download count"), 1);
    assert_eq!(plan.id().expect("planned object"), shared_object_id);
    assert_eq!(plan.id().expect("planned store"), remote_store_id);
    assert_eq!(plan.u64().expect("planned length"), ciphertext.len() as u64);
    plan.finish().expect("plan");

    // The signed content log carries a commitment only. The receiver requests
    // this exact object with a disposable key before it can open its container.
    let request_input = [
        collection_id.as_bytes().as_slice(),
        shared_object_id.as_bytes().as_slice(),
    ]
    .concat();
    let mut request_bytes = vec![0u8; 227];
    let mut request_length = 0;
    assert_eq!(
        unsafe {
            chur_object_key_request(
                recipient_session,
                request_input.as_ptr(),
                request_input.len() as u32,
                request_bytes.as_mut_ptr(),
                request_bytes.len(),
                &mut request_length,
            )
        },
        0
    );
    request_bytes.truncate(request_length);
    assert_eq!(request_bytes[0], 1);
    let prekey_bytes = request_bytes[1..].to_vec();
    let mut object_grant_bytes = vec![0u8; 346];
    let mut object_grant_length = 0;
    assert_eq!(
        unsafe {
            chur_object_key_issue(
                session,
                prekey_bytes.as_ptr(),
                prekey_bytes.len() as u32,
                object_grant_bytes.as_mut_ptr(),
                object_grant_bytes.len(),
                &mut object_grant_length,
            )
        },
        0
    );
    object_grant_bytes.truncate(object_grant_length);
    let mut accept_object_key = Writer::new();
    accept_object_key
        .variable(&bundle)
        .expect("issuer evidence");
    accept_object_key
        .variable(&object_grant_bytes)
        .expect("object key grant");
    let accept_object_key = accept_object_key.finish();
    let mut ignored_length = 0;
    assert_eq!(
        unsafe {
            chur_object_key_accept(
                recipient_session,
                accept_object_key.as_ptr(),
                accept_object_key.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut ignored_length,
            )
        },
        0
    );
    assert_eq!(
        unsafe {
            chur_object_key_accept(
                recipient_session,
                accept_object_key.as_ptr(),
                accept_object_key.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut ignored_length,
            )
        },
        0,
        "grant acceptance retries without retaining its private prekey"
    );

    let mut offset = u64::MAX;
    assert_eq!(
        unsafe {
            chur_sharing_download_offset(
                recipient_session,
                collection_id.as_bytes().as_ptr(),
                shared_object_id.as_bytes().as_ptr(),
                &mut offset,
            )
        },
        0
    );
    assert_eq!(offset, 0, "absent staging starts at zero");
    let mut corrupt = ciphertext.clone();
    let corrupt_at = corrupt.len() / 2;
    corrupt[corrupt_at] ^= 1;
    assert_eq!(
        unsafe {
            chur_sharing_download_append(
                recipient_session,
                collection_id.as_bytes().as_ptr(),
                shared_object_id.as_bytes().as_ptr(),
                0,
                corrupt.as_ptr(),
                corrupt_at as u32,
            )
        },
        0
    );
    assert_eq!(
        unsafe {
            chur_sharing_download_offset(
                recipient_session,
                collection_id.as_bytes().as_ptr(),
                shared_object_id.as_bytes().as_ptr(),
                &mut offset,
            )
        },
        0
    );
    assert_eq!(
        offset, corrupt_at as u64,
        "staging length survives the call"
    );
    assert_eq!(unsafe { chur_session_close(recipient_session) }, 0);
    assert_eq!(
        unsafe { chur_vault_unlock(recipient_runtime, &unlock, &mut recipient_session) },
        0
    );
    offset = 0;
    assert_eq!(
        unsafe {
            chur_sharing_download_offset(
                recipient_session,
                collection_id.as_bytes().as_ptr(),
                shared_object_id.as_bytes().as_ptr(),
                &mut offset,
            )
        },
        0
    );
    assert_eq!(
        offset, corrupt_at as u64,
        "staging survives session restart"
    );
    assert_eq!(
        unsafe {
            chur_sharing_download_append(
                recipient_session,
                collection_id.as_bytes().as_ptr(),
                shared_object_id.as_bytes().as_ptr(),
                0,
                corrupt.as_ptr(),
                corrupt.len() as u32,
            )
        },
        0
    );
    assert_ne!(
        unsafe {
            chur_sharing_download_finish(
                recipient_session,
                collection_id.as_bytes().as_ptr(),
                shared_object_id.as_bytes().as_ptr(),
                2,
            )
        },
        0,
        "modified ciphertext cannot activate"
    );
    offset = u64::MAX;
    assert_eq!(
        unsafe {
            chur_sharing_download_offset(
                recipient_session,
                collection_id.as_bytes().as_ptr(),
                shared_object_id.as_bytes().as_ptr(),
                &mut offset,
            )
        },
        0
    );
    assert_eq!(
        offset, 0,
        "rejected ciphertext is discarded so the download restarts"
    );
    assert_eq!(
        unsafe {
            chur_sharing_download_append(
                recipient_session,
                collection_id.as_bytes().as_ptr(),
                shared_object_id.as_bytes().as_ptr(),
                0,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
            )
        },
        0
    );

    // Simulate a disk/SQL failure after the verified container rename but
    // before catalog activation. A later finish must recover this window.
    assert_eq!(unsafe { chur_session_close(recipient_session) }, 0);
    let mut interrupted = chur_catalog::vault::unlock_with_password(&recipient_root, PASSWORD, 1)
        .expect("recipient unlock for interrupted activation");
    let received_key = interrupted.root_secret().expect("root key").duplicate();
    let planned = chur_catalog::sharing_receive::pending_for_collection(
        interrupted.catalog().expect("catalog"),
        &received_key,
        recipient_vault_id,
        collection_id,
    )
    .expect("verified local plan");
    let planned_object = planned
        .objects
        .iter()
        .find(|item| item.object_id == shared_object_id)
        .expect("pending shared object");
    let received_collection_key =
        chur_media::keys::collection_key(&interrupted, &collection_id, 1).expect("collection key");
    let received_object_key = chur_catalog::object_grants::pending_envelope(
        interrupted.catalog_ref().expect("catalog"),
        &collection_id,
        &shared_object_id,
    )
    .expect("local pending key envelope")
    .open(&received_collection_key)
    .expect("object key");
    let expectation = chur_media::sync_download::Expectation::new(
        shared_object_id,
        planned_object.stream_id,
        planned_object.container_length,
        planned_object.container_commitment,
    )
    .expect("commitment");
    let local_store_id = interrupted.object_store_id();
    chur_media::sync_download::verify_staged(
        interrupted.root_dir(),
        &local_store_id,
        &shared_object_id,
        &received_object_key,
        &expectation,
    )
    .expect("verified container")
    .commit(interrupted.root_dir(), &local_store_id, &shared_object_id)
    .expect("rename before activation");
    assert!(
        !chur_catalog::store::object_present(
            interrupted.catalog_ref().expect("catalog"),
            &shared_object_id,
        )
        .expect("catalog lookup")
    );
    drop(interrupted);
    assert_eq!(
        unsafe { chur_vault_unlock(recipient_runtime, &unlock, &mut recipient_session) },
        0
    );
    offset = 0;
    assert_eq!(
        unsafe {
            chur_sharing_download_offset(
                recipient_session,
                collection_id.as_bytes().as_ptr(),
                shared_object_id.as_bytes().as_ptr(),
                &mut offset,
            )
        },
        0
    );
    assert_eq!(
        offset,
        ciphertext.len() as u64,
        "committed ciphertext resumes at its signed length after restart"
    );
    assert_eq!(
        unsafe {
            chur_sharing_download_finish(
                recipient_session,
                collection_id.as_bytes().as_ptr(),
                shared_object_id.as_bytes().as_ptr(),
                3,
            )
        },
        0,
        "committed ciphertext without a row activates on retry"
    );
    assert_eq!(
        unsafe { chur_sharing_accept(recipient_session, bundle.as_ptr(), bundle.len() as u32,) },
        0
    );

    let mut share_replay = vec![0u8; 4096];
    let mut share_replay_written = 0;
    assert_eq!(
        unsafe {
            chur_sharing_prepare(
                session,
                collection_id.as_bytes().as_ptr(),
                recipient_enrollment.as_ptr(),
                recipient_enrollment.len() as u32,
                PermissionProfile::Contribute as u8,
                1,
                share_replay.as_mut_ptr(),
                share_replay.len(),
                &mut share_replay_written,
            )
        },
        0
    );
    assert_eq!(&share_replay[..share_replay_written], share.as_slice());

    let mut revoke_short = [0xa5];
    let mut revoke_written = usize::MAX;
    assert_eq!(
        unsafe {
            chur_sharing_revoke(
                session,
                collection_id.as_bytes().as_ptr(),
                recipient_vault_id.as_bytes().as_ptr(),
                recipient_device_id.as_bytes().as_ptr(),
                1_000,
                revoke_short.as_mut_ptr(),
                revoke_short.len(),
                &mut revoke_written,
            )
        },
        chur_core::ChurStatus::ResourceLimitExceeded.as_i32()
    );
    assert_eq!(revoke_written, 0);
    assert_eq!(revoke_short, [0xa5]);

    let mut revoke = vec![0u8; 16_777_216];
    assert_eq!(
        unsafe {
            chur_sharing_revoke(
                session,
                collection_id.as_bytes().as_ptr(),
                recipient_vault_id.as_bytes().as_ptr(),
                recipient_device_id.as_bytes().as_ptr(),
                1_000,
                revoke.as_mut_ptr(),
                revoke.len(),
                &mut revoke_written,
            )
        },
        0
    );
    revoke.truncate(revoke_written);
    assert_eq!(
        unsafe {
            chur_sharing_overview(session, overview.as_mut_ptr(), overview.len(), &mut written)
        },
        0
    );
    let mut overview_reader = Reader::new(
        &overview[..written],
        chur_core::ChurStatus::NonCanonicalEncoding,
    );
    assert_eq!(overview_reader.u16().expect("overview version"), 1);
    assert_eq!(
        overview_reader.id().expect("default collection"),
        collection_id
    );
    assert_eq!(overview_reader.u32().expect("historical members"), 1);
    assert_eq!(
        overview_reader.id().expect("revoked vault"),
        recipient_vault_id
    );
    assert_eq!(
        overview_reader.id().expect("revoked device"),
        recipient_device_id
    );
    assert_eq!(
        overview_reader.u8().expect("old permission"),
        PermissionProfile::Contribute as u8
    );
    assert_eq!(overview_reader.u8().expect("inactive"), 0);
    assert_eq!(overview_reader.u8().expect("verified"), 1);
    assert_eq!(
        overview_reader
            .variable(49)
            .expect("revoked fingerprint")
            .len(),
        49
    );
    overview_reader.finish().expect("complete revoked overview");
    let mut revoke_reader = Reader::new(&revoke, chur_core::ChurStatus::NonCanonicalEncoding);
    assert_eq!(revoke_reader.u16().expect("revoke version"), 1);
    let revoked_membership = CollectionMembershipRecord::decode(
        revoke_reader
            .variable(CollectionMembershipRecord::LEN as u32)
            .expect("revoked membership"),
    )
    .expect("valid revoked membership");
    assert!(revoked_membership.action() == CollectionMembershipAction::Revoke);
    Operation::decode(
        revoke_reader
            .variable(16_777_216)
            .expect("revoked membership operation"),
    )
    .expect("valid revoked membership operation");
    let rotation_count = revoke_reader.u32().expect("rotation operation count");
    assert!(rotation_count >= 1);
    for _ in 0..rotation_count {
        Operation::decode(
            revoke_reader
                .variable(16_777_216)
                .expect("rotation operation"),
        )
        .expect("valid rotation operation");
    }
    assert_eq!(revoke_reader.u32().expect("grant count"), 0);
    assert_eq!(revoke_reader.u8().expect("rotation complete"), 1);
    revoke_reader.finish().expect("complete revocation record");

    let mut replay = vec![0u8; 4096];
    let mut replay_written = 0;
    assert_eq!(
        unsafe {
            chur_sharing_identity(
                session,
                replay.as_mut_ptr(),
                replay.len(),
                &mut replay_written,
            )
        },
        0
    );
    assert_eq!(&replay[..replay_written], bytes.as_slice());
    assert_eq!(unsafe { chur_session_close(session) }, 0);
    assert_eq!(unsafe { chur_runtime_close(runtime) }, 0);
    assert_eq!(unsafe { chur_session_close(recipient_session) }, 0);
    assert_eq!(unsafe { chur_runtime_close(recipient_runtime) }, 0);
    let mut received =
        chur_catalog::vault::unlock_with_password(&recipient_root, PASSWORD, 1).expect("unlock");
    let received_object =
        chur_catalog::store::object(received.catalog_ref().expect("catalog"), &shared_object_id)
            .expect("recipient materialized object");
    assert_eq!(received_object.plaintext_size, plaintext.len() as u64);
    assert_eq!(received_object.collection_id, collection_id);
    let mut before_epoch = chur_media::reader::open(
        &received,
        &shared_object_id,
        chur_format::constants::StreamKind::Original,
    )
    .expect("read before epoch change");
    assert_eq!(
        before_epoch
            .read_range(0, plaintext.len() as u64)
            .expect("original"),
        plaintext
    );
    drop(before_epoch);
    let recipient_root_key = received.root_secret().expect("recipient root").duplicate();
    let new_collection_key = chur_crypto::Key::new([53; 32]);
    let next_envelope = CollectionKeyEnvelope::seal(
        &recipient_root_key,
        recipient_vault_id,
        collection_id,
        2,
        1,
        chur_crypto::Nonce::new([54; 24]),
        &new_collection_key,
    )
    .expect("next epoch envelope");
    chur_catalog::store::put_collection_with_envelope(
        received.catalog().expect("catalog"),
        &chur_catalog::model::Collection {
            collection_id,
            current_epoch: 2,
            policy_type: chur_catalog::model::COLLECTION_POLICY_SHARED,
            created_revision: 1,
            status: chur_catalog::model::COLLECTION_STATUS_ACTIVE,
        },
        1,
        &next_envelope.encode(),
    )
    .expect("advance recipient collection epoch");
    let mut after_epoch = chur_media::reader::open(
        &received,
        &shared_object_id,
        chur_format::constants::StreamKind::Original,
    )
    .expect("read after epoch change");
    assert_eq!(
        after_epoch
            .read_range(0, plaintext.len() as u64)
            .expect("retained original"),
        plaintext
    );
    drop(after_epoch);
    assert_eq!(
        chur_catalog::store::collection(received.catalog().expect("catalog"), &collection_id)
            .expect("shared collection")
            .policy_type,
        chur_catalog::model::COLLECTION_POLICY_SHARED
    );
    let received_root = chur_crypto::Key::new(*received.root_secret().expect("root").expose());
    let received_envelope = CollectionKeyEnvelope::decode(
        &chur_catalog::store::active_collection_envelope(
            received.catalog().expect("catalog"),
            &collection_id,
            1,
        )
        .expect("received envelope"),
    )
    .expect("valid envelope");
    assert_eq!(received_envelope.vault_id(), &recipient_vault_id);
    assert_eq!(
        received_envelope
            .open(&received_root)
            .expect("collection key")
            .expose(),
        collection_key.expose()
    );
    // Local permanent deletion must leave no content key reachable through
    // old public requests, grants, signed logs, retained epoch keys or root.
    chur_catalog::deletion::begin(received.catalog().expect("catalog"), &shared_object_id)
        .expect("begin recipient erasure");
    chur_catalog::deletion::erase_with_sync(
        received.catalog().expect("catalog"),
        &received_root,
        recipient_vault_id,
        &shared_object_id,
        4,
    )
    .expect("erase recipient key");
    assert!(
        chur_catalog::sharing_log::outbound_after(
            received.catalog_ref().expect("catalog"),
            &recipient_vault_id,
            &recipient_device_id,
            0
        )
        .expect("recipient outbound page")
        .is_empty(),
        "recipient local deletion must not publish a global purge"
    );
    for entry in
        chur_catalog::deletion::sweep(received.catalog_ref().expect("catalog")).expect("sweep")
    {
        for container in entry.containers {
            chur_media::store::unlink_container(
                received.root_dir(),
                &received.object_store_id(),
                &container,
            )
            .expect("collect recipient ciphertext");
        }
    }
    chur_catalog::deletion::finish(received.catalog().expect("catalog"), &shared_object_id)
        .expect("finish recipient deletion");
    chur_catalog::deletion::discard_tombstone(
        received.catalog().expect("catalog"),
        &shared_object_id,
    )
    .expect("retain shared tombstone");
    assert!(
        chur_catalog::object_grants::pending_envelope(
            received.catalog_ref().expect("catalog"),
            &collection_id,
            &shared_object_id
        )
        .is_err()
    );
    assert!(
        chur_catalog::object_grants::request(
            received.catalog().expect("catalog"),
            &received_root,
            recipient_vault_id,
            collection_id,
            shared_object_id
        )
        .is_err(),
        "old commits cannot request a new key after deletion"
    );
    drop(received);
    let mut received = chur_catalog::vault::unlock_with_password(&recipient_root, PASSWORD, 5)
        .expect("recipient restart after delete");
    assert!(chur_media::keys::object_key(&received, &shared_object_id).is_err());
    assert!(
        chur_catalog::object_grants::pending_envelope(
            received.catalog_ref().expect("catalog"),
            &collection_id,
            &shared_object_id
        )
        .is_err()
    );
    // A backup created after erasure retains the tombstone and no object key.
    let mut package = std::io::Cursor::new(Vec::new());
    chur_media::backup::create(
        &mut received,
        &mut package,
        6,
        &mut chur_media::progress::Uninterrupted,
    )
    .expect("backup after erasure");
    let restored_path = std::env::temp_dir().join(format!(
        "chur-erased-restore-{}",
        chur_crypto::random::id().expect("id").to_hex()
    ));
    let restored_root = chur_catalog::paths::VaultRoot::new(&restored_path);
    chur_media::backup::restore(
        &restored_root,
        &mut package,
        PASSWORD,
        &mut chur_media::progress::Uninterrupted,
    )
    .expect("restore after erasure");
    let restored = chur_catalog::vault::unlock_with_password(&restored_root, PASSWORD, 7)
        .expect("restored vault");
    assert!(chur_media::keys::object_key(&restored, &shared_object_id).is_err());
    assert!(
        chur_catalog::object_grants::pending_envelope(
            restored.catalog_ref().expect("catalog"),
            &collection_id,
            &shared_object_id
        )
        .is_err()
    );
    drop(restored);
    std::fs::remove_dir_all(restored_path).expect("cleanup restore");
    drop(received);

    let mut source_after =
        chur_catalog::vault::unlock_with_password(&root, PASSWORD, 5).expect("source restart");
    let source_root_after = source_after.root_secret().expect("source root").duplicate();
    let signed_commit =
        chur_sync_protocol::collection_operation::CollectionOperation::decode(&commit)
            .expect("retained commit");
    let source_keys = chur_catalog::sync_keys::key_directory(
        source_after.catalog_ref().expect("catalog"),
        &source_root_after,
        source_vault_id,
    )
    .expect("retained epoch keys");
    let payload = chur_sync_protocol::payload::OperationPayload::open_for_collection_operation(
        &signed_commit,
        &source_keys,
    )
    .expect("old log authenticates");
    assert!(
        matches!(payload.body(), chur_sync_protocol::payload::PayloadBody::CommitObject { object_key_commitment, .. } if *object_key_commitment != [0; 32])
    );
    chur_catalog::deletion::begin(source_after.catalog().expect("catalog"), &shared_object_id)
        .expect("begin source erasure");
    chur_catalog::deletion::erase_with_sync(
        source_after.catalog().expect("catalog"),
        &source_root_after,
        source_vault_id,
        &shared_object_id,
        8,
    )
    .expect("erase source key despite retained logs");
    assert!(chur_media::keys::object_key(&source_after, &shared_object_id).is_err());
    let old_request = chur_sync_protocol::object_grant::ObjectPrekey::decode(&prekey_bytes)
        .expect("old public request");
    assert!(
        chur_catalog::object_grants::issue(
            source_after.catalog().expect("catalog"),
            &source_root_after,
            source_vault_id,
            &old_request
        )
        .is_err(),
        "source cannot reopen a key from retained signed logs or grant cache"
    );
    drop(source_after);
    std::fs::remove_dir_all(path).expect("cleanup");
    std::fs::remove_dir_all(recipient_path).expect("cleanup recipient");
}

/// A data-plane record above the control-plane argument bound reaches the parser.
///
/// `FFI_CONTRACT.md` section 6.11 admits an acceptance bundle of up to 16 MiB
/// and section 6.13 admits recipient evidence of up to 16 MiB. Both borrowed
/// through the control-plane helper, whose own bound is 64 KiB, so every input
/// between the two ceilings failed as `INVALID_INPUT` before it was parsed and
/// the documented ceiling was unreachable.
///
/// No session is needed: in both exports the length check, the borrow and the
/// decode all precede the registry lookup, so handle zero never reaches it. The
/// buffer is one byte past the argument bound rather than 16 MiB, because the
/// bound being proved is the argument one. A zeroed record decodes as version
/// zero, so the parser answers `UNSUPPORTED_VERSION` — a status neither
/// rejected size can produce, which is what makes the assertion discriminate:
/// the old 64 KiB refusal is `INVALID_INPUT` and the 16 MiB refusal is
/// `RESOURCE_LIMIT_EXCEEDED`.
#[test]
fn a_sharing_record_above_the_argument_bound_reaches_the_parser() {
    let oversize = vec![0u8; 65_537];
    let length = u32::try_from(oversize.len()).expect("length fits the ABI");

    // SAFETY: the buffer outlives the call and the length describes it.
    let accepted = unsafe { chur_sharing_accept(0, oversize.as_ptr(), length) };
    assert_eq!(accepted, chur_core::ChurStatus::UnsupportedVersion.as_i32());

    let mut destination = [0u8; 64];
    let mut written: usize = 0;
    // SAFETY: every pointer is to a live local and every length describes one.
    let prepared = unsafe {
        chur_sharing_prepare_device(
            0,
            [7u8; 16].as_ptr(),
            oversize.as_ptr(),
            length,
            [9u8; 16].as_ptr(),
            PermissionProfile::Read as u8,
            0,
            destination.as_mut_ptr(),
            destination.len(),
            &raw mut written,
        )
    };
    assert_eq!(prepared, chur_core::ChurStatus::UnsupportedVersion.as_i32());
}

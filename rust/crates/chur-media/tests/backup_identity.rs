//! A backup of the ordinary production identity restores recovery-only keys.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use chur_catalog::paths::VaultRoot;
use chur_catalog::{store, sync_keys, sync_log, sync_membership, sync_receive, vault};
use chur_crypto::random;
use chur_format::constants::{MediaClass, StreamKind};
use chur_media::import::{CanonicalMedia, SourceCapability};
use chur_media::progress::Uninterrupted;
use chur_media::{backup, export, import};

const PASSWORD: &[u8] = b"ordinary identity backup password";
const NOW: u64 = 1_700_000_000_000;

fn scratch_root() -> VaultRoot {
    let path = std::env::temp_dir().join(format!(
        "chur-backup-identity-{}",
        random::id().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&path).unwrap();
    VaultRoot::new(path)
}

#[test]
fn production_local_identity_backs_up_and_restores_without_replacing_the_live_signer() {
    let source = scratch_root();
    let mut session = vault::create(&source, PASSWORD, NOW)
        .unwrap()
        .activate()
        .unwrap();
    let root = session.root_secret().unwrap().duplicate();
    let vault_id = session.vault_id();
    // This is the production path used by the native sharing identity boundary.
    let (enrollment, _) =
        sync_receive::provision_local_identity(session.catalog().unwrap(), &root, vault_id)
            .unwrap();
    let plaintext = b"photo content survives backup of an ordinary sync identity";
    let object_id = import::import_bytes(
        &mut session,
        SourceCapability {
            requested_object_id: None,
            seekable: true,
            known_length: Some(plaintext.len() as u64),
            content_type_hint: "image/jpeg".into(),
            original_filename: Some("photo.jpg".into()),
            capture_time_ms: None,
        },
        CanonicalMedia {
            media_class: MediaClass::Image,
            width: 10,
            height: 10,
            duration_ms: 0,
        },
        "image/jpeg",
        &zeroize::Zeroizing::new(plaintext.to_vec()),
        NOW,
    )
    .unwrap();
    let generation = chur_catalog::schema::generation(session.catalog_ref().unwrap()).unwrap();
    let incoming = source.incoming(&session.object_store_id());
    assert_eq!(std::fs::read_dir(&incoming).unwrap().count(), 0);
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut session, &mut package, NOW + 1, &mut Uninterrupted)
        .expect("ordinary production identity must permit backup");
    assert_eq!(
        std::fs::read_dir(&incoming).unwrap().count(),
        0,
        "backup snapshot must be removed after success"
    );
    let membership = sync_membership::load(session.catalog_ref().unwrap())
        .unwrap()
        .unwrap();
    let (device_id, identity) =
        sync_keys::local_identity(session.catalog_ref().unwrap(), &root, &membership)
            .unwrap()
            .expect("live identity stays ordinary");
    assert_eq!(&device_id, enrollment.device_id());
    assert_eq!(
        &identity.signing_public_key(),
        enrollment.signing_public_key()
    );
    assert_eq!(
        chur_catalog::schema::generation(session.catalog_ref().unwrap()).unwrap(),
        generation,
        "backup must not modify live catalog state"
    );
    assert!(
        !sync_log::load(session.catalog_ref().unwrap(), &membership)
            .unwrap()
            .own_checkpoint_covers_current_heads(session.catalog_ref().unwrap(), &membership)
            .unwrap(),
        "backup checkpoint belongs only to the snapshot"
    );
    let destination = scratch_root();
    backup::restore(&destination, &mut package, PASSWORD, &mut Uninterrupted)
        .expect("actual restore");
    let restored = vault::unlock_with_password(&destination, PASSWORD, NOW + 2).unwrap();
    let membership = sync_membership::load(restored.catalog_ref().unwrap())
        .unwrap()
        .unwrap();
    let envelope = sync_keys::portable_identity_envelope(
        restored.catalog_ref().unwrap(),
        restored.root_secret().unwrap(),
        &membership,
    )
    .unwrap()
    .unwrap();
    assert!(envelope.is_recovery_only());
    assert_eq!(envelope.device_id(), enrollment.device_id());
    let log = sync_log::load(restored.catalog_ref().unwrap(), &membership).unwrap();
    assert!(
        log.own_checkpoint_covers_current_heads(restored.catalog_ref().unwrap(), &membership)
            .unwrap()
    );
    assert_eq!(log.floor(&device_id), log.head(&device_id));
    let mut actual = Vec::new();
    export::export_stream(
        &restored,
        &object_id,
        StreamKind::Original,
        &mut actual,
        &mut Uninterrupted,
    )
    .unwrap();
    assert_eq!(actual, plaintext);
    assert_eq!(
        store::streams(restored.catalog_ref().unwrap(), &object_id)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn cancelled_backup_removes_its_encrypted_catalog_snapshot() {
    struct CancelAfterFirstProbe(std::cell::Cell<u32>);
    impl chur_media::progress::Progress for CancelAfterFirstProbe {
        fn cancelled(&self) -> bool {
            let calls = self.0.get();
            self.0.set(calls + 1);
            calls > 0
        }
        fn advance(&mut self, _processed: u64) {}
    }
    let source = scratch_root();
    let mut session = vault::create(&source, PASSWORD, NOW)
        .unwrap()
        .activate()
        .unwrap();
    let root = session.root_secret().unwrap().duplicate();
    let vault_id = session.vault_id();
    sync_receive::provision_local_identity(session.catalog().unwrap(), &root, vault_id).unwrap();
    let incoming = source.incoming(&session.object_store_id());
    let mut package = Cursor::new(Vec::new());
    let error = backup::create(
        &mut session,
        &mut package,
        NOW,
        &mut CancelAfterFirstProbe(std::cell::Cell::new(0)),
    )
    .unwrap_err();
    assert_eq!(error.status(), chur_core::ChurStatus::Cancelled);
    assert_eq!(std::fs::read_dir(&incoming).unwrap().count(), 0);
    let membership = sync_membership::load(session.catalog_ref().unwrap())
        .unwrap()
        .unwrap();
    assert!(
        sync_keys::local_identity(session.catalog_ref().unwrap(), &root, &membership)
            .unwrap()
            .is_some()
    );
}

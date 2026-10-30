//! Creating a portable package and restoring it into an empty root.
//!
//! `docs/ROADMAP.md` Phase 2 makes "backup restore succeeds across Android,
//! iOS, and CLI" an exit criterion. All three run this code; what differs
//! between them is the file the package is written to. These tests are that
//! code path end to end, plus the failures
//! `docs/format/BACKUP_FORMAT_V1.md` §14 names: a truncated package, a
//! reordered one, a wrong credential, and a device-bound slot that must not
//! travel.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Cursor;

use chur_catalog::paths::VaultRoot;
use chur_catalog::query::{ObjectQuery, page};
use chur_catalog::vault::{self, Session};
use chur_core::{ChurStatus, Id, Result};
use chur_crypto::{Key, Nonce, random, recovery};
use chur_format::constants::{MediaClass, StreamKind};
use chur_media::import::{CanonicalMedia, SourceCapability};
use chur_media::progress::Uninterrupted;
use chur_media::{backup, export, import};
use chur_sync_protocol::{identity::DeviceIdentity, membership::EnrollmentRecord};
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"correct horse battery staple";
const NOW: u64 = 1_700_000_000_000;

fn scratch_root() -> VaultRoot {
    let mut path = std::env::temp_dir();
    path.push(format!("chur-backup-{}", random::id().unwrap().to_hex()));
    std::fs::create_dir_all(&path).unwrap();
    VaultRoot::new(path)
}

fn new_vault() -> (VaultRoot, Session) {
    let root = scratch_root();
    let session = vault::create(&root, PASSWORD, NOW)
        .expect("create")
        .activate()
        .expect("activate");
    (root, session)
}

fn plaintext(length: usize, seed: u64) -> Zeroizing<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    let mut state = seed | 1;
    for byte in &mut bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state & 0xff) as u8;
    }
    Zeroizing::new(bytes)
}

fn import_one(session: &mut Session, length: usize, name: &str, seed: u64) -> (Id, Vec<u8>) {
    let bytes = plaintext(length, seed);
    let object_id = import::import_bytes(
        session,
        SourceCapability {
            requested_object_id: None,
            seekable: true,
            known_length: Some(length as u64),
            content_type_hint: String::from("image/jpeg"),
            original_filename: Some(String::from(name)),
            capture_time_ms: Some(NOW - 86_400_000),
        },
        CanonicalMedia {
            media_class: MediaClass::Image,
            width: 800,
            height: 600,
            duration_ms: 0,
        },
        "image/jpeg",
        &bytes,
        NOW,
    )
    .expect("import");
    (object_id, bytes.to_vec())
}

fn exported(session: &Session, object_id: &Id) -> Vec<u8> {
    let mut out = Vec::new();
    export::export_stream(
        session,
        object_id,
        StreamKind::Original,
        &mut out,
        &mut Uninterrupted,
    )
    .expect("export");
    out
}

fn rejection<T>(outcome: Result<T>) -> ChurStatus {
    let Err(error) = outcome else {
        panic!("the backup path accepted something the specification forbids");
    };
    error.status()
}

/// A package with content, restored into an empty root, produces a vault whose
/// objects export the bytes that went in. This is the Phase 2 exit criterion.
#[test]
fn a_package_restores_a_vault_whose_objects_export_the_original_bytes() {
    let (_root, mut session) = new_vault();
    let (first, first_bytes) = import_one(&mut session, 300_000, "a.jpg", 0x1111);
    let (second, second_bytes) = import_one(&mut session, 4_096, "b.jpg", 0x2222);
    let source_vault = session.vault_id();
    use chur_catalog::{note_attachments as files, note_workspace as workspace, notes};
    let n = notes::save(
        session.catalog().unwrap(),
        None,
        0,
        "Note backup",
        "# original source",
        false,
        notes::NoteFormat::Markdown,
        NOW,
    )
    .unwrap();
    let attachment = random::id().unwrap();
    let n = files::put(
        session.catalog().unwrap(),
        &n.id,
        n.revision,
        files::AttachmentData {
            attachment: files::Attachment {
                id: attachment,
                name: "historical.bin".into(),
                mime_type: "application/octet-stream".into(),
                size: b"HISTORICAL_BACKUP_SECRET".len() as u64,
            },
            data: Zeroizing::new(b"HISTORICAL_BACKUP_SECRET".to_vec()),
        },
        NOW,
    )
    .unwrap();
    let n = workspace::set_organization(
        session.catalog().unwrap(),
        &n.id,
        n.revision,
        "Backup folder",
        &["private"],
        NOW,
    )
    .unwrap();
    let original_revision = n.revision;
    let n = files::remove(
        session.catalog().unwrap(),
        &n.id,
        n.revision,
        &attachment,
        NOW,
    )
    .unwrap();

    let mut package = Cursor::new(Vec::new());
    let summary =
        backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    assert_eq!(summary.vault_id, source_vault);
    assert_eq!(summary.stream_count, 2);
    assert_eq!(summary.slot_count, 1);
    // The manifest, the descriptor, the catalog, two containers, the commit.
    assert_eq!(summary.record_count, 6);
    assert_eq!(summary.package_length, package.get_ref().len() as u64);
    assert!(
        !package
            .get_ref()
            .windows(b"HISTORICAL_BACKUP_SECRET".len())
            .any(|w| w == b"HISTORICAL_BACKUP_SECRET")
    );
    session.lock().expect("lock");

    let destination = scratch_root();
    let restored =
        backup::restore(&destination, &mut package, PASSWORD, &mut Uninterrupted).expect("restore");
    assert_eq!(restored.vault_id, source_vault);
    assert_eq!(restored.backup_id, summary.backup_id);
    assert_eq!(restored.stream_count, 2);

    let mut opened =
        vault::unlock_with_password(&destination, PASSWORD, NOW + 2_000).expect("unlock");
    assert_eq!(opened.vault_id(), source_vault);
    let listed = page(opened.catalog_ref().unwrap(), &ObjectQuery::timeline()).expect("page");
    assert_eq!(listed.total_count, 2);
    assert_eq!(exported(&opened, &first), first_bytes);
    assert_eq!(exported(&opened, &second), second_bytes);
    assert_eq!(
        workspace::get_organization(opened.catalog_ref().unwrap(), &n.id)
            .unwrap()
            .folder,
        "Backup folder"
    );
    let current = notes::get(opened.catalog_ref().unwrap(), &n.id).unwrap();
    assert_eq!(current.attachment_count, 0);
    let recovered = workspace::restore(
        opened.catalog().unwrap(),
        &n.id,
        current.revision,
        original_revision,
        NOW + 2001,
    )
    .unwrap();
    assert_eq!(recovered.body, "# original source");
    assert_eq!(
        &*files::read(opened.catalog_ref().unwrap(), &n.id, &attachment).unwrap(),
        b"HISTORICAL_BACKUP_SECRET"
    );
}

#[test]
fn a_restored_vault_keeps_the_container_ceiling_of_its_padded_objects() {
    // ADR-0066: the restored descriptor must still admit the v2 containers it
    // installs, or a v1-only build would open the vault and fail per object.
    let (_root, mut session) = new_vault();
    let (object_id, bytes) = import_one(&mut session, 300_000, "a.jpg", 0x3333);
    assert_eq!(
        session.descriptor().object_store.container_version_ceiling,
        2
    );
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    session.lock().expect("lock");

    let destination = scratch_root();
    backup::restore(&destination, &mut package, PASSWORD, &mut Uninterrupted).expect("restore");
    let opened = vault::unlock_with_password(&destination, PASSWORD, NOW + 2_000).expect("unlock");
    assert_eq!(opened.descriptor().object_store.container_version_floor, 1);
    assert_eq!(
        opened.descriptor().object_store.container_version_ceiling,
        2
    );
    let stream =
        &chur_catalog::store::streams(opened.catalog_ref().unwrap(), &object_id).unwrap()[0];
    assert_eq!(stream.container_version, 2);
    assert_eq!(stream.plaintext_size, 300_000);
    assert_eq!(exported(&opened, &object_id), bytes);
}

#[test]
fn backup_rejects_damaged_source_containers_before_writing_a_package() {
    for damage_final_commit in [false, true] {
        let (_root, mut session) = new_vault();
        let (object_id, _) = import_one(&mut session, 2_097_152, "damaged.jpg", 0x9911);
        let stream = chur_catalog::store::streams(session.catalog_ref().unwrap(), &object_id)
            .expect("streams")
            .remove(0);
        let path = session
            .root_dir()
            .container(&session.object_store_id(), &stream.container_path_id);
        let mut bytes = std::fs::read(&path).expect("container");
        let offset = if damage_final_commit {
            bytes.len() - 1
        } else {
            1_500
        };
        bytes[offset] ^= 1;
        std::fs::write(&path, bytes).expect("damage");
        let mut package = Cursor::new(Vec::new());
        assert_eq!(
            rejection(backup::create(
                &mut session,
                &mut package,
                NOW,
                &mut Uninterrupted
            )),
            ChurStatus::ObjectCorrupt
        );
        assert!(
            package.into_inner().is_empty(),
            "a rejected source must not produce a partial package"
        );
    }
}

#[test]
fn backup_rejects_an_object_already_marked_corrupt() {
    let (_root, mut session) = new_vault();
    let (object_id, _) = import_one(&mut session, 8_192, "corrupt.jpg", 0x9922);
    chur_catalog::store::mark_corrupt(session.catalog().unwrap(), &object_id)
        .expect("mark corrupt");
    let mut package = Cursor::new(Vec::new());
    assert_eq!(
        rejection(backup::create(
            &mut session,
            &mut package,
            NOW,
            &mut Uninterrupted
        )),
        ChurStatus::ObjectCorrupt
    );
    assert!(package.into_inner().is_empty());
}

/// An empty vault is the §14 minimal case: the package holds no container and
/// its inventory commitment is over the slot entries alone.
#[test]
fn an_empty_vault_makes_a_package_that_restores_to_an_empty_vault() {
    let (_root, mut session) = new_vault();
    let mut package = Cursor::new(Vec::new());
    let summary =
        backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    assert_eq!(summary.stream_count, 0);
    assert_eq!(summary.record_count, 4);
    session.lock().expect("lock");

    let destination = scratch_root();
    backup::restore(&destination, &mut package, PASSWORD, &mut Uninterrupted).expect("restore");
    let opened = vault::unlock_with_password(&destination, PASSWORD, NOW + 2_000).expect("unlock");
    let listed = page(opened.catalog_ref().unwrap(), &ObjectQuery::timeline()).expect("page");
    assert_eq!(listed.total_count, 0);
}

#[test]
fn a_sync_backup_requires_a_portable_identity() {
    let (_root, mut session) = new_vault();
    let identity = DeviceIdentity::from_seeds([1; 32], [2; 32]);
    let enrollment = EnrollmentRecord::initial(
        session.vault_id(),
        Id::new([3; 16]).expect("device"),
        identity.signing_public_key(),
        identity.hpke_public_key(),
    )
    .expect("enrollment")
    .sign(identity.signing_key());
    chur_catalog::sync_membership::provision(session.catalog().expect("catalog"), &enrollment)
        .expect("membership");

    let mut package = Cursor::new(Vec::new());
    assert_eq!(
        rejection(backup::create(
            &mut session,
            &mut package,
            NOW,
            &mut Uninterrupted,
        )),
        ChurStatus::VaultIncomplete
    );
}

#[test]
fn a_sync_backup_authenticates_and_restores_its_recovery_identity() {
    let (_root, mut session) = new_vault();
    let root = session.root_secret().expect("root").duplicate();
    let vault_id = session.vault_id();
    let device_id = Id::new([11; 16]).expect("device");
    let identity = DeviceIdentity::from_seeds([12; 32], [13; 32]);
    let enrollment = EnrollmentRecord::initial(
        vault_id,
        device_id,
        identity.signing_public_key(),
        identity.hpke_public_key(),
    )
    .expect("enrollment")
    .sign(identity.signing_key());
    let membership =
        chur_catalog::sync_membership::provision(session.catalog().expect("catalog"), &enrollment)
            .expect("membership");
    let mut log =
        chur_catalog::sync_log::load(session.catalog_ref().expect("catalog"), &membership)
            .expect("log");
    let operation = log
        .author(
            Id::new([14; 16]).expect("operation"),
            vault_id,
            device_id,
            Id::new([15; 16]).expect("selector"),
            &Key::new([16; 32]),
            Nonce::new([17; 24]),
            b"checkpoint seed operation",
            identity.signing_key(),
            &membership,
        )
        .expect("operation");
    log.accept_with(
        session.catalog().expect("catalog"),
        &operation,
        &membership,
        |_| Ok(()),
    )
    .expect("accept");
    log.issue_own_checkpoint(
        session.catalog().expect("catalog"),
        &membership,
        &device_id,
        identity.signing_key(),
        NOW,
    )
    .expect("checkpoint");
    let envelope = chur_sync_protocol::identity::DeviceIdentityEnvelope::seal_for_recovery(
        &root,
        vault_id,
        device_id,
        1,
        Nonce::new([18; 24]),
        &identity,
    )
    .expect("envelope");
    chur_catalog::sync_keys::store_portable_identity_envelope(
        session.catalog().expect("catalog"),
        &root,
        &membership,
        &envelope,
    )
    .expect("store identity");

    let mut package = Cursor::new(Vec::new());
    let summary =
        backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("backup");
    assert_eq!(summary.record_count, 5);
    let whole = package.into_inner();
    session.lock().expect("lock");

    let destination = scratch_root();
    backup::restore(
        &destination,
        &mut Cursor::new(whole.clone()),
        PASSWORD,
        &mut Uninterrupted,
    )
    .expect("restore");
    let opened = vault::unlock_with_password(&destination, PASSWORD, NOW + 1).expect("unlock");
    let membership = chur_catalog::sync_membership::load(opened.catalog_ref().expect("catalog"))
        .expect("membership")
        .expect("sync membership");
    assert!(
        chur_catalog::sync_keys::portable_identity_envelope(
            opened.catalog_ref().expect("catalog"),
            opened.root_secret().expect("root"),
            &membership,
        )
        .expect("identity")
        .is_some()
    );

    let mut damaged = whole;
    let envelope_payload = record_payload_byte(&damaged, 0x05);
    damaged[envelope_payload] ^= 1;
    let destination = scratch_root();
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut Cursor::new(damaged),
            PASSWORD,
            &mut Uninterrupted,
        )),
        ChurStatus::VaultCorrupt
    );
    assert!(destination.registry_names().expect("registry").is_empty());
}

/// §7's whole point: the package is authenticated as a unit. A truncated one,
/// one with a byte changed inside a container, and one with two container
/// records swapped must each fail, and none of them may install a vault.
#[test]
fn a_damaged_package_installs_nothing() {
    let (_root, mut session) = new_vault();
    import_one(&mut session, 8_192, "a.jpg", 0x3333);
    import_one(&mut session, 8_192, "b.jpg", 0x4444);
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    session.lock().expect("lock");
    let whole = package.into_inner();

    // A package that ends early.
    let destination = scratch_root();
    let truncated = whole[..whole.len() - 64].to_vec();
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut Cursor::new(truncated),
            PASSWORD,
            &mut Uninterrupted,
        )),
        ChurStatus::VaultCorrupt
    );
    assert!(destination.registry_names().unwrap().is_empty());

    // A byte changed inside a container's ciphertext, which changes the
    // container's ordered commitment and therefore the inventory. The offset is
    // found rather than guessed: the package is mostly catalog, and a byte
    // picked by arithmetic would land there and test a different rule.
    let destination = scratch_root();
    let mut flipped = whole.clone();
    let at = container_byte(&flipped);
    flipped[at] ^= 0x01;
    let status = rejection(backup::restore(
        &destination,
        &mut Cursor::new(flipped),
        PASSWORD,
        &mut Uninterrupted,
    ));
    assert_eq!(status, ChurStatus::VaultCorrupt);
    assert!(destination.registry_names().unwrap().is_empty());

    // The container's final commit is outside the chunk commitment. It must
    // still authenticate before the descriptor makes the vault openable.
    let destination = scratch_root();
    let mut final_commit = whole.clone();
    let at = container_final_commit_byte(&final_commit);
    final_commit[at] ^= 0x01;
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut Cursor::new(final_commit),
            PASSWORD,
            &mut Uninterrupted,
        )),
        ChurStatus::VaultCorrupt
    );
    assert!(destination.registry_names().unwrap().is_empty());

    // A byte changed inside the catalog export. ADR-0068 seals each catalog
    // export record, and the record commitment covers it, so the restore
    // refuses the package before it installs anything.
    let destination = scratch_root();
    let mut catalog = whole.clone();
    let at = catalog_header_byte(&catalog);
    catalog[at] ^= 0x01;
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut Cursor::new(catalog),
            PASSWORD,
            &mut Uninterrupted,
        )),
        ChurStatus::VaultCorrupt
    );
    assert!(destination.registry_names().unwrap().is_empty());

    // Bytes appended after the final commit. §2.2 puts none there.
    let destination = scratch_root();
    let mut extended = whole.clone();
    extended.push(0);
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut Cursor::new(extended),
            PASSWORD,
            &mut Uninterrupted,
        )),
        ChurStatus::VaultCorrupt
    );
    assert!(destination.registry_names().unwrap().is_empty());
}

/// The package's records as `(record type, header and payload)` in order.
fn records(package: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut offset = 32usize;
    while offset < package.len() {
        let header = &package[offset..offset + 12];
        let length = usize::try_from(u64::from_be_bytes(header[4..12].try_into().unwrap()))
            .expect("a record length fits a usize");
        out.push((header[0], package[offset..offset + 12 + length].to_vec()));
        offset += 12 + length;
    }
    out
}

/// Two packages of the same vault share the catalog's salt, so the header
/// commitment cannot tell their catalogs apart. A package whose catalog export
/// comes from an older package of the same vault, with every other record its
/// own, must not restore the older state under the newer package's identity.
#[test]
fn a_catalog_export_spliced_from_an_older_package_installs_nothing() {
    let (_root, mut session) = new_vault();
    import_one(&mut session, 8_192, "a.jpg", 0x6161);
    let mut older = Cursor::new(Vec::new());
    backup::create(&mut session, &mut older, NOW, &mut Uninterrupted).expect("older");

    // Only catalog state changes between the two packages.
    chur_catalog::notes::save(
        session.catalog().expect("catalog"),
        None,
        0,
        "later",
        "a note the older package does not hold",
        false,
        chur_catalog::notes::NoteFormat::PlainText,
        NOW + 1,
    )
    .expect("save a note");
    let mut newer = Cursor::new(Vec::new());
    backup::create(&mut session, &mut newer, NOW + 2, &mut Uninterrupted).expect("newer");
    session.lock().expect("lock");
    let older = older.into_inner();
    let newer = newer.into_inner();

    let older_catalog = records(&older)
        .into_iter()
        .find(|(record_type, _)| *record_type == 0x03)
        .expect("the older package has a catalog export")
        .1;
    let mut spliced = newer[..32].to_vec();
    for (record_type, bytes) in records(&newer) {
        if record_type == 0x03 {
            spliced.extend_from_slice(&older_catalog);
        } else {
            spliced.extend_from_slice(&bytes);
        }
    }

    let destination = scratch_root();
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut Cursor::new(spliced),
            PASSWORD,
            &mut Uninterrupted,
        )),
        ChurStatus::VaultCorrupt
    );
    assert!(destination.registry_names().unwrap().is_empty());

    // The newer package itself still restores.
    let destination = scratch_root();
    backup::restore(
        &destination,
        &mut Cursor::new(newer),
        PASSWORD,
        &mut Uninterrupted,
    )
    .expect("restore the newer package");
}

/// An offset inside the first container record's ciphertext.
///
/// A container begins with the `CHUROBJ1` magic, and the flip is placed well
/// past it so the damage lands in a chunk record rather than in the preamble.
fn container_byte(package: &[u8]) -> usize {
    let at = package
        .windows(8)
        .position(|window| window == b"CHUROBJ1")
        .expect("the package carries no container");
    at + 4_000
}

fn container_final_commit_byte(package: &[u8]) -> usize {
    let mut offset = 32usize;
    loop {
        let header = &package[offset..offset + 12];
        let length = usize::try_from(u64::from_be_bytes(header[4..12].try_into().unwrap()))
            .expect("a record length fits a usize");
        if header[0] == 0x04 {
            return offset + 12 + length - 1;
        }
        offset += 12 + length;
    }
}

/// An offset inside the first catalog export record.
///
/// The byte is inside the record's nonce, which the AEAD and the record
/// commitment both cover. The record is found by walking the package's own
/// headers, which is what a reader does.
fn catalog_header_byte(package: &[u8]) -> usize {
    let mut offset = 32usize;
    loop {
        let header = &package[offset..offset + 12];
        let length = usize::try_from(u64::from_be_bytes(header[4..12].try_into().unwrap()))
            .expect("a record length fits a usize");
        if header[0] == 0x03 {
            return offset + 12 + 4;
        }
        offset += 12 + length;
    }
}

fn record_payload_byte(package: &[u8], record_type: u8) -> usize {
    let mut offset = 32usize;
    loop {
        let header = &package[offset..offset + 12];
        let length = usize::try_from(u64::from_be_bytes(header[4..12].try_into().unwrap()))
            .expect("a record length fits a usize");
        if header[0] == record_type {
            return offset + 12 + length / 2;
        }
        offset += 12 + length;
    }
}

/// §8 step 2 obtains the factor before anything else is read. A credential that
/// opens no portable slot fails before a byte reaches the destination.
#[test]
fn a_wrong_credential_restores_nothing() {
    let (_root, mut session) = new_vault();
    import_one(&mut session, 4_096, "a.jpg", 0x5555);
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    session.lock().expect("lock");

    let destination = scratch_root();
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut package,
            b"not the password",
            &mut Uninterrupted,
        )),
        ChurStatus::AuthenticationFailed
    );
    assert!(destination.registry_names().unwrap().is_empty());
    assert!(!destination.base().join("vaults").exists());
}

/// §3 excludes every device-bound slot. A vault whose only extra slot is an
/// Apple Keychain slot still backs up, and the package carries the password and
/// recovery slots alone — a package carrying a `ThisDeviceOnly` item would
/// restore a vault with a slot nothing on the new device can open.
#[test]
fn a_device_bound_slot_does_not_travel() {
    let (_root, mut session) = new_vault();
    session.add_recovery_slot().expect("recovery");
    session
        .add_apple_keychain_slot(random::id().unwrap())
        .expect("keychain");
    assert_eq!(session.slots().len(), 3);

    let mut package = Cursor::new(Vec::new());
    let summary =
        backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    assert_eq!(summary.slot_count, 2);
    session.lock().expect("lock");

    let destination = scratch_root();
    backup::restore(&destination, &mut package, PASSWORD, &mut Uninterrupted).expect("restore");
    let opened = vault::unlock_with_password(&destination, PASSWORD, NOW + 2_000).expect("unlock");
    assert_eq!(opened.slots().len(), 2);
    assert!(
        opened
            .slots()
            .iter()
            .all(|(_, kind, _)| *kind != chur_format::constants::SlotType::AppleKeychain),
        "a device-bound slot reached the restored vault"
    );
}

#[test]
fn recovery_phrase_restores_backups_with_and_without_a_password_slot() {
    let (_root, mut session) = new_vault();
    let (object_id, bytes) = import_one(&mut session, 4_096, "recover.jpg", 0x9090);
    let secret = session.add_recovery_slot().expect("recovery");
    let phrase = recovery::to_phrase(&secret);

    let mut both_slots = Cursor::new(Vec::new());
    backup::create(&mut session, &mut both_slots, NOW, &mut Uninterrupted).expect("backup");
    let destination = scratch_root();
    backup::restore(
        &destination,
        &mut both_slots,
        phrase.as_bytes(),
        &mut Uninterrupted,
    )
    .expect("restore with recovery despite password slot");
    let opened = vault::unlock_with_recovery(&destination, &phrase, NOW + 1).expect("unlock");
    assert_eq!(exported(&opened, &object_id), bytes);

    let password_slot = session
        .slots()
        .into_iter()
        .find(|(_, kind, _)| *kind == chur_format::constants::SlotType::Password)
        .expect("password slot")
        .0;
    session
        .remove_slot(&password_slot)
        .expect("remove password");
    let mut recovery_only = Cursor::new(Vec::new());
    backup::create(&mut session, &mut recovery_only, NOW, &mut Uninterrupted).expect("backup");
    let wrong_phrase = recovery::to_phrase(&random::secret::<32>().expect("secret"));
    let destination = scratch_root();
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut Cursor::new(recovery_only.get_ref().clone()),
            wrong_phrase.as_bytes(),
            &mut Uninterrupted,
        )),
        ChurStatus::AuthenticationFailed
    );
    assert!(destination.registry_names().expect("registry").is_empty());
    let destination = scratch_root();
    backup::restore(
        &destination,
        &mut recovery_only,
        phrase.as_bytes(),
        &mut Uninterrupted,
    )
    .expect("restore with recovery only");
    let opened = vault::unlock_with_recovery(&destination, &phrase, NOW + 1).expect("unlock");
    assert_eq!(exported(&opened, &object_id), bytes);
}

/// §11: one package holds one vault identity. A restore into a root that
/// already holds the two identities `VAULT_DESCRIPTOR_V1.md` §11 admits is
/// refused rather than making a third.
#[test]
fn a_restore_into_a_full_registry_is_refused() {
    let (_root, mut session) = new_vault();
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    session.lock().expect("lock");

    let destination = scratch_root();
    vault::create(&destination, b"first identity here", NOW)
        .expect("first")
        .activate()
        .expect("activate")
        .lock()
        .expect("lock");
    vault::create(&destination, b"second identity here", NOW)
        .expect("second")
        .activate()
        .expect("activate")
        .lock()
        .expect("lock");

    // A wrong password learns nothing about the registry: it fails as it does
    // on a device with room, `DECOY_VAULT.md` §10.
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut package,
            b"not the package password",
            &mut Uninterrupted,
        )),
        ChurStatus::AuthenticationFailed
    );
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut package,
            PASSWORD,
            &mut Uninterrupted,
        )),
        ChurStatus::Conflict
    );
}

/// §2.3: an `age`-wrapped package is named rather than reported as not a Chur
/// backup. The two are different problems and the user can only act on one of
/// them.
#[test]
fn an_age_wrapped_package_is_named_as_wrapped() {
    let destination = scratch_root();
    let mut wrapped = Cursor::new(b"age-encryption.org/v1\nnot really".to_vec());
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut wrapped,
            PASSWORD,
            &mut Uninterrupted,
        )),
        ChurStatus::UnsupportedVersion
    );

    let mut foreign = Cursor::new(b"PK\x03\x04not a backup at all".to_vec());
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut foreign,
            PASSWORD,
            &mut Uninterrupted,
        )),
        ChurStatus::VaultCorrupt
    );
}

/// The package copies ciphertext and never decrypts it: a restore of a vault
/// whose containers this build could not open would still be byte-exact. The
/// observable form of that is simpler — the container bytes in the package are
/// the container bytes on disk.
#[test]
fn a_container_travels_as_its_own_ciphertext() {
    let (root, mut session) = new_vault();
    let (object_id, _) = import_one(&mut session, 20_000, "a.jpg", 0x6666);
    let store_id = session.object_store_id();
    let stream = chur_catalog::store::streams(session.catalog_ref().unwrap(), &object_id)
        .expect("streams")
        .into_iter()
        .find(|stream| stream.stream_kind == StreamKind::Original)
        .expect("original");
    let on_disk =
        std::fs::read(root.container(&store_id, &stream.container_path_id)).expect("container");

    let mut package = Cursor::new(Vec::new());
    backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    let bytes = package.into_inner();

    let at = bytes
        .windows(on_disk.len())
        .position(|window| window == on_disk.as_slice());
    assert!(
        at.is_some(),
        "the package does not carry the container's own bytes"
    );
}

/// A caller that cancels after the first progress report.
///
/// `chur_vault_lock` drains and joins every operation before it takes the
/// session, so an operation that cannot stop is a lock that cannot complete.
/// A vault can hold one object of a terabyte, and a copy that checked its flag
/// only between files would make the lock wait for that whole copy.
struct CancelAtOnce {
    cancelled: std::cell::Cell<bool>,
}

impl chur_media::progress::Progress for CancelAtOnce {
    fn cancelled(&self) -> bool {
        let seen = self.cancelled.get();
        self.cancelled.set(true);
        seen
    }

    fn advance(&mut self, _processed: u64) {}
}

#[test]
fn a_backup_stops_inside_a_container_rather_than_between_files() {
    let (_root, mut session) = new_vault();
    // Several buffers' worth, so a copy that only checked between files would
    // run to the end of this one.
    import_one(&mut session, 262_144 * 4, "big.jpg", 0x7777);

    let mut package = Cursor::new(Vec::new());
    let mut progress = CancelAtOnce {
        cancelled: std::cell::Cell::new(false),
    };
    assert_eq!(
        rejection(backup::create(
            &mut session,
            &mut package,
            NOW,
            &mut progress
        )),
        ChurStatus::Cancelled
    );
    assert!(
        (package.into_inner().len() as u64) < 262_144 * 4,
        "a cancelled backup wrote the whole object"
    );
}

/// The same for the restore half: a package with one large object must stop
/// inside it, not after it.
#[test]
fn a_restore_stops_inside_a_container_rather_than_between_files() {
    let (_root, mut session) = new_vault();
    import_one(&mut session, 262_144 * 4, "big.jpg", 0x8888);
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    session.lock().expect("lock");

    let destination = scratch_root();
    let mut progress = CancelAtOnce {
        cancelled: std::cell::Cell::new(false),
    };
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut package,
            PASSWORD,
            &mut progress,
        )),
        ChurStatus::Cancelled
    );
    assert!(destination.registry_names().unwrap().is_empty());
}

/// A package restored beside the vault it came from is refused and leaves
/// that vault alone.
///
/// A second copy of one identity, or a second identity under a password the
/// first already opens, would make unlock pick between them at random
/// (`KEY_SLOTS.md` §8). Each clause of `vault::ensure_restorable` has its own
/// case: the password opens an installed identity, and, through the recovery
/// phrase which no installed password slot can match, the `vault_id` alone
/// is installed.
#[test]
fn a_restore_beside_its_source_is_refused_and_leaves_the_source_alone() {
    let (root, mut session) = new_vault();
    let (object_id, bytes) = import_one(&mut session, 40_000, "a.jpg", 0x9999);
    let source_store = session.object_store_id();
    let source_vault_id = session.vault_id();
    let phrase = recovery::to_phrase(&session.add_recovery_slot().expect("recovery"));

    let mut package = Cursor::new(Vec::new());
    backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    session.lock().expect("lock");

    // The same root, which already holds the identity this package carries.
    assert_eq!(
        rejection(backup::restore(
            &root,
            &mut package,
            PASSWORD,
            &mut Uninterrupted,
        )),
        ChurStatus::Conflict
    );
    assert_eq!(root.registry_names().unwrap().len(), 1);
    assert_eq!(
        rejection(backup::restore(
            &root,
            &mut package,
            phrase.as_bytes(),
            &mut Uninterrupted,
        )),
        ChurStatus::Conflict
    );
    assert_eq!(root.registry_names().unwrap().len(), 1);

    // The source directory is untouched and still opens its own objects.
    assert!(
        root.vault(&source_store).exists(),
        "the restore removed the vault it was taken from"
    );
    let reopened = vault::unlock_with_password(&root, PASSWORD, NOW + 2_000).expect("unlock");
    assert_eq!(reopened.vault_id(), source_vault_id);
    assert_eq!(exported(&reopened, &object_id), bytes);
}

/// §7.1 orders slot entries by ascending `slot_id`, not by the order a
/// descriptor happens to store them in. Two writers over one vault must emit
/// one sequence, so a package's commitment may not depend on enrolment order.
#[test]
fn the_slot_inventory_order_does_not_depend_on_enrolment_order() {
    // Enrolling a second slot appends it to the descriptor, so at least one of
    // these two vaults has a descriptor whose slots are not in ascending
    // identifier order. Both must still restore, which is what proves the
    // commitment was taken in the sorted order rather than the stored one.
    for _ in 0..8 {
        let (_root, mut session) = new_vault();
        session.add_recovery_slot().expect("recovery");
        session
            .add_apple_keychain_slot(random::id().unwrap())
            .expect("keychain");
        let mut package = Cursor::new(Vec::new());
        let summary =
            backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
        assert_eq!(summary.slot_count, 2);
        session.lock().expect("lock");

        let destination = scratch_root();
        backup::restore(&destination, &mut package, PASSWORD, &mut Uninterrupted).expect("restore");
    }
}

#[test]
fn encrypted_backup_restores_content_only_cyrillic_search_and_its_source_identity() {
    use chur_catalog::{content_index, query::Scope, store};
    let (root, mut source) = new_vault();
    let (object_id, original_bytes) = import_one(&mut source, 4096, "scan.jpg", 0x7342);
    let stream_id = store::object(source.catalog_ref().unwrap(), &object_id)
        .unwrap()
        .primary_stream_id;
    let vault_id = source.vault_id();
    let text = "Конфиденциальная расшифровка OCR_BACKUP_CANARY_934817";
    content_index::put(
        source.catalog().unwrap(),
        &object_id,
        &stream_id,
        1,
        1,
        text,
    )
    .expect("encrypted content index");
    let query = ObjectQuery {
        scope: Scope::Search,
        terms: Some("конфиденциальная расшифровка".into()),
        ..ObjectQuery::timeline()
    };
    assert_eq!(
        page(source.catalog_ref().unwrap(), &query).unwrap().objects[0].object_id,
        object_id
    );
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut source, &mut package, NOW, &mut Uninterrupted).expect("backup");
    for canary in [text.as_bytes(), b"OCR_BACKUP_CANARY_934817".as_slice()] {
        assert!(
            !package
                .get_ref()
                .windows(canary.len())
                .any(|bytes| bytes == canary)
        );
    }
    source.lock().unwrap();
    let destination = scratch_root();
    backup::restore(&destination, &mut package, PASSWORD, &mut Uninterrupted).expect("restore");
    let opened = vault::unlock_with_password(&destination, PASSWORD, NOW + 2000).expect("unlock");
    assert_eq!(opened.vault_id(), vault_id);
    assert_eq!(
        store::object(opened.catalog_ref().unwrap(), &object_id)
            .unwrap()
            .primary_stream_id,
        stream_id
    );
    let restored_hits =
        page(opened.catalog_ref().unwrap(), &query).expect("restored content search");
    assert_eq!(restored_hits.objects.len(), 1);
    assert_eq!(restored_hits.objects[0].object_id, object_id);
    assert!(
        content_index::candidates(opened.catalog_ref().unwrap(), None, 100, false)
            .unwrap()
            .is_empty()
    );
    let indexed =
        content_index::candidates(opened.catalog_ref().unwrap(), None, 100, true).unwrap();
    assert_eq!(indexed.len(), 1);
    assert_eq!(indexed[0].object_id, object_id);
    assert_eq!(indexed[0].primary_stream_id, stream_id);
    assert_eq!(exported(&opened, &object_id), original_bytes);
    drop(opened);
    drop(source);
    std::fs::remove_dir_all(root.base()).unwrap();
    std::fs::remove_dir_all(destination.base()).unwrap();
}

// Read the storage tables directly: the normal query's Active join can hide
// residual content belonging to an already deleted object.
fn assert_content_absent(session: &mut Session, object: &Id, term: &str) {
    session
        .catalog()
        .unwrap()
        .transaction(|tx| {
            let rows: i64 = tx
                .query_row(
                    "SELECT count(*) FROM content_index WHERE object_id = ?1",
                    [object.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(rows, 0);
            tx.execute_batch(
                "CREATE VIRTUAL TABLE temp.ocr_vocab USING fts5vocab(main, object_search, row)",
            )
            .unwrap();
            let terms: i64 = tx
                .query_row(
                    "SELECT count(*) FROM temp.ocr_vocab WHERE term = ?1",
                    [term],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                terms, 0,
                "deleted OCR must not remain in the FTS vocabulary"
            );
            tx.execute_batch("DROP TABLE temp.ocr_vocab").unwrap();
            Ok(())
        })
        .unwrap();
}

#[test]
fn permanently_deleted_ocr_stays_absent_after_restart_and_full_backup_restore() {
    use chur_catalog::{content_index, deletion, query::Scope, store};
    let (root, mut source) = new_vault();
    let (removed, _) = import_one(&mut source, 4096, "removed.jpg", 512);
    let (neighbor, original) = import_one(&mut source, 4096, "neighbor.jpg", 513);
    let stream = store::object(source.catalog_ref().unwrap(), &removed)
        .unwrap()
        .primary_stream_id;
    let neighbor_stream = store::object(source.catalog_ref().unwrap(), &neighbor)
        .unwrap()
        .primary_stream_id;
    content_index::put(
        source.catalog().unwrap(),
        &removed,
        &stream,
        1,
        1,
        "erasedocrsecretcanary",
    )
    .unwrap();
    content_index::put(
        source.catalog().unwrap(),
        &neighbor,
        &neighbor_stream,
        1,
        1,
        "healthyocrneighbor",
    )
    .unwrap();
    deletion::begin(source.catalog().unwrap(), &removed).unwrap();
    deletion::erase(source.catalog().unwrap(), &removed, NOW + 1).unwrap();
    assert_content_absent(&mut source, &removed, "erasedocrsecretcanary");
    let store_id = source.object_store_id();
    for pending in deletion::sweep(source.catalog_ref().unwrap()).unwrap() {
        for container in pending.containers {
            chur_media::store::unlink_container(source.root_dir(), &store_id, &container).unwrap();
        }
        deletion::finish(source.catalog().unwrap(), &pending.object_id).unwrap();
    }
    source.lock().unwrap();
    let mut source = vault::unlock_with_password(&root, PASSWORD, NOW + 2).unwrap();
    assert_content_absent(&mut source, &removed, "erasedocrsecretcanary");
    assert_eq!(
        rejection(content_index::put(
            source.catalog().unwrap(),
            &removed,
            &stream,
            1,
            1,
            "erasedocrsecretcanary"
        )),
        ChurStatus::NotFound
    );
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut source, &mut package, NOW + 3, &mut Uninterrupted).unwrap();
    let destination = scratch_root();
    backup::restore(&destination, &mut package, PASSWORD, &mut Uninterrupted).unwrap();
    let mut restored = vault::unlock_with_password(&destination, PASSWORD, NOW + 4).unwrap();
    assert_content_absent(&mut restored, &removed, "erasedocrsecretcanary");
    assert_eq!(
        rejection(content_index::put(
            restored.catalog().unwrap(),
            &removed,
            &stream,
            1,
            1,
            "erasedocrsecretcanary"
        )),
        ChurStatus::NotFound
    );
    let query = ObjectQuery {
        scope: Scope::Search,
        terms: Some("healthyocrneighbor".into()),
        ..ObjectQuery::timeline()
    };
    let hits = page(restored.catalog_ref().unwrap(), &query)
        .unwrap()
        .objects;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].object_id, neighbor);
    assert_eq!(exported(&restored, &neighbor), original);
    drop(restored);
    drop(source);
    std::fs::remove_dir_all(root.base()).unwrap();
    std::fs::remove_dir_all(destination.base()).unwrap();
}

#[test]
fn clearing_ocr_while_trashed_does_not_resurrect_text_on_restore_or_backup() {
    use chur_catalog::{content_index, query::Scope, store, trash};
    let (root, mut source) = new_vault();
    let (object, original) = import_one(&mut source, 4096, "retainedmetadata.jpg", 514);
    let stream = store::object(source.catalog_ref().unwrap(), &object)
        .unwrap()
        .primary_stream_id;
    content_index::put(
        source.catalog().unwrap(),
        &object,
        &stream,
        1,
        1,
        "clearedtrashcanary",
    )
    .unwrap();
    trash::set(source.catalog().unwrap(), &[object], false, NOW + 1).unwrap();
    content_index::clear(source.catalog().unwrap()).unwrap();
    assert_content_absent(&mut source, &object, "clearedtrashcanary");
    trash::set(source.catalog().unwrap(), &[object], true, NOW + 2).unwrap();
    assert_content_absent(&mut source, &object, "clearedtrashcanary");
    source.lock().unwrap();
    let mut source = vault::unlock_with_password(&root, PASSWORD, NOW + 3).unwrap();
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut source, &mut package, NOW + 4, &mut Uninterrupted).unwrap();
    let destination = scratch_root();
    backup::restore(&destination, &mut package, PASSWORD, &mut Uninterrupted).unwrap();
    let mut restored = vault::unlock_with_password(&destination, PASSWORD, NOW + 5).unwrap();
    assert_content_absent(&mut restored, &object, "clearedtrashcanary");
    let query = ObjectQuery {
        scope: Scope::Search,
        terms: Some("retainedmetadata".into()),
        ..ObjectQuery::timeline()
    };
    let hits = page(restored.catalog_ref().unwrap(), &query)
        .unwrap()
        .objects;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].object_id, object);
    assert_eq!(exported(&restored, &object), original);
    let candidates =
        content_index::candidates(restored.catalog_ref().unwrap(), None, 100, false).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].object_id, object);
    drop(restored);
    drop(source);
    std::fs::remove_dir_all(root.base()).unwrap();
    std::fs::remove_dir_all(destination.base()).unwrap();
}

/// The catalog snapshot has one fixed name. A copy that a killed backup left
/// behind does not stop the next backup, and neither copy survives it.
#[test]
fn a_backup_replaces_and_removes_a_stale_catalog_snapshot() {
    let (root, mut session) = new_vault();
    let snapshot = root
        .incoming(&session.object_store_id())
        .join(backup::SNAPSHOT_DIRECTORY);
    std::fs::create_dir_all(&snapshot).unwrap();
    std::fs::write(snapshot.join("catalog.db"), b"an abandoned catalog copy").unwrap();

    let mut package = Cursor::new(Vec::new());
    backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    assert!(!snapshot.exists());

    std::fs::create_dir_all(&snapshot).unwrap();
    assert!(backup::clear_snapshot(&session).expect("clear"));
    assert!(!snapshot.exists());
    assert!(!backup::clear_snapshot(&session).expect("clear again"));
    session.lock().expect("lock");
}

/// The whole catalog as one `CatalogExportV1` stream. Two catalogs whose
/// streams are equal hold the same rows in every table.
fn logical_catalog(db: &chur_catalog::CatalogDb) -> Vec<u8> {
    let mut out = Vec::new();
    chur_catalog::catalog_export::export(
        db,
        |chunk, _| {
            out.extend_from_slice(chunk);
            Ok(())
        },
        &|| false,
    )
    .expect("export the catalog");
    out
}

/// A package rebuilt from its records with a new record count.
fn reassemble(package: &[u8], records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = package[..32].to_vec();
    out[24..32].copy_from_slice(&(records.len() as u64).to_be_bytes());
    for record in records {
        out.extend_from_slice(record);
    }
    out
}

/// The records of one type, by position.
fn positions_of(package: &[u8], record_type: u8) -> Vec<usize> {
    records(package)
        .iter()
        .enumerate()
        .filter(|(_, (kind, _))| *kind == record_type)
        .map(|(index, _)| index)
        .collect()
}

/// A vault with every kind of catalog state the export must carry: objects,
/// an album with a member, a tag, a favorite, a trashed object, a note with an
/// attachment large enough to cross several export records, and content text.
fn populated_vault() -> (VaultRoot, Session, Vec<(Id, Vec<u8>)>, Id) {
    use chur_catalog::{note_attachments as files, notes};
    let (root, mut session) = new_vault();
    let first = import_one(&mut session, 300_000, "first.jpg", 0x7171);
    let second = import_one(&mut session, 4_096, "second.jpg", 0x7272);
    let trashed = import_one(&mut session, 4_096, "trashed.jpg", 0x7373);
    let album = Id::new([0x0b; 16]).unwrap();
    chur_catalog::store::put_album(
        session.catalog().unwrap(),
        &chur_catalog::model::Album {
            album_id: album,
            name: "Holiday".into(),
            created_ms: NOW,
            revision: 1,
        },
    )
    .unwrap();
    chur_catalog::store::set_album_membership(
        session.catalog().unwrap(),
        &album,
        &first.0,
        true,
        NOW,
    )
    .unwrap();
    chur_catalog::store::set_favorite(session.catalog().unwrap(), &second.0, true, NOW).unwrap();
    let stream = chur_catalog::store::streams(session.catalog_ref().unwrap(), &first.0).unwrap()[0]
        .stream_id;
    chur_catalog::content_index::put(
        session.catalog().unwrap(),
        &first.0,
        &stream,
        1,
        1,
        "lighthouse harbour",
    )
    .unwrap();
    chur_catalog::trash::set(session.catalog().unwrap(), &[trashed.0], false, NOW).unwrap();
    let note = notes::save(
        session.catalog().unwrap(),
        None,
        0,
        "Portable",
        "rows, not pages",
        false,
        notes::NoteFormat::PlainText,
        NOW,
    )
    .unwrap();
    let data = plaintext(2_500_000, 0x7474);
    files::put(
        session.catalog().unwrap(),
        &note.id,
        note.revision,
        files::AttachmentData {
            attachment: files::Attachment {
                id: random::id().unwrap(),
                name: "scan.bin".into(),
                mime_type: "application/octet-stream".into(),
                size: data.len() as u64,
            },
            data,
        },
        NOW,
    )
    .unwrap();
    (root, session, vec![first, second, trashed], note.id)
}

/// ADR-0068: a version 2 package carries the catalog as rows, and the restored
/// catalog holds exactly the rows of the source in every table, with both FTS
/// indexes rebuilt from them.
#[test]
fn a_version_two_package_restores_every_catalog_row() {
    let (_root, mut session, objects, note) = populated_vault();
    let mut package = Cursor::new(Vec::new());
    let summary =
        backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    let source_rows = logical_catalog(session.catalog_ref().unwrap());
    session.lock().expect("lock");
    let package = package.into_inner();

    assert_eq!(&package[8..10], &[0x00, 0x02], "the package is version 2");
    let exports = positions_of(&package, 0x03);
    assert!(
        exports.len() >= 3,
        "the attachment spans several export records"
    );
    assert_eq!(exports, (2..2 + exports.len()).collect::<Vec<_>>());
    assert_eq!(summary.record_count, 3 + exports.len() as u64 + 3);

    let destination = scratch_root();
    backup::restore(
        &destination,
        &mut Cursor::new(package),
        PASSWORD,
        &mut Uninterrupted,
    )
    .expect("restore");
    let mut opened =
        vault::unlock_with_password(&destination, PASSWORD, NOW + 2_000).expect("unlock");
    assert_eq!(logical_catalog(opened.catalog_ref().unwrap()), source_rows);
    for (object_id, bytes) in &objects {
        assert_eq!(&exported(&opened, object_id), bytes);
    }
    let listed = page(opened.catalog_ref().unwrap(), &ObjectQuery::timeline()).expect("page");
    assert_eq!(listed.total_count, 2, "the trashed object stays in trash");
    let mut query = ObjectQuery::timeline();
    query.terms = Some("lighthouse".into());
    assert_eq!(
        page(opened.catalog_ref().unwrap(), &query)
            .unwrap()
            .total_count,
        1,
        "the content text is searchable after the index rebuild"
    );
    assert_eq!(
        chur_catalog::notes::get(opened.catalog_ref().unwrap(), &note)
            .unwrap()
            .attachment_count,
        1
    );
    opened.lock().expect("lock");
}

/// Portable backup preserves real video originals, derived streams and resume rows.
#[test]
fn a_version_two_package_preserves_video_resume_and_derived_streams() {
    let (_root, mut session) = new_vault();
    let cases = [
        (
            include_bytes!("../../../../tests/media/hevc-main10/sdr10-hvc1.mp4").as_slice(),
            192,
            96,
            1250,
            500,
            StreamKind::CompatibleVideo,
            include_bytes!("../../../../tests/media/video-compatibility/reference-sdr.mp4")
                .as_slice(),
            192,
            96,
            "video/mp4",
        ),
        (
            include_bytes!("../../../../tests/media/video-acceptance/main10-long-gop-vfr.mp4")
                .as_slice(),
            320,
            180,
            64_000,
            31_000,
            StreamKind::VideoStoryboard,
            include_bytes!("../../../../tests/media/video-timeline/reference-storyboard.jpg")
                .as_slice(),
            640,
            270,
            "image/jpeg",
        ),
    ];
    let mut objects = Vec::new();
    for (
        original,
        width,
        height,
        duration,
        position,
        kind,
        derived,
        derived_width,
        derived_height,
        _,
    ) in &cases
    {
        let object_id = import::import_bytes(
            &mut session,
            SourceCapability {
                requested_object_id: None,
                seekable: true,
                known_length: Some(original.len() as u64),
                content_type_hint: "video/mp4".into(),
                original_filename: Some("video.mp4".into()),
                capture_time_ms: None,
            },
            CanonicalMedia {
                media_class: MediaClass::Video,
                width: *width,
                height: *height,
                duration_ms: *duration,
            },
            "video/mp4",
            &Zeroizing::new(original.to_vec()),
            NOW,
        )
        .expect("import actual video");
        chur_media::derived::put(
            &mut session,
            &object_id,
            *kind,
            *derived_width,
            *derived_height,
            &Zeroizing::new(derived.to_vec()),
            NOW,
        )
        .expect("store actual derived stream");
        chur_catalog::playback::put(session.catalog().unwrap(), &object_id, *position, *duration)
            .expect("save resume position");
        objects.push(object_id);
    }
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    let source_rows = logical_catalog(session.catalog_ref().unwrap());
    session.lock().expect("lock source");
    let destination = scratch_root();
    backup::restore(
        &destination,
        &mut Cursor::new(package.into_inner()),
        PASSWORD,
        &mut Uninterrupted,
    )
    .expect("restore video catalog");
    let mut opened =
        vault::unlock_with_password(&destination, PASSWORD, NOW + 2000).expect("unlock");
    assert_eq!(logical_catalog(opened.catalog_ref().unwrap()), source_rows);
    for (object_id, (original, _, _, _, position, kind, derived, width, height, content_type)) in
        objects.iter().zip(&cases)
    {
        assert_eq!(
            chur_catalog::playback::get(opened.catalog_ref().unwrap(), object_id).unwrap(),
            *position
        );
        assert_eq!(exported(&opened, object_id), *original);
        let mut reader = chur_media::reader::open(&opened, object_id, *kind)
            .expect("open restored derived stream");
        let info = reader.content_info().unwrap();
        assert_eq!(info.content_type, *content_type);
        assert_eq!(
            info.media_kind,
            u16::from(match kind {
                StreamKind::VideoStoryboard => MediaClass::Image.value(),
                StreamKind::CompatibleVideo => MediaClass::Video.value(),
                _ => panic!("unexpected derived fixture"),
            })
        );
        assert_eq!(reader.dimensions(), (*width, *height));
        assert_eq!(
            reader
                .read_range(0, info.plaintext_size)
                .unwrap()
                .as_slice(),
            *derived
        );
    }
    opened.lock().expect("lock restored vault");
}

/// ADR-0068: the catalog export records are bound to their place. Two records
/// swapped, the last record removed, a record from another package of the same
/// vault, or a changed descriptor each fail before anything is installed.
#[test]
fn a_moved_cut_or_foreign_catalog_export_record_installs_nothing() {
    let (_root, mut session, _, _) = populated_vault();
    let mut first = Cursor::new(Vec::new());
    backup::create(&mut session, &mut first, NOW, &mut Uninterrupted).expect("first");
    let mut second = Cursor::new(Vec::new());
    backup::create(&mut session, &mut second, NOW + 1, &mut Uninterrupted).expect("second");
    session.lock().expect("lock");
    let package = first.into_inner();
    let other = second.into_inner();
    let parts: Vec<Vec<u8>> = records(&package)
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect();
    let exports = positions_of(&package, 0x03);

    let mut reordered = parts.clone();
    reordered.swap(exports[0], exports[1]);

    let mut truncated = parts.clone();
    truncated.remove(*exports.last().unwrap());

    let mut spliced = parts.clone();
    spliced[exports[1]] = records(&other)[exports[1]].1.clone();

    let mut altered = parts.clone();
    let descriptor = &mut altered[1];
    let last = descriptor.len() - 1;
    descriptor[last] ^= 0x01;

    for (case, damaged, expected) in [
        (
            "reordered",
            reassemble(&package, &reordered),
            ChurStatus::VaultCorrupt,
        ),
        (
            "truncated",
            reassemble(&package, &truncated),
            ChurStatus::VaultCorrupt,
        ),
        (
            "spliced",
            reassemble(&package, &spliced),
            ChurStatus::VaultCorrupt,
        ),
        // The descriptor's own authenticator fails first, under the root its
        // slot returned, and the record commitment would refuse it next.
        (
            "altered descriptor",
            reassemble(&package, &altered),
            ChurStatus::AuthenticationFailed,
        ),
    ] {
        let destination = scratch_root();
        assert_eq!(
            rejection(backup::restore(
                &destination,
                &mut Cursor::new(damaged),
                PASSWORD,
                &mut Uninterrupted,
            )),
            expected,
            "{case}"
        );
        assert!(destination.registry_names().unwrap().is_empty(), "{case}");
        assert_eq!(
            std::fs::read_dir(destination.vaults())
                .map(|entries| entries.count())
                .unwrap_or(0),
            0,
            "{case}: no partial vault directory survives"
        );
    }

    // The undamaged package restores.
    backup::restore(
        &scratch_root(),
        &mut Cursor::new(package),
        PASSWORD,
        &mut Uninterrupted,
    )
    .expect("restore the undamaged package");
}

/// The object identifier inside `tests/fixtures/backup-v1-raw-catalog.churbak`.
const LEGACY_OBJECT: &str = "06476c2ab576645cad147b2b45a839d7";

/// A version 1 package, written by a build before ADR-0068 with a copy of the
/// SQLCipher file as its catalog and a v1 object container, still restores.
/// The restored vault then travels through a version 2 package with a new v2
/// container beside the old one, so both container versions and both package
/// versions meet in one chain.
#[test]
fn a_version_one_package_still_restores_and_moves_on_to_version_two() {
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/backup-v1-raw-catalog.churbak"
    ))
    .expect("the version 1 fixture");
    assert_eq!(&fixture[8..10], &[0x00, 0x01], "the fixture is version 1");
    // The object the fixture build imported, as its generator printed it.
    let legacy = Id::new(
        (0..16)
            .map(|i| u8::from_str_radix(&LEGACY_OBJECT[2 * i..2 * i + 2], 16).unwrap())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap(),
    )
    .expect("fixture object");

    let first = scratch_root();
    backup::restore(
        &first,
        &mut Cursor::new(fixture),
        PASSWORD,
        &mut Uninterrupted,
    )
    .expect("restore the version 1 package");
    let mut session = vault::unlock_with_password(&first, PASSWORD, NOW + 1_000).expect("unlock");
    let legacy_bytes = plaintext(4_096, 0x5151).to_vec();
    assert_eq!(exported(&session, &legacy), legacy_bytes);
    assert_eq!(
        chur_catalog::store::streams(session.catalog_ref().unwrap(), &legacy).unwrap()[0]
            .container_version,
        1
    );
    let album = Id::new([0x0a; 16]).unwrap();
    assert_eq!(
        chur_catalog::store::album_name(session.catalog_ref().unwrap(), &album).unwrap(),
        Some(String::from("Legacy album"))
    );

    let (fresh, fresh_bytes) = import_one(&mut session, 70_000, "fresh.jpg", 0x5252);
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut session, &mut package, NOW + 2_000, &mut Uninterrupted).expect("create");
    let source_rows = logical_catalog(session.catalog_ref().unwrap());
    session.lock().expect("lock");
    assert_eq!(&package.get_ref()[8..10], &[0x00, 0x02]);

    let second = scratch_root();
    backup::restore(&second, &mut package, PASSWORD, &mut Uninterrupted).expect("restore v2");
    let opened = vault::unlock_with_password(&second, PASSWORD, NOW + 3_000).expect("unlock");
    assert_eq!(logical_catalog(opened.catalog_ref().unwrap()), source_rows);
    assert_eq!(exported(&opened, &legacy), legacy_bytes);
    assert_eq!(exported(&opened, &fresh), fresh_bytes);
    let versions: Vec<u16> = [legacy, fresh]
        .iter()
        .map(|id| {
            chur_catalog::store::streams(opened.catalog_ref().unwrap(), id).unwrap()[0]
                .container_version
        })
        .collect();
    assert_eq!(versions, vec![1, 2]);
    assert_eq!(
        chur_catalog::store::album_name(opened.catalog_ref().unwrap(), &album).unwrap(),
        Some(String::from("Legacy album"))
    );
}

/// A package source whose byte at `target` changes after its first read, as a
/// file can when another process writes it during a restore.
struct ChangesAfterFirstRead {
    data: Vec<u8>,
    position: u64,
    target: usize,
    seen: bool,
}

impl std::io::Read for ChangesAfterFirstRead {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let start = usize::try_from(self.position).unwrap().min(self.data.len());
        let count = buffer.len().min(self.data.len() - start);
        buffer[..count].copy_from_slice(&self.data[start..start + count]);
        if (start..start + count).contains(&self.target) {
            if self.seen {
                buffer[self.target - start] ^= 0x01;
            }
            self.seen = true;
        }
        self.position += count as u64;
        Ok(count)
    }
}

impl std::io::Seek for ChangesAfterFirstRead {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        let mut cursor = Cursor::new(&self.data);
        cursor.set_position(self.position);
        self.position = cursor.seek(to)?;
        Ok(self.position)
    }
}

/// The step-4 check reads a container from the package, and the install reads
/// it again. A container that changes between the two reads must not install,
/// so the extracted copy is verified on its own, chunk by chunk.
#[test]
fn a_container_changed_after_its_check_installs_nothing() {
    let (_root, mut session) = new_vault();
    import_one(&mut session, 300_000, "a.jpg", 0x7575);
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    session.lock().expect("lock");
    let data = package.into_inner();
    let target = container_byte(&data);

    let destination = scratch_root();
    let mut source = ChangesAfterFirstRead {
        data,
        position: 0,
        target,
        seen: false,
    };
    assert_eq!(
        rejection(backup::restore(
            &destination,
            &mut source,
            PASSWORD,
            &mut Uninterrupted
        )),
        ChurStatus::VaultCorrupt
    );
    assert!(source.seen, "the changed byte was read");
    assert!(destination.registry_names().unwrap().is_empty());
}

/// A package of a different vault whose password already opens an installed
/// identity is refused, so unlock never has two identities for one password.
#[test]
fn a_restore_under_a_password_an_installed_identity_opens_is_refused() {
    let (_other, mut session) = new_vault();
    let mut package = Cursor::new(Vec::new());
    backup::create(&mut session, &mut package, NOW, &mut Uninterrupted).expect("create");
    session.lock().expect("lock");

    let (root, mut installed) = new_vault();
    let installed_id = installed.vault_id();
    installed.lock().expect("lock");

    assert_eq!(
        rejection(backup::restore(
            &root,
            &mut package,
            PASSWORD,
            &mut Uninterrupted,
        )),
        ChurStatus::Conflict
    );
    assert_eq!(root.registry_names().unwrap().len(), 1);
    let reopened = vault::unlock_with_password(&root, PASSWORD, NOW + 1).expect("unlock");
    assert_eq!(reopened.vault_id(), installed_id);
}

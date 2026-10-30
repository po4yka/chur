//! The fault-injection matrix of `docs/assurance/RELEASE_GATES.md` Gate 2.
//!
//! Gate 2 requires "fault injection for initialization/import/slot/migration",
//! and `../../ROADMAP.md` makes the same four a Phase 1 exit criterion. The
//! difference between this file and the cases already in `pipeline.rs` is that
//! this one enumerates: each flow declares its ordered interruption points, and
//! the test walks every one of them rather than the one a case happened to
//! pick. A point added to a flow is a variant, and the loop covers it.
//!
//! "The process died" is modelled the way the recovery path meets it: the
//! in-flight value is dropped without its commit or its abandon, the session is
//! dropped with it, and the vault is reopened from the directory. Nothing is
//! stubbed and no code path is special-cased for the test, because the property
//! under test is what the bytes on disk allow after the process is gone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chur_catalog::db::{CatalogDb, CatalogKey, CatalogLocation};
use chur_catalog::paths::VaultRoot;
use chur_catalog::query::{ObjectQuery, page};
use chur_catalog::vault;
use chur_catalog::{journal, store};
use chur_core::{ChurStatus, Result};
use chur_crypto::random;
use chur_format::constants::{CATALOG_FORMAT_VERSION_V18, MediaClass, ObjectState};
use chur_media::import::{self, CanonicalMedia, SourceCapability};

const PASSWORD: &[u8] = b"correct horse battery staple";
const REPLACEMENT: &[u8] = b"a different correct horse";
const NOW: u64 = 1_700_000_000_000;

fn scratch_root() -> VaultRoot {
    let mut path = std::env::temp_dir();
    path.push(format!("chur-fault-{}", random::id().unwrap().to_hex()));
    std::fs::create_dir_all(&path).unwrap();
    VaultRoot::new(path)
}

fn rejection<T>(outcome: Result<T>) -> ChurStatus {
    match outcome {
        Err(error) => error.status(),
        Ok(_) => panic!("the vault accepted something the specification forbids"),
    }
}

fn source(length: u64) -> SourceCapability {
    SourceCapability {
        requested_object_id: None,
        seekable: true,
        known_length: Some(length),
        content_type_hint: String::from("image/jpeg"),
        original_filename: Some(String::from("a.jpg")),
        capture_time_ms: Some(NOW - 86_400_000),
    }
}

fn photo() -> CanonicalMedia {
    CanonicalMedia {
        media_class: MediaClass::Image,
        width: 4_000,
        height: 3_000,
        duration_ms: 0,
    }
}

fn plaintext(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// The ordered points of `PROVISIONING.md` §3 and `VAULT_DESCRIPTOR_V1.md` §9.
// The prefix is the point: each variant names the step the process died after.
#[expect(
    clippy::enum_variant_names,
    reason = "each variant names a step it follows"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitPoint {
    /// The temporary descriptor and the catalog exist; nothing is installed.
    AfterCreate,
    /// The recovery slot of step 5 is sealed into the temporary descriptor.
    AfterRecoverySlot,
    /// Step 6 installed the descriptor.
    AfterActivate,
}

const INIT_POINTS: [InitPoint; 3] = [
    InitPoint::AfterCreate,
    InitPoint::AfterRecoverySlot,
    InitPoint::AfterActivate,
];

#[test]
fn initialization_leaves_nothing_openable_until_it_commits() {
    for point in INIT_POINTS {
        let root = scratch_root();
        let mut creation = vault::create(&root, PASSWORD, NOW).expect("create");
        let mut phrase = None;
        if point != InitPoint::AfterCreate {
            phrase = Some(chur_crypto::recovery::to_phrase(
                &creation.add_recovery_slot().expect("recovery slot"),
            ));
        }

        if point == InitPoint::AfterActivate {
            drop(creation.activate().expect("activate"));
            assert_eq!(
                vault::unlock_with_password(&root, PASSWORD, NOW)
                    .expect("unlock")
                    .vault_id()
                    .to_hex()
                    .len(),
                32,
                "an activated vault opens at {point:?}"
            );
            let phrase = phrase.expect("the offer ran");
            drop(
                vault::unlock_with_recovery(&root, &phrase, NOW)
                    .expect("the offered phrase opens the vault"),
            );
            continue;
        }

        // The process died before step 6.
        drop(creation);

        assert_eq!(
            rejection(vault::unlock_with_password(&root, PASSWORD, NOW)),
            ChurStatus::AuthenticationFailed,
            "an interrupted creation must not be openable at {point:?}"
        );
        assert!(
            root.registry_names().expect("registry").is_empty(),
            "an uninstalled descriptor must not be enumerated at {point:?}"
        );
        if let Some(phrase) = phrase {
            assert_eq!(
                rejection(vault::unlock_with_recovery(&root, &phrase, NOW)),
                ChurStatus::AuthenticationFailed,
                "a phrase from an interrupted creation opens nothing"
            );
        }
        assert!(
            root.sweep_temporary().expect("sweep") >= 1,
            "the sweep must reclaim the interrupted creation at {point:?}"
        );
        assert_eq!(
            root.sweep_temporary().expect("sweep"),
            0,
            "the sweep must be idempotent at {point:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// The ordered points of `OBJECT_CONTAINER_V1.md` §14.2.
#[expect(
    clippy::enum_variant_names,
    reason = "each variant names a step it follows"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImportPoint {
    /// The manifest is durable, the index is reserved, the record is written.
    AfterBegin,
    /// Chunks are written; no final commit exists.
    AfterChunks,
    /// The object is committed and activated.
    AfterCommit,
}

const IMPORT_POINTS: [ImportPoint; 3] = [
    ImportPoint::AfterBegin,
    ImportPoint::AfterChunks,
    ImportPoint::AfterCommit,
];

#[test]
fn an_interrupted_import_is_recoverable_and_exposes_no_partial_object() {
    for point in IMPORT_POINTS {
        let root = scratch_root();
        let mut session = vault::create(&root, PASSWORD, NOW)
            .expect("create")
            .activate()
            .expect("activate");
        let store_id = session.object_store_id();

        let mut running = import::begin(&mut session, source(5_000), photo(), NOW).expect("begin");
        let transaction_id = running.transaction_id();
        let record = journal::read(session.catalog_ref().unwrap(), &transaction_id).unwrap();
        let temporary = root.temporary_container(&store_id, &record.temp_path_id);
        assert!(temporary.exists(), "the container is durable at {point:?}");

        if point != ImportPoint::AfterBegin {
            running
                .write(&mut session, &plaintext(5_000))
                .expect("write");
        }
        if point == ImportPoint::AfterCommit {
            let object_id = running
                .commit(&mut session, "image/jpeg", NOW)
                .expect("commit");
            drop(session);

            let mut reopened = vault::unlock_with_password(&root, PASSWORD, NOW).expect("unlock");
            assert_eq!(
                import::reconcile(&mut reopened).expect("reconcile"),
                0,
                "a committed import leaves nothing to reconcile"
            );
            let row = store::object(reopened.catalog_ref().expect("catalog"), &object_id)
                .expect("the committed object is present");
            assert_eq!(row.state, ObjectState::Active);
            continue;
        }

        // The process died mid-import: no commit, no abandon, no lock.
        drop(running);
        drop(session);

        let mut reopened = vault::unlock_with_password(&root, PASSWORD, NOW).expect("unlock");
        assert_eq!(
            page(
                reopened.catalog_ref().expect("catalog"),
                &ObjectQuery::timeline()
            )
            .expect("page")
            .objects
            .len(),
            0,
            "an uncommitted import must appear in no scope at {point:?}"
        );
        assert_eq!(
            journal::live(reopened.catalog_ref().unwrap())
                .unwrap()
                .len(),
            1,
            "the record survives the death at {point:?}"
        );

        assert_eq!(
            import::reconcile(&mut reopened).expect("reconcile"),
            1,
            "the next unlock reclaims the import at {point:?}"
        );
        assert!(
            !temporary.exists(),
            "reconciliation left the container behind at {point:?}"
        );
        assert!(
            journal::live(reopened.catalog_ref().unwrap())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            import::reconcile(&mut reopened).expect("reconcile"),
            0,
            "reconciliation must be idempotent at {point:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Key slots
// ---------------------------------------------------------------------------

/// The ordered points of `KEY_SLOTS.md` §9.
///
/// §9 requires every slot change to be one descriptor generation: an
/// intermediate generation carrying neither the old slot nor the new one would
/// be a vault nobody can open. There is no public call that stops between the
/// two, which is the point; what this walks is every observable state around a
/// change, and at each one exactly the credentials that should open the vault
/// do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotPoint {
    BeforeAnyChange,
    AfterRecoveryAdded,
    AfterPasswordReplaced,
    AfterTheLastPortableRemovalIsRefused,
}

const SLOT_POINTS: [SlotPoint; 4] = [
    SlotPoint::BeforeAnyChange,
    SlotPoint::AfterRecoveryAdded,
    SlotPoint::AfterPasswordReplaced,
    SlotPoint::AfterTheLastPortableRemovalIsRefused,
];

#[test]
fn a_slot_change_never_leaves_a_vault_nobody_can_open() {
    for point in SLOT_POINTS {
        let root = scratch_root();
        let mut session = vault::create(&root, PASSWORD, NOW)
            .expect("create")
            .activate()
            .expect("activate");

        let mut phrase = None;
        let mut password: &[u8] = PASSWORD;
        match point {
            SlotPoint::BeforeAnyChange => {}
            SlotPoint::AfterRecoveryAdded => {
                phrase = Some(chur_crypto::recovery::to_phrase(
                    &session.add_recovery_slot().expect("recovery slot"),
                ));
            }
            SlotPoint::AfterPasswordReplaced => {
                phrase = Some(chur_crypto::recovery::to_phrase(
                    &session.add_recovery_slot().expect("recovery slot"),
                ));
                session
                    .replace_password(
                        REPLACEMENT,
                        chur_crypto::password::Argon2Params::v1_default(),
                    )
                    .expect("replace");
                password = REPLACEMENT;
            }
            SlotPoint::AfterTheLastPortableRemovalIsRefused => {
                let (slot_id, _, _) = session
                    .slots()
                    .into_iter()
                    .find(|(_, family, _)| *family == chur_format::constants::SlotType::Password)
                    .expect("the password slot");
                assert_eq!(
                    rejection(session.remove_slot(&slot_id)),
                    ChurStatus::Conflict,
                    "removing the last portable slot must be refused"
                );
            }
        }

        // The process died right after whatever the point did.
        drop(session);

        drop(vault::unlock_with_password(&root, password, NOW).expect("the password still opens"));
        if let Some(phrase) = &phrase {
            drop(
                vault::unlock_with_recovery(&root, phrase, NOW)
                    .expect("the recovery phrase still opens"),
            );
        }
        if point == SlotPoint::AfterPasswordReplaced {
            assert_eq!(
                rejection(vault::unlock_with_password(&root, PASSWORD, NOW)),
                ChurStatus::AuthenticationFailed,
                "the retired password must not open the vault"
            );
        }

        let reopened = vault::unlock_with_password(&root, password, NOW).expect("unlock");
        let passwords = reopened
            .slots()
            .into_iter()
            .filter(|(_, family, _)| *family == chur_format::constants::SlotType::Password)
            .count();
        assert_eq!(
            passwords, 1,
            "exactly one password slot exists at {point:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

/// The two failures a vault on disk can present to a build that cannot read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MigrationPoint {
    /// The catalog records a format version this build does not read.
    CatalogFromTheFuture,
    /// A registry entry this build cannot parse sits beside a good one.
    UnreadableRegistryEntry,
}

const MIGRATION_POINTS: [MigrationPoint; 2] = [
    MigrationPoint::CatalogFromTheFuture,
    MigrationPoint::UnreadableRegistryEntry,
];

#[test]
fn a_vault_this_build_cannot_read_fails_closed() {
    for point in MIGRATION_POINTS {
        let root = scratch_root();
        let session = vault::create(&root, PASSWORD, NOW)
            .expect("create")
            .activate()
            .expect("activate");
        let vault_id = session.vault_id();
        let store_id = session.object_store_id();
        let key = CatalogKey::derive(session.root_secret().expect("root"), &vault_id)
            .expect("catalog key");
        drop(session);

        match point {
            MigrationPoint::CatalogFromTheFuture => {
                let catalog = std::fs::read_dir(root.vault(&store_id))
                    .expect("vault directory")
                    .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                    .find(|path| path.extension().is_some_and(|value| value == "db"))
                    .expect("the catalog file");
                let mut db =
                    CatalogDb::open(&CatalogLocation::File(&catalog), &key).expect("open catalog");
                db.transaction(|transaction| {
                    transaction
                        .execute(
                            "UPDATE vault_state SET catalog_format_version = ?1 WHERE only_row = 1",
                            [i64::from(CATALOG_FORMAT_VERSION_V18) + 1],
                        )
                        .map(|_| ())
                        .map_err(|_| {
                            chur_core::Error::new(
                                ChurStatus::InternalFailure,
                                "the test could not stamp a later version",
                            )
                        })
                })
                .expect("stamp");
                db.close().expect("close");

                assert_eq!(
                    rejection(vault::unlock_with_password(&root, PASSWORD, NOW)),
                    ChurStatus::MigrationRequired,
                    "a catalog from the future is a migration, not corruption"
                );
            }
            MigrationPoint::UnreadableRegistryEntry => {
                // A file the parser refuses, in the registry, with the name a
                // real entry would have. §11 skips it before any credential is
                // used, so the vault beside it still opens.
                let junk = root
                    .registry()
                    .join(format!("{}.vd", random::id().expect("id").to_hex()));
                std::fs::write(&junk, b"not a descriptor").expect("write");

                drop(
                    vault::unlock_with_password(&root, PASSWORD, NOW)
                        .expect("the readable vault still opens"),
                );
                assert!(junk.exists(), "an unreadable entry is skipped, not deleted");
            }
        }
    }
}

//! Creating and restoring a portable backup package.
//!
//! `docs/format/BACKUP_FORMAT_V1.md` owns the bytes and `chur_format::backup`
//! writes them. This module is the transaction around them: §7's streaming
//! creation and §8's restore, over a real vault on a real filesystem.
//!
//! Three properties are the reason the code looks as it does.
//!
//! **Containers travel unchanged.** §1 requires the package to preserve
//! immutable object containers as byte copies. Restore opens each container's
//! final commit before activation so damage cannot become an openable vault.
//!
//! **Memory does not scale with the vault.** The inventory is walked twice
//! rather than collected: `docs/format/CATALOG_SCHEMA_V1.md` §21 admits a
//! million objects, and a materialized inventory would be over a hundred
//! megabytes. One entry and one copy buffer are in flight at a time.
//!
//! **Completeness is authenticated.** The ordered inventory commitment of §7.2
//! is recomputed while the package is read, and the final backup commit seals
//! it together with the record count the public preamble declared. A package
//! with a container removed, a record added, or two records reordered fails
//! there rather than restoring a vault that is quietly missing something. In a
//! version 2 package the commit also seals the record commitment of ADR-0068
//! over every record that is not a container.
//!
//! **The catalog travels as rows.** This build writes version 2 packages only:
//! the catalog is a logical `CatalogExportV1` stream in sealed records, and a
//! restore imports it into a new SQLCipher catalog. A version 1 package, which
//! carries a copy of the SQLCipher file, still restores through the path that
//! version 1 defined.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chur_catalog::paths::{RegistryName, VaultRoot};
use chur_catalog::vault::{self, Session};
use chur_catalog::{schema, store};
use chur_core::{ChurStatus, Id, Result, bail, ensure, limits::backup as bounds};
use chur_crypto::{Key, Nonce, random};
use chur_format::backup::{
    BackupManifest, CatalogExportPosition, FinalBackupCommit, Framing, InventoryCommitter,
    PublicPreamble, RECORD_HEADER_LEN, RecordCommitter, RecordHeader, RecordSeal, RecordType,
    SlotInventoryEntry, StreamInventoryEntry, framing_of, manifest_key, open_catalog_export,
    seal_catalog_export,
};
use chur_format::catalog_export::ChunkSource;
use chur_format::constants::{
    BACKUP_VERSION_V1, BACKUP_VERSION_V2, CONTAINER_VERSION_V1, ObjectState, SlotType, VaultState,
};
use chur_format::container::{PublicPreamble as ContainerPreamble, StreamIdentity, StreamReader};
use chur_format::descriptor::VaultDescriptor;
use chur_sync_protocol::identity::DeviceIdentityEnvelope;
use zeroize::Zeroizing;

use crate::keys;
use crate::progress::{self, Progress};
use crate::store::ContainerFile;

/// How much of a container is read to recompute its manifest commitment.
///
/// The manifest record follows the container preamble, and its length is the
/// preamble's one field, so the head is read in two steps and never as a guess.
const CONTAINER_HEAD_MAX: usize = 65_536;

/// The buffer one container copy holds.
const COPY_BUFFER: usize = 262_144;

/// What a created package holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupSummary {
    /// The package's identity.
    pub backup_id: Id,
    /// The vault identity it carries. §11: one package, one identity.
    pub vault_id: Id,
    /// Records written, which the public preamble declares.
    pub record_count: u64,
    /// Stream inventory entries.
    pub stream_count: u32,
    /// Portable slot inventory entries.
    pub slot_count: u32,
    /// Bytes written.
    pub package_length: u64,
}

/// What a restore installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreSummary {
    /// The package's identity.
    pub backup_id: Id,
    /// The vault identity that was installed.
    pub vault_id: Id,
    /// Containers written.
    pub stream_count: u32,
    /// When the package was created.
    pub created_time_ms: u64,
}

// ---------------------------------------------------------------------------
// §3 Portable slots
// ---------------------------------------------------------------------------

/// Whether a slot family travels in a package, §3.
///
/// A device-bound slot is excluded, and not as an optimization: an Android
/// Keystore alias and a `ThisDeviceOnly` Keychain item name key material that
/// exists on one device only, so a package carrying them would restore a vault
/// with a slot nothing can open, on a device that cannot be told why.
const fn is_portable(slot_type: SlotType) -> bool {
    match slot_type {
        SlotType::Password | SlotType::Recovery => true,
        SlotType::AndroidKeystore | SlotType::AppleKeychain | SlotType::PeerDevice => false,
        _ => false,
    }
}

/// The descriptor a package carries: the live one with §3's exclusions applied.
///
/// The state is forced to `ACTIVE` and the generation to 1. A restore installs a
/// new vault rather than continuing this one, and carrying a generation from the
/// source device would make the restored descriptor claim a history it does not
/// have — `VAULT_DESCRIPTOR_V1.md` §10 uses the generation for local rollback
/// detection, which is a per-device fact.
fn portable_descriptor(live: &VaultDescriptor) -> Result<VaultDescriptor> {
    let key_slots: Vec<_> = live
        .key_slots
        .iter()
        .filter(|slot| is_portable(slot.slot_type))
        .cloned()
        .collect();
    ensure!(
        !key_slots.is_empty(),
        Conflict,
        "the vault has no portable slot, so a package of it could never be opened"
    );
    ensure!(
        key_slots.len() <= bounds::SLOT_ENTRIES_MAX,
        ResourceLimitExceeded,
        "the vault holds more portable slots than §13 admits"
    );
    Ok(VaultDescriptor {
        vault_id: live.vault_id,
        descriptor_generation: 1,
        state: VaultState::Active,
        catalog: live.catalog,
        object_store: live.object_store,
        key_slots,
        migration: None,
    })
}

/// The slot inventory entries of §7.1, in the order that section fixes.
///
/// "Slot entries follow, sorted by ascending `slot_id` byte order." A
/// descriptor stores its slots in the order they were enrolled and nothing
/// sorts them, so a writer that walked the descriptor would produce a
/// commitment that depended on enrolment history. §7.1's whole purpose is that
/// two conforming writers over the same content emit the same sequence.
fn slot_entries(descriptor: &VaultDescriptor) -> Vec<SlotInventoryEntry> {
    let mut entries: Vec<SlotInventoryEntry> = descriptor
        .key_slots
        .iter()
        .map(|slot| SlotInventoryEntry {
            slot_id: slot.slot_id,
            slot_type: slot.slot_type.value(),
            slot_generation: slot.slot_generation,
        })
        .collect();
    entries.sort_unstable_by_key(|entry| *entry.slot_id.as_bytes());
    entries
}

// ---------------------------------------------------------------------------
// §7 Streaming creation
// ---------------------------------------------------------------------------

/// Writes a full backup package of the session's vault, §5 and §7.
///
/// The walk runs twice. The first pass computes the ordered inventory
/// commitment and the record count, and authenticates each complete container
/// before any content is written; the second writes the records. Both
/// read the same ordered query, so neither holds the inventory.
///
/// # Errors
///
/// Returns [`ChurStatus::Cancelled`] when `progress` asks it to stop, and the
/// storage and catalog errors of the walk.
pub fn create(
    session: &mut Session,
    destination: &mut (impl Write + Seek),
    now_ms: u64,
    progress: &mut impl Progress,
) -> Result<BackupSummary> {
    // §7 step 1: a consistent catalog snapshot. Committed pages can live in the
    // write-ahead log, and a package that copied only the database file would
    // carry a catalog older than the containers beside it.
    session.checkpoint_catalog()?;

    let snapshot = CatalogSnapshot::create(session, progress)?;
    let catalog_path = snapshot.directory.join("catalog.db");
    // The snapshot is a private copy of the catalog. The identity preparation
    // below changes it, never the live catalog, and the export reads the
    // changed copy.
    let catalog_key =
        chur_catalog::db::CatalogKey::derive(session.root_secret()?, &session.vault_id())?;
    let mut catalog = chur_catalog::CatalogDb::open(
        &chur_catalog::db::CatalogLocation::File(&catalog_path),
        &catalog_key,
    )?;
    let identity_payload = match chur_catalog::sync_membership::load(&catalog)? {
        Some(membership) => Some(
            chur_catalog::sync_keys::prepare_backup_identity(
                &mut catalog,
                session.root_secret()?,
                &membership,
                now_ms,
            )?
            .ok_or_else(|| {
                chur_core::err!(
                    VaultIncomplete,
                    "the sync vault has no portable device identity"
                )
            })?
            .encode(),
        ),
        None => None,
    };
    let vault_id = session.vault_id();
    let store_id = session.object_store_id();
    let backup_id = random::id()?;
    let key = manifest_key(session.root_secret()?, &vault_id)?;

    // ADR-0068: the catalog leaves as rows, sealed record by record into a
    // file beside the snapshot, so the record count is known before the
    // preamble is written and no plaintext row reaches the disk.
    let export_path = snapshot.directory.join("catalog.export");
    let export = write_catalog_export(
        &catalog,
        &key,
        &vault_id,
        &backup_id,
        &export_path,
        progress,
    )?;
    let catalog_generation = export.header.catalog_generation;
    catalog.close()?;

    let descriptor = portable_descriptor(session.descriptor())?;
    ensure!(
        export.header.catalog_format_version == descriptor.catalog.catalog_format_version,
        Conflict,
        "the catalog schema differs from the version the descriptor names"
    );
    let descriptor_bytes = session.seal_descriptor(&descriptor)?;
    let root_dir = session.root_dir().clone();

    // Pass one: the inventory commitment and the counts.
    let mut committer = InventoryCommitter::new();
    let mut content_length = 0u64;
    store::for_each_stream_ordered(session.catalog_ref()?, |object_id, stream| {
        if progress.cancelled() {
            return Err(progress::cancelled("the backup was cancelled"));
        }
        ensure!(
            store::object(session.catalog_ref()?, object_id)?.state != ObjectState::Corrupt,
            ObjectCorrupt,
            "a backup cannot include an object marked corrupt"
        );
        let object_key = keys::object_key(session, object_id)?;
        let file = ContainerFile::open(&root_dir, &store_id, &stream.container_path_id)?;
        let identity = StreamIdentity {
            object_id: *object_id,
            stream_id: stream.stream_id,
            stream_kind: stream.stream_kind,
            stream_revision: stream.stream_revision,
        };
        let mut reader = StreamReader::open(file, &object_key, &identity)?;
        reader.verify_complete_with(&|| progress.cancelled())?;
        ensure!(
            reader.read_final_commit()?.ordered_chunk_commitment() == &stream.final_commitment,
            ObjectCorrupt,
            "a container's final commit contradicts its catalog stream"
        );
        let entry = inventory_entry(&root_dir, &store_id, object_id, stream)?;
        content_length = content_length.saturating_add(entry.ciphertext_length);
        committer.add_stream(&entry)
    })?;
    for entry in slot_entries(&descriptor) {
        committer.add_slot(&entry)?;
    }
    let stream_count = committer.stream_count();
    let slot_count = committer.slot_count();
    let inventory_commitment = committer.finish();

    // The manifest, the descriptor, the catalog export records, one record per
    // stream, the identity envelope when there is one, and the final commit.
    let record_count = 3
        + u64::from(export.record_count)
        + u64::from(stream_count)
        + u64::from(identity_payload.is_some());
    let preamble = PublicPreamble::new(BACKUP_VERSION_V2, record_count)?;

    let manifest = BackupManifest {
        backup_id,
        backup_version: BACKUP_VERSION_V2,
        vault_id,
        created_time_ms: now_ms,
        base_backup_id: None,
        catalog_generation,
        catalog_format_version: descriptor.catalog.catalog_format_version,
        stream_entry_count: stream_count,
        slot_entry_count: slot_count,
        inventory_commitment,
        free_space_required: content_length
            .saturating_add(export.length)
            .saturating_add(bounds::RESTORE_HEADROOM),
    };
    let manifest_payload = manifest.seal(&key, &Nonce::random()?)?;
    ensure!(
        manifest_payload.len() <= bounds::MANIFEST_PAYLOAD_MAX,
        ResourceLimitExceeded,
        "the manifest record exceeds the §13 payload bound"
    );

    // ADR-0068: every record that is not a container is fed to the record
    // commitment in package order, with its index, as it is written.
    let mut records = RecordCommitter::new();
    let mut written = write_all(destination, &preamble.encode())?;
    records.add(0, RecordType::Manifest, &manifest_payload);
    written += write_record(destination, RecordType::Manifest, &manifest_payload)?;
    records.add(1, RecordType::Descriptor, &descriptor_bytes);
    written += write_record(destination, RecordType::Descriptor, &descriptor_bytes)?;
    written += copy_export_records(destination, &export, &mut records, progress)?;

    // Pass two: the containers, in the same order the commitment was taken in.
    let mut copied = 0u64;
    store::for_each_stream_ordered(session.catalog_ref()?, |object_id, stream| {
        if progress.cancelled() {
            return Err(progress::cancelled("the backup was cancelled"));
        }
        let entry = inventory_entry(&root_dir, &store_id, object_id, stream)?;
        let path = root_dir.container(&store_id, &stream.container_path_id);
        let entry_bytes = entry.encode();
        let payload_length = entry_bytes.len() as u64 + entry.ciphertext_length;
        let header = RecordHeader {
            record_type: RecordType::Container,
            payload_length,
        };
        copied += write_all(destination, &header.encode())?;
        copied += write_all(destination, &entry_bytes)?;
        copied += copy_file(destination, &path, entry.ciphertext_length, progress)?;
        progress.advance(copied);
        Ok(())
    })?;
    written += copied;

    if let Some(identity_payload) = identity_payload {
        let index = 2 + u64::from(export.record_count) + u64::from(stream_count);
        records.add(index, RecordType::Envelope, &identity_payload);
        written += write_record(destination, RecordType::Envelope, &identity_payload)?;
    }

    let commit = FinalBackupCommit {
        backup_id,
        record_count,
        stream_entry_count: stream_count,
        slot_entry_count: slot_count,
        inventory_commitment,
        records: Some(RecordSeal {
            catalog_export_record_count: export.record_count,
            record_commitment: records.finish(),
        }),
    };
    let commit_payload = commit.seal(&key, &vault_id, &Nonce::random()?)?;
    written += write_record(destination, RecordType::FinalCommit, &commit_payload)?;
    destination
        .flush()
        .map_err(|_| chur_core::err!(IoFailure, "the package destination could not be flushed"))?;

    Ok(BackupSummary {
        backup_id,
        vault_id,
        record_count,
        stream_count,
        slot_count,
        package_length: written,
    })
}

/// The name of the catalog snapshot directory under `incoming/`.
///
/// The name is fixed, so a snapshot that a killed process left behind is found
/// and removed: at the next unlock by [`clear_snapshot`], and at the next
/// backup before the new copy is written. It is not a hexadecimal identifier,
/// so it cannot be read as the name of a temporary container.
pub const SNAPSHOT_DIRECTORY: &str = "backup-snapshot";

/// Removes the catalog snapshot a killed backup left behind.
///
/// The snapshot is an encrypted copy of the whole catalog. `Drop` removes it
/// when a backup ends in this process, but a process that is killed keeps no
/// `Drop`, and each kept copy holds rows the user may delete later. It runs at
/// unlock, before the session becomes a handle, so no backup of this session
/// can be in progress. It returns whether a snapshot was removed.
///
/// # Errors
///
/// Returns [`ChurStatus::IoFailure`] when the directory exists and cannot be
/// removed.
pub fn clear_snapshot(session: &Session) -> Result<bool> {
    remove_snapshot(&snapshot_directory(session))
}

fn snapshot_directory(session: &Session) -> PathBuf {
    session
        .root_dir()
        .incoming(&session.object_store_id())
        .join(SNAPSHOT_DIRECTORY)
}

fn remove_snapshot(directory: &Path) -> Result<bool> {
    match std::fs::remove_dir_all(directory) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(chur_core::err!(
            IoFailure,
            "a stale backup snapshot could not be removed"
        )),
    }
}

/// Owns the encrypted catalog copy, including any SQLite sidecar files.
struct CatalogSnapshot {
    directory: PathBuf,
}

impl CatalogSnapshot {
    fn create(session: &Session, progress: &impl Progress) -> Result<Self> {
        let directory = snapshot_directory(session);
        remove_snapshot(&directory)?;
        std::fs::create_dir(&directory).map_err(|_| {
            chur_core::err!(
                IoFailure,
                "the backup snapshot directory could not be created"
            )
        })?;
        let snapshot = Self { directory };
        let mut destination = std::fs::File::create(snapshot.directory.join("catalog.db"))
            .map_err(|_| {
                chur_core::err!(
                    IoFailure,
                    "the backup catalog snapshot could not be created"
                )
            })?;
        let source = session.catalog_path();
        copy_file(&mut destination, &source, file_length(&source)?, progress)?;
        Ok(snapshot)
    }
}

impl Drop for CatalogSnapshot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// Builds one stream's inventory entry, §7.1.
///
/// The manifest commitment is not a catalog column, so it is recomputed from
/// the container's own head. That is the honest source: the entry must describe
/// the bytes the package carries, and a value copied from a row would describe
/// what the catalog believes about them.
fn inventory_entry(
    root_dir: &VaultRoot,
    store_id: &Id,
    object_id: &Id,
    stream: &chur_catalog::model::Stream,
) -> Result<StreamInventoryEntry> {
    let path = root_dir.container(store_id, &stream.container_path_id);
    let ciphertext_length = file_length(&path)?;
    Ok(StreamInventoryEntry {
        object_id: *object_id,
        stream_id: stream.stream_id,
        stream_kind: stream.stream_kind,
        stream_revision: stream.stream_revision,
        ciphertext_length,
        manifest_commitment: manifest_commitment_of(&path)?,
        ordered_chunk_commitment: stream.final_commitment,
    })
}

/// Recomputes one container's manifest commitment from its first records.
fn manifest_commitment_of(path: &Path) -> Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)
        .map_err(|_| chur_core::err!(NotFound, "a container named by the catalog is absent"))?;
    let mut preamble = vec![0u8; ContainerPreamble::LEN];
    file.read_exact(&mut preamble).map_err(|_| {
        chur_core::err!(ObjectIncomplete, "a container is shorter than its preamble")
    })?;
    let head = ContainerPreamble::decode(&preamble)?;
    let length = usize::try_from(head.manifest_record_length())
        .map_err(|_| chur_core::err!(ObjectCorrupt, "a manifest record length exceeds a usize"))?;
    ensure!(
        length <= CONTAINER_HEAD_MAX,
        ResourceLimitExceeded,
        "a manifest record exceeds the head this reader admits"
    );
    let mut record = vec![0u8; length];
    file.read_exact(&mut record)
        .map_err(|_| chur_core::err!(ObjectIncomplete, "a container has no manifest record"))?;
    // The record is a 24-byte nonce followed by the sealed manifest, and the
    // commitment of `OBJECT_CONTAINER_V1.md` §5 is over both.
    let nonce_len = chur_core::limits::NONCE_LEN;
    ensure!(
        record.len() > nonce_len,
        ObjectCorrupt,
        "a manifest record is shorter than its nonce"
    );
    let nonce = Nonce::from_slice(&record[..nonce_len])?;
    Ok(chur_format::container::manifest_commitment(
        &nonce,
        &record[nonce_len..],
    ))
}

fn file_length(path: &Path) -> Result<u64> {
    std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|_| chur_core::err!(NotFound, "a file the package needs is absent"))
}

fn write_all(destination: &mut impl Write, bytes: &[u8]) -> Result<u64> {
    destination
        .write_all(bytes)
        .map_err(|_| chur_core::err!(IoFailure, "the package destination rejected a write"))?;
    Ok(bytes.len() as u64)
}

fn write_record(
    destination: &mut impl Write,
    record_type: RecordType,
    payload: &[u8],
) -> Result<u64> {
    let header = RecordHeader {
        record_type,
        payload_length: payload.len() as u64,
    };
    let mut written = write_all(destination, &header.encode())?;
    written += write_all(destination, payload)?;
    Ok(written)
}

/// The sealed catalog export records written beside the snapshot.
struct SealedExport {
    path: PathBuf,
    header: chur_format::catalog_export::ExportHeader,
    record_count: u32,
    length: u64,
}

/// Writes the catalog as sealed catalog export records, ADR-0068.
///
/// The records are the package's records 2 onward, so each is sealed at its
/// final index here and copied unchanged later. The file holds ciphertext only.
fn write_catalog_export(
    catalog: &chur_catalog::CatalogDb,
    key: &Key,
    vault_id: &Id,
    backup_id: &Id,
    path: &Path,
    progress: &impl Progress,
) -> Result<SealedExport> {
    let mut file = std::fs::File::create(path).map_err(|_| {
        chur_core::err!(IoFailure, "the backup catalog export could not be created")
    })?;
    let mut record_count = 0u32;
    let mut length = 0u64;
    let header = chur_catalog::catalog_export::export(
        catalog,
        |chunk, is_final| {
            ensure!(
                u64::from(record_count) < bounds::CATALOG_EXPORT_RECORDS_MAX,
                ResourceLimitExceeded,
                "the catalog export exceeds the record bound of a package"
            );
            let position = CatalogExportPosition {
                vault_id: *vault_id,
                backup_id: *backup_id,
                record_index: 2 + u64::from(record_count),
                chunk_index: record_count,
                is_final,
            };
            let payload = seal_catalog_export(key, &Nonce::random()?, &position, chunk)?;
            length += write_record(&mut file, RecordType::CatalogExport, &payload)?;
            record_count += 1;
            Ok(())
        },
        &|| progress.cancelled(),
    )?;
    file.flush().map_err(|_| {
        chur_core::err!(IoFailure, "the backup catalog export could not be written")
    })?;
    Ok(SealedExport {
        path: path.to_path_buf(),
        header,
        record_count,
        length,
    })
}

/// Copies the sealed catalog export records into the package and feeds each
/// to the record commitment at its index.
fn copy_export_records(
    destination: &mut impl Write,
    export: &SealedExport,
    records: &mut RecordCommitter,
    progress: &impl Progress,
) -> Result<u64> {
    let mut file = std::fs::File::open(&export.path)
        .map_err(|_| chur_core::err!(NotFound, "the backup catalog export is absent"))?;
    let mut written = 0u64;
    let mut buffer = vec![0u8; COPY_BUFFER];
    for index in 0..u64::from(export.record_count) {
        let mut head = [0u8; RECORD_HEADER_LEN];
        file.read_exact(&mut head)
            .map_err(|_| chur_core::err!(VaultIncomplete, "the backup catalog export is short"))?;
        let header = RecordHeader::decode(&head)?;
        records.begin(2 + index, &header);
        written += write_all(destination, &head)?;
        let mut remaining = header.payload_length;
        while remaining > 0 {
            if progress.cancelled() {
                return Err(progress::cancelled("the backup was cancelled"));
            }
            let take = usize::try_from(remaining.min(COPY_BUFFER as u64))
                .map_err(|_| chur_core::err!(InternalFailure, "a copy step exceeds a usize"))?;
            file.read_exact(&mut buffer[..take]).map_err(|_| {
                chur_core::err!(VaultIncomplete, "the backup catalog export is short")
            })?;
            records.update(&buffer[..take]);
            written += write_all(destination, &buffer[..take])?;
            remaining -= take as u64;
        }
    }
    ensure!(
        written == export.length,
        InternalFailure,
        "the backup catalog export changed while it was copied"
    );
    Ok(written)
}

/// Copies exactly `length` bytes of a file into the package.
///
/// The probe is read once per buffer rather than once per file. A vault can
/// hold one object of a terabyte, and a copy that checked only between files
/// would make `chur_vault_lock` wait for that whole copy: the lock drains and
/// joins every operation before it takes the session, so an operation that
/// cannot stop is a lock that cannot complete, against a p95 budget of 100 ms
/// in `docs/assurance/PERFORMANCE_BUDGETS.md` §2.
fn copy_file(
    destination: &mut impl Write,
    path: &Path,
    length: u64,
    progress: &impl Progress,
) -> Result<u64> {
    let mut file = std::fs::File::open(path)
        .map_err(|_| chur_core::err!(NotFound, "a file the package needs is absent"))?;
    let mut buffer = vec![0u8; COPY_BUFFER];
    let mut remaining = length;
    while remaining > 0 {
        if progress.cancelled() {
            return Err(progress::cancelled("the backup was cancelled"));
        }
        let take = usize::try_from(remaining.min(COPY_BUFFER as u64))
            .map_err(|_| chur_core::err!(InternalFailure, "a copy step exceeds a usize"))?;
        file.read_exact(&mut buffer[..take]).map_err(|_| {
            chur_core::err!(
                VaultIncomplete,
                "a file shrank while the package was being written"
            )
        })?;
        destination
            .write_all(&buffer[..take])
            .map_err(|_| chur_core::err!(IoFailure, "the package destination rejected a write"))?;
        remaining -= take as u64;
    }
    Ok(length)
}

// ---------------------------------------------------------------------------
// §8 Restore transaction
// ---------------------------------------------------------------------------

/// One record's place in the package, from the header scan.
struct RecordSlot {
    record_type: RecordType,
    offset: u64,
    payload_length: u64,
}

/// Restores a package into `root_dir`, §8.
///
/// The steps run in §8's order and the two that matter are the two that come
/// before activation: the inventory is authenticated before the first byte
/// lands in the vault namespace, and each container's final commit is opened
/// before the descriptor is installed. A restore interrupted at any earlier
/// point leaves no openable vault, exactly as an abandoned creation does.
///
/// It takes no clock. A restore installs bytes the package already fixed and
/// records no time of its own: the manifest carries the creation time and the
/// catalog carries every row's, so there is nothing here for a clock to stamp.
///
/// # Errors
///
/// Returns [`ChurStatus::VaultCorrupt`] for a package that does not parse or
/// does not authenticate, [`ChurStatus::AuthenticationFailed`] when the
/// credential opens no portable slot, [`ChurStatus::Conflict`] when the registry
/// is full, and [`ChurStatus::StorageUnavailable`] when a write fails.
///
/// §13 also asks a restore to refuse to begin unless the destination holds the
/// package length plus 64 MiB. That preflight is not run here. The standard
/// library exposes no filesystem-capacity call, and the only way to ask the
/// platform is `statvfs`, which needs `unsafe` in a crate that forbids it — a
/// worse trade than an error one step later, because the manifest carries
/// `free_space_required` for a caller that can ask, and a destination that
/// fills fails on the write and takes the partial vault directory with it, so
/// nothing openable survives either way.
pub fn restore(
    root_dir: &VaultRoot,
    source: &mut (impl Read + Seek),
    credential: &[u8],
    progress: &mut impl Progress,
) -> Result<RestoreSummary> {
    restore_inner(root_dir, source, credential, progress, None)
}

/// Restores an archive whose catalog export is at most `catalog_limit` bytes.
///
/// A version 2 catalog is authenticated record by record before import, and a
/// version 1 catalog page by page before any migration. Logical import
/// additionally verifies all container chunks before touching its target.
pub fn restore_limited(
    root_dir: &VaultRoot,
    source: &mut (impl Read + Seek),
    credential: &[u8],
    progress: &mut impl Progress,
    catalog_limit: u64,
) -> Result<RestoreSummary> {
    restore_inner(root_dir, source, credential, progress, Some(catalog_limit))
}

fn restore_inner(
    root_dir: &VaultRoot,
    source: &mut (impl Read + Seek),
    credential: &[u8],
    progress: &mut impl Progress,
    catalog_limit: Option<u64>,
) -> Result<RestoreSummary> {
    let package_length = source
        .seek(SeekFrom::End(0))
        .map_err(|_| chur_core::err!(IoFailure, "the package length could not be read"))?;
    let (backup_version, slots) = scan(source, package_length)?;
    // A version 1 package carries the catalog in one record and a version 2
    // package in a contiguous run of records, ADR-0068.
    let export_records = if backup_version == BACKUP_VERSION_V1 {
        let slot = find(&slots, RecordType::CatalogExport)?;
        let index = slots
            .iter()
            .position(|candidate| std::ptr::eq(candidate, slot))
            .unwrap_or(0);
        index..index + 1
    } else {
        version_two_layout(&slots)?
    };
    if let Some(limit) = catalog_limit {
        let total = slots[export_records.clone()]
            .iter()
            .try_fold(0u64, |sum, slot| sum.checked_add(slot.payload_length))
            .ok_or_else(|| chur_core::err!(VaultCorrupt, "the catalog export length overflows"))?;
        ensure!(
            total <= limit,
            ResourceLimitExceeded,
            "the archive catalog exceeds its verification bound"
        );
    }

    // §8 steps 2 and 3. The root comes from a portable slot of the package's own
    // descriptor, so the manifest key exists only for a credential that opens
    // one; nothing else in the package is read before that.
    let descriptor_bytes = read_payload_bounded(
        source,
        find(&slots, RecordType::Descriptor)?,
        chur_core::limits::descriptor::LENGTH_MAX as u64,
    )?;
    let (descriptor, root_secret) = open_portable_descriptor(&descriptor_bytes, credential)?;
    // §11 and `VAULT_DESCRIPTOR_V1.md` §11: the registry holds two identities.
    // The refusal follows the credential check, so a full registry is told only
    // to a caller who holds the package's credential; before it, any file and
    // any password would answer differently on a device with two identities,
    // `DECOY_VAULT.md` §10.
    ensure!(
        root_dir.registry_names()?.len() < chur_catalog::paths::REGISTRY_MAX,
        Conflict,
        "the registry already holds the two identities §11 admits"
    );
    let key = manifest_key(&root_secret, &descriptor.vault_id)?;

    let manifest_payload = read_payload_bounded(
        source,
        find(&slots, RecordType::Manifest)?,
        bounds::MANIFEST_PAYLOAD_MAX as u64,
    )?;
    let manifest = BackupManifest::open(
        &manifest_payload,
        &key,
        &descriptor.vault_id,
        backup_version,
    )?;
    ensure!(
        manifest.vault_id == descriptor.vault_id
            && manifest.catalog_format_version == descriptor.catalog.catalog_format_version,
        VaultCorrupt,
        "the backup manifest contradicts its descriptor"
    );

    let commit_payload =
        read_payload_bounded(source, find(&slots, RecordType::FinalCommit)?, 4_096)?;
    let commit = FinalBackupCommit::open(
        &commit_payload,
        &key,
        &descriptor.vault_id,
        &manifest.backup_id,
        backup_version,
    )?;

    // §2.1: `record_count` is the one variable preamble field, and the final
    // commit authenticates it. §4: the manifest and the commit must agree.
    ensure!(
        commit.record_count == slots.len() as u64
            && commit.stream_entry_count == manifest.stream_entry_count
            && commit.slot_entry_count == manifest.slot_entry_count
            && commit.inventory_commitment == manifest.inventory_commitment,
        VaultCorrupt,
        "the final backup commit contradicts the package it closes"
    );
    let identity_payload = match find_optional(&slots, RecordType::Envelope)? {
        Some(slot) => {
            ensure!(
                slot.payload_length == DeviceIdentityEnvelope::LEN as u64,
                VaultCorrupt,
                "the backup identity envelope has the wrong length"
            );
            Some(read_payload_bounded(
                source,
                slot,
                DeviceIdentityEnvelope::LEN as u64,
            )?)
        }
        None => None,
    };
    // ADR-0068: in a version 2 package the record commitment covers every
    // record that is not a container. It is fed the exact buffers this restore
    // uses: the manifest, the descriptor, and the envelope already in memory,
    // and each catalog export record as the import reads and opens it, so no
    // byte is used that was not committed. The comparison runs after the
    // import and before any container is extracted or the descriptor is
    // installed; a failure removes the restore's directory with the catalog.
    let mut records = match &commit.records {
        Some(seal) => {
            ensure!(
                export_records.len() == seal.catalog_export_record_count as usize,
                VaultCorrupt,
                "the package carries another number of catalog export records than its commit seals"
            );
            let mut records = RecordCommitter::new();
            records.add(0, RecordType::Manifest, &manifest_payload);
            records.add(1, RecordType::Descriptor, &descriptor_bytes);
            Some(records)
        }
        None => None,
    };
    let envelope_index = slots
        .iter()
        .position(|slot| slot.record_type == RecordType::Envelope);

    // §8 step 4: completeness before anything is written. Every container entry
    // is read in package order and folded into the commitment the commit sealed.
    let mut committer = InventoryCommitter::new();
    let mut entries = Vec::with_capacity(slots.len());
    let mut highest_version = CONTAINER_VERSION_V1;
    for slot in slots
        .iter()
        .filter(|s| s.record_type == RecordType::Container)
    {
        if progress.cancelled() {
            return Err(progress::cancelled("the restore was cancelled"));
        }
        let entry = read_container_entry(source, slot)?;
        // §5: completeness verification checks every inventory entry before
        // activation. That means checking the container against the entry that
        // describes it, not only that an entry is present — a package whose
        // ciphertext was altered would otherwise install and fail at the first
        // read, after the vault existed.
        let version = verify_container(source, slot, &entry, progress)?;
        highest_version = highest_version.max(version);
        committer.add_stream(&entry)?;
        entries.push((entry, slot.offset, version));
    }
    // ADR-0066: the descriptor names the highest container version its store
    // holds, so a restored store keeps the source's range, and the range must
    // cover every container the package carries.
    ensure!(
        highest_version <= descriptor.object_store.container_version_ceiling,
        VaultCorrupt,
        "a container in the package is newer than its descriptor admits"
    );
    for entry in slot_entries(&descriptor) {
        committer.add_slot(&entry)?;
    }
    ensure!(
        committer.stream_count() == commit.stream_entry_count
            && committer.slot_count() == commit.slot_entry_count
            && committer.finish() == commit.inventory_commitment,
        VaultCorrupt,
        "the package's contents do not match the inventory its final commit seals"
    );

    // §8 steps 5 to 9. Everything below writes into the vault namespace, and
    // the descriptor rename at the end is what makes any of it openable.
    //
    // The local path identifiers are drawn fresh rather than taken from the
    // package. `VAULT_DESCRIPTOR_V1.md` §6 makes them opaque random names of
    // this device's storage layout, not of the identity, and reusing the source
    // device's would collide with whatever already occupies that name here —
    // including, when a package is restored beside the vault it came from,
    // that very vault. The descriptor is re-sealed under the root the package's
    // own slot returned, which is the same operation a creation performs.
    let store_id = random::id()?;
    let catalog_path_id = random::id()?;
    let mut local = VaultDescriptor {
        catalog: chur_format::descriptor::CatalogDescriptor {
            catalog_format_version: descriptor.catalog.catalog_format_version,
            opaque_catalog_path_id: catalog_path_id,
            ..descriptor.catalog
        },
        object_store: chur_format::descriptor::ObjectStoreDescriptor {
            opaque_root_path_id: store_id,
            ..descriptor.object_store
        },
        ..descriptor.clone()
    };
    // The claim keeps the orphan sweep of another runtime on this root off the
    // directory until this function returns, after the install below.
    let _claim = root_dir.prepare(&store_id)?;
    let catalog_path = root_dir.catalog(&store_id, &catalog_path_id);
    let installed = (|| -> Result<()> {
        let mut catalog = if backup_version == BACKUP_VERSION_V1 {
            install_page_copy(
                source,
                &slots[export_records.start],
                &catalog_path,
                &local,
                &root_secret,
                progress,
            )?
        } else {
            let records = records.as_mut().ok_or_else(|| {
                chur_core::err!(
                    InternalFailure,
                    "a version 2 restore has no record commitment"
                )
            })?;
            let catalog = import_catalog_export(
                source,
                &ExportRecords {
                    slots: &slots[export_records.clone()],
                    first_index: export_records.start as u64,
                    key: &key,
                    vault_id: descriptor.vault_id,
                    backup_id: manifest.backup_id,
                    catalog_format_version: manifest.catalog_format_version,
                },
                records,
                &catalog_path,
                &root_secret,
                progress,
            )?;
            if let (Some(index), Some(payload)) = (envelope_index, identity_payload.as_deref()) {
                records.add(index as u64, RecordType::Envelope, payload);
            }
            let sealed = commit
                .records
                .map(|seal| seal.record_commitment)
                .unwrap_or_default();
            ensure!(
                chur_crypto::secret::constant_time_eq(&records.finish(), &sealed),
                VaultCorrupt,
                "the package's records do not match the record commitment its final commit seals"
            );
            // The new catalog has its own SQLCipher header, so the restored
            // descriptor commits to that one, `VAULT_DESCRIPTOR_V1.md` §5.
            local.catalog.catalog_header_commitment =
                vault::catalog_header_commitment(&catalog_path)?;
            catalog
        };
        // §8 step 6: the catalog is the one the sealed manifest describes. In
        // a version 1 package the header commitment is the file's salt, which
        // every copy of the same catalog shares, so it cannot tell this
        // package's catalog from an older package's. The generation can: the manifest records the
        // snapshot's generation under the manifest key, and the final commit
        // binds the manifest to this package. The descriptor records the
        // generation of the source's last lock, which the snapshot can only
        // equal or pass. Both are checked before migration changes the value.
        let restored_generation = schema::generation(&catalog)
            .map_err(|_| chur_core::err!(VaultCorrupt, "the backup catalog has no generation"))?;
        ensure!(
            restored_generation == manifest.catalog_generation
                && restored_generation >= descriptor.catalog.catalog_generation,
            VaultCorrupt,
            "the package's catalog is not the one its manifest describes"
        );
        if vault::prepare_restored_catalog(&mut catalog, &local)? {
            let target = chur_format::constants::CATALOG_FORMAT_VERSION_V17;
            let migration_steps = target - local.catalog.catalog_format_version;
            local.descriptor_generation = local
                .descriptor_generation
                .checked_add(u64::from(migration_steps) * 2)
                .ok_or_else(|| {
                    chur_core::err!(
                        VaultCorrupt,
                        "the restored descriptor generation overflowed"
                    )
                })?;
            local.catalog.catalog_format_version = target;
            local.catalog.catalog_header_commitment =
                vault::catalog_header_commitment(&catalog_path)?;
        }
        match chur_catalog::sync_membership::load(&catalog)
            .map_err(|_| chur_core::err!(VaultCorrupt, "the backup sync membership is invalid"))?
        {
            Some(membership) => {
                let package_identity = identity_payload.as_deref().ok_or_else(|| {
                    chur_core::err!(
                        VaultCorrupt,
                        "the sync backup has no portable device identity"
                    )
                })?;
                let catalog_identity = chur_catalog::sync_keys::portable_identity_envelope(
                    &catalog,
                    &root_secret,
                    &membership,
                )
                .map_err(|_| {
                    chur_core::err!(VaultCorrupt, "the backup device identity is invalid")
                })?
                .ok_or_else(|| {
                    chur_core::err!(
                        VaultCorrupt,
                        "the backup catalog has no portable device identity"
                    )
                })?;
                ensure!(
                    package_identity == catalog_identity.encode(),
                    VaultCorrupt,
                    "the backup device identities do not match"
                );
                let log = chur_catalog::sync_log::load(&catalog, &membership).map_err(|_| {
                    chur_core::err!(VaultCorrupt, "the backup operation log is invalid")
                })?;
                ensure!(
                    log.own_checkpoint_covers_current_heads(&catalog, &membership)
                        .map_err(|_| {
                            chur_core::err!(VaultCorrupt, "the backup checkpoint is invalid")
                        })?,
                    VaultCorrupt,
                    "the backup has no checkpoint for its current heads"
                );
            }
            None => ensure!(
                identity_payload.is_none(),
                VaultCorrupt,
                "a local-only backup carries a device identity"
            ),
        }
        let mut index = 0usize;
        let mut done = 0u64;
        store::for_each_stream_ordered(&catalog, |object_id, stream| {
            if progress.cancelled() {
                return Err(progress::cancelled("the restore was cancelled"));
            }
            let Some((entry, offset, version)) = entries.get(index) else {
                bail!(
                    VaultCorrupt,
                    "the restored catalog names more streams than the package carries"
                );
            };
            ensure!(
                entry.object_id == *object_id
                    && entry.stream_id == stream.stream_id
                    && entry.stream_revision == stream.stream_revision
                    && entry.ordered_chunk_commitment == stream.final_commitment
                    && *version == stream.container_version,
                VaultCorrupt,
                "a container entry does not describe the stream the catalog holds"
            );
            let head = RECORD_HEADER_LEN as u64 + chur_format::backup::STREAM_ENTRY_LEN as u64;
            let path = root_dir.container(&store_id, &stream.container_path_id);
            extract_range(
                source,
                offset + head,
                entry.ciphertext_length,
                &path,
                progress,
            )?;
            // The copy is a second read of the package, so the step-4 check of
            // the package bytes says nothing about it. The extracted file is
            // checked again on its own: its length and manifest commitment
            // against the inventory entry here, and every chunk and the final
            // commit under the object key below.
            ensure!(
                file_length(&path)? == entry.ciphertext_length
                    && manifest_commitment_of(&path)? == entry.manifest_commitment,
                VaultCorrupt,
                "a restored container differs from the inventory entry that describes it"
            );
            let object_key = keys::object_key_from_catalog(&catalog, &root_secret, object_id)
                .map_err(|_| chur_core::err!(VaultCorrupt, "a restored object key is invalid"))?;
            let file = ContainerFile::open(root_dir, &store_id, &stream.container_path_id)?;
            let identity = StreamIdentity {
                object_id: *object_id,
                stream_id: stream.stream_id,
                stream_kind: stream.stream_kind,
                stream_revision: stream.stream_revision,
            };
            let mut reader = StreamReader::open(file, &object_key, &identity)
                .map_err(|_| chur_core::err!(VaultCorrupt, "a restored container is invalid"))?;
            reader
                .verify_complete_with(&|| progress.cancelled())
                .map_err(|error| match error.status() {
                    ChurStatus::Cancelled => error,
                    _ => chur_core::err!(VaultCorrupt, "a restored container does not verify"),
                })?;
            ensure!(
                reader.read_final_commit()?.ordered_chunk_commitment()
                    == &entry.ordered_chunk_commitment,
                VaultCorrupt,
                "a container's final commit contradicts the backup inventory"
            );
            index += 1;
            done += entry.ciphertext_length;
            progress.advance(done);
            Ok(())
        })?;
        ensure!(
            index == entries.len(),
            VaultCorrupt,
            "the package carries containers the restored catalog does not name"
        );
        catalog.close()?;
        sync_restored_tree(root_dir, &store_id)
    })();
    if let Err(error) = installed {
        // Nothing openable was created, so removal is the whole recovery — the
        // same rule `VAULT_DESCRIPTOR_V1.md` §9 applies to an abandoned
        // creation. The directory is this restore's own, because its name was
        // drawn above, so removing it can reach nothing else.
        let _ = std::fs::remove_dir_all(root_dir.vault(&store_id));
        return Err(error);
    }

    // §8 step 9. The descriptor is installed by the atomic rename of §9's last
    // step, then authenticated from the bytes that were written rather than
    // from the value still in memory — the same read-back a creation performs.
    //
    // It is not verified by unlocking. An unlock resolves a credential across
    // the whole registry and returns the first identity it opens, so a device
    // that already holds an identity with this password would hand back that
    // one, and the check would fail on a restore that had in fact succeeded.
    // The root is already here; authenticating with it asks the question this
    // step actually has.
    let entry_name = RegistryName::random()?;
    let local_bytes = local.encode(&root_secret)?;
    vault::install_descriptor(root_dir, &entry_name, &local_bytes)?;
    let confirmed = (|| -> Result<()> {
        let written = std::fs::read(root_dir.registry_entry(&entry_name))
            .map_err(|_| chur_core::err!(IoFailure, "the descriptor could not be read back"))?;
        let parsed = VaultDescriptor::authenticate(&written, Some(&root_secret))?;
        ensure!(
            parsed.vault_id == descriptor.vault_id
                && parsed.object_store.opaque_root_path_id == store_id,
            VaultCorrupt,
            "the installed descriptor is not the one this restore wrote"
        );
        Ok(())
    })();
    if let Err(error) = confirmed {
        // The entry is installed at this point, so the recovery has to remove
        // it as well. Leaving it would consume one of the two identities §11
        // admits, permanently and with nothing able to open it.
        let _ = std::fs::remove_file(root_dir.registry_entry(&entry_name));
        let _ = std::fs::remove_dir_all(root_dir.vault(&store_id));
        return Err(error);
    }

    Ok(RestoreSummary {
        backup_id: manifest.backup_id,
        vault_id: manifest.vault_id,
        stream_count: commit.stream_entry_count,
        created_time_ms: manifest.created_time_ms,
    })
}

/// Walks the record headers, §2.2.
///
/// It reads headers only, so the scan of a 40 GB package costs twelve bytes per
/// record. §13 requires the 32-byte preamble plus every header and payload to
/// total the package length exactly, and this is where that is checked.
fn scan(source: &mut (impl Read + Seek), package_length: u64) -> Result<(u16, Vec<RecordSlot>)> {
    let mut head = vec![0u8; chur_format::backup::PREAMBLE_LEN];
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| chur_core::err!(IoFailure, "the package could not be positioned"))?;
    source
        .read_exact(&mut head)
        .map_err(|_| chur_core::err!(VaultCorrupt, "the package is shorter than its preamble"))?;
    match framing_of(&head)? {
        Framing::Native => {}
        Framing::AgeBinary | Framing::AgeArmored => bail!(
            UnsupportedVersion,
            "the package is age-wrapped; unwrap it with the age tool and restore the result"
        ),
    }
    let preamble = PublicPreamble::decode(&head)?;

    let mut slots = Vec::new();
    let mut offset = chur_format::backup::PREAMBLE_LEN as u64;
    for _ in 0..preamble.record_count() {
        let mut header = [0u8; RECORD_HEADER_LEN];
        source.read_exact(&mut header).map_err(|_| {
            chur_core::err!(VaultCorrupt, "the package ends inside a record header")
        })?;
        let parsed = RecordHeader::decode(&header)?;
        let next = offset
            .checked_add(RECORD_HEADER_LEN as u64)
            .and_then(|value| value.checked_add(parsed.payload_length))
            .filter(|value| *value <= package_length)
            .ok_or_else(|| {
                chur_core::err!(VaultCorrupt, "a record claims to end past the package")
            })?;
        slots.push(RecordSlot {
            record_type: parsed.record_type,
            offset,
            payload_length: parsed.payload_length,
        });
        offset = next;
        source
            .seek(SeekFrom::Start(offset))
            .map_err(|_| chur_core::err!(IoFailure, "the package could not be positioned"))?;
    }
    // §13: the preamble plus every header and payload total the length exactly,
    // and §2.2 puts no bytes after the final commit.
    ensure!(
        offset == package_length,
        VaultCorrupt,
        "the package carries bytes outside its declared records"
    );
    ensure!(
        slots.first().map(|slot| slot.record_type) == Some(RecordType::Manifest)
            && slots.last().map(|slot| slot.record_type) == Some(RecordType::FinalCommit),
        VaultCorrupt,
        "the manifest is not first or the final commit is not last"
    );
    Ok((preamble.backup_version(), slots))
}

/// Checks the record order of a version 2 package and returns the range of its
/// catalog export records, ADR-0068.
///
/// The order is the package model's, with nothing optional but the envelope:
/// the manifest, the descriptor, one or more catalog export records, the
/// containers, at most one identity envelope, and the final commit. A version 1
/// reader found each record by type; a version 2 reader also needs the export
/// records to be one run, because their AAD binds their indexes.
fn version_two_layout(slots: &[RecordSlot]) -> Result<std::ops::Range<usize>> {
    let kind = |index: usize| slots.get(index).map(|slot| slot.record_type);
    ensure!(
        kind(1) == Some(RecordType::Descriptor),
        VaultCorrupt,
        "the descriptor is not the second record of the package"
    );
    let mut index = 2;
    while kind(index) == Some(RecordType::CatalogExport) {
        index += 1;
    }
    let export = 2..index;
    ensure!(
        !export.is_empty(),
        VaultCorrupt,
        "the package carries no catalog export"
    );
    while kind(index) == Some(RecordType::Container) {
        index += 1;
    }
    if kind(index) == Some(RecordType::Envelope) {
        index += 1;
    }
    ensure!(
        index + 1 == slots.len(),
        VaultCorrupt,
        "the package records are not in the order of its package model"
    );
    Ok(export)
}

/// Installs the catalog of a version 1 package, which is a copy of the source
/// SQLCipher file, and authenticates every page of it.
fn install_page_copy(
    source: &mut (impl Read + Seek),
    slot: &RecordSlot,
    catalog_path: &Path,
    local: &VaultDescriptor,
    root_secret: &Key,
    progress: &impl Progress,
) -> Result<chur_catalog::CatalogDb> {
    extract(source, slot, catalog_path, progress)?;
    // `VAULT_DESCRIPTOR_V1.md` §5: the descriptor commits to the catalog it
    // names. Checking it here rather than at the next unlock is the
    // difference between a package that does not install and a vault that
    // installs and then cannot be opened.
    ensure!(
        chur_crypto::secret::constant_time_eq(
            &vault::catalog_header_commitment(catalog_path)?,
            &local.catalog.catalog_header_commitment
        ),
        VaultCorrupt,
        "the package's catalog is not the one its descriptor commits to"
    );
    let catalog_key = chur_catalog::db::CatalogKey::derive(root_secret, &local.vault_id)?;
    let catalog = chur_catalog::db::CatalogDb::open(
        &chur_catalog::db::CatalogLocation::File(catalog_path),
        &catalog_key,
    )?;
    if progress.cancelled() {
        return Err(progress::cancelled(
            "the archive verification was cancelled",
        ));
    }
    catalog.verify_cipher_pages()?;
    if progress.cancelled() {
        return Err(progress::cancelled(
            "the archive verification was cancelled",
        ));
    }
    Ok(catalog)
}

/// Where the catalog export records of a version 2 package are, and what
/// their AAD binds.
struct ExportRecords<'a> {
    slots: &'a [RecordSlot],
    first_index: u64,
    key: &'a Key,
    vault_id: Id,
    backup_id: Id,
    catalog_format_version: u16,
}

/// The opened chunks of a version 2 catalog export, read from the package one
/// record at a time.
///
/// Each payload is read once. The same buffer is fed to the record commitment
/// and opened, so the rows the import writes come only from committed bytes.
struct PackageChunks<'a, R: Read + Seek> {
    source: &'a mut R,
    records: &'a ExportRecords<'a>,
    commitment: &'a mut RecordCommitter,
    next: usize,
}

impl<R: Read + Seek> ChunkSource for PackageChunks<'_, R> {
    fn next_chunk(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let Some(slot) = self.records.slots.get(self.next) else {
            return Ok(None);
        };
        let chunk_index = u32::try_from(self.next).map_err(|_| {
            chur_core::err!(VaultCorrupt, "the catalog export has too many records")
        })?;
        let payload = Zeroizing::new(read_payload_bounded(
            self.source,
            slot,
            bounds::CATALOG_EXPORT_PAYLOAD_MAX,
        )?);
        let record_index = self.records.first_index + u64::from(chunk_index);
        self.commitment
            .add(record_index, RecordType::CatalogExport, &payload);
        let position = CatalogExportPosition {
            vault_id: self.records.vault_id,
            backup_id: self.records.backup_id,
            record_index,
            chunk_index,
            is_final: self.next + 1 == self.records.slots.len(),
        };
        let chunk = open_catalog_export(&payload, self.records.key, &position)?;
        self.next += 1;
        Ok(Some(chunk))
    }
}

/// Imports the catalog of a version 2 package into a new SQLCipher catalog,
/// ADR-0068.
///
/// The catalog file is created here, with a new salt and this build's page
/// format, so nothing of the source device's storage reaches this one. The
/// export must name the schema version that the manifest and the descriptor
/// name.
fn import_catalog_export(
    source: &mut (impl Read + Seek),
    records: &ExportRecords<'_>,
    commitment: &mut RecordCommitter,
    catalog_path: &Path,
    root_secret: &Key,
    progress: &impl Progress,
) -> Result<chur_catalog::CatalogDb> {
    if let Some(parent) = catalog_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| chur_core::err!(IoFailure, "a restore directory could not be created"))?;
    }
    let catalog_key = chur_catalog::db::CatalogKey::derive(root_secret, &records.vault_id)?;
    let mut catalog = chur_catalog::db::CatalogDb::open(
        &chur_catalog::db::CatalogLocation::File(catalog_path),
        &catalog_key,
    )?;
    let chunks = PackageChunks {
        source,
        records,
        commitment,
        next: 0,
    };
    chur_catalog::catalog_export::import(
        &mut catalog,
        chunks,
        records.catalog_format_version,
        &|| progress.cancelled(),
    )?;
    Ok(catalog)
}

fn find(slots: &[RecordSlot], record_type: RecordType) -> Result<&RecordSlot> {
    let mut found = slots.iter().filter(|slot| slot.record_type == record_type);
    let Some(slot) = found.next() else {
        bail!(VaultCorrupt, "the package is missing a required record");
    };
    ensure!(
        found.next().is_none(),
        VaultCorrupt,
        "the package carries two of a record it may carry once"
    );
    Ok(slot)
}

fn find_optional(slots: &[RecordSlot], record_type: RecordType) -> Result<Option<&RecordSlot>> {
    let mut found = slots.iter().filter(|slot| slot.record_type == record_type);
    let slot = found.next();
    ensure!(
        found.next().is_none(),
        VaultCorrupt,
        "the package carries two of a record it may carry once"
    );
    Ok(slot)
}

/// Reads one record's payload, refusing one above `maximum`.
///
/// Every payload this reads is a small fixed-shape record. A container payload
/// is never read this way; it is copied by range.
fn read_payload_bounded(
    source: &mut (impl Read + Seek),
    slot: &RecordSlot,
    maximum: u64,
) -> Result<Vec<u8>> {
    ensure!(
        slot.payload_length <= maximum,
        ResourceLimitExceeded,
        "a package record exceeds the bound its type carries"
    );
    let length = usize::try_from(slot.payload_length)
        .map_err(|_| chur_core::err!(ResourceLimitExceeded, "a record exceeds a usize"))?;
    source
        .seek(SeekFrom::Start(slot.offset + RECORD_HEADER_LEN as u64))
        .map_err(|_| chur_core::err!(IoFailure, "the package could not be positioned"))?;
    let mut payload = vec![0u8; length];
    source
        .read_exact(&mut payload)
        .map_err(|_| chur_core::err!(VaultCorrupt, "the package ends inside a record"))?;
    Ok(payload)
}

/// Reads one container record's inventory entry, without its ciphertext.
fn read_container_entry(
    source: &mut (impl Read + Seek),
    slot: &RecordSlot,
) -> Result<StreamInventoryEntry> {
    let entry_len = chur_format::backup::STREAM_ENTRY_LEN as u64;
    ensure!(
        slot.payload_length >= entry_len,
        VaultCorrupt,
        "a container record is shorter than its inventory entry"
    );
    source
        .seek(SeekFrom::Start(slot.offset + RECORD_HEADER_LEN as u64))
        .map_err(|_| chur_core::err!(IoFailure, "the package could not be positioned"))?;
    let mut bytes = vec![0u8; chur_format::backup::STREAM_ENTRY_LEN];
    source
        .read_exact(&mut bytes)
        .map_err(|_| chur_core::err!(VaultCorrupt, "the package ends inside a container entry"))?;
    let entry = StreamInventoryEntry::decode(&bytes)?;
    ensure!(
        slot.payload_length == entry_len + entry.ciphertext_length,
        VaultCorrupt,
        "a container record's length contradicts its inventory entry"
    );
    Ok(entry)
}

/// Recomputes one container's two commitments from the package's own bytes,
/// and returns the container version of its preamble.
///
/// Neither computation needs a key. §5 of `OBJECT_CONTAINER_V1.md` takes the
/// manifest commitment over the manifest record's nonce and ciphertext, and §10
/// takes the ordered chunk commitment over the chunk records in order; the chunk
/// records are contiguous between the manifest and the final commit, and the
/// commitment is a hash of their concatenation, so the whole range hashes at
/// once without the chunk boundaries the encrypted manifest would give.
///
/// This catches damaged manifests and chunks before writing. Restore also
/// authenticates the final commit with the object key before activation.
fn verify_container(
    source: &mut (impl Read + Seek),
    slot: &RecordSlot,
    entry: &StreamInventoryEntry,
    progress: &impl Progress,
) -> Result<u16> {
    let content =
        slot.offset + RECORD_HEADER_LEN as u64 + chur_format::backup::STREAM_ENTRY_LEN as u64;
    let mut preamble = vec![0u8; ContainerPreamble::LEN];
    read_exact_at(source, content, &mut preamble)?;
    let head = ContainerPreamble::decode(&preamble)?;
    let manifest_length = u64::from(head.manifest_record_length());
    let first_chunk = ContainerPreamble::LEN as u64 + manifest_length;
    ensure!(
        entry.ciphertext_length >= first_chunk + chur_format::container::FINAL_COMMIT_RECORD_LEN,
        VaultCorrupt,
        "a container in the package is shorter than its own records"
    );
    ensure!(
        manifest_length <= CONTAINER_HEAD_MAX as u64,
        ResourceLimitExceeded,
        "a manifest record exceeds the head this reader admits"
    );

    let mut record = vec![0u8; usize::try_from(manifest_length).unwrap_or(CONTAINER_HEAD_MAX)];
    read_exact_at(source, content + ContainerPreamble::LEN as u64, &mut record)?;
    let nonce_len = chur_core::limits::NONCE_LEN;
    ensure!(
        record.len() > nonce_len,
        VaultCorrupt,
        "a manifest record is shorter than its nonce"
    );
    let nonce = Nonce::from_slice(&record[..nonce_len])?;
    ensure!(
        chur_format::container::manifest_commitment(&nonce, &record[nonce_len..])
            == entry.manifest_commitment,
        VaultCorrupt,
        "a container's manifest does not match the inventory entry that describes it"
    );

    let chunks_end = entry.ciphertext_length - chur_format::container::FINAL_COMMIT_RECORD_LEN;
    let mut committer =
        chur_crypto::commit::Committer::new(chur_crypto::tuple::tag::OBJECT_ORDERED_COMMITMENT);
    hash_range(
        source,
        content + first_chunk,
        chunks_end - first_chunk,
        &mut |bytes| committer.update(bytes),
        progress,
    )?;
    ensure!(
        committer.finish() == entry.ordered_chunk_commitment,
        VaultCorrupt,
        "a container's chunks do not match the inventory entry that describes them"
    );
    Ok(head.container_version().value())
}

/// Reads exactly `buffer.len()` bytes at `offset`.
fn read_exact_at(source: &mut (impl Read + Seek), offset: u64, buffer: &mut [u8]) -> Result<()> {
    source
        .seek(SeekFrom::Start(offset))
        .map_err(|_| chur_core::err!(IoFailure, "the package could not be positioned"))?;
    source
        .read_exact(buffer)
        .map_err(|_| chur_core::err!(VaultCorrupt, "the package ends inside a record"))
}

/// Feeds a byte range of the package into a commitment, one buffer at a time.
fn hash_range(
    source: &mut (impl Read + Seek),
    offset: u64,
    length: u64,
    feed: &mut impl FnMut(&[u8]),
    progress: &impl Progress,
) -> Result<()> {
    source
        .seek(SeekFrom::Start(offset))
        .map_err(|_| chur_core::err!(IoFailure, "the package could not be positioned"))?;
    let mut buffer = vec![0u8; COPY_BUFFER];
    let mut remaining = length;
    while remaining > 0 {
        if progress.cancelled() {
            return Err(progress::cancelled("the restore was cancelled"));
        }
        let take = usize::try_from(remaining.min(COPY_BUFFER as u64))
            .map_err(|_| chur_core::err!(InternalFailure, "a hash step exceeds a usize"))?;
        source
            .read_exact(&mut buffer[..take])
            .map_err(|_| chur_core::err!(VaultCorrupt, "the package ends inside a record"))?;
        feed(&buffer[..take]);
        remaining -= take as u64;
    }
    Ok(())
}

/// Makes every directory entry the restore created durable.
///
/// Each restored file is synced when it is written, but its directory entry is
/// durable only after its directory is synced. The descriptor install that
/// follows is what makes the vault openable, so a crash after the install must
/// not find a descriptor whose containers or catalog have no directory entry.
/// The order is bottom-up: each shard directory, `objects/`, the vault
/// directory that holds the catalog and `objects/`, and the directory that
/// holds the vault directory.
fn sync_restored_tree(root_dir: &VaultRoot, store_id: &Id) -> Result<()> {
    let objects = root_dir.objects(store_id);
    match std::fs::read_dir(&objects) {
        Ok(listing) => {
            for entry in listing {
                let entry = entry.map_err(|_| {
                    chur_core::err!(IoFailure, "a restored directory could not be listed")
                })?;
                let is_directory = entry.file_type().map_err(|_| {
                    chur_core::err!(IoFailure, "a restored directory could not be listed")
                })?;
                if is_directory.is_dir() {
                    chur_catalog::paths::sync_directory(&entry.path())?;
                }
            }
            chur_catalog::paths::sync_directory(&objects)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => bail!(IoFailure, "a restored directory could not be listed"),
    }
    chur_catalog::paths::sync_directory(&root_dir.vault(store_id))?;
    chur_catalog::paths::sync_directory(&root_dir.vaults())
}

/// Writes one record's payload out to a file.
fn extract(
    source: &mut (impl Read + Seek),
    slot: &RecordSlot,
    path: &Path,
    progress: &impl Progress,
) -> Result<()> {
    extract_range(
        source,
        slot.offset + RECORD_HEADER_LEN as u64,
        slot.payload_length,
        path,
        progress,
    )
}

/// Copies a byte range of the package into a file, one buffer at a time.
fn extract_range(
    source: &mut (impl Read + Seek),
    offset: u64,
    length: u64,
    path: &Path,
    progress: &impl Progress,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| chur_core::err!(IoFailure, "a restore directory could not be created"))?;
    }
    source
        .seek(SeekFrom::Start(offset))
        .map_err(|_| chur_core::err!(IoFailure, "the package could not be positioned"))?;
    let mut file = std::fs::File::create(path)
        .map_err(|_| chur_core::err!(IoFailure, "a restored file could not be created"))?;
    let mut buffer = vec![0u8; COPY_BUFFER];
    let mut remaining = length;
    while remaining > 0 {
        if progress.cancelled() {
            return Err(progress::cancelled("the restore was cancelled"));
        }
        let take = usize::try_from(remaining.min(COPY_BUFFER as u64))
            .map_err(|_| chur_core::err!(InternalFailure, "a copy step exceeds a usize"))?;
        source
            .read_exact(&mut buffer[..take])
            .map_err(|_| chur_core::err!(VaultCorrupt, "the package ends inside a record"))?;
        file.write_all(&buffer[..take]).map_err(|_| {
            chur_core::err!(StorageUnavailable, "a restored file could not be written")
        })?;
        remaining -= take as u64;
    }
    file.sync_all()
        .map_err(|_| chur_core::err!(IoFailure, "a restored file could not be made durable"))?;
    Ok(())
}

/// Opens the package's descriptor with the credential, §8 steps 2 and 3.
fn open_portable_descriptor(bytes: &[u8], credential: &[u8]) -> Result<(VaultDescriptor, Key)> {
    let parsed = VaultDescriptor::parse(bytes)?;
    for slot in &parsed.key_slots {
        ensure!(
            is_portable(slot.slot_type),
            VaultCorrupt,
            "the package carries a device-bound slot §3 excludes"
        );
    }
    let root = match vault::open_password_slot_of(&parsed, credential) {
        Ok(root) => root,
        Err(error)
            if matches!(
                error.status(),
                ChurStatus::AuthenticationFailed | ChurStatus::VaultIncomplete
            ) && parsed
                .key_slots
                .iter()
                .any(|slot| slot.slot_type == SlotType::Recovery) =>
        {
            vault::open_recovery_slot_of(&parsed, credential)?
        }
        Err(error) => return Err(error),
    };
    // §8 step 5 of KEY_SLOTS: the descriptor is authenticated under the root the
    // slot returned, so a package whose body was edited fails here.
    let authenticated = VaultDescriptor::authenticate(bytes, Some(&root))?;
    ensure!(
        authenticated.state == VaultState::Active,
        VaultIncomplete,
        "the package's descriptor is not in the only ordinarily openable state"
    );
    Ok((authenticated, root))
}

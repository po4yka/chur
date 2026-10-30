//! Bounded ciphertext download and complete local container verification.

use chur_catalog::model::{MetadataRevision, Object, Stream};
use chur_catalog::paths::VaultRoot;
use chur_catalog::sharing_receive::SharedObject;
use chur_catalog::store::{self as catalog_store, ObjectActivation};
use chur_catalog::vault::Session;
use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::Key;
use chur_format::constants::{IntegritySummary, ObjectState, SUITE_V1, StreamKind};
use chur_format::container::{
    CanonicalFinalCommit, CanonicalManifest, ContainerVersion, ReadAt, StreamIdentity, StreamReader,
};

use crate::keys;
use crate::store::{self, ContainerFile, TemporaryContainer};
use chur_sync_protocol::payload::MetadataFieldId;

const RANGE_BYTES: usize = 1024 * 1024;

/// Reads a durable download prefix without creating a container.
/// A committed container from a crash before catalog activation is verified by finish.
/// A committed container exists only after verification, so its full length means complete.
/// Bytes damaged at rest after that are not a download fault, and the download is not restarted.
pub fn staged_offset(
    root_dir: &VaultRoot,
    local_store_id: &Id,
    temp_path_id: &Id,
    expected: &Expectation,
) -> Result<u64> {
    let path = root_dir.temporary_container(local_store_id, temp_path_id);
    let length = match std::fs::metadata(path) {
        Ok(metadata) => {
            return Ok(if metadata.len() <= expected.container_length {
                metadata.len()
            } else {
                0
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let committed = root_dir.container(local_store_id, temp_path_id);
            match std::fs::metadata(committed) {
                Ok(metadata) => metadata.len(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
                Err(_) => {
                    return Err(chur_core::err!(
                        IoFailure,
                        "committed download length could not be read"
                    ));
                }
            }
        }
        Err(_) => {
            return Err(chur_core::err!(
                IoFailure,
                "staged download length could not be read"
            ));
        }
    };
    Ok(if length == expected.container_length {
        length
    } else {
        0
    })
}

/// Authenticated values carried by a committed object operation.
pub struct Expectation {
    identity: StreamIdentity,
    container_length: u64,
    ordered_chunk_commitment: [u8; 32],
}

impl Expectation {
    /// Creates the immutable original-stream expectation.
    pub fn new(
        object_id: Id,
        stream_id: Id,
        container_length: u64,
        ordered_chunk_commitment: [u8; 32],
    ) -> Result<Self> {
        ensure!(
            container_length != 0 && ordered_chunk_commitment != [0; 32],
            InvalidInput,
            "sync download expectation is empty"
        );
        Ok(Self {
            identity: StreamIdentity {
                object_id,
                stream_id,
                stream_kind: StreamKind::Original,
                stream_revision: 1,
            },
            container_length,
            ordered_chunk_commitment,
        })
    }
}

/// A complete authenticated temporary container that is safe to publish locally.
pub struct VerifiedDownload {
    container: TemporaryContainer,
    manifest: CanonicalManifest,
    final_commit: CanonicalFinalCommit,
    ciphertext_size: u64,
    container_version: ContainerVersion,
}

impl VerifiedDownload {
    /// Authenticated sealed manifest.
    #[must_use]
    pub const fn manifest(&self) -> &CanonicalManifest {
        &self.manifest
    }

    /// Authenticated final commit.
    #[must_use]
    pub const fn final_commit(&self) -> &CanonicalFinalCommit {
        &self.final_commit
    }

    /// Complete encoded ciphertext length.
    #[must_use]
    pub const fn ciphertext_size(&self) -> u64 {
        self.ciphertext_size
    }

    /// The container version of the verified bytes.
    #[must_use]
    pub const fn container_version(&self) -> ContainerVersion {
        self.container_version
    }

    /// Authenticated original plaintext length.
    #[must_use]
    pub const fn plaintext_size(&self) -> u64 {
        self.final_commit.total_plaintext_length()
    }

    /// Atomically moves the verified bytes into the committed object namespace.
    pub fn commit(
        self,
        root_dir: &VaultRoot,
        local_store_id: &Id,
        container_path_id: &Id,
    ) -> Result<()> {
        self.container
            .commit(root_dir, local_store_id, container_path_id)
    }

    /// Deletes the temporary ciphertext without publishing it.
    pub fn discard(self) -> Result<()> {
        self.container.discard()
    }
}

/// Downloads opaque bytes into the temporary namespace and authenticates every record.
pub fn stage(
    root_dir: &VaultRoot,
    local_store_id: &Id,
    temp_path_id: &Id,
    source: &mut impl ReadAt,
    object_key: &Key,
    expected: &Expectation,
) -> Result<VerifiedDownload> {
    ensure!(
        source.length() >= expected.container_length,
        ObjectIncomplete,
        "sync download is shorter than its committed length"
    );
    ensure!(
        source.length() == expected.container_length,
        ObjectCorrupt,
        "sync download has bytes after its committed length"
    );
    let mut container = TemporaryContainer::open(root_dir, local_store_id, temp_path_id)?;
    let mut offset = container.length()?;
    ensure!(
        offset <= expected.container_length,
        ObjectCorrupt,
        "resumable sync download exceeds its committed length"
    );
    container.truncate_to(offset)?;
    let mut buffer = vec![0; RANGE_BYTES];
    while offset < expected.container_length {
        let remaining = expected.container_length - offset;
        let length = usize::try_from(remaining.min(RANGE_BYTES as u64))
            .map_err(|_| chur_core::err!(ResourceLimitExceeded, "download range is too large"))?;
        source.read_at(offset, &mut buffer[..length])?;
        container.write(&buffer[..length])?;
        container.sync()?;
        offset += length as u64;
    }

    verify_container(container, object_key, expected)
}

/// Appends one bounded server range to the private temporary namespace.
pub fn append_range(
    root_dir: &VaultRoot,
    local_store_id: &Id,
    temp_path_id: &Id,
    offset: u64,
    bytes: &[u8],
    expected: &Expectation,
) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= RANGE_BYTES,
        InvalidInput,
        "shared download range has an invalid length"
    );
    ensure!(
        offset
            .checked_add(bytes.len() as u64)
            .is_some_and(|end| end <= expected.container_length),
        ObjectCorrupt,
        "shared download exceeds its committed length"
    );
    let mut container = TemporaryContainer::open(root_dir, local_store_id, temp_path_id)?;
    if offset == 0 {
        container.truncate_to(0)?;
    } else {
        ensure!(
            container.length()? == offset,
            Conflict,
            "shared download offset differs from durable temporary length"
        );
        container.truncate_to(offset)?;
    }
    container.write(bytes)?;
    container.sync()
}

/// Authenticates a fully staged shared container before its catalog activation.
pub fn verify_staged(
    root_dir: &VaultRoot,
    local_store_id: &Id,
    temp_path_id: &Id,
    object_key: &Key,
    expected: &Expectation,
) -> Result<VerifiedDownload> {
    let container = TemporaryContainer::open(root_dir, local_store_id, temp_path_id)?;
    verify_container(container, object_key, expected)
}

fn verify_container(
    mut container: TemporaryContainer,
    object_key: &Key,
    expected: &Expectation,
) -> Result<VerifiedDownload> {
    // An incomplete file stays: more ranges can still complete it.
    ensure!(
        container.length()? == expected.container_length,
        ObjectIncomplete,
        "shared download is not complete"
    );
    match check_container(&mut container, object_key, expected) {
        Ok((manifest, final_commit, container_version)) => Ok(VerifiedDownload {
            container,
            manifest,
            final_commit,
            ciphertext_size: expected.container_length,
            container_version,
        }),
        Err(error)
            if !matches!(
                error.status(),
                ChurStatus::IoFailure
                    | ChurStatus::StorageUnavailable
                    | ChurStatus::Cancelled
                    | ChurStatus::InternalFailure
            ) =>
        {
            // Range bytes are unauthenticated until now, so any content-derived rejection
            // (corrupt, unsupported header field, trailing bytes) of a full-length file would
            // make staged_offset report a complete download and block every retry. The
            // original rejection wins over a failed delete, which the next append redoes.
            let _ = container.discard();
            Err(error)
        }
        Err(error) => Err(error),
    }
}

fn check_container(
    container: &mut TemporaryContainer,
    object_key: &Key,
    expected: &Expectation,
) -> Result<(CanonicalManifest, CanonicalFinalCommit, ContainerVersion)> {
    let mut view = Downloaded {
        container,
        length: expected.container_length,
    };
    let mut reader = StreamReader::open(&mut view, object_key, &expected.identity)?;
    let manifest = reader.manifest().clone();
    let container_version = reader.version();
    let final_commit = reader.read_final_commit()?;
    reader.verify_complete()?;
    ensure!(
        final_commit.ordered_chunk_commitment() == &expected.ordered_chunk_commitment,
        ObjectCorrupt,
        "downloaded container commitment differs from the signed operation"
    );
    Ok((manifest, final_commit, container_version))
}

/// Verifies the signed object against its container and activates the local row.
pub fn activate_shared(session: &mut Session, object: &SharedObject, now_ms: u64) -> Result<()> {
    // The mutable session serializes activation through filesystem publication.
    // A stale plan must not replace an active container before SQL rejects its ID.
    ensure!(
        !catalog_store::object_present(session.catalog_ref()?, &object.object_id)?,
        Conflict,
        "download target object is already activated"
    );
    let object_key_envelope = chur_catalog::object_grants::pending_envelope(
        session.catalog_ref()?,
        &object.collection_id,
        &object.object_id,
    )?;
    ensure!(
        object_key_envelope.vault_id() == &session.vault_id()
            && object_key_envelope.collection_id() == &object.collection_id
            && object_key_envelope.object_id() == &object.object_id,
        AuthenticationFailed,
        "shared object envelope names another source"
    );
    let collection = catalog_store::collection(session.catalog_ref()?, &object.collection_id)?;
    ensure!(
        object_key_envelope.collection_epoch() <= collection.current_epoch,
        AuthenticationFailed,
        "shared object envelope uses a future collection epoch"
    );
    let collection_key = keys::collection_key(
        session,
        &object.collection_id,
        object_key_envelope.collection_epoch(),
    )?;
    let object_key = object_key_envelope.open(&collection_key)?;
    ensure!(
        chur_sync_protocol::object_grant::object_key_commitment(
            &object.collection_id,
            &object.object_id,
            &object_key
        ) == object.object_key_commitment,
        AuthenticationFailed,
        "received object key differs from the signed commitment"
    );
    // A grant can be accepted before a later metadata-key epoch arrives.
    // The signed content-key commitment stays unchanged across that rotation.
    let object_key_envelope = if object_key_envelope.collection_epoch() == collection.current_epoch
    {
        object_key_envelope
    } else {
        let current =
            keys::collection_key(session, &object.collection_id, collection.current_epoch)?;
        object_key_envelope.rewrap(
            &collection_key,
            &current,
            object.collection_id,
            collection.current_epoch,
            object_key_envelope
                .envelope_generation()
                .checked_add(1)
                .ok_or_else(|| {
                    Error::new(
                        ChurStatus::ResourceLimitExceeded,
                        "pending envelope generation overflowed",
                    )
                })?,
            chur_crypto::Nonce::random()?,
        )?
    };
    let expected = Expectation::new(
        object.object_id,
        object.stream_id,
        object.container_length,
        object.container_commitment,
    )?;
    let local_store_id = session.object_store_id();
    let (manifest, plaintext_size, ciphertext_size, container_version, staged) =
        if store::container_exists(session.root_dir(), &local_store_id, &object.object_id) {
            match verify_committed(
                session.root_dir(),
                &local_store_id,
                &object.object_id,
                &object_key,
                &expected,
            ) {
                Ok((manifest, plaintext_size, version)) => (
                    manifest,
                    plaintext_size,
                    expected.container_length,
                    version,
                    None,
                ),
                Err(_)
                    if store::temporary_exists(
                        session.root_dir(),
                        &local_store_id,
                        &object.object_id,
                    ) =>
                {
                    let verified = verify_staged(
                        session.root_dir(),
                        &local_store_id,
                        &object.object_id,
                        &object_key,
                        &expected,
                    )?;
                    let manifest = verified.manifest().clone();
                    let plaintext_size = verified.plaintext_size();
                    let ciphertext_size = verified.ciphertext_size();
                    let version = verified.container_version();
                    (
                        manifest,
                        plaintext_size,
                        ciphertext_size,
                        version,
                        Some(verified),
                    )
                }
                Err(error) => return Err(error),
            }
        } else {
            let verified = verify_staged(
                session.root_dir(),
                &local_store_id,
                &object.object_id,
                &object_key,
                &expected,
            )?;
            let manifest = verified.manifest().clone();
            let plaintext_size = verified.plaintext_size();
            let ciphertext_size = verified.ciphertext_size();
            let version = verified.container_version();
            (
                manifest,
                plaintext_size,
                ciphertext_size,
                version,
                Some(verified),
            )
        };
    let properties = *manifest.media_properties();
    let chunk_size = manifest.chunk_size();
    let content_type = object
        .metadata
        .iter()
        .find(|field| field.id() == MetadataFieldId::MediaType)
        .map(|field| std::str::from_utf8(field.value()))
        .transpose()
        .map_err(|_| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "shared media type is invalid",
            )
        })?
        .unwrap_or("application/octet-stream")
        .to_owned();
    let original_filename = object
        .metadata
        .iter()
        .find(|field| field.id() == MetadataFieldId::OriginalFilename)
        .map(|field| std::str::from_utf8(field.value()))
        .transpose()
        .map_err(|_| {
            Error::new(
                ChurStatus::AuthenticationFailed,
                "shared filename is invalid",
            )
        })?
        .map(str::to_owned);
    let capture_time_ms = object
        .metadata
        .iter()
        .find(|field| field.id() == MetadataFieldId::CaptureTime)
        .map(|field| {
            field
                .value()
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| {
                    Error::new(
                        ChurStatus::AuthenticationFailed,
                        "shared capture time is invalid",
                    )
                })
        })
        .transpose()?;
    // A received container may carry a version this store does not yet hold.
    session.admit_container_version(container_version.value())?;
    if let Some(verified) = staged {
        if store::container_exists(session.root_dir(), &local_store_id, &object.object_id) {
            store::unlink_container(session.root_dir(), &local_store_id, &object.object_id)?;
        }
        verified.commit(session.root_dir(), &local_store_id, &object.object_id)?;
    }
    catalog_store::activate_object(
        session.catalog()?,
        &ObjectActivation {
            object: Object {
                object_id: object.object_id,
                object_generation: object.object_generation,
                collection_id: object.collection_id,
                primary_stream_id: object.stream_id,
                media_kind: properties.media_class(),
                capture_time_ms: capture_time_ms.unwrap_or(now_ms),
                import_time_ms: now_ms,
                capture_time_substituted: capture_time_ms.is_none(),
                plaintext_size,
                width: properties.pixel_width(),
                height: properties.pixel_height(),
                duration_ms: properties.duration_ms(),
                favorite: false,
                state: ObjectState::Active,
                integrity_summary: IntegritySummary::CompleteVerified,
                thumbnail_ready: false,
                active_metadata_revision: 1,
            },
            stream: Stream {
                stream_id: object.stream_id,
                object_id: object.object_id,
                stream_kind: StreamKind::Original,
                stream_revision: 1,
                source_content_revision: 0,
                container_path_id: object.object_id,
                container_version: container_version.value(),
                suite_id: SUITE_V1,
                ciphertext_size,
                plaintext_size,
                chunk_size,
                complete_verified_ms: Some(now_ms),
                final_commitment: object.container_commitment,
            },
            envelope: object_key_envelope.encode(),
            envelope_generation: object_key_envelope.envelope_generation(),
            metadata: MetadataRevision {
                object_id: object.object_id,
                revision: 1,
                active: true,
                record: Vec::new(),
                original_filename,
                caption: None,
                content_type,
                capture_time_ms,
                width: properties.pixel_width(),
                height: properties.pixel_height(),
                duration_ms: properties.duration_ms(),
            },
        },
    )?;
    if chur_catalog::own_sync::is_local_collection(session.catalog_ref()?, &object.collection_id)? {
        let root = session.root_secret()?.duplicate();
        let vault = session.vault_id();
        chur_catalog::own_sync::project_received_album_memberships(
            session.catalog()?,
            &root,
            vault,
            &object.object_id,
        )?;
    }
    Ok(())
}

fn verify_committed(
    root_dir: &VaultRoot,
    local_store_id: &Id,
    container_path_id: &Id,
    object_key: &Key,
    expected: &Expectation,
) -> Result<(CanonicalManifest, u64, ContainerVersion)> {
    let mut file = ContainerFile::open(root_dir, local_store_id, container_path_id)?;
    ensure!(
        file.length() == expected.container_length,
        ObjectCorrupt,
        "committed shared container length differs from signed commit"
    );
    let mut reader = StreamReader::open(&mut file, object_key, &expected.identity)?;
    let manifest = reader.manifest().clone();
    let plaintext_size = reader.verify_complete()?;
    ensure!(
        reader.read_final_commit()?.ordered_chunk_commitment()
            == &expected.ordered_chunk_commitment,
        ObjectCorrupt,
        "committed shared container differs from signed commit"
    );
    Ok((manifest, plaintext_size, reader.version()))
}

struct Downloaded<'a> {
    container: &'a mut TemporaryContainer,
    length: u64,
}

impl ReadAt for Downloaded<'_> {
    fn length(&self) -> u64 {
        self.length
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        let bytes = self.container.read_at(offset, buffer.len())?;
        buffer.copy_from_slice(&bytes);
        Ok(())
    }
}

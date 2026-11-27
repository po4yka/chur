//! The canonical encrypted plaintext of `docs/sync/OPERATION_PAYLOAD_V1.md`.

use chur_core::limits::{COMMITMENT_LEN, envelope as envelope_bounds, sync as sync_bounds};
use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_format::codec::{Reader, Writer};
use chur_format::envelope::CollectionKeyEnvelope;

use crate::KeyDirectory;
use crate::collection_membership::CollectionMembershipRecord;
use crate::collection_operation::CollectionOperation;
use crate::grant::CollectionGrant;
use crate::membership::{EnrollmentRecord, RevocationRecord};
use crate::operation::{Operation, PROTOCOL_VERSION_V1};

const HEADER_LEN: usize = 2 + 1 + 16 + 8;
const ALBUM_OR_TAG_NAME_MAX: u32 = 4_096;
const METADATA_FIELD_COUNT_MAX: usize = 32;
const METADATA_VALUE_TOTAL_MAX: usize = 262_144;
const TOKEN_COUNT_MAX: usize = 256;
const ENROLLMENT_LEN: usize = 270;
const REVOCATION_LEN: usize = 194;

/// One allocated metadata field identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum MetadataFieldId {
    /// Original import filename.
    OriginalFilename = 0x0001,
    /// Lowercase ASCII MIME type.
    MediaType = 0x0002,
    /// Big-endian capture time in milliseconds.
    CaptureTime = 0x0003,
    /// User caption.
    Caption = 0x0004,
    /// Rating from zero through five.
    Rating = 0x0005,
}

impl MetadataFieldId {
    fn decode(value: u16) -> Result<Self> {
        match value {
            0x0001 => Ok(Self::OriginalFilename),
            0x0002 => Ok(Self::MediaType),
            0x0003 => Ok(Self::CaptureTime),
            0x0004 => Ok(Self::Caption),
            0x0005 => Ok(Self::Rating),
            _ => Err(Error::new(
                ChurStatus::UnsupportedVersion,
                "sync metadata field is not supported",
            )),
        }
    }
}

/// One bounded canonical metadata value.
#[derive(Clone, PartialEq, Eq)]
pub struct MetadataField {
    id: MetadataFieldId,
    value: Vec<u8>,
}

impl MetadataField {
    /// Builds and validates one metadata field.
    pub fn new(id: MetadataFieldId, value: Vec<u8>) -> Result<Self> {
        validate_metadata_value(id, &value)?;
        Ok(Self { id, value })
    }

    /// Allocated field identifier.
    #[must_use]
    pub const fn id(&self) -> MetadataFieldId {
        self.id
    }

    /// Canonical field value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// The exact body selected by `operation_kind`.
#[derive(Clone, PartialEq, Eq)]
pub enum PayloadBody {
    /// Starts an object that is not presentable until committed.
    CreateObject {
        /// Object identifier.
        object_id: Id,
        /// Object generation.
        object_generation: u64,
        /// Opaque remote store identifier.
        store_id: Id,
        /// Primary original stream identifier required to open the sealed manifest.
        stream_id: Id,
        /// Sorted initial metadata.
        metadata_fields: Vec<MetadataField>,
    },
    /// Commits one authenticated immutable object.
    CommitObject {
        /// Object identifier.
        object_id: Id,
        /// Object generation.
        object_generation: u64,
        /// Opaque remote store identifier.
        store_id: Id,
        /// Encoded container length.
        container_length: u64,
        /// Container final commitment.
        container_commitment: [u8; COMMITMENT_LEN],
        /// Commitment to the object key; the key is delivered by a disposable grant.
        object_key_commitment: [u8; 32],
    },
    /// Replaces one scalar metadata value.
    UpdateMetadata {
        /// Object identifier.
        object_id: Id,
        /// Object generation.
        object_generation: u64,
        /// Changed field.
        field: MetadataField,
    },
    /// Creates one logical album.
    CreateAlbum {
        /// Album identifier.
        album_id: Id,
        /// Private album name.
        name: String,
    },
    /// Renames one logical album.
    RenameAlbum {
        /// Album identifier.
        album_id: Id,
        /// Private album name.
        name: String,
    },
    /// Adds an object to an album using the outer operation identifier as token.
    AddAlbumMembership {
        /// Album identifier.
        album_id: Id,
        /// Object identifier.
        object_id: Id,
    },
    /// Removes observed album-membership add tokens.
    RemoveAlbumMembership {
        /// Album identifier.
        album_id: Id,
        /// Object identifier.
        object_id: Id,
        /// Sorted observed add tokens.
        removed_tokens: Vec<Id>,
    },
    /// Adds or removes favorite tokens.
    SetFavorite {
        /// Object identifier.
        object_id: Id,
        /// `true` adds the outer operation token; `false` removes listed tokens.
        favorite: bool,
        /// Sorted observed add tokens.
        removed_tokens: Vec<Id>,
    },
    /// Adds one tag token to an object.
    AddTag {
        /// Tag identifier.
        tag_id: Id,
        /// Object identifier.
        object_id: Id,
        /// Private tag name.
        name: String,
    },
    /// Removes observed tag add tokens.
    RemoveTag {
        /// Tag identifier.
        tag_id: Id,
        /// Object identifier.
        object_id: Id,
        /// Sorted observed add tokens.
        removed_tokens: Vec<Id>,
    },
    /// Creates a durable object tombstone.
    DeleteObject {
        /// Object identifier.
        object_id: Id,
        /// Deleted object generation.
        object_generation: u64,
        /// Signed retention hint in Unix milliseconds.
        authored_at_ms: u64,
    },
    /// Permanently removes content keys and prevents every later restore.
    PurgeObject {
        /// Object identifier.
        object_id: Id,
        /// Observed object generation.
        object_generation: u64,
        /// Signed deletion time in Unix milliseconds.
        authored_at_ms: u64,
    },
    /// Explicitly restores the currently visible tombstone.
    RestoreObject {
        /// Object identifier.
        object_id: Id,
        /// Outer operation identifier of the tombstone.
        tombstone_operation_id: Id,
        /// Next object generation.
        new_object_generation: u64,
    },
    /// Carries a signed device enrollment.
    AddDevice(EnrollmentRecord),
    /// Starts an enrolled ordinary device's own signed chain without changing content.
    DeviceReady,
    /// Makes one vault-owned metadata key discoverable through the root domain.
    DeclareCollection {
        /// Root-wrapped collection metadata key, never an object content key.
        collection_key_envelope: CollectionKeyEnvelope,
    },
    /// Carries a signed device revocation.
    RevokeDevice(RevocationRecord),
    /// Creates the next collection epoch.
    CreateCollectionEpoch {
        /// Epoch whose key encrypted this operation.
        previous_collection_epoch: u64,
        /// Membership generation authorizing the epoch.
        membership_generation: u64,
        /// Root-wrapped new collection key.
        collection_key_envelope: CollectionKeyEnvelope,
    },
    /// Rewraps one object key into the current collection epoch.
    RewrapObjectKey {
        /// Object identifier.
        object_id: Id,
        /// Commitment to the unchanged object key.
        object_key_commitment: [u8; 32],
    },
    /// Changes one recipient-device membership entry.
    ChangeCollectionMembership(CollectionMembershipRecord),
    /// Issues one signed HPKE collection grant.
    IssueCollectionGrant(CollectionGrant),
}

impl PayloadBody {
    const fn kind(&self) -> u8 {
        match self {
            Self::CreateObject { .. } => 0x01,
            Self::CommitObject { .. } => 0x02,
            Self::UpdateMetadata { .. } => 0x03,
            Self::CreateAlbum { .. } => 0x04,
            Self::RenameAlbum { .. } => 0x05,
            Self::AddAlbumMembership { .. } => 0x06,
            Self::RemoveAlbumMembership { .. } => 0x07,
            Self::SetFavorite { .. } => 0x08,
            Self::AddTag { .. } => 0x09,
            Self::RemoveTag { .. } => 0x0a,
            Self::DeleteObject { .. } => 0x0b,
            Self::RestoreObject { .. } => 0x0c,
            Self::AddDevice(_) => 0x0d,
            Self::RevokeDevice(_) => 0x0e,
            Self::CreateCollectionEpoch { .. } => 0x0f,
            Self::RewrapObjectKey { .. } => 0x10,
            Self::ChangeCollectionMembership(_) => 0x11,
            Self::IssueCollectionGrant(_) => 0x12,
            Self::DeviceReady => 0x13,
            Self::PurgeObject { .. } => 0x14,
            Self::DeclareCollection { .. } => 0x15,
        }
    }
}

/// One validated private operation payload.
#[derive(Clone, PartialEq, Eq)]
pub struct OperationPayload {
    collection_id: Id,
    collection_epoch: u64,
    body: PayloadBody,
}

impl OperationPayload {
    /// Builds a payload and validates its kind-local invariants.
    pub fn new(collection_id: Id, collection_epoch: u64, body: PayloadBody) -> Result<Self> {
        let payload = Self {
            collection_id,
            collection_epoch,
            body,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Collection named inside the encrypted payload.
    #[must_use]
    pub const fn collection_id(&self) -> &Id {
        &self.collection_id
    }

    /// Collection epoch named inside the encrypted payload.
    #[must_use]
    pub const fn collection_epoch(&self) -> u64 {
        self.collection_epoch
    }

    /// Validated logical body.
    #[must_use]
    pub const fn body(&self) -> &PayloadBody {
        &self.body
    }

    /// Encodes the canonical plaintext.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(HEADER_LEN + 128);
        writer
            .u16(PROTOCOL_VERSION_V1)
            .u8(self.body.kind())
            .id(&self.collection_id)
            .u64(self.collection_epoch);
        self.write_body(&mut writer);
        writer.finish()
    }

    /// Decodes and validates one canonical plaintext.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= sync_bounds::PAYLOAD_PLAINTEXT_MAX,
            ResourceLimitExceeded,
            "sync payload exceeds the protocol limit"
        );
        let mut reader = Reader::new(bytes, ChurStatus::NonCanonicalEncoding);
        ensure!(
            reader.u16()? == PROTOCOL_VERSION_V1,
            UnsupportedVersion,
            "sync payload version is not supported"
        );
        let kind = reader.u8()?;
        let collection_id = reader.id()?;
        let collection_epoch = reader.u64()?;
        let body = decode_body(kind, &mut reader)?;
        reader.finish()?;
        Self::new(collection_id, collection_epoch, body)
    }

    /// Opens, decodes, and binds a payload to its resolved outer selector.
    pub fn open_for_operation(operation: &Operation, keys: &KeyDirectory) -> Result<Self> {
        let domain = keys.domain(operation.key_selector())?;
        let plaintext = operation.open_payload(domain.operation_key())?;
        let payload = Self::decode(&plaintext)?;
        payload.validate_for_operation(
            operation,
            domain.collection_id(),
            domain.collection_epoch(),
        )?;
        Ok(payload)
    }

    /// Opens and binds a payload from a shared-collection operation stream.
    pub fn open_for_collection_operation(
        operation: &CollectionOperation,
        keys: &KeyDirectory,
    ) -> Result<Self> {
        let domain = keys.domain(operation.key_selector())?;
        let plaintext = operation.open_payload(domain.operation_key())?;
        let payload = Self::decode(&plaintext)?;
        payload
            .validate_for_collection_operation(domain.collection_id(), domain.collection_epoch())?;
        Ok(payload)
    }

    /// Validates the payload kind and collection epoch for a shared stream.
    pub fn validate_for_collection_operation(
        &self,
        selected_collection_id: &Id,
        selected_collection_epoch: u64,
    ) -> Result<()> {
        ensure!(
            &self.collection_id == selected_collection_id
                && self.collection_epoch == selected_collection_epoch,
            AuthenticationFailed,
            "payload does not match the resolved collection selector"
        );
        ensure!(
            matches!(
                self.body,
                PayloadBody::CreateObject { .. }
                    | PayloadBody::CommitObject { .. }
                    | PayloadBody::UpdateMetadata { .. }
                    | PayloadBody::CreateAlbum { .. }
                    | PayloadBody::RenameAlbum { .. }
                    | PayloadBody::AddAlbumMembership { .. }
                    | PayloadBody::RemoveAlbumMembership { .. }
                    | PayloadBody::SetFavorite { .. }
                    | PayloadBody::AddTag { .. }
                    | PayloadBody::RemoveTag { .. }
                    | PayloadBody::DeleteObject { .. }
                    | PayloadBody::PurgeObject { .. }
                    | PayloadBody::RestoreObject { .. }
                    | PayloadBody::RewrapObjectKey { .. }
            ),
            AuthenticationFailed,
            "payload kind is not allowed in a collection operation stream"
        );
        Ok(())
    }

    /// Validates the private payload against its authenticated outer operation.
    pub fn validate_for_operation(
        &self,
        operation: &Operation,
        selected_collection_id: &Id,
        selected_collection_epoch: u64,
    ) -> Result<()> {
        ensure!(
            &self.collection_id == selected_collection_id
                && self.collection_epoch == selected_collection_epoch,
            AuthenticationFailed,
            "payload does not match the resolved outer key selector"
        );
        let root_domain = matches!(
            self.body,
            PayloadBody::AddDevice(_)
                | PayloadBody::RevokeDevice(_)
                | PayloadBody::DeviceReady
                | PayloadBody::DeclareCollection { .. }
        );
        if root_domain {
            ensure!(
                self.collection_id == *operation.vault_id() && self.collection_epoch == 0,
                AuthenticationFailed,
                "root payload does not match the operation vault"
            );
        }
        match &self.body {
            PayloadBody::DeclareCollection {
                collection_key_envelope,
            } => ensure!(
                collection_key_envelope.vault_id() == operation.vault_id(),
                AuthenticationFailed,
                "declared collection belongs to another vault"
            ),
            PayloadBody::DeviceReady => ensure!(
                operation.device_sequence() == 1,
                AuthenticationFailed,
                "device readiness is only the first signed device operation"
            ),
            PayloadBody::AddDevice(record) => {
                ensure!(
                    record.vault_id() == operation.vault_id()
                        && record.issuer_device_id() == operation.device_id()
                        && record.created_sequence() == operation.device_sequence(),
                    AuthenticationFailed,
                    "enrollment does not match its containing operation"
                );
            }
            PayloadBody::RevokeDevice(record) => {
                ensure!(
                    record.vault_id() == operation.vault_id()
                        && record.issuer_device_id() == operation.device_id(),
                    AuthenticationFailed,
                    "revocation does not match its containing operation"
                );
            }
            PayloadBody::CreateCollectionEpoch {
                previous_collection_epoch,
                collection_key_envelope,
                ..
            } => {
                ensure!(
                    collection_key_envelope.vault_id() == operation.vault_id()
                        && collection_key_envelope.collection_id() == &self.collection_id
                        && *previous_collection_epoch == self.collection_epoch
                        && collection_key_envelope.collection_epoch() == self.collection_epoch + 1,
                    AuthenticationFailed,
                    "collection-key envelope does not match its containing operation"
                );
            }
            PayloadBody::ChangeCollectionMembership(record) => {
                ensure!(
                    record.collection_id() == &self.collection_id
                        && record.issuer_identity_vault_id() == operation.vault_id()
                        && record.issuer_device_id() == operation.device_id()
                        && record.created_sequence() == operation.device_sequence(),
                    AuthenticationFailed,
                    "collection membership record does not match its containing operation"
                );
            }
            PayloadBody::IssueCollectionGrant(grant) => {
                ensure!(
                    grant.grant_id() == operation.operation_id()
                        && grant.collection_id() == &self.collection_id
                        && grant.collection_epoch() == self.collection_epoch
                        && grant.sender_device_id() == operation.device_id()
                        && grant.created_sequence() == operation.device_sequence(),
                    AuthenticationFailed,
                    "collection grant does not match its containing operation"
                );
            }
            _ => {}
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        let root_domain = matches!(
            self.body,
            PayloadBody::AddDevice(_)
                | PayloadBody::RevokeDevice(_)
                | PayloadBody::DeviceReady
                | PayloadBody::DeclareCollection { .. }
        );
        ensure!(
            root_domain == (self.collection_epoch == 0),
            NonCanonicalEncoding,
            "sync payload root and collection domains disagree"
        );
        ensure!(
            root_domain || self.collection_epoch != u64::MAX,
            NonCanonicalEncoding,
            "sync collection epoch has no successor"
        );
        match &self.body {
            PayloadBody::CreateObject {
                object_generation,
                metadata_fields,
                ..
            } => {
                validate_counter(*object_generation, "object generation")?;
                validate_metadata_fields(metadata_fields)?;
            }
            PayloadBody::CommitObject {
                object_generation,
                container_length,
                container_commitment,
                object_key_commitment,
                ..
            } => {
                validate_counter(*object_generation, "object generation")?;
                ensure!(
                    *container_length != 0 && *container_commitment != [0; COMMITMENT_LEN],
                    NonCanonicalEncoding,
                    "object commit length or commitment is zero"
                );
                ensure!(
                    *object_key_commitment != [0; 32],
                    NonCanonicalEncoding,
                    "object key commitment is zero"
                );
            }
            PayloadBody::UpdateMetadata {
                object_generation,
                field,
                ..
            } => {
                validate_counter(*object_generation, "object generation")?;
                validate_metadata_value(field.id, &field.value)?;
            }
            PayloadBody::CreateAlbum { name, .. }
            | PayloadBody::RenameAlbum { name, .. }
            | PayloadBody::AddTag { name, .. } => validate_name(name)?,
            PayloadBody::RemoveAlbumMembership { removed_tokens, .. }
            | PayloadBody::RemoveTag { removed_tokens, .. } => {
                validate_tokens(removed_tokens)?;
            }
            PayloadBody::SetFavorite {
                favorite,
                removed_tokens,
                ..
            } => {
                validate_tokens(removed_tokens)?;
                ensure!(
                    *favorite == removed_tokens.is_empty(),
                    NonCanonicalEncoding,
                    "favorite add/remove tokens are not canonical"
                );
            }
            PayloadBody::DeleteObject {
                object_generation, ..
            }
            | PayloadBody::PurgeObject {
                object_generation, ..
            } => validate_counter(*object_generation, "object generation")?,
            PayloadBody::RestoreObject {
                new_object_generation,
                ..
            } => validate_counter(*new_object_generation, "object generation")?,
            PayloadBody::CreateCollectionEpoch {
                previous_collection_epoch,
                membership_generation,
                collection_key_envelope,
            } => {
                ensure!(
                    *previous_collection_epoch == self.collection_epoch,
                    NonCanonicalEncoding,
                    "previous collection epoch does not match payload header"
                );
                validate_counter(*membership_generation, "membership generation")?;
                ensure!(
                    collection_key_envelope.collection_id() == &self.collection_id
                        && collection_key_envelope.collection_epoch() == self.collection_epoch + 1,
                    NonCanonicalEncoding,
                    "new collection-key envelope does not follow the payload epoch"
                );
            }
            PayloadBody::RewrapObjectKey {
                object_key_commitment,
                ..
            } => {
                ensure!(
                    *object_key_commitment != [0; 32],
                    NonCanonicalEncoding,
                    "object key commitment is zero"
                );
            }
            PayloadBody::ChangeCollectionMembership(record) => {
                ensure!(
                    record.collection_id() == &self.collection_id
                        && match record.action() {
                            crate::collection_membership::CollectionMembershipAction::Upsert(_) =>
                                record.collection_epoch() == self.collection_epoch,
                            crate::collection_membership::CollectionMembershipAction::Revoke =>
                                self.collection_epoch
                                    .checked_add(1)
                                    .is_some_and(|epoch| { epoch == record.collection_epoch() }),
                        },
                    NonCanonicalEncoding,
                    "collection membership record does not match the payload header"
                );
            }
            PayloadBody::IssueCollectionGrant(grant) => ensure!(
                grant.collection_id() == &self.collection_id
                    && grant.collection_epoch() == self.collection_epoch,
                NonCanonicalEncoding,
                "collection grant does not match the payload header"
            ),
            PayloadBody::AddAlbumMembership { .. }
            | PayloadBody::AddDevice(_)
            | PayloadBody::RevokeDevice(_)
            | PayloadBody::DeviceReady
            | PayloadBody::DeclareCollection { .. } => {}
        }
        ensure!(
            self.encode().len() <= sync_bounds::PAYLOAD_PLAINTEXT_MAX,
            ResourceLimitExceeded,
            "sync payload exceeds the protocol limit"
        );
        Ok(())
    }

    fn write_body(&self, writer: &mut Writer) {
        match &self.body {
            PayloadBody::CreateObject {
                object_id,
                object_generation,
                store_id,
                stream_id,
                metadata_fields,
            } => {
                writer
                    .id(object_id)
                    .u64(*object_generation)
                    .id(store_id)
                    .id(stream_id);
                write_metadata_fields(writer, metadata_fields);
            }
            PayloadBody::CommitObject {
                object_id,
                object_generation,
                store_id,
                container_length,
                container_commitment,
                object_key_commitment,
            } => {
                writer
                    .id(object_id)
                    .u64(*object_generation)
                    .id(store_id)
                    .u64(*container_length)
                    .fixed(container_commitment)
                    .fixed(object_key_commitment);
            }
            PayloadBody::UpdateMetadata {
                object_id,
                object_generation,
                field,
            } => {
                writer.id(object_id).u64(*object_generation);
                write_metadata_field(writer, field);
            }
            PayloadBody::CreateAlbum { album_id, name }
            | PayloadBody::RenameAlbum { album_id, name } => {
                writer.id(album_id);
                write_variable(writer, name.as_bytes());
            }
            PayloadBody::AddAlbumMembership {
                album_id,
                object_id,
            } => {
                writer.id(album_id).id(object_id);
            }
            PayloadBody::RemoveAlbumMembership {
                album_id,
                object_id,
                removed_tokens,
            } => {
                writer.id(album_id).id(object_id);
                write_tokens(writer, removed_tokens);
            }
            PayloadBody::SetFavorite {
                object_id,
                favorite,
                removed_tokens,
            } => {
                writer.id(object_id).bool(*favorite);
                write_tokens(writer, removed_tokens);
            }
            PayloadBody::AddTag {
                tag_id,
                object_id,
                name,
            } => {
                writer.id(tag_id).id(object_id);
                write_variable(writer, name.as_bytes());
            }
            PayloadBody::RemoveTag {
                tag_id,
                object_id,
                removed_tokens,
            } => {
                writer.id(tag_id).id(object_id);
                write_tokens(writer, removed_tokens);
            }
            PayloadBody::DeleteObject {
                object_id,
                object_generation,
                authored_at_ms,
            }
            | PayloadBody::PurgeObject {
                object_id,
                object_generation,
                authored_at_ms,
            } => {
                writer
                    .id(object_id)
                    .u64(*object_generation)
                    .u64(*authored_at_ms);
            }
            PayloadBody::RestoreObject {
                object_id,
                tombstone_operation_id,
                new_object_generation,
            } => {
                writer
                    .id(object_id)
                    .id(tombstone_operation_id)
                    .u64(*new_object_generation);
            }
            PayloadBody::DeclareCollection {
                collection_key_envelope,
            } => {
                writer.fixed(&collection_key_envelope.encode());
            }
            PayloadBody::DeviceReady => {}
            PayloadBody::AddDevice(record) => {
                writer.fixed(&record.encode());
            }
            PayloadBody::RevokeDevice(record) => {
                writer.fixed(&record.encode());
            }
            PayloadBody::CreateCollectionEpoch {
                previous_collection_epoch,
                membership_generation,
                collection_key_envelope,
            } => {
                writer
                    .u64(*previous_collection_epoch)
                    .u64(*membership_generation)
                    .fixed(&collection_key_envelope.encode());
            }
            PayloadBody::RewrapObjectKey {
                object_id,
                object_key_commitment,
            } => {
                writer.id(object_id).fixed(object_key_commitment);
            }
            PayloadBody::ChangeCollectionMembership(record) => {
                writer.fixed(&record.encode());
            }
            PayloadBody::IssueCollectionGrant(grant) => {
                writer.fixed(&grant.encode());
            }
        }
    }
}

fn decode_body(kind: u8, reader: &mut Reader<'_>) -> Result<PayloadBody> {
    Ok(match kind {
        0x01 => PayloadBody::CreateObject {
            object_id: reader.id()?,
            object_generation: reader.u64()?,
            store_id: reader.id()?,
            stream_id: reader.id()?,
            metadata_fields: read_metadata_fields(reader)?,
        },
        0x02 => PayloadBody::CommitObject {
            object_id: reader.id()?,
            object_generation: reader.u64()?,
            store_id: reader.id()?,
            container_length: reader.u64()?,
            container_commitment: reader.fixed::<COMMITMENT_LEN>()?,
            object_key_commitment: reader.fixed::<32>()?,
        },
        0x03 => PayloadBody::UpdateMetadata {
            object_id: reader.id()?,
            object_generation: reader.u64()?,
            field: read_metadata_field(reader)?,
        },
        0x04 => PayloadBody::CreateAlbum {
            album_id: reader.id()?,
            name: reader.string(ALBUM_OR_TAG_NAME_MAX)?.to_owned(),
        },
        0x05 => PayloadBody::RenameAlbum {
            album_id: reader.id()?,
            name: reader.string(ALBUM_OR_TAG_NAME_MAX)?.to_owned(),
        },
        0x06 => PayloadBody::AddAlbumMembership {
            album_id: reader.id()?,
            object_id: reader.id()?,
        },
        0x07 => PayloadBody::RemoveAlbumMembership {
            album_id: reader.id()?,
            object_id: reader.id()?,
            removed_tokens: read_tokens(reader)?,
        },
        0x08 => PayloadBody::SetFavorite {
            object_id: reader.id()?,
            favorite: reader.bool()?,
            removed_tokens: read_tokens(reader)?,
        },
        0x09 => PayloadBody::AddTag {
            tag_id: reader.id()?,
            object_id: reader.id()?,
            name: reader.string(ALBUM_OR_TAG_NAME_MAX)?.to_owned(),
        },
        0x0a => PayloadBody::RemoveTag {
            tag_id: reader.id()?,
            object_id: reader.id()?,
            removed_tokens: read_tokens(reader)?,
        },
        0x0b => PayloadBody::DeleteObject {
            object_id: reader.id()?,
            object_generation: reader.u64()?,
            authored_at_ms: reader.u64()?,
        },
        0x0c => PayloadBody::RestoreObject {
            object_id: reader.id()?,
            tombstone_operation_id: reader.id()?,
            new_object_generation: reader.u64()?,
        },
        0x15 => PayloadBody::DeclareCollection {
            collection_key_envelope: CollectionKeyEnvelope::decode(
                reader.slice(CollectionKeyEnvelope::LEN)?,
            )?,
        },
        0x13 => PayloadBody::DeviceReady,
        0x14 => PayloadBody::PurgeObject {
            object_id: reader.id()?,
            object_generation: reader.u64()?,
            authored_at_ms: reader.u64()?,
        },
        0x0d => PayloadBody::AddDevice(EnrollmentRecord::decode(reader.slice(ENROLLMENT_LEN)?)?),
        0x0e => PayloadBody::RevokeDevice(RevocationRecord::decode(reader.slice(REVOCATION_LEN)?)?),
        0x0f => PayloadBody::CreateCollectionEpoch {
            previous_collection_epoch: reader.u64()?,
            membership_generation: reader.u64()?,
            collection_key_envelope: CollectionKeyEnvelope::decode(
                reader.slice(envelope_bounds::COLLECTION_KEY_ENVELOPE_LEN)?,
            )?,
        },
        0x10 => PayloadBody::RewrapObjectKey {
            object_id: reader.id()?,
            object_key_commitment: reader.fixed::<32>()?,
        },
        0x11 => PayloadBody::ChangeCollectionMembership(CollectionMembershipRecord::decode(
            reader.slice(CollectionMembershipRecord::LEN)?,
        )?),
        0x12 => PayloadBody::IssueCollectionGrant(CollectionGrant::decode(
            reader.slice(CollectionGrant::LEN)?,
        )?),
        _ => {
            return Err(Error::new(
                ChurStatus::UnsupportedVersion,
                "sync operation kind is not supported",
            ));
        }
    })
}

fn validate_counter(value: u64, name: &'static str) -> Result<()> {
    if value != 0 && value != u64::MAX {
        return Ok(());
    }
    Err(Error::new(ChurStatus::NonCanonicalEncoding, name))
}

fn validate_name(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty(),
        NonCanonicalEncoding,
        "album or tag name is empty"
    );
    ensure!(
        value.len() <= ALBUM_OR_TAG_NAME_MAX as usize,
        ResourceLimitExceeded,
        "album or tag name exceeds the protocol limit"
    );
    Ok(())
}

fn validate_metadata_fields(fields: &[MetadataField]) -> Result<()> {
    ensure!(
        fields.len() <= METADATA_FIELD_COUNT_MAX,
        ResourceLimitExceeded,
        "metadata field count exceeds the protocol limit"
    );
    let mut previous = None;
    let mut total = 0usize;
    for field in fields {
        let id = field.id as u16;
        ensure!(
            previous.is_none_or(|value| value < id),
            NonCanonicalEncoding,
            "metadata fields are not sorted and unique"
        );
        validate_metadata_value(field.id, &field.value)?;
        total = total.checked_add(field.value.len()).ok_or_else(|| {
            Error::new(
                ChurStatus::ResourceLimitExceeded,
                "metadata value length overflows the address space",
            )
        })?;
        previous = Some(id);
    }
    ensure!(
        total <= METADATA_VALUE_TOTAL_MAX,
        ResourceLimitExceeded,
        "metadata values exceed the protocol limit"
    );
    Ok(())
}

fn validate_metadata_value(id: MetadataFieldId, value: &[u8]) -> Result<()> {
    match id {
        MetadataFieldId::OriginalFilename => validate_utf8(value, 4_096)?,
        MetadataFieldId::MediaType => {
            let mut parts = value.split(|byte| *byte == b'/');
            ensure!(
                value.len() <= 255
                    && parts.next().is_some_and(is_mime_token)
                    && parts.next().is_some_and(is_mime_token)
                    && parts.next().is_none(),
                NonCanonicalEncoding,
                "media type is not canonical lowercase ASCII"
            );
        }
        MetadataFieldId::CaptureTime => ensure!(
            value.len() == 8,
            NonCanonicalEncoding,
            "capture time is not one u64"
        ),
        MetadataFieldId::Caption => validate_utf8(value, 65_536)?,
        MetadataFieldId::Rating => ensure!(
            matches!(value, [0..=5]),
            NonCanonicalEncoding,
            "rating is outside zero through five"
        ),
    }
    Ok(())
}

fn is_mime_token(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().all(|byte| {
            matches!(
                byte,
                b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'!'
                    | b'#'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
        })
}

fn validate_utf8(value: &[u8], maximum: usize) -> Result<()> {
    ensure!(
        value.len() <= maximum,
        ResourceLimitExceeded,
        "metadata string exceeds the protocol limit"
    );
    core::str::from_utf8(value).map_err(|_| {
        Error::new(
            ChurStatus::NonCanonicalEncoding,
            "metadata string is not valid UTF-8",
        )
    })?;
    Ok(())
}

fn validate_tokens(tokens: &[Id]) -> Result<()> {
    ensure!(
        tokens.len() <= TOKEN_COUNT_MAX,
        ResourceLimitExceeded,
        "removed-token count exceeds the protocol limit"
    );
    ensure!(
        tokens.windows(2).all(|pair| pair[0] < pair[1]),
        NonCanonicalEncoding,
        "removed tokens are not sorted and unique"
    );
    Ok(())
}

fn write_metadata_fields(writer: &mut Writer, fields: &[MetadataField]) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "validated metadata field count is at most 32"
    )]
    writer.u32(fields.len() as u32);
    for field in fields {
        write_metadata_field(writer, field);
    }
}

fn write_metadata_field(writer: &mut Writer, field: &MetadataField) {
    writer.u16(field.id as u16);
    write_variable(writer, &field.value);
}

fn write_tokens(writer: &mut Writer, tokens: &[Id]) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "validated token count is at most 256"
    )]
    writer.u32(tokens.len() as u32);
    for token in tokens {
        writer.id(token);
    }
}

fn write_variable(writer: &mut Writer, bytes: &[u8]) {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "every payload variable is validated below u32::MAX"
    )]
    writer.u32(bytes.len() as u32).fixed(bytes);
}

fn read_metadata_fields(reader: &mut Reader<'_>) -> Result<Vec<MetadataField>> {
    let count = usize::try_from(reader.u32()?).map_err(|_| {
        Error::new(
            ChurStatus::ResourceLimitExceeded,
            "metadata field count does not fit this platform",
        )
    })?;
    ensure!(
        count <= METADATA_FIELD_COUNT_MAX,
        ResourceLimitExceeded,
        "metadata field count exceeds the protocol limit"
    );
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        fields.push(read_metadata_field(reader)?);
    }
    validate_metadata_fields(&fields)?;
    Ok(fields)
}

fn read_metadata_field(reader: &mut Reader<'_>) -> Result<MetadataField> {
    let id = MetadataFieldId::decode(reader.u16()?)?;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "metadata value limit is 262144"
    )]
    let value = reader.variable(METADATA_VALUE_TOTAL_MAX as u32)?.to_vec();
    MetadataField::new(id, value)
}

fn read_tokens(reader: &mut Reader<'_>) -> Result<Vec<Id>> {
    let count = usize::try_from(reader.u32()?).map_err(|_| {
        Error::new(
            ChurStatus::ResourceLimitExceeded,
            "removed-token count does not fit this platform",
        )
    })?;
    ensure!(
        count <= TOKEN_COUNT_MAX,
        ResourceLimitExceeded,
        "removed-token count exceeds the protocol limit"
    );
    let mut tokens = Vec::with_capacity(count);
    for _ in 0..count {
        tokens.push(reader.id()?);
    }
    validate_tokens(&tokens)?;
    Ok(tokens)
}

const _: () = assert!(envelope_bounds::OBJECT_KEY_ENVELOPE_LEN == 142);
const _: () = assert!(envelope_bounds::COLLECTION_KEY_ENVELOPE_LEN == 126);
const _: () = assert!(CollectionMembershipRecord::LEN == 292);
const _: () = assert!(CollectionGrant::LEN == 309);

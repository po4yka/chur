//! `VaultDescriptorV1`, the small pre-unlock structure.
//!
//! `docs/format/VAULT_DESCRIPTOR_V1.md` freezes a 40-byte public head, a body
//! of sub-descriptors, and a trailing 32-byte keyed authenticator. The
//! descriptor identifies a vault format, lists bounded key-slot descriptors,
//! locates encrypted catalog and object state, and records transaction and
//! migration generation. It contains no private user metadata.
//!
//! The verification order of §8 is what this module enforces: parse and bound
//! the body before any credential is used, then unwrap a candidate root, then
//! derive the authentication key, recompute the tag, and compare in constant
//! time. A mismatch is `AUTHENTICATION_FAILED` and never `VAULT_CORRUPT`,
//! because a damaged descriptor and a wrong credential must share one external
//! failure.

use chur_core::limits::{COMMITMENT_LEN, ID_LEN, descriptor as bounds, slot as slot_bounds};
use chur_core::status::ChurStatus;
use chur_core::{Error, Id, Result, ensure};
use chur_crypto::commit::{self, Commitment};
use chur_crypto::kdf::{self, Context, Label};
use chur_crypto::secret::{Key, constant_time_eq};
use chur_crypto::tuple::tag;

use crate::codec::{Reader, Writer};
use crate::constants::{
    CATALOG_FORMAT_VERSION_V1, CATALOG_FORMAT_VERSION_V2, CATALOG_FORMAT_VERSION_V3,
    CATALOG_FORMAT_VERSION_V4, CATALOG_FORMAT_VERSION_V5, CATALOG_FORMAT_VERSION_V6,
    CATALOG_FORMAT_VERSION_V7, CATALOG_FORMAT_VERSION_V8, CATALOG_FORMAT_VERSION_V9,
    CATALOG_FORMAT_VERSION_V10, CATALOG_FORMAT_VERSION_V11, CATALOG_FORMAT_VERSION_V12,
    CATALOG_FORMAT_VERSION_V13, CATALOG_FORMAT_VERSION_V14, CATALOG_FORMAT_VERSION_V15,
    CATALOG_FORMAT_VERSION_V16, CATALOG_FORMAT_VERSION_V17, CATALOG_FORMAT_VERSION_V18,
    CATALOG_FORMAT_VERSION_V19, CONTAINER_VERSION_V1, CONTAINER_VERSION_V2, CRYPTO_POLICY_V1,
    DESCRIPTOR_VERSION_V1, ENCODING_PROFILE_V1, FLAGS_V1, MAGIC_VAULT, NAMING_PROFILE_V1,
    OBJECT_STORE_FORMAT_VERSION_V1, SLOT_VERSION_V1, SUITE_V1, SlotType, VaultState,
};
use crate::slot::{SlotBinding, WRAP_SUITE_ANDROID_KEYSTORE, WRAP_SUITE_RUST};

/// The status a structural descriptor failure carries.
///
/// Steps 1 and 2 of §8 run before any credential is used and keep their own
/// parser error codes, so a malformed descriptor is not reported as an
/// authentication result.
const STRUCTURAL: ChurStatus = ChurStatus::VaultCorrupt;

/// An identifier read from a descriptor.
///
/// [`Id::new`] reports the reserved all-zero value as `INVALID_INPUT`, the
/// status of a bad caller argument. Inside a descriptor the value is a
/// malformed field, so the parser reports it as `VAULT_CORRUPT`.
fn descriptor_id(bytes: [u8; ID_LEN]) -> Result<Id> {
    Id::new(bytes).map_err(|_| {
        Error::new(
            STRUCTURAL,
            "the descriptor carries the reserved all-zero identifier",
        )
    })
}

/// The catalog sub-descriptor of §5: exactly 60 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogDescriptor {
    /// Physical private-catalog schema version.
    pub catalog_format_version: u16,
    /// Random opaque identifier of the catalog file.
    pub opaque_catalog_path_id: Id,
    /// Catalog transaction generation.
    pub catalog_generation: u64,
    /// BLAKE3-256 commitment over the catalog header.
    pub catalog_header_commitment: Commitment,
}

impl CatalogDescriptor {
    /// Exact encoded length.
    pub const LEN: usize = bounds::CATALOG_DESCRIPTOR_LEN;

    fn write(&self, writer: &mut Writer) {
        writer
            .u16(self.catalog_format_version)
            .u16(SUITE_V1)
            .id(&self.opaque_catalog_path_id)
            .u64(self.catalog_generation)
            .fixed(&self.catalog_header_commitment);
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let catalog_format_version = reader.u16()?;
        ensure!(
            matches!(
                catalog_format_version,
                CATALOG_FORMAT_VERSION_V1
                    | CATALOG_FORMAT_VERSION_V2
                    | CATALOG_FORMAT_VERSION_V3
                    | CATALOG_FORMAT_VERSION_V4
                    | CATALOG_FORMAT_VERSION_V5
                    | CATALOG_FORMAT_VERSION_V6
                    | CATALOG_FORMAT_VERSION_V7
                    | CATALOG_FORMAT_VERSION_V8
                    | CATALOG_FORMAT_VERSION_V9
                    | CATALOG_FORMAT_VERSION_V10
                    | CATALOG_FORMAT_VERSION_V11
                    | CATALOG_FORMAT_VERSION_V12
                    | CATALOG_FORMAT_VERSION_V13
                    | CATALOG_FORMAT_VERSION_V14
                    | CATALOG_FORMAT_VERSION_V15
                    | CATALOG_FORMAT_VERSION_V16
                    | CATALOG_FORMAT_VERSION_V17
                    | CATALOG_FORMAT_VERSION_V18
                    | CATALOG_FORMAT_VERSION_V19
            ),
            UnsupportedVersion,
            "catalog format version is not supported"
        );
        ensure!(
            reader.u16()? == SUITE_V1,
            UnsupportedSuite,
            "catalog crypto suite is not supported"
        );
        Ok(Self {
            catalog_format_version,
            opaque_catalog_path_id: descriptor_id(reader.fixed()?)?,
            catalog_generation: reader.u64()?,
            catalog_header_commitment: reader.fixed::<COMMITMENT_LEN>()?,
        })
    }
}

/// The object-store sub-descriptor of §6: exactly 24 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectStoreDescriptor {
    /// Random opaque identifier of the object-store root.
    pub opaque_root_path_id: Id,
    /// Lowest container version this store holds.
    pub container_version_floor: u16,
    /// Highest container version this store holds.
    pub container_version_ceiling: u16,
}

impl ObjectStoreDescriptor {
    /// Exact encoded length.
    pub const LEN: usize = bounds::OBJECT_STORE_DESCRIPTOR_LEN;

    /// A store that holds only v1 containers.
    #[must_use]
    pub const fn v1(opaque_root_path_id: Id) -> Self {
        Self {
            opaque_root_path_id,
            container_version_floor: CONTAINER_VERSION_V1,
            container_version_ceiling: CONTAINER_VERSION_V1,
        }
    }

    /// A new store, whose writers produce the bucket-padded v2 containers of
    /// ADR-0066.
    #[must_use]
    pub const fn current(opaque_root_path_id: Id) -> Self {
        Self {
            opaque_root_path_id,
            container_version_floor: CONTAINER_VERSION_V1,
            container_version_ceiling: CONTAINER_VERSION_V2,
        }
    }

    fn write(&self, writer: &mut Writer) {
        writer
            .u16(OBJECT_STORE_FORMAT_VERSION_V1)
            .id(&self.opaque_root_path_id)
            .u16(NAMING_PROFILE_V1)
            .u16(self.container_version_floor)
            .u16(self.container_version_ceiling);
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        ensure!(
            reader.u16()? == OBJECT_STORE_FORMAT_VERSION_V1,
            UnsupportedVersion,
            "object store format version is not supported"
        );
        let opaque_root_path_id = descriptor_id(reader.fixed()?)?;
        ensure!(
            reader.u16()? == NAMING_PROFILE_V1,
            UnsupportedVersion,
            "object store naming profile is not supported"
        );
        let container_version_floor = reader.u16()?;
        let container_version_ceiling = reader.u16()?;
        ensure!(
            container_version_floor <= container_version_ceiling,
            VaultCorrupt,
            "container version floor exceeds the ceiling"
        );
        ensure!(
            container_version_floor == CONTAINER_VERSION_V1
                && (container_version_ceiling == CONTAINER_VERSION_V1
                    || container_version_ceiling == CONTAINER_VERSION_V2),
            UnsupportedVersion,
            "container version range is not supported"
        );
        Ok(Self {
            opaque_root_path_id,
            container_version_floor,
            container_version_ceiling,
        })
    }
}

/// `MigrationDescriptorV1` of §2.2: exactly 32 bytes when present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationDescriptor {
    /// Descriptor version the migration starts from.
    pub from_descriptor_version: u16,
    /// Descriptor version the migration targets.
    pub to_descriptor_version: u16,
    /// Catalog format version the migration starts from.
    pub from_catalog_format_version: u16,
    /// Catalog format version the migration targets.
    pub to_catalog_format_version: u16,
    /// Migration generation.
    pub migration_generation: u64,
    /// Opaque checkpoint identifier.
    pub checkpoint_id: Id,
}

impl MigrationDescriptor {
    /// Exact encoded length.
    pub const LEN: usize = bounds::MIGRATION_DESCRIPTOR_LEN;

    fn write(&self, writer: &mut Writer) {
        writer
            .u16(self.from_descriptor_version)
            .u16(self.to_descriptor_version)
            .u16(self.from_catalog_format_version)
            .u16(self.to_catalog_format_version)
            .u64(self.migration_generation)
            .id(&self.checkpoint_id);
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            from_descriptor_version: reader.u16()?,
            to_descriptor_version: reader.u16()?,
            from_catalog_format_version: reader.u16()?,
            to_catalog_format_version: reader.u16()?,
            migration_generation: reader.u64()?,
            checkpoint_id: descriptor_id(reader.fixed()?)?,
        })
    }
}

/// One `KeySlotDescriptorV1`: a fixed 34-byte header and one length-prefixed
/// body whose schema `slot_type` selects, §7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySlotDescriptor {
    /// Random slot identity.
    pub slot_id: Id,
    /// The slot family.
    pub slot_type: SlotType,
    /// The slot format version.
    pub slot_version: u16,
    /// The wrapping suite of this family.
    pub wrap_suite_id: u16,
    /// The generation of this slot.
    pub slot_generation: u64,
    /// The family body, owned by `docs/format/KEY_SLOT_BODIES_V1.md`.
    pub slot_body: Vec<u8>,
}

impl KeySlotDescriptor {
    /// Exact encoded length of the header.
    pub const HEADER_LEN: usize = bounds::SLOT_HEADER_LEN;

    /// Builds a v1 descriptor entry with the version and suite its family takes.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::ResourceLimitExceeded`] when the body is outside
    /// the 16 to 4096 range.
    pub fn v1(
        slot_id: Id,
        slot_type: SlotType,
        slot_generation: u64,
        slot_body: Vec<u8>,
    ) -> Result<Self> {
        let entry = Self {
            slot_id,
            slot_type,
            slot_version: SLOT_VERSION_V1,
            wrap_suite_id: match slot_type {
                SlotType::AndroidKeystore => WRAP_SUITE_ANDROID_KEYSTORE,
                _ => WRAP_SUITE_RUST,
            },
            slot_generation,
            slot_body,
        };
        entry.check()?;
        Ok(entry)
    }

    /// The six binding elements this entry contributes to its family AAD.
    #[must_use]
    pub const fn binding(&self, vault_id: Id) -> SlotBinding {
        SlotBinding {
            vault_id,
            slot_id: self.slot_id,
            slot_type: self.slot_type,
            slot_version: self.slot_version,
            wrap_suite_id: self.wrap_suite_id,
            slot_generation: self.slot_generation,
        }
    }

    /// The encoded length of this entry.
    #[must_use]
    pub fn len(&self) -> usize {
        Self::HEADER_LEN + self.slot_body.len()
    }

    /// Always false: an entry always carries a header.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    fn check(&self) -> Result<()> {
        let length = u32::try_from(self.slot_body.len()).unwrap_or(u32::MAX);
        ensure!(
            (slot_bounds::BODY_MIN..=slot_bounds::BODY_MAX).contains(&length),
            ResourceLimitExceeded,
            "slot body length is outside the v1 bounds"
        );
        // The vault identity is not a descriptor-entry field, so the shared
        // check runs over the five fields the entry does carry.
        check_slot_family(
            self.slot_type,
            self.slot_version,
            self.wrap_suite_id,
            self.slot_generation,
        )
    }

    fn write(&self, writer: &mut Writer) {
        writer
            .id(&self.slot_id)
            .u8(self.slot_type.value())
            .u8(0x00)
            .u16(self.slot_version)
            .u16(self.wrap_suite_id)
            .u64(self.slot_generation)
            .u32(self.slot_body.len() as u32)
            .fixed(&self.slot_body);
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let slot_id = descriptor_id(reader.fixed()?)?;
        let slot_type = SlotType::from_value(reader.u8()?)
            .ok_or_else(|| Error::new(STRUCTURAL, "slot type is unallocated"))?;
        ensure!(
            reader.u8()? == 0x00,
            VaultCorrupt,
            "key-slot descriptor reserved byte is not zero"
        );
        let slot_version = reader.u16()?;
        let wrap_suite_id = reader.u16()?;
        let slot_generation = reader.u64()?;
        let slot_body = reader.variable(slot_bounds::BODY_MAX)?.to_vec();
        let entry = Self {
            slot_id,
            slot_type,
            slot_version,
            wrap_suite_id,
            slot_generation,
            slot_body,
        };
        entry.check()?;
        Ok(entry)
    }
}

/// `VaultDescriptorV1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultDescriptor {
    /// Random vault identity.
    pub vault_id: Id,
    /// Strictly increasing local descriptor generation.
    pub descriptor_generation: u64,
    /// Transaction state.
    pub state: VaultState,
    /// The catalog sub-descriptor.
    pub catalog: CatalogDescriptor,
    /// The object-store sub-descriptor.
    pub object_store: ObjectStoreDescriptor,
    /// Bounded key-slot descriptors, 1 to 16 entries.
    pub key_slots: Vec<KeySlotDescriptor>,
    /// Present exactly when `state` is `MIGRATING` or `RECOVERING`.
    pub migration: Option<MigrationDescriptor>,
}

/// Checks the version, the family-to-suite pairing, and the generation of one
/// key-slot descriptor entry.
fn check_slot_family(
    slot_type: SlotType,
    slot_version: u16,
    wrap_suite_id: u16,
    slot_generation: u64,
) -> Result<()> {
    ensure!(
        slot_version == SLOT_VERSION_V1,
        UnsupportedVersion,
        "slot version is not supported"
    );
    let expected = match slot_type {
        SlotType::AndroidKeystore => WRAP_SUITE_ANDROID_KEYSTORE,
        _ => WRAP_SUITE_RUST,
    };
    ensure!(
        wrap_suite_id == expected,
        UnsupportedSuite,
        "slot family and wrap suite are not a permitted pairing"
    );
    ensure!(
        slot_generation != u64::MAX,
        VaultCorrupt,
        "slot generation has no successor"
    );
    Ok(())
}

/// Derives `DescriptorAuthKey` for one vault.
///
/// The key is stable for the life of the root secret. A new descriptor
/// generation reuses it and does not derive a new one.
///
/// # Errors
///
/// Returns an error only if the derivation itself fails.
pub fn descriptor_auth_key(root: &Key, vault_id: &Id) -> Result<Key> {
    kdf::derive_from(root, Label::RootDescriptorAuth, &Context::vault(vault_id))
}

/// Computes the §8 authenticator over a descriptor body.
#[must_use]
pub fn descriptor_auth_tag(auth_key: &Key, descriptor_body: &[u8]) -> Commitment {
    commit::keyed_commit(auth_key, tag::VAULT_DESCRIPTOR_AUTH, descriptor_body)
}

impl VaultDescriptor {
    /// Encodes the descriptor and appends its authentication tag.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::VaultCorrupt`] when the value violates a §2 or §13
    /// rule, and [`ChurStatus::ResourceLimitExceeded`] when a bound is exceeded.
    pub fn encode(&self, root: &Key) -> Result<Vec<u8>> {
        self.check()?;
        let mut body = Writer::with_capacity(512);
        body.u64(self.descriptor_generation).u8(self.state.value());
        self.catalog.write(&mut body);
        self.object_store.write(&mut body);
        body.u32(self.key_slots.len() as u32);
        for entry in &self.key_slots {
            entry.write(&mut body);
        }
        match &self.migration {
            Some(migration) => {
                body.presence(true);
                migration.write(&mut body);
            }
            None => {
                body.presence(false);
            }
        }
        let body = body.finish();

        let descriptor_length = u32::try_from(bounds::HEAD_LEN + body.len() + bounds::AUTH_TAG_LEN)
            .map_err(|_| Error::new(ChurStatus::ResourceLimitExceeded, "descriptor exceeds u32"))?;
        ensure!(
            (bounds::LENGTH_MIN..=bounds::LENGTH_MAX).contains(&descriptor_length),
            ResourceLimitExceeded,
            "descriptor length is outside the v1 bounds"
        );

        let mut out = Writer::with_capacity(descriptor_length as usize);
        out.fixed(&MAGIC_VAULT)
            .u16(DESCRIPTOR_VERSION_V1)
            .u16(ENCODING_PROFILE_V1)
            .u16(CRYPTO_POLICY_V1)
            .u16(FLAGS_V1)
            .u32(bounds::HEAD_LEN as u32)
            .u32(descriptor_length)
            .id(&self.vault_id)
            .fixed(&body);
        debug_assert_eq!(out.len(), descriptor_length as usize - bounds::AUTH_TAG_LEN);

        let auth_key = descriptor_auth_key(root, &self.vault_id)?;
        let auth_tag = descriptor_auth_tag(&auth_key, out.as_slice());
        out.fixed(&auth_tag);
        Ok(out.finish())
    }

    /// Parses and bounds a descriptor with no credential.
    ///
    /// This is steps 1 and 2 of §8. Nothing here inspects the authentication
    /// tag, so a caller can enumerate a registry before any password exists.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::VaultCorrupt`] for a malformed descriptor,
    /// including a reserved all-zero identifier, `UNSUPPORTED_*` for an
    /// unknown version, profile, policy, or suite identifier, and
    /// [`ChurStatus::ResourceLimitExceeded`] for a §13 bound violation.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= bounds::LENGTH_MIN as usize,
            VaultCorrupt,
            "descriptor is shorter than the smallest v1 descriptor"
        );
        ensure!(
            bytes.len() <= bounds::LENGTH_MAX as usize,
            ResourceLimitExceeded,
            "descriptor exceeds the v1 maximum length"
        );
        let mut reader = Reader::new(bytes, STRUCTURAL);
        reader.constant(&MAGIC_VAULT, STRUCTURAL, "wrong vault descriptor magic")?;
        ensure!(
            reader.u16()? == DESCRIPTOR_VERSION_V1,
            UnsupportedVersion,
            "descriptor version is not supported"
        );
        ensure!(
            reader.u16()? == ENCODING_PROFILE_V1,
            UnsupportedVersion,
            "descriptor encoding profile is not supported"
        );
        ensure!(
            reader.u16()? == CRYPTO_POLICY_V1,
            UnsupportedVersion,
            "descriptor crypto policy is not supported"
        );
        ensure!(
            reader.u16()? == FLAGS_V1,
            VaultCorrupt,
            "descriptor flags are not the v1 value"
        );
        ensure!(
            reader.u32()? == bounds::HEAD_LEN as u32,
            VaultCorrupt,
            "descriptor public header length is not 40"
        );
        let descriptor_length = reader.u32()?;
        ensure!(
            descriptor_length as usize == bytes.len(),
            VaultCorrupt,
            "declared descriptor length does not match the encoded bytes"
        );
        let vault_id = descriptor_id(reader.fixed()?)?;

        let descriptor_generation = reader.u64()?;
        ensure!(
            descriptor_generation != u64::MAX,
            VaultCorrupt,
            "descriptor generation has no successor"
        );
        let state = VaultState::from_value(reader.u8()?)
            .ok_or_else(|| Error::new(STRUCTURAL, "descriptor state is unallocated"))?;
        let catalog = CatalogDescriptor::read(&mut reader)?;
        let object_store = ObjectStoreDescriptor::read(&mut reader)?;

        let slot_count = reader.u32()?;
        ensure!(
            (bounds::SLOT_COUNT_MIN..=bounds::SLOT_COUNT_MAX).contains(&slot_count),
            ResourceLimitExceeded,
            "key-slot count is outside the v1 bounds"
        );
        let mut key_slots = Vec::with_capacity(slot_count as usize);
        for _ in 0..slot_count {
            key_slots.push(KeySlotDescriptor::read(&mut reader)?);
        }

        let migration = if reader.presence()? {
            Some(MigrationDescriptor::read(&mut reader)?)
        } else {
            None
        };

        // The tag is verified in §8 step 5, not here. Reading it advances the
        // cursor so `finish` proves that nothing follows it.
        reader.fixed::<COMMITMENT_LEN>()?;
        reader
            .finish()
            .map_err(|_| Error::new(STRUCTURAL, "descriptor carries bytes after its tag"))?;

        let descriptor = Self {
            vault_id,
            descriptor_generation,
            state,
            catalog,
            object_store,
            key_slots,
            migration,
        };
        descriptor.check()?;
        Ok(descriptor)
    }

    /// The §2 and §13 rules that do not depend on the encoded length.
    fn check(&self) -> Result<()> {
        ensure!(
            self.descriptor_generation != u64::MAX,
            VaultCorrupt,
            "descriptor generation has no successor"
        );
        ensure!(
            self.catalog.catalog_generation != u64::MAX,
            VaultCorrupt,
            "catalog generation has no successor"
        );
        ensure!(
            matches!(
                self.catalog.catalog_format_version,
                CATALOG_FORMAT_VERSION_V1
                    | CATALOG_FORMAT_VERSION_V2
                    | CATALOG_FORMAT_VERSION_V3
                    | CATALOG_FORMAT_VERSION_V4
                    | CATALOG_FORMAT_VERSION_V5
                    | CATALOG_FORMAT_VERSION_V6
                    | CATALOG_FORMAT_VERSION_V7
                    | CATALOG_FORMAT_VERSION_V8
                    | CATALOG_FORMAT_VERSION_V9
                    | CATALOG_FORMAT_VERSION_V10
                    | CATALOG_FORMAT_VERSION_V11
                    | CATALOG_FORMAT_VERSION_V12
                    | CATALOG_FORMAT_VERSION_V13
                    | CATALOG_FORMAT_VERSION_V14
                    | CATALOG_FORMAT_VERSION_V15
                    | CATALOG_FORMAT_VERSION_V16
                    | CATALOG_FORMAT_VERSION_V17
                    | CATALOG_FORMAT_VERSION_V18
                    | CATALOG_FORMAT_VERSION_V19
            ),
            UnsupportedVersion,
            "catalog format version is not supported"
        );
        let count = u32::try_from(self.key_slots.len()).unwrap_or(u32::MAX);
        ensure!(
            (bounds::SLOT_COUNT_MIN..=bounds::SLOT_COUNT_MAX).contains(&count),
            ResourceLimitExceeded,
            "key-slot count is outside the v1 bounds"
        );
        let migration_expected =
            matches!(self.state, VaultState::Migrating | VaultState::Recovering);
        ensure!(
            self.migration.is_some() == migration_expected,
            VaultCorrupt,
            "migration descriptor is not present exactly for MIGRATING or RECOVERING"
        );
        if let Some(migration) = &self.migration {
            ensure!(
                migration.migration_generation != u64::MAX,
                VaultCorrupt,
                "migration generation has no successor"
            );
        }

        let mut total_body = 0u32;
        let mut password_identities = 0usize;
        for (index, entry) in self.key_slots.iter().enumerate() {
            entry.check()?;
            total_body = total_body
                .checked_add(entry.slot_body.len() as u32)
                .ok_or_else(|| {
                    Error::new(
                        ChurStatus::ResourceLimitExceeded,
                        "total slot body length overflows",
                    )
                })?;
            for other in self.key_slots.iter().take(index) {
                ensure!(
                    other.slot_id != entry.slot_id,
                    VaultCorrupt,
                    "two key-slot descriptors share one slot identity"
                );
            }
            if entry.slot_type == SlotType::Password {
                password_identities += 1;
            }
        }
        ensure!(
            total_body <= slot_bounds::BODY_TOTAL_MAX,
            ResourceLimitExceeded,
            "total slot body length exceeds the v1 maximum"
        );
        ensure!(
            password_identities <= slot_bounds::MAX_PASSWORD_SLOT_IDENTITIES,
            ResourceLimitExceeded,
            "descriptor offers more than one password-slot identity"
        );
        Ok(())
    }

    /// Verifies the §8 authenticator under a candidate root, in constant time.
    ///
    /// The comparison covers all 32 bytes and never returns early, so its
    /// duration does not reveal how many leading bytes of a forged tag matched.
    ///
    /// # Errors
    ///
    /// Returns the structural errors of [`VaultDescriptor::parse`].
    pub fn verify(bytes: &[u8], candidate_root: &Key) -> Result<bool> {
        let descriptor = Self::parse(bytes)?;
        let split = bytes.len() - bounds::AUTH_TAG_LEN;
        let auth_key = descriptor_auth_key(candidate_root, &descriptor.vault_id)?;
        let recomputed = descriptor_auth_tag(&auth_key, &bytes[..split]);
        Ok(constant_time_eq(&recomputed, &bytes[split..]))
    }

    /// Performs the §8 authentication work whatever the slot unwrap produced.
    ///
    /// When `candidate_root` is `None`, a failed slot unwrap has already
    /// happened; the same derivation and tag computation still run over a
    /// random substitute root and the result is discarded, so an invalid
    /// credential and a credential valid for a sibling vault cost the same work
    /// and return the same error.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::AuthenticationFailed`] when the tag does not
    /// match, whatever the cause, and the structural errors of
    /// [`VaultDescriptor::parse`] only for a descriptor that failed steps 1 and
    /// 2 before any credential was used.
    pub fn authenticate(bytes: &[u8], candidate_root: Option<&Key>) -> Result<VaultDescriptor> {
        let descriptor = Self::parse(bytes)?;
        let substitute;
        let candidate = match candidate_root {
            Some(root) => root,
            None => {
                substitute = chur_crypto::random::secret::<32>()?;
                &substitute
            }
        };
        let split = bytes.len() - bounds::AUTH_TAG_LEN;
        let auth_key = descriptor_auth_key(candidate, &descriptor.vault_id)?;
        let recomputed = descriptor_auth_tag(&auth_key, &bytes[..split]);
        let matched = constant_time_eq(&recomputed, &bytes[split..]) && candidate_root.is_some();
        if matched {
            Ok(descriptor)
        } else {
            Err(Error::new(
                ChurStatus::AuthenticationFailed,
                "no candidate root authenticated this vault descriptor",
            ))
        }
    }

    /// The highest-generation password slot, the candidate of `KEY_SLOTS.md` §8.
    #[must_use]
    pub fn password_slot(&self) -> Option<&KeySlotDescriptor> {
        self.key_slots
            .iter()
            .filter(|entry| entry.slot_type == SlotType::Password)
            .max_by_key(|entry| entry.slot_generation)
    }
}

const _: () = assert!(CatalogDescriptor::LEN == 2 + 2 + ID_LEN + 8 + COMMITMENT_LEN);
const _: () = assert!(ObjectStoreDescriptor::LEN == 2 + ID_LEN + 2 + 2 + 2);
const _: () = assert!(MigrationDescriptor::LEN == 2 + 2 + 2 + 2 + 8 + ID_LEN);
const _: () = assert!(KeySlotDescriptor::HEADER_LEN == ID_LEN + 1 + 1 + 2 + 2 + 8 + 4);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use super::*;

    fn id(byte: u8) -> Id {
        Id::new([byte; ID_LEN]).unwrap()
    }

    fn root() -> Key {
        Key::new([0x0f; 32])
    }

    fn minimal() -> VaultDescriptor {
        VaultDescriptor {
            vault_id: id(0x01),
            descriptor_generation: 1,
            state: VaultState::Active,
            catalog: CatalogDescriptor {
                catalog_format_version: CATALOG_FORMAT_VERSION_V1,
                opaque_catalog_path_id: id(0x02),
                catalog_generation: 1,
                catalog_header_commitment: [0x03; COMMITMENT_LEN],
            },
            object_store: ObjectStoreDescriptor::v1(id(0x04)),
            key_slots: vec![
                KeySlotDescriptor::v1(id(0x05), SlotType::Password, 1, vec![0xaa; 16]).unwrap(),
            ],
            migration: None,
        }
    }

    #[test]
    fn the_smallest_descriptor_is_220_bytes() {
        let encoded = minimal().encode(&root()).unwrap();
        assert_eq!(encoded.len(), bounds::LENGTH_MIN as usize);
        assert_eq!(encoded.len(), 220);
    }

    #[test]
    fn the_head_holds_the_documented_bytes() {
        let encoded = minimal().encode(&root()).unwrap();
        assert_eq!(&encoded[0x00..0x08], b"CHURVLT1");
        assert_eq!(&encoded[0x08..0x0a], &[0, 1]);
        assert_eq!(&encoded[0x0a..0x0c], &[0, 1]);
        assert_eq!(&encoded[0x0c..0x0e], &[0, 1]);
        assert_eq!(&encoded[0x0e..0x10], &[0, 0]);
        assert_eq!(&encoded[0x10..0x14], &40u32.to_be_bytes());
        assert_eq!(&encoded[0x14..0x18], &220u32.to_be_bytes());
        assert_eq!(&encoded[0x18..0x28], &[0x01; 16]);
    }

    #[test]
    fn a_descriptor_round_trips_and_authenticates() {
        let descriptor = minimal();
        let encoded = descriptor.encode(&root()).unwrap();
        assert_eq!(VaultDescriptor::parse(&encoded).unwrap(), descriptor);
        assert!(VaultDescriptor::verify(&encoded, &root()).unwrap());
        assert_eq!(
            VaultDescriptor::authenticate(&encoded, Some(&root())).unwrap(),
            descriptor
        );
    }

    #[test]
    fn the_v1_descriptor_carries_supported_catalog_versions() {
        let mut descriptor = minimal();
        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V2;
        let encoded = descriptor.encode(&root()).expect("catalog v2 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);

        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V3;
        let encoded = descriptor.encode(&root()).expect("catalog v3 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);

        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V4;
        let encoded = descriptor.encode(&root()).expect("catalog v4 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);

        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V5;
        let encoded = descriptor.encode(&root()).expect("catalog v5 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);

        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V6;
        let encoded = descriptor.encode(&root()).expect("catalog v6 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);

        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V7;
        let encoded = descriptor.encode(&root()).expect("catalog v7 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);

        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V8;
        let encoded = descriptor.encode(&root()).expect("catalog v8 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);

        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V9;
        let encoded = descriptor.encode(&root()).expect("catalog v9 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);

        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V10;
        let encoded = descriptor.encode(&root()).expect("catalog v10 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);

        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V11;
        let encoded = descriptor.encode(&root()).expect("catalog v11 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);

        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V12;
        let encoded = descriptor.encode(&root()).expect("catalog v12 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);

        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V13;
        let encoded = descriptor.encode(&root()).expect("catalog v13 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);

        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V14;
        let encoded = descriptor.encode(&root()).expect("catalog v14 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);
        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V15;
        let encoded = descriptor.encode(&root()).expect("catalog v15 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);
        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V16;
        let encoded = descriptor.encode(&root()).expect("catalog v16 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);
        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V17;
        let encoded = descriptor.encode(&root()).expect("catalog v17 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);
        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V18;
        let encoded = descriptor.encode(&root()).expect("catalog v18 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);
        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V19;
        let encoded = descriptor.encode(&root()).expect("catalog v19 descriptor");
        assert_eq!(VaultDescriptor::parse(&encoded).expect("parse"), descriptor);
        descriptor.catalog.catalog_format_version = 20;
        assert_eq!(
            descriptor
                .encode(&root())
                .expect_err("catalog v20")
                .status(),
            ChurStatus::UnsupportedVersion
        );
    }

    #[test]
    fn a_wrong_root_fails_as_authentication_and_never_as_corruption() {
        let encoded = minimal().encode(&root()).unwrap();
        assert!(!VaultDescriptor::verify(&encoded, &Key::new([0x10; 32])).unwrap());
        let Err(error) = VaultDescriptor::authenticate(&encoded, Some(&Key::new([0x10; 32])))
        else {
            panic!("a wrong root authenticated")
        };
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
    }

    #[test]
    fn a_failed_slot_unwrap_still_returns_the_authentication_failure() {
        let encoded = minimal().encode(&root()).unwrap();
        let Err(error) = VaultDescriptor::authenticate(&encoded, None) else {
            panic!("an absent candidate authenticated")
        };
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);
    }

    #[test]
    fn the_tag_covers_every_body_byte() {
        let encoded = minimal().encode(&root()).unwrap();
        for index in 0..encoded.len() - bounds::AUTH_TAG_LEN {
            let mut damaged = encoded.clone();
            damaged[index] ^= 0x01;
            let caught = match VaultDescriptor::verify(&damaged, &root()) {
                Ok(matched) => !matched,
                Err(_) => true,
            };
            assert!(
                caught,
                "a flipped bit at byte {index} did not change the outcome"
            );
        }
    }

    #[test]
    fn a_descriptor_bound_to_another_vault_does_not_authenticate() {
        let mut other = minimal();
        other.vault_id = id(0x09);
        let encoded = other.encode(&root()).unwrap();
        // The tag is over the encoded bytes, so the vault identity is inside it;
        // an identity swap after signing changes both the key and the input.
        let mut swapped = encoded.clone();
        swapped[0x18..0x28].copy_from_slice(&[0x01; 16]);
        assert!(!VaultDescriptor::verify(&swapped, &root()).unwrap());
    }

    #[test]
    fn a_wrong_declared_length_is_rejected_before_any_credential() {
        let mut encoded = minimal().encode(&root()).unwrap();
        encoded[0x17] = 0xdb;
        assert_eq!(
            VaultDescriptor::parse(&encoded).unwrap_err().status(),
            ChurStatus::VaultCorrupt
        );
    }

    #[test]
    fn an_unknown_identifier_fails_closed() {
        for (offset, expected) in [
            (0x09, ChurStatus::UnsupportedVersion),
            (0x0b, ChurStatus::UnsupportedVersion),
            (0x0d, ChurStatus::UnsupportedVersion),
        ] {
            let mut encoded = minimal().encode(&root()).unwrap();
            encoded[offset] = 0x02;
            assert_eq!(
                VaultDescriptor::parse(&encoded).unwrap_err().status(),
                expected,
                "offset {offset:#x}"
            );
        }
        let mut encoded = minimal().encode(&root()).unwrap();
        encoded[0x0f] = 0x01;
        assert_eq!(
            VaultDescriptor::parse(&encoded).unwrap_err().status(),
            ChurStatus::VaultCorrupt
        );
    }

    #[test]
    fn an_unallocated_state_or_slot_type_is_rejected() {
        let encoded = minimal().encode(&root()).unwrap();
        let mut damaged = encoded.clone();
        damaged[0x30] = 0x06;
        assert_eq!(
            VaultDescriptor::parse(&damaged).unwrap_err().status(),
            ChurStatus::VaultCorrupt
        );
        // slot_type sits 16 bytes into the first key-slot descriptor.
        let slot_type_offset = 0x28 + 8 + 1 + 60 + 24 + 4 + 16;
        let mut damaged = encoded;
        damaged[slot_type_offset] = 0x06;
        assert_eq!(
            VaultDescriptor::parse(&damaged).unwrap_err().status(),
            ChurStatus::VaultCorrupt
        );
    }

    #[test]
    fn a_migration_descriptor_is_present_exactly_for_two_states() {
        let mut descriptor = minimal();
        descriptor.state = VaultState::Migrating;
        assert!(descriptor.encode(&root()).is_err());
        descriptor.migration = Some(MigrationDescriptor {
            from_descriptor_version: 1,
            to_descriptor_version: 1,
            from_catalog_format_version: 1,
            to_catalog_format_version: 1,
            migration_generation: 1,
            checkpoint_id: id(0x0a),
        });
        let encoded = descriptor.encode(&root()).unwrap();
        assert_eq!(encoded.len(), 220 + 32);
        assert_eq!(VaultDescriptor::parse(&encoded).unwrap(), descriptor);

        descriptor.state = VaultState::Active;
        assert!(descriptor.encode(&root()).is_err());
    }

    /// `CANONICAL_ENCODING_V1.md` §8 reserves the all-zero identifier, and §2,
    /// §5, §6, and §7 repeat the rule here. The codec reports the reserved
    /// value as `INVALID_INPUT`, the status of a bad caller argument. Inside a
    /// descriptor it is a malformed field, and `parse` documents
    /// `VAULT_CORRUPT` for that.
    #[test]
    fn a_reserved_identifier_in_the_descriptor_is_vault_corrupt() {
        let mut descriptor = minimal();
        descriptor.state = VaultState::Migrating;
        descriptor.migration = Some(MigrationDescriptor {
            from_descriptor_version: 1,
            to_descriptor_version: 1,
            from_catalog_format_version: 1,
            to_catalog_format_version: 1,
            migration_generation: 1,
            checkpoint_id: id(0x0a),
        });
        let encoded = descriptor.encode(&root()).unwrap();
        // The vault, catalog path, object-store root, slot, and checkpoint
        // identifiers of `minimal` and the migration above.
        for byte in [0x01, 0x02, 0x04, 0x05, 0x0a] {
            let at = encoded
                .windows(ID_LEN)
                .position(|window| window == [byte; ID_LEN])
                .unwrap();
            let mut bytes = encoded.clone();
            bytes[at..at + ID_LEN].fill(0);
            assert_eq!(
                VaultDescriptor::parse(&bytes).unwrap_err().status(),
                ChurStatus::VaultCorrupt,
                "identifier {byte:#04x}"
            );
        }
    }

    #[test]
    fn a_generation_without_a_successor_is_rejected_in_every_generation_field() {
        // §13: `0xFFFFFFFFFFFFFFFF` is rejected in every generation field so an
        // increment always exists. `descriptor_generation` and
        // `slot_generation` were checked before; `catalog_generation` and
        // `migration_generation` complete the rule.
        let mut descriptor = minimal();
        descriptor.catalog.catalog_generation = u64::MAX;
        assert_eq!(
            descriptor.encode(&root()).unwrap_err().status(),
            ChurStatus::VaultCorrupt
        );

        let mut descriptor = minimal();
        descriptor.state = VaultState::Migrating;
        descriptor.migration = Some(MigrationDescriptor {
            from_descriptor_version: 1,
            to_descriptor_version: 1,
            from_catalog_format_version: 1,
            to_catalog_format_version: 1,
            migration_generation: u64::MAX,
            checkpoint_id: id(0x0a),
        });
        assert_eq!(
            descriptor.encode(&root()).unwrap_err().status(),
            ChurStatus::VaultCorrupt
        );

        // The parser applies the same rule to the wire bytes. `parse` does not
        // verify the tag, so flipping the field reaches the §13 check.
        let mut encoded = minimal().encode(&root()).unwrap();
        // catalog_generation sits after the 40-byte head, the descriptor
        // generation, the state byte, the catalog version and suite, and the
        // 16-byte catalog path id.
        let generation_offset = 0x28 + 8 + 1 + 2 + 2 + 16;
        encoded[generation_offset..generation_offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            VaultDescriptor::parse(&encoded).unwrap_err().status(),
            ChurStatus::VaultCorrupt
        );
    }

    #[test]
    fn duplicate_slot_identities_and_a_second_password_identity_are_rejected() {
        let mut descriptor = minimal();
        descriptor
            .key_slots
            .push(KeySlotDescriptor::v1(id(0x05), SlotType::Recovery, 1, vec![0xbb; 16]).unwrap());
        assert_eq!(
            descriptor.encode(&root()).unwrap_err().status(),
            ChurStatus::VaultCorrupt
        );

        let mut descriptor = minimal();
        descriptor
            .key_slots
            .push(KeySlotDescriptor::v1(id(0x06), SlotType::Password, 1, vec![0xbb; 16]).unwrap());
        assert_eq!(
            descriptor.encode(&root()).unwrap_err().status(),
            ChurStatus::ResourceLimitExceeded
        );
    }

    #[test]
    fn the_slot_count_and_body_bounds_hold() {
        let mut descriptor = minimal();
        descriptor.key_slots.clear();
        assert_eq!(
            descriptor.encode(&root()).unwrap_err().status(),
            ChurStatus::ResourceLimitExceeded
        );

        let mut descriptor = minimal();
        for index in 1..16u8 {
            descriptor.key_slots.push(
                KeySlotDescriptor::v1(id(0x10 + index), SlotType::Recovery, 1, vec![0xbb; 16])
                    .unwrap(),
            );
        }
        assert_eq!(descriptor.key_slots.len(), 16);
        assert!(descriptor.encode(&root()).is_ok());
        descriptor
            .key_slots
            .push(KeySlotDescriptor::v1(id(0x40), SlotType::Recovery, 1, vec![0xbb; 16]).unwrap());
        assert_eq!(
            descriptor.encode(&root()).unwrap_err().status(),
            ChurStatus::ResourceLimitExceeded
        );

        assert!(KeySlotDescriptor::v1(id(0x07), SlotType::Recovery, 1, vec![0; 15]).is_err());
        assert!(KeySlotDescriptor::v1(id(0x07), SlotType::Recovery, 1, vec![0; 4097]).is_err());
    }

    #[test]
    fn the_peer_device_family_parses_and_offers_no_unlock() {
        let mut descriptor = minimal();
        descriptor.key_slots.push(
            KeySlotDescriptor::v1(id(0x08), SlotType::PeerDevice, 1, vec![0xcc; 16]).unwrap(),
        );
        let encoded = descriptor.encode(&root()).unwrap();
        let parsed = VaultDescriptor::parse(&encoded).unwrap();
        assert_eq!(parsed.key_slots[1].slot_type, SlotType::PeerDevice);
        assert_eq!(parsed.password_slot().unwrap().slot_id, id(0x05));
    }

    #[test]
    fn the_password_candidate_is_the_highest_generation() {
        let mut descriptor = minimal();
        descriptor.key_slots[0].slot_generation = 3;
        assert_eq!(descriptor.password_slot().unwrap().slot_generation, 3);
    }

    #[test]
    fn truncation_at_every_boundary_is_rejected() {
        let encoded = minimal().encode(&root()).unwrap();
        for cut in 0..encoded.len() {
            assert!(
                VaultDescriptor::parse(&encoded[..cut]).is_err(),
                "cut {cut}"
            );
        }
        let mut extended = encoded;
        extended.push(0);
        assert!(VaultDescriptor::parse(&extended).is_err());
    }
}

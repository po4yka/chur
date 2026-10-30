//! Vault provisioning, unlock, and lock.
//!
//! `docs/security/PROVISIONING.md` §3 fixes the creation order,
//! `docs/format/VAULT_DESCRIPTOR_V1.md` §9 the byte-level transaction inside
//! it, `docs/security/KEY_SLOTS.md` §8 the unlock flow and its constant work,
//! and `docs/security/PLAINTEXT_LIFECYCLE.md` §8 the lock sequence.
//!
//! The session lives here because ADR-0004 ties it to the catalog: the catalog
//! key exists only in an unlocked session, and lock closes the database before
//! zeroizing the key. Nothing above this module ever holds a root secret.
//!
//! Native sessions require Unix file-identity validation. Other targets return
//! `IoFailure` before a credential slot can be opened.

use chur_core::limits::{GCM_NONCE_LEN, WRAPPED_KEY_LEN};
use chur_core::{ChurStatus, Error, Id, Result, bail, ensure};
use chur_crypto::{
    Key, Nonce, commit,
    password::{self, Argon2Params},
    random, recovery,
};
use chur_format::constants::{
    CATALOG_FORMAT_VERSION_V1, CATALOG_FORMAT_VERSION_V2, CATALOG_FORMAT_VERSION_V3,
    CATALOG_FORMAT_VERSION_V4, CATALOG_FORMAT_VERSION_V5, CATALOG_FORMAT_VERSION_V6,
    CATALOG_FORMAT_VERSION_V7, CATALOG_FORMAT_VERSION_V8, CATALOG_FORMAT_VERSION_V9,
    CATALOG_FORMAT_VERSION_V10, CATALOG_FORMAT_VERSION_V11, CATALOG_FORMAT_VERSION_V12,
    CATALOG_FORMAT_VERSION_V13, CATALOG_FORMAT_VERSION_V14, CATALOG_FORMAT_VERSION_V15,
    CATALOG_FORMAT_VERSION_V16, CATALOG_FORMAT_VERSION_V17, DESCRIPTOR_VERSION_V1, SlotType,
    VaultState,
};
use chur_format::descriptor::{
    CatalogDescriptor, KeySlotDescriptor, MigrationDescriptor, ObjectStoreDescriptor,
    VaultDescriptor,
};
use chur_format::slot::{
    AndroidKeystoreSlotBody, AppleKeychainSlotBody, PasswordSlotBody, RecoverySlotBody, SlotBinding,
};

use crate::db::{CatalogDb, CatalogKey, CatalogLocation};
use crate::paths::{DirectoryClaim, RegistryName, VaultRoot};
use crate::schema;

/// The salt length a v1 writer produces, `KEY_SLOT_BODIES_V1.md` §8.
const SALT_LEN: usize = 16;

/// The alias length a v1 enrollment generates.
///
/// `KEY_SLOTS.md` §4 requires an opaque alias that reveals no identity, and
/// `chur-core::limits::slot` bounds it to 16 to 64 bytes. Thirty-two is inside
/// that range with room on both sides and is the width every other opaque
/// identifier in the descriptor uses.
const KEYSTORE_ALIAS_LEN: usize = 32;

/// The number of Argon2id derivations one password attempt runs, §8.
///
/// It is a constant and not a candidate count. A list shorter than two is
/// padded with dummy candidates, so an attempt costs the same whether it
/// succeeds, fails, or matches a sibling identity.
const PASSWORD_DERIVATIONS: usize = 2;

/// A vault being created, `docs/security/PROVISIONING.md` §3.
///
/// The type exists because the flow has a middle: the recovery slot is offered
/// at step 5, after the password slot is verified at step 4 and before the
/// descriptor reaches `ACTIVE` at step 6. A single `create` function would have
/// to either skip the offer or take a callback, and both hide the ordering the
/// specification fixes.
///
/// Dropping it without [`VaultCreation::activate`] leaves the temporary
/// descriptor and the vault directory, which [`VaultCreation::abandon`] removes, and which
/// [`VaultRoot::sweep_temporary`] and [`sweep_orphaned_directories`] remove at
/// the next start. Nothing openable exists in the meantime, because §11
/// enumerates only installed `.vd` entries.
pub struct VaultCreation {
    root_dir: VaultRoot,
    root_secret: Key,
    descriptor: VaultDescriptor,
    entry_name: RegistryName,
    catalog: CatalogDb,
    /// The claim on the vault directory, held for the life of the creation so
    /// that the orphan sweep of another runtime on this root leaves it.
    claim: DirectoryClaim,
}

/// The advisory lock `docs/interop/FFI_CONTRACT.md` §8.1 takes on a descriptor
/// file.
///
/// One process opens a vault: an unlock takes an exclusive advisory lock on
/// the descriptor file before any slot unwrap, and the session holds it for
/// its life, so a split Android process or a second launch that cannot take
/// the lock returns `CONFLICT` and attempts no slot unwrap. The lock lives on
/// the open file description, so it releases when the session releases it.
///
/// Each replacement is locked before its atomic rename. The session then
/// retains that already-held lock, so the installed inode is never unlocked
/// while the session is open.
///
/// The file is never read: holding the open description is the lock, and
/// dropping it releases.
struct DescriptorLock(std::fs::File);

impl DescriptorLock {
    /// Takes the exclusive advisory lock on the descriptor file at `path`.
    fn acquire(path: &std::path::Path) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| chur_core::err!(IoFailure, "the descriptor file could not be opened"))?;
        Self::lock_opened(file, path)
    }

    fn lock_opened(file: std::fs::File, path: &std::path::Path) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (file, path);
            Err(chur_core::err!(
                IoFailure,
                "descriptor file identity cannot be verified on this platform"
            ))
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            file.try_lock().map_err(|error| match error {
                std::fs::TryLockError::WouldBlock => {
                    chur_core::err!(Conflict, "the vault is open in another process")
                }
                std::fs::TryLockError::Error(_) => {
                    chur_core::err!(IoFailure, "the descriptor file could not be locked")
                }
            })?;
            let held = file.metadata().map_err(|_| {
                chur_core::err!(IoFailure, "the locked descriptor could not be inspected")
            })?;
            let current = std::fs::metadata(path).map_err(|_| {
                chur_core::err!(Conflict, "the descriptor changed while it was opened")
            })?;
            ensure!(
                held.dev() == current.dev() && held.ino() == current.ino(),
                Conflict,
                "the opened descriptor was replaced before it was locked"
            );
            Ok(Self(file))
        }
    }

    /// Candidate bytes are read before credential work. Bind them to the
    /// locked file, so a completed password change cannot admit an old slot.
    fn acquire_snapshot(path: &std::path::Path, expected: &[u8]) -> Result<Self> {
        use std::io::Read as _;
        let lock = Self::acquire(path)?;
        let length = lock
            .0
            .metadata()
            .map_err(|_| {
                chur_core::err!(IoFailure, "the locked descriptor could not be inspected")
            })?
            .len();
        ensure!(
            length == expected.len() as u64,
            Conflict,
            "the descriptor changed before it was locked"
        );
        let mut bytes = vec![0; expected.len()];
        (&lock.0)
            .read_exact(&mut bytes)
            .map_err(|_| chur_core::err!(IoFailure, "the locked descriptor could not be read"))?;
        ensure!(
            bytes == expected,
            Conflict,
            "the descriptor changed before it was locked"
        );
        Ok(lock)
    }
}

/// An unlocked vault session.
///
/// Every handle above this one captures the session generation, so lock makes
/// them all fail in one step, `docs/interop/FFI_CONTRACT.md` §4.
pub struct Session {
    root_dir: VaultRoot,
    /// The vault root, present only while the session is unlocked.
    ///
    /// It is an `Option` and not a `Key` because step 6 of
    /// `docs/security/PLAINTEXT_LIFECYCLE.md` §8 zeroizes the root at lock and
    /// SEC-032 requires that erasure to be real rather than deferred. Taking
    /// the `Option` drops the `Key`, and `chur_crypto::Secret` zeroizes on
    /// drop. Overwriting a `Key` in place would instead leave a valid-looking
    /// all-zero root that every method below would still seal a slot under;
    /// `None` is the state none of them can read.
    root_secret: Option<Key>,
    descriptor: VaultDescriptor,
    entry_name: RegistryName,
    catalog: Option<CatalogDb>,
    pending_keystore: Option<PendingKeystore>,
    /// A sealed recovery slot waiting for the user to confirm its phrase.
    ///
    /// `RECOVERY.md` §8 commits a new recovery slot only after the phrase is
    /// confirmed, and `PROVISIONING.md` §4 runs the presentation "before the
    /// slot commits". A lock takes the root the commit needs, and closing the
    /// session drops the slot, so a phrase the user never confirmed opens
    /// nothing.
    pending_recovery: Option<KeySlotDescriptor>,
    /// The §8.1 advisory lock on the descriptor file, held for the life of the
    /// session, including the session returned by creation.
    descriptor_lock: Option<DescriptorLock>,
}

/// A Keystore enrollment waiting for the platform's answer.
///
/// The slot identity is decided before the wrap rather than after, because the
/// AAD of `KEY_SLOTS.md` §4 binds the slot id and the generation: a wrap
/// performed under one identity and stored under another would never unwrap.
struct PendingKeystore {
    slot_id: Id,
    generation: u64,
    alias: Vec<u8>,
}

/// What the platform needs to perform the wrap, `KEY_SLOTS.md` §4.
///
/// It carries the root secret because this is the one slot family whose AEAD
/// runs outside Rust. [ADR-0041](../../../docs/adr/0041-the-android-keystore-slot-exchanges-root-bytes.md)
/// records that exception, what it costs, and why the alternative costs more.
pub struct KeystoreEnrollment {
    /// The opaque alias bytes the platform turns into a Keystore alias.
    pub alias: Vec<u8>,
    /// The additional authenticated data the wrap must use.
    pub aad: Vec<u8>,
    /// The bytes to wrap.
    pub root_secret: Key,
}

/// What the platform needs to perform the unwrap.
pub struct KeystoreUnlockMaterial {
    /// The opaque alias bytes the slot was enrolled under.
    pub alias: Vec<u8>,
    /// The additional authenticated data the unwrap must use.
    pub aad: Vec<u8>,
    /// The 96-bit GCM nonce the wrap produced.
    pub gcm_nonce: [u8; GCM_NONCE_LEN],
    /// The wrapped root secret the wrap produced.
    pub wrapped_root_secret: [u8; WRAPPED_KEY_LEN],
}

/// Creates a vault, running steps 3 and 4 of `PROVISIONING.md` §3.
///
/// Step 3 is the transaction of `VAULT_DESCRIPTOR_V1.md` §9, whose first step
/// generates the `VaultRootSecret` from the OS CSPRNG. No password, device
/// identifier, or other user input contributes to it; the password derives a
/// KEK only, as SEC-001 requires.
///
/// Step 4 verifies the password slot by unwrapping the committed root with the
/// entered password, before the descriptor reaches `ACTIVE`. The verification
/// reads the encoded slot back rather than reusing the value in memory, so it
/// proves the bytes that were written are the bytes that open.
pub fn create(root_dir: &VaultRoot, password: &[u8], now_ms: u64) -> Result<VaultCreation> {
    create_with_params(root_dir, password, Argon2Params::v1_default(), now_ms)
}

/// Creates a vault under a calibrated Argon2id profile,
/// `docs/security/PASSWORD_PROFILE.md` §6.
///
/// The profile is validated before any work, so a value below the frozen floor
/// writes no slot.
pub fn create_with_params(
    root_dir: &VaultRoot,
    password: &[u8],
    params: Argon2Params,
    now_ms: u64,
) -> Result<VaultCreation> {
    // §6 of PASSWORD_PROFILE: a creation that cannot allocate the floor must
    // not write a slot.
    password::check_memory_available(params)?;
    let canonical = password::canonical_bytes(password)?;
    check_new_password(&canonical)?;

    // §11: the registry holds at most two entries.
    let existing = root_dir.registry_names()?;
    ensure!(
        existing.len() < crate::paths::REGISTRY_MAX,
        ResourceLimitExceeded,
        "the registry already holds the two identities §11 admits"
    );

    // `docs/security/DECOY_VAULT.md` §3 has the user confirm that the second
    // identity's credential is distinct. This is the mechanical half of that,
    // and it is a correctness rule rather than a policy: `KEY_SLOTS.md` §8
    // returns the first candidate a password opens, so a second identity
    // created under a password that already opens the first would be
    // unreachable forever. One extra derivation at creation is the price, and
    // creation is not the constant-cost path §8 protects.
    for name in &existing {
        let bytes = read_entry(root_dir, name)?;
        let Ok(descriptor) = VaultDescriptor::parse(&bytes) else {
            continue;
        };
        if open_password_slot(&descriptor, &canonical).is_ok() {
            bail!(
                Conflict,
                "that credential already opens an identity in this root"
            );
        }
    }

    // §9 step 1: a random vault identity and root secret.
    let vault_id = random::id()?;
    let root_secret: Key = random::secret::<32>()?;
    let object_store_id = random::id()?;
    let catalog_path_id = random::id()?;
    let claim = root_dir.prepare(&object_store_id)?;

    // §9 step 2: the encrypted catalog, created and keyed.
    let catalog_key = CatalogKey::derive(&root_secret, &vault_id)?;
    let catalog_path = root_dir.catalog(&object_store_id, &catalog_path_id);
    let mut catalog = CatalogDb::open(&CatalogLocation::File(&catalog_path), &catalog_key)?;
    schema::open_at_current_version(&mut catalog, now_ms)?;
    let catalog_generation = schema::generation(&catalog)?;
    let header_commitment = catalog_header_commitment(&catalog_path)?;

    // §9 step 4: at least one key slot. ADR-0032 makes it a password slot.
    let slot = seal_password_slot(&vault_id, &canonical, params, &root_secret, 1)?;

    // §9 step 5: descriptor generation 0 as INITIALIZING, written to a name
    // §11 does not enumerate.
    let mut descriptor = VaultDescriptor {
        vault_id,
        descriptor_generation: 0,
        state: VaultState::Initializing,
        catalog: CatalogDescriptor {
            catalog_format_version: CATALOG_FORMAT_VERSION_V17,
            opaque_catalog_path_id: catalog_path_id,
            catalog_generation,
            catalog_header_commitment: header_commitment,
        },
        object_store: ObjectStoreDescriptor::current(object_store_id),
        key_slots: vec![slot],
        migration: None,
    };
    let entry_name = RegistryName::random()?;
    write_temporary(root_dir, &entry_name, &descriptor, &root_secret)?;

    // §9 step 7 and PROVISIONING step 4: verify the slot from the bytes that
    // were written, not from the value still in memory.
    let written = std::fs::read(root_dir.registry_temporary(&entry_name))
        .map_err(|_| chur_core::err!(IoFailure, "the descriptor could not be read back"))?;
    let parsed = VaultDescriptor::authenticate(&written, Some(&root_secret))?;
    let verified = open_password_slot(&parsed, &canonical)?;
    ensure!(
        verified.expose() == root_secret.expose(),
        VaultIncomplete,
        "the written password slot did not return the committed root"
    );

    descriptor.descriptor_generation = 1;
    Ok(VaultCreation {
        root_dir: root_dir.clone(),
        root_secret,
        descriptor,
        entry_name,
        catalog,
        claim,
    })
}

impl VaultCreation {
    /// The vault identity, which the caller needs for nothing but diagnostics.
    #[must_use]
    pub fn vault_id(&self) -> Id {
        self.descriptor.vault_id
    }

    /// Adds the recovery slot of `PROVISIONING.md` §4, step 5 of §3.
    ///
    /// It returns the recovery secret so the caller can render the presentation
    /// of `RECOVERY.md` §2. The value is never stored and is never shown again
    /// afterwards; a user who loses it rotates the slot under §8 there.
    pub fn add_recovery_slot(&mut self) -> Result<Key> {
        let secret: Key = random::secret::<32>()?;
        let slot = seal_recovery_slot(&self.descriptor.vault_id, &secret, &self.root_secret, 1)?;
        self.descriptor.key_slots.push(slot);
        Ok(secret)
    }

    /// Reaches `ACTIVE` and opens the session, step 6 of §3.
    ///
    /// The descriptor is written at generation 1 with state `ACTIVE` and
    /// installed by an atomic rename, which is §9's last step. Until that rename
    /// no `.vd` entry exists, so a crash at any earlier point leaves no openable
    /// vault.
    pub fn activate(mut self) -> Result<Session> {
        self.descriptor.state = VaultState::Active;
        let bytes = self.descriptor.encode(&self.root_secret)?;
        let temporary = self.root_dir.registry_temporary(&self.entry_name);
        let installed = self.root_dir.registry_entry(&self.entry_name);
        write_durably(&temporary, &bytes)?;
        let descriptor_lock = DescriptorLock::acquire(&temporary)?;
        std::fs::rename(&temporary, &installed)
            .map_err(|_| chur_core::err!(IoFailure, "the descriptor could not be installed"))?;
        sync_directory(&self.root_dir.registry())?;
        // Released only after the install, so a sweep that takes the claim
        // next reads a registry that names this directory.
        drop(self.claim);
        Ok(Session {
            root_dir: self.root_dir,
            root_secret: Some(self.root_secret),
            descriptor: self.descriptor,
            entry_name: self.entry_name,
            catalog: Some(self.catalog),
            pending_keystore: None,
            pending_recovery: None,
            descriptor_lock: Some(descriptor_lock),
        })
    }

    /// Removes everything the interrupted creation wrote.
    ///
    /// §9 requires a crash before `ACTIVE` to be recoverable or removable
    /// without exposing a partially trusted vault. Nothing here was ever
    /// openable, so removal is the whole recovery.
    pub fn abandon(self) -> Result<()> {
        let store = self.descriptor.object_store.opaque_root_path_id;
        let temporary = self.root_dir.registry_temporary(&self.entry_name);
        let directory = self.root_dir.vault(&store);
        drop(self.catalog);
        let _ = std::fs::remove_file(temporary);
        std::fs::remove_dir_all(&directory)
            .map_err(|_| chur_core::err!(IoFailure, "the abandoned vault could not be removed"))?;
        Ok(())
    }
}

/// Removes every vault directory that no installed descriptor names.
///
/// `docs/security/PROVISIONING.md` §9 requires a creation that was interrupted
/// at any step of `VAULT_DESCRIPTOR_V1.md` §9 and then restarted to leave no
/// orphaned directory. A process that stops before the atomic install (a
/// crash, a power loss, or a kill while the recovery phrase waits at step 5 of
/// `PROVISIONING.md` §3) leaves its directory with no `.vd` entry, and
/// [`VaultRoot::sweep_temporary`] removes only the temporary descriptor. A
/// restore that stops before its install leaves the same. No entry names such
/// a directory, so nothing can open it and removal is the whole recovery. A
/// directory that stays is also the extra storage that `DECOY_VAULT.md` §5
/// lists as a signal.
///
/// The runtime runs this when it opens. `FFI_CONTRACT.md` §14 gives a process
/// one runtime, but §8.1 expects a second process on the same root, so a
/// creation or a restore can still be running elsewhere. Each one holds the
/// [`DirectoryClaim`] on its directory until its descriptor is installed, and
/// a directory whose claim cannot be taken is skipped. Once the claim is held
/// the registry is read again, because an activation releases its claim only
/// after its install. The directory is then renamed before it is removed, so a
/// creation that has not yet claimed the directory it just made finds it gone
/// rather than half removed. An entry that cannot be read or parsed can name
/// any directory, so it stops the sweep before anything more is removed.
///
/// The sweep is best-effort. An I/O failure skips the directory it hit and the
/// sweep goes on, and the runtime opens anyway: a directory that stays is
/// inert, because nothing names it, and the next start tries it again.
pub fn sweep_orphaned_directories(root_dir: &VaultRoot) {
    let Some(named) = named_directories(root_dir) else {
        return;
    };
    let Ok(listing) = std::fs::read_dir(root_dir.vaults()) else {
        return;
    };
    for entry in listing.flatten() {
        let path = entry.path();
        if named.contains(&path) || !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let Ok(_claim) = DirectoryClaim::take(&path) else {
            continue;
        };
        match named_directories(root_dir) {
            None => return,
            Some(named) if named.contains(&path) => continue,
            Some(_) => {}
        }
        let removing = path.with_extension("removing");
        if std::fs::rename(&path, &removing).is_ok() {
            let _ = std::fs::remove_dir_all(&removing);
        }
    }
}

/// The directory of every installed descriptor, or `None` when an entry
/// cannot be read or parsed and so could name any directory.
fn named_directories(root_dir: &VaultRoot) -> Option<Vec<std::path::PathBuf>> {
    let names = root_dir.registry_names().ok()?;
    names
        .iter()
        .map(|name| {
            let bytes = read_entry(root_dir, name).ok()?;
            let descriptor = VaultDescriptor::parse(&bytes).ok()?;
            Some(root_dir.vault(&descriptor.object_store.opaque_root_path_id))
        })
        .collect()
}

/// One password unlock attempt over the whole registry, `KEY_SLOTS.md` §8.
///
/// The attempt runs exactly `PASSWORD_DERIVATIONS` Argon2id derivations
/// whatever the device holds. Argon2 output is salt-bound and every slot has
/// its own random salt, so one derivation can never be tried against a second
/// slot; a constant candidate count, not a reused derivation, is what removes
/// the cost signal.
///
/// Every candidate, real or dummy, runs to completion before any result is
/// used, so peak Argon2 memory is one profile allocation and the attempt costs
/// the same whether it succeeds, fails, or matches a sibling identity.
pub fn unlock_with_password(root_dir: &VaultRoot, password: &[u8], now_ms: u64) -> Result<Session> {
    let canonical = password::canonical_bytes(password)?;
    let candidates = password_candidates(root_dir)?;

    // §8: the memory the profile requires is checked once, before the first
    // candidate; a device that cannot allocate it runs no candidate at all.
    let profile = candidates
        .first()
        .map_or_else(Argon2Params::v1_default, |candidate| candidate.params);
    password::check_memory_available(profile)?;

    // §8.1 of the interop contract: the advisory lock on a descriptor file is
    // taken before any slot unwrap, so a vault open in another process
    // conflicts here rather than double-opening. A candidate whose lock is not
    // taken attempts no unwrap; its derivation slot runs the dummy work
    // instead, which keeps the attempt's cost constant.
    let mut locks: Vec<Option<DescriptorLock>> = Vec::with_capacity(candidates.len());
    let mut conflict = false;
    for candidate in &candidates {
        match DescriptorLock::acquire_snapshot(
            &root_dir.registry_entry(&candidate.entry_name),
            &candidate.bytes,
        ) {
            Ok(lock) => locks.push(Some(lock)),
            Err(error) if error.status() == ChurStatus::Conflict => {
                locks.push(None);
                conflict = true;
            }
            Err(error) => return Err(error),
        }
    }

    let mut opened: Option<(usize, Key)> = None;
    for index in 0..PASSWORD_DERIVATIONS {
        match candidates.get(index) {
            Some(candidate) if locks.get(index).is_some_and(Option::is_some) => {
                match candidate.body.open(&candidate.binding, &canonical) {
                    Ok(root) if opened.is_none() => opened = Some((index, root)),
                    _ => {}
                }
            }
            _ => {
                // A dummy candidate runs the parameters of the first real
                // candidate over a fresh random 16-byte salt and discards the
                // output, §8.
                let salt = random::array::<SALT_LEN>()?;
                let _ = password::derive_kek(&canonical, &salt, profile);
            }
        }
    }

    match opened {
        Some((index, root)) => {
            let candidate = &candidates[index];
            let lock = locks[index].take().ok_or_else(|| {
                chur_core::err!(InternalFailure, "the opened candidate holds no lock")
            })?;
            finish_unlock(
                root_dir,
                &candidate.entry_name,
                &candidate.bytes,
                root,
                now_ms,
                lock,
            )
        }
        None if conflict => bail!(Conflict, "the vault is open in another process"),
        None => {
            // §8 step 5 still runs over a random substitute root, so an invalid
            // credential and a credential valid for a sibling vault cost the
            // same work and return the same error.
            let bytes = candidates
                .first()
                .map(|candidate| candidate.bytes.clone())
                .unwrap_or_default();
            let _ = VaultDescriptor::authenticate(&bytes, None);
            bail!(
                AuthenticationFailed,
                "no candidate slot returned a root that authenticated a descriptor"
            )
        }
    }
}

/// Unlocks with the recovery phrase of `RECOVERY.md`.
///
/// Recovery runs no Argon2id: `KEY_SLOTS.md` §6 says the mnemonic is a
/// presentation encoding of 32 canonical random bytes, not a low-entropy
/// password, so its KEK comes from HKDF alone.
pub fn unlock_with_recovery(root_dir: &VaultRoot, phrase: &str, now_ms: u64) -> Result<Session> {
    let secret = recovery::decode(phrase)?;
    unlock_with_slot(root_dir, SlotType::Recovery, &secret, now_ms)
}

/// Unlocks with the `DeviceUnlockSecret` an Apple Keychain returned.
pub fn unlock_with_apple_keychain(
    root_dir: &VaultRoot,
    device_unlock_secret: &Key,
    now_ms: u64,
) -> Result<Session> {
    unlock_with_slot(
        root_dir,
        SlotType::AppleKeychain,
        device_unlock_secret,
        now_ms,
    )
}

/// Unlocks with the root secret an Android Keystore unwrap returned.
///
/// There is no slot body to open here: the Keystore already performed the
/// unwrap, so what arrives is the root itself. The descriptor authentication
/// inside `finish_unlock` is the check that it is the right root, which is
/// the same check every other family passes through, so a wrong or substituted
/// value fails as `AUTHENTICATION_FAILED` and not as corruption.
///
/// A descriptor with no Keystore slot is skipped. Otherwise a root obtained
/// some other way would open a vault that was never enrolled on this device,
/// which is a claim `KEY_SLOTS.md` §4 does not make.
pub fn unlock_with_android_keystore(
    root_dir: &VaultRoot,
    root_secret: &Key,
    now_ms: u64,
) -> Result<Session> {
    let mut conflict = false;
    for name in root_dir.registry_names()? {
        let bytes = read_entry(root_dir, &name)?;
        let Ok(descriptor) = VaultDescriptor::parse(&bytes) else {
            continue;
        };
        let enrolled = descriptor
            .key_slots
            .iter()
            .any(|entry| entry.slot_type == SlotType::AndroidKeystore);
        if !enrolled {
            continue;
        }
        // §8.1: the advisory lock is taken before this entry's work runs, so a
        // vault open in another process conflicts rather than double-opens.
        let lock = match DescriptorLock::acquire_snapshot(&root_dir.registry_entry(&name), &bytes) {
            Ok(lock) => lock,
            Err(error) if error.status() == ChurStatus::Conflict => {
                conflict = true;
                continue;
            }
            Err(error) => return Err(error),
        };
        let candidate = root_secret.duplicate();
        if let Ok(session) = finish_unlock(root_dir, &name, &bytes, candidate, now_ms, lock) {
            return Ok(session);
        }
    }
    if conflict {
        bail!(Conflict, "the vault is open in another process");
    }
    bail!(
        AuthenticationFailed,
        "no candidate slot returned a root that authenticated a descriptor"
    )
}

/// What every enrolled Android Keystore slot needs for its unwrap.
///
/// A locked vault has to answer this, because the platform cannot ask the
/// Keystore without the alias, the nonce, the wrapped bytes, and the AAD, and
/// none of those is a secret: they are stored in the clear in the descriptor.
///
/// The result is a list because `DECOY_VAULT.md` admits two identities. Nothing
/// in the list says which identity a member belongs to, and a caller is
/// expected to try each in order.
pub fn android_keystore_material(root_dir: &VaultRoot) -> Result<Vec<KeystoreUnlockMaterial>> {
    let mut material = Vec::new();
    for name in root_dir.registry_names()? {
        let bytes = read_entry(root_dir, &name)?;
        let Ok(descriptor) = VaultDescriptor::parse(&bytes) else {
            continue;
        };
        for entry in descriptor
            .key_slots
            .iter()
            .filter(|entry| entry.slot_type == SlotType::AndroidKeystore)
        {
            // A malformed body is skipped rather than returned as an error,
            // as an entry that fails the parser is: one bad slot must not
            // stop device unlock for every other slot on the device.
            let Ok(body) = AndroidKeystoreSlotBody::decode(&entry.slot_body) else {
                continue;
            };
            let binding = entry.binding(descriptor.vault_id);
            let Ok(aad) = AndroidKeystoreSlotBody::aad(&binding, body.alias()) else {
                continue;
            };
            material.push(KeystoreUnlockMaterial {
                aad,
                alias: body.alias().to_vec(),
                gcm_nonce: *body.gcm_nonce(),
                wrapped_root_secret: *body.wrapped_root_secret(),
            });
        }
    }
    Ok(material)
}

fn unlock_with_slot(
    root_dir: &VaultRoot,
    slot_type: SlotType,
    secret: &Key,
    now_ms: u64,
) -> Result<Session> {
    let mut conflict = false;
    for name in root_dir.registry_names()? {
        let bytes = read_entry(root_dir, &name)?;
        let Ok(descriptor) = VaultDescriptor::parse(&bytes) else {
            // §11: an entry that fails the parser limits is skipped before any
            // credential is used, and its failure is attributed to no credential.
            continue;
        };
        // §8.1: the advisory lock is taken before any slot unwrap, so a vault
        // open in another process conflicts rather than double-opens.
        let lock = match DescriptorLock::acquire_snapshot(&root_dir.registry_entry(&name), &bytes) {
            Ok(lock) => lock,
            Err(error) if error.status() == ChurStatus::Conflict => {
                conflict = true;
                continue;
            }
            Err(error) => return Err(error),
        };
        for entry in descriptor
            .key_slots
            .iter()
            .filter(|entry| entry.slot_type == slot_type)
        {
            let binding = entry.binding(descriptor.vault_id);
            let opened = match slot_type {
                SlotType::Recovery => RecoverySlotBody::decode(&entry.slot_body)
                    .and_then(|body| body.open(&binding, secret)),
                SlotType::AppleKeychain => AppleKeychainSlotBody::decode(&entry.slot_body)
                    .and_then(|body| body.open(&binding, secret)),
                _ => Err(Error::new(
                    ChurStatus::UnsupportedSuite,
                    "that slot family is not an unlock method in v1",
                )),
            };
            if let Ok(root) = opened {
                return finish_unlock(root_dir, &name, &bytes, root, now_ms, lock);
            }
        }
        drop(lock);
    }
    if conflict {
        bail!(Conflict, "the vault is open in another process");
    }
    bail!(
        AuthenticationFailed,
        "no candidate slot returned a root that authenticated a descriptor"
    )
}

/// Steps 5 to 7 of `KEY_SLOTS.md` §8.
///
/// `descriptor_lock` is the §8.1 advisory lock the caller took on this entry
/// before any slot unwrap; the session holds it for its life.
fn finish_unlock(
    root_dir: &VaultRoot,
    entry_name: &RegistryName,
    bytes: &[u8],
    root_secret: Key,
    now_ms: u64,
    mut descriptor_lock: DescriptorLock,
) -> Result<Session> {
    let mut descriptor = VaultDescriptor::authenticate(bytes, Some(&root_secret))?;
    ensure!(
        matches!(descriptor.state, VaultState::Active | VaultState::Migrating),
        VaultIncomplete,
        "the descriptor is neither active nor a resumable migration"
    );
    let catalog_key = CatalogKey::derive(&root_secret, &descriptor.vault_id)?;
    let path = root_dir.catalog(
        &descriptor.object_store.opaque_root_path_id,
        &descriptor.catalog.opaque_catalog_path_id,
    );
    // §5 of the descriptor specification: the descriptor commits to the catalog
    // header, so a substituted catalog file fails here rather than at the first
    // query that reads a row from it.
    let commitment = catalog_header_commitment(&path)?;
    ensure!(
        chur_crypto::secret::constant_time_eq(
            &commitment,
            &descriptor.catalog.catalog_header_commitment
        ),
        VaultCorrupt,
        "the catalog file is not the one this descriptor commits to"
    );
    let mut catalog = CatalogDb::open(&CatalogLocation::File(&path), &catalog_key)?;
    loop {
        let version = schema::recorded_version(catalog.connection())?
            .ok_or_else(|| chur_core::err!(CatalogCorrupt, "the catalog schema is absent"))?;
        if descriptor.state == VaultState::Active {
            let (to, migration_generation) =
                match (descriptor.catalog.catalog_format_version, version) {
                    (CATALOG_FORMAT_VERSION_V17, CATALOG_FORMAT_VERSION_V17) => break,
                    (CATALOG_FORMAT_VERSION_V16, CATALOG_FORMAT_VERSION_V16) => {
                        (CATALOG_FORMAT_VERSION_V17, 16)
                    }
                    (CATALOG_FORMAT_VERSION_V15, CATALOG_FORMAT_VERSION_V15) => {
                        (CATALOG_FORMAT_VERSION_V16, 15)
                    }
                    (CATALOG_FORMAT_VERSION_V14, CATALOG_FORMAT_VERSION_V14) => {
                        (CATALOG_FORMAT_VERSION_V15, 14)
                    }
                    (CATALOG_FORMAT_VERSION_V13, CATALOG_FORMAT_VERSION_V13) => {
                        (CATALOG_FORMAT_VERSION_V14, 13)
                    }
                    (CATALOG_FORMAT_VERSION_V12, CATALOG_FORMAT_VERSION_V12) => {
                        (CATALOG_FORMAT_VERSION_V13, 12)
                    }
                    (CATALOG_FORMAT_VERSION_V11, CATALOG_FORMAT_VERSION_V11) => {
                        (CATALOG_FORMAT_VERSION_V12, 11)
                    }
                    (CATALOG_FORMAT_VERSION_V10, CATALOG_FORMAT_VERSION_V10) => {
                        (CATALOG_FORMAT_VERSION_V11, 10)
                    }
                    (CATALOG_FORMAT_VERSION_V9, CATALOG_FORMAT_VERSION_V9) => {
                        (CATALOG_FORMAT_VERSION_V10, 9)
                    }
                    (CATALOG_FORMAT_VERSION_V8, CATALOG_FORMAT_VERSION_V8) => {
                        (CATALOG_FORMAT_VERSION_V9, 8)
                    }
                    (CATALOG_FORMAT_VERSION_V7, CATALOG_FORMAT_VERSION_V7) => {
                        (CATALOG_FORMAT_VERSION_V8, 7)
                    }
                    (CATALOG_FORMAT_VERSION_V6, CATALOG_FORMAT_VERSION_V6) => {
                        (CATALOG_FORMAT_VERSION_V7, 6)
                    }
                    (CATALOG_FORMAT_VERSION_V5, CATALOG_FORMAT_VERSION_V5) => {
                        (CATALOG_FORMAT_VERSION_V6, 5)
                    }
                    (CATALOG_FORMAT_VERSION_V4, CATALOG_FORMAT_VERSION_V4) => {
                        (CATALOG_FORMAT_VERSION_V5, 4)
                    }
                    (CATALOG_FORMAT_VERSION_V1, CATALOG_FORMAT_VERSION_V1) => {
                        (CATALOG_FORMAT_VERSION_V2, 1)
                    }
                    (CATALOG_FORMAT_VERSION_V2, CATALOG_FORMAT_VERSION_V2) => {
                        (CATALOG_FORMAT_VERSION_V3, 2)
                    }
                    (CATALOG_FORMAT_VERSION_V3, CATALOG_FORMAT_VERSION_V3) => {
                        (CATALOG_FORMAT_VERSION_V4, 3)
                    }
                    _ => bail!(
                        MigrationRequired,
                        "the active descriptor and catalog versions are unsupported"
                    ),
                };
            descriptor = begin_catalog_migration(
                root_dir,
                entry_name,
                &descriptor,
                &root_secret,
                to,
                migration_generation,
                &mut descriptor_lock,
            )?;
        }

        let migration = validate_catalog_migration(&descriptor)?;
        ensure!(
            version == migration.from_catalog_format_version
                || version == migration.to_catalog_format_version,
            MigrationRequired,
            "the migrating descriptor and catalog versions are unsupported"
        );
        if version == migration.from_catalog_format_version {
            match (
                migration.from_catalog_format_version,
                migration.to_catalog_format_version,
            ) {
                (CATALOG_FORMAT_VERSION_V1, CATALOG_FORMAT_VERSION_V2) => {
                    schema::migrate_v1_to_v2(&mut catalog, &descriptor.vault_id)?;
                }
                (CATALOG_FORMAT_VERSION_V2, CATALOG_FORMAT_VERSION_V3) => {
                    schema::migrate_v2_to_v3(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V3, CATALOG_FORMAT_VERSION_V4) => {
                    schema::migrate_v3_to_v4(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V4, CATALOG_FORMAT_VERSION_V5) => {
                    schema::migrate_v4_to_v5(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V5, CATALOG_FORMAT_VERSION_V6) => {
                    schema::migrate_v5_to_v6(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V6, CATALOG_FORMAT_VERSION_V7) => {
                    schema::migrate_v6_to_v7(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V9, CATALOG_FORMAT_VERSION_V10) => {
                    schema::migrate_v9_to_v10(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V10, CATALOG_FORMAT_VERSION_V11) => {
                    schema::migrate_v10_to_v11(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V11, CATALOG_FORMAT_VERSION_V12) => {
                    schema::migrate_v11_to_v12(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V16, CATALOG_FORMAT_VERSION_V17) => {
                    schema::migrate_v16_to_v17(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V15, CATALOG_FORMAT_VERSION_V16) => {
                    schema::migrate_v15_to_v16(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V14, CATALOG_FORMAT_VERSION_V15) => {
                    schema::migrate_v14_to_v15(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V13, CATALOG_FORMAT_VERSION_V14) => {
                    schema::migrate_v13_to_v14(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V12, CATALOG_FORMAT_VERSION_V13) => {
                    schema::migrate_v12_to_v13(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V8, CATALOG_FORMAT_VERSION_V9) => {
                    schema::migrate_v8_to_v9(&mut catalog)?;
                }
                (CATALOG_FORMAT_VERSION_V7, CATALOG_FORMAT_VERSION_V8) => {
                    schema::migrate_v7_to_v8(&mut catalog)?;
                }
                _ => unreachable!("validated migration"),
            }
        }
        catalog.checkpoint()?;
        let commitment = catalog_header_commitment(&path)?;
        descriptor = finish_catalog_migration(
            root_dir,
            entry_name,
            &descriptor,
            &root_secret,
            commitment,
            migration.to_catalog_format_version,
            &mut descriptor_lock,
        )?;
    }

    let version = schema::open_at_current_version(&mut catalog, now_ms)?;
    ensure!(
        descriptor.state == VaultState::Active
            && descriptor.catalog.catalog_format_version == CATALOG_FORMAT_VERSION_V17
            && version == CATALOG_FORMAT_VERSION_V17,
        CatalogCorrupt,
        "the catalog format version disagrees with the descriptor"
    );
    let catalog_generation = schema::generation(&catalog)?;
    // §5 of the descriptor specification: catalog_generation is checked at
    // every unlock. The header commitment above cannot detect a rollback to an
    // older copy of the same file, because the committed header never changes;
    // the generation can. A catalog older than the generation the descriptor
    // last recorded is a restored old copy and must not open.
    ensure!(
        catalog_generation >= descriptor.catalog.catalog_generation,
        VaultCorrupt,
        "the catalog is older than the generation the descriptor records"
    );
    if catalog_generation != descriptor.catalog.catalog_generation {
        // The catalog ran ahead of the descriptor: the session that wrote
        // those states died before its lock could record them. Record the
        // generation the catalog actually holds before the session starts.
        let mut candidate = descriptor.clone();
        candidate.descriptor_generation = next_descriptor_generation(&descriptor)?;
        candidate.catalog.catalog_generation = catalog_generation;
        descriptor_lock =
            install_locked_descriptor(root_dir, entry_name, &candidate, &root_secret)?;
        descriptor = candidate;
        sync_directory(&root_dir.registry())?;
    }
    Ok(Session {
        root_dir: root_dir.clone(),
        root_secret: Some(root_secret),
        descriptor,
        entry_name: entry_name.clone(),
        catalog: Some(catalog),
        pending_keystore: None,
        pending_recovery: None,
        descriptor_lock: Some(descriptor_lock),
    })
}

fn begin_catalog_migration(
    root_dir: &VaultRoot,
    entry_name: &RegistryName,
    descriptor: &VaultDescriptor,
    root: &Key,
    to_catalog_format_version: u16,
    migration_generation: u64,
    descriptor_lock: &mut DescriptorLock,
) -> Result<VaultDescriptor> {
    let mut candidate = descriptor.clone();
    candidate.descriptor_generation = next_descriptor_generation(descriptor)?;
    candidate.state = VaultState::Migrating;
    candidate.migration = Some(MigrationDescriptor {
        from_descriptor_version: DESCRIPTOR_VERSION_V1,
        to_descriptor_version: DESCRIPTOR_VERSION_V1,
        from_catalog_format_version: descriptor.catalog.catalog_format_version,
        to_catalog_format_version,
        migration_generation,
        checkpoint_id: random::id()?,
    });
    *descriptor_lock = install_locked_descriptor(root_dir, entry_name, &candidate, root)?;
    sync_directory(&root_dir.registry())?;
    Ok(candidate)
}

fn validate_catalog_migration(descriptor: &VaultDescriptor) -> Result<MigrationDescriptor> {
    let migration = descriptor
        .migration
        .ok_or_else(|| chur_core::err!(VaultCorrupt, "the migration descriptor is absent"))?;
    ensure!(
        descriptor.catalog.catalog_format_version == migration.from_catalog_format_version
            && migration.from_descriptor_version == DESCRIPTOR_VERSION_V1
            && migration.to_descriptor_version == DESCRIPTOR_VERSION_V1
            && matches!(
                (
                    migration.from_catalog_format_version,
                    migration.to_catalog_format_version,
                    migration.migration_generation,
                ),
                (CATALOG_FORMAT_VERSION_V1, CATALOG_FORMAT_VERSION_V2, 1)
                    | (CATALOG_FORMAT_VERSION_V2, CATALOG_FORMAT_VERSION_V3, 2)
                    | (CATALOG_FORMAT_VERSION_V3, CATALOG_FORMAT_VERSION_V4, 3)
                    | (CATALOG_FORMAT_VERSION_V4, CATALOG_FORMAT_VERSION_V5, 4)
                    | (CATALOG_FORMAT_VERSION_V5, CATALOG_FORMAT_VERSION_V6, 5)
                    | (CATALOG_FORMAT_VERSION_V6, CATALOG_FORMAT_VERSION_V7, 6)
                    | (CATALOG_FORMAT_VERSION_V7, CATALOG_FORMAT_VERSION_V8, 7)
                    | (CATALOG_FORMAT_VERSION_V8, CATALOG_FORMAT_VERSION_V9, 8)
                    | (CATALOG_FORMAT_VERSION_V9, CATALOG_FORMAT_VERSION_V10, 9)
                    | (CATALOG_FORMAT_VERSION_V10, CATALOG_FORMAT_VERSION_V11, 10)
                    | (CATALOG_FORMAT_VERSION_V11, CATALOG_FORMAT_VERSION_V12, 11)
                    | (CATALOG_FORMAT_VERSION_V12, CATALOG_FORMAT_VERSION_V13, 12)
                    | (CATALOG_FORMAT_VERSION_V13, CATALOG_FORMAT_VERSION_V14, 13)
                    | (CATALOG_FORMAT_VERSION_V14, CATALOG_FORMAT_VERSION_V15, 14)
                    | (CATALOG_FORMAT_VERSION_V15, CATALOG_FORMAT_VERSION_V16, 15)
                    | (CATALOG_FORMAT_VERSION_V16, CATALOG_FORMAT_VERSION_V17, 16)
            ),
        MigrationRequired,
        "the descriptor names an unsupported migration"
    );
    Ok(migration)
}

fn finish_catalog_migration(
    root_dir: &VaultRoot,
    entry_name: &RegistryName,
    descriptor: &VaultDescriptor,
    root: &Key,
    catalog_header_commitment: commit::Commitment,
    catalog_format_version: u16,
    descriptor_lock: &mut DescriptorLock,
) -> Result<VaultDescriptor> {
    let mut candidate = descriptor.clone();
    candidate.descriptor_generation = next_descriptor_generation(descriptor)?;
    candidate.state = VaultState::Active;
    candidate.catalog.catalog_format_version = catalog_format_version;
    candidate.catalog.catalog_header_commitment = catalog_header_commitment;
    candidate.migration = None;
    *descriptor_lock = install_locked_descriptor(root_dir, entry_name, &candidate, root)?;
    sync_directory(&root_dir.registry())?;
    Ok(candidate)
}

fn next_descriptor_generation(descriptor: &VaultDescriptor) -> Result<u64> {
    descriptor
        .descriptor_generation
        .checked_add(1)
        .ok_or_else(|| chur_core::err!(VaultCorrupt, "the descriptor generation has no successor"))
}

impl Session {
    /// The catalog, while the session is unlocked.
    pub fn catalog(&mut self) -> Result<&mut CatalogDb> {
        self.catalog
            .as_mut()
            .ok_or_else(|| chur_core::err!(VaultLocked, "the session is locked"))
    }

    /// The catalog for reading only.
    pub fn catalog_ref(&self) -> Result<&CatalogDb> {
        self.catalog
            .as_ref()
            .ok_or_else(|| chur_core::err!(VaultLocked, "the session is locked"))
    }

    /// The vault identity.
    #[must_use]
    pub fn vault_id(&self) -> Id {
        self.descriptor.vault_id
    }

    /// The opaque object-store root identifier, which resolves every path.
    #[must_use]
    pub fn object_store_id(&self) -> Id {
        self.descriptor.object_store.opaque_root_path_id
    }

    /// The storage root.
    #[must_use]
    pub fn root_dir(&self) -> &VaultRoot {
        &self.root_dir
    }

    /// The root secret, for the derivations only this crate and `chur-media`
    /// perform.
    ///
    /// `docs/interop/FFI_CONTRACT.md` §12 keeps object, collection, and root
    /// keys away from application feature code; nothing above `chur-ffi` can
    /// reach this, because `Session` is never handed out across the boundary.
    /// This is the one place the root is read, so it is the one place the lock
    /// is checked. Every root-backed method below goes through it rather than
    /// through the field.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::VaultLocked`] once [`Session::lock`] has run step
    /// 6 of `docs/security/PLAINTEXT_LIFECYCLE.md` §8.
    pub fn root_secret(&self) -> Result<&Key> {
        self.root_secret
            .as_ref()
            .ok_or_else(|| chur_core::err!(VaultLocked, "the session is locked"))
    }

    /// The descriptor, for the backup package that copies it.
    ///
    /// `docs/format/BACKUP_FORMAT_V1.md` §3 lists what a portable package may
    /// carry, and the caller of this decides which slots survive that filter.
    #[must_use]
    pub const fn descriptor(&self) -> &VaultDescriptor {
        &self.descriptor
    }

    /// The catalog file this session opened.
    ///
    /// A backup copies the file whole, so it needs the path the descriptor
    /// resolves rather than the identifiers that resolve it.
    #[must_use]
    pub fn catalog_path(&self) -> std::path::PathBuf {
        self.root_dir.catalog(
            &self.descriptor.object_store.opaque_root_path_id,
            &self.descriptor.catalog.opaque_catalog_path_id,
        )
    }

    /// Encodes and authenticates a descriptor under this session's root.
    ///
    /// A portable descriptor differs from the live one — §3 excludes every
    /// device-bound slot — so it is authenticated again rather than copied: the
    /// §8 tag covers the body, and a body with slots removed is a different
    /// body.
    pub fn seal_descriptor(&self, descriptor: &VaultDescriptor) -> Result<Vec<u8>> {
        descriptor.encode(self.root_secret()?)
    }

    /// Makes every committed catalog page durable, `BACKUP_FORMAT_V1.md` §7.
    ///
    /// §7 opens a backup on a consistent catalog snapshot. SQLCipher may hold
    /// committed pages in a write-ahead log, and a package that copied only the
    /// database file would carry a catalog older than the containers beside it.
    pub fn checkpoint_catalog(&mut self) -> Result<()> {
        self.catalog()?.checkpoint()
    }

    /// Adds a recovery slot to an active vault, `RECOVERY.md` §8.
    ///
    /// It commits before anyone has seen the phrase, so it is for callers with
    /// no confirmation step, such as the command line. A host that presents
    /// the phrase stages the slot with [`Session::begin_recovery_slot`]
    /// instead. This never reads or replaces a slot staged there.
    pub fn add_recovery_slot(&mut self) -> Result<Key> {
        let (secret, slot) = self.seal_new_recovery_slot()?;
        self.commit_slots(|slots| slots.push(slot))?;
        Ok(secret)
    }

    /// Stages a recovery slot until its phrase is confirmed, `RECOVERY.md` §8.
    ///
    /// The slot is sealed now and held in the session; nothing reaches the
    /// descriptor until [`Session::finish_recovery_slot`]. The returned secret
    /// is what the caller presents. A second begin replaces the staged slot,
    /// so only the phrase shown last can be committed.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::VaultLocked`] once the session is locked.
    pub fn begin_recovery_slot(&mut self) -> Result<Key> {
        let (secret, slot) = self.seal_new_recovery_slot()?;
        self.pending_recovery = Some(slot);
        Ok(secret)
    }

    /// Commits the staged recovery slot as one descriptor generation,
    /// `KEY_SLOTS.md` §9.
    ///
    /// The same generation retires every earlier recovery slot, which is the
    /// rotation of `RECOVERY.md` §8: a user who confirms a new phrase has
    /// replaced the old one, and a lost phrase stops opening the vault. It is
    /// one generation for the reason [`Session::replace_password`] gives, so
    /// no descriptor ever carries neither phrase. A host calls this only once
    /// the user confirmed the new phrase, so the old slot goes only after
    /// that success, as §8 orders.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::VaultLocked`] once the session is locked, whether
    /// or not a slot was staged, and [`ChurStatus::Conflict`] when no slot is
    /// waiting, which is what a second commit or a commit without a begin is.
    pub fn finish_recovery_slot(&mut self) -> Result<()> {
        self.root_secret()?;
        let slot = self.pending_recovery.take().ok_or_else(|| {
            Error::new(
                ChurStatus::Conflict,
                "no recovery slot is waiting for confirmation",
            )
        })?;
        self.commit_slots(|slots| {
            slots.retain(|entry| entry.slot_type != SlotType::Recovery);
            slots.push(slot);
        })
    }

    fn seal_new_recovery_slot(&self) -> Result<(Key, KeySlotDescriptor)> {
        let secret: Key = random::secret::<32>()?;
        let generation = self.next_slot_generation(SlotType::Recovery);
        let slot = seal_recovery_slot(
            &self.descriptor.vault_id,
            &secret,
            self.root_secret()?,
            generation,
        )?;
        Ok((secret, slot))
    }

    /// Adds the Apple Keychain slot of `KEY_SLOTS.md` §5, step 7 of
    /// `PROVISIONING.md` §3.
    ///
    /// The `DeviceUnlockSecret` is generated here and returned so the platform
    /// can store it as a `ThisDeviceOnly` Keychain item. Rust wraps the root
    /// under a KEK derived from it, so the Keychain never holds vault
    /// ciphertext and the envelope stays test-vectorable at the Rust layer.
    pub fn add_apple_keychain_slot(&mut self, keychain_item_id: Id) -> Result<Key> {
        self.root_secret()?;
        self.refuse_device_slot_of_another_identity()?;
        let secret: Key = random::secret::<32>()?;
        let generation = self.next_slot_generation(SlotType::AppleKeychain);
        let slot_id = random::id()?;
        let binding = SlotBinding::v1(
            self.descriptor.vault_id,
            slot_id,
            SlotType::AppleKeychain,
            generation,
        );
        let body = AppleKeychainSlotBody::seal(
            &binding,
            &secret,
            keychain_item_id,
            Nonce::random()?,
            self.root_secret()?,
        )?;
        let slot =
            KeySlotDescriptor::v1(slot_id, SlotType::AppleKeychain, generation, body.encode())?;
        self.commit_slots(|slots| slots.push(slot))?;
        Ok(secret)
    }

    /// Begins the Android Keystore slot of `KEY_SLOTS.md` §4.
    ///
    /// The enrollment is two calls because the AEAD is the platform's: Rust
    /// decides the slot identity and the AAD, the Keystore performs the wrap,
    /// and [`Session::finish_android_keystore_slot`] stores what it returned.
    /// Nothing is written to the descriptor until that second call, so an
    /// enrollment the platform abandons leaves the vault exactly as it was.
    ///
    /// The returned secret is the vault root. ADR-0041 records why this family
    /// is the one that hands it out, and the caller must destroy its copy as
    /// soon as the wrap returns.
    pub fn begin_android_keystore_slot(&mut self) -> Result<KeystoreEnrollment> {
        // ADR-0041 makes this the one export that hands the root itself to the
        // platform, so the lock is checked before anything is drawn or
        // recorded: a locked session must neither release the root nor leave a
        // half-opened enrollment behind.
        let root_secret = self.root_secret()?.duplicate();
        self.refuse_device_slot_of_another_identity()?;
        let slot_id = random::id()?;
        let generation = self.next_slot_generation(SlotType::AndroidKeystore);
        let alias = random::array::<KEYSTORE_ALIAS_LEN>()?.to_vec();
        let binding = SlotBinding::v1(
            self.descriptor.vault_id,
            slot_id,
            SlotType::AndroidKeystore,
            generation,
        );
        let aad = AndroidKeystoreSlotBody::aad(&binding, &alias)?;
        self.pending_keystore = Some(PendingKeystore {
            slot_id,
            generation,
            alias: alias.clone(),
        });
        Ok(KeystoreEnrollment {
            alias,
            aad,
            root_secret,
        })
    }

    /// Stores what the Keystore wrap returned, completing the slot.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::Conflict`] when no enrollment is open, which
    /// is what a second commit or a commit without a begin is.
    pub fn finish_android_keystore_slot(
        &mut self,
        gcm_nonce: [u8; GCM_NONCE_LEN],
        wrapped_root_secret: [u8; WRAPPED_KEY_LEN],
    ) -> Result<()> {
        let pending = self.pending_keystore.take().ok_or_else(|| {
            Error::new(
                ChurStatus::Conflict,
                "no Keystore enrollment is waiting for a wrap",
            )
        })?;
        let binding = SlotBinding::v1(
            self.descriptor.vault_id,
            pending.slot_id,
            SlotType::AndroidKeystore,
            pending.generation,
        );
        let body =
            AndroidKeystoreSlotBody::new(&binding, pending.alias, gcm_nonce, wrapped_root_secret)?;
        let slot = KeySlotDescriptor::v1(
            pending.slot_id,
            SlotType::AndroidKeystore,
            pending.generation,
            body.encode(),
        )?;
        self.commit_slots(|slots| slots.push(slot))
    }

    /// Removes one slot, `KEY_SLOTS.md` §9.
    ///
    /// At least one verified recovery path must remain through every update, so
    /// removing the last portable slot is refused. That is what makes a device
    /// slot never the only slot, `PROVISIONING.md` §5.
    pub fn remove_slot(&mut self, slot_id: &Id) -> Result<()> {
        let remaining: Vec<&KeySlotDescriptor> = self
            .descriptor
            .key_slots
            .iter()
            .filter(|entry| entry.slot_id != *slot_id)
            .collect();
        ensure!(
            remaining.len() < self.descriptor.key_slots.len(),
            NotFound,
            "no slot carries that id"
        );
        let portable = remaining
            .iter()
            .any(|entry| matches!(entry.slot_type, SlotType::Password | SlotType::Recovery));
        ensure!(
            portable,
            Conflict,
            "removing the last portable slot would leave no verified recovery path"
        );
        let slot_id = *slot_id;
        self.commit_slots(|slots| slots.retain(|entry| entry.slot_id != slot_id))
    }

    /// Replaces the password slot, `KEY_SLOTS.md` §3 and §9.
    ///
    /// The replacement is created and verified before the old slot goes, which
    /// is why the whole change is one descriptor generation: an intermediate
    /// generation carrying neither slot would be a vault nobody can open.
    pub fn replace_password(&mut self, password: &[u8], params: Argon2Params) -> Result<()> {
        // Before the Argon2id work, not after: a locked session is refused
        // without spending the derivation `PASSWORD_PROFILE.md` §4 sizes.
        let root = self.root_secret()?;
        password::check_memory_available(params)?;
        let canonical = password::canonical_bytes(password)?;
        check_new_password(&canonical)?;
        let generation = self.next_slot_generation(SlotType::Password);
        let slot = seal_password_slot(
            &self.descriptor.vault_id,
            &canonical,
            params,
            root,
            generation,
        )?;
        let binding = slot.binding(self.descriptor.vault_id);
        let verified = PasswordSlotBody::decode(&slot.slot_body)?.open(&binding, &canonical)?;
        ensure!(
            verified.expose() == root.expose(),
            VaultIncomplete,
            "the replacement password slot did not return the committed root"
        );
        self.commit_slots(|slots| {
            slots.retain(|entry| entry.slot_type != SlotType::Password);
            slots.push(slot);
        })
    }

    /// The lock sequence of `PLAINTEXT_LIFECYCLE.md` §8.
    ///
    /// Steps 1 to 4 and 7 belong to the caller: the session generation and the
    /// decoded caches live above this crate. Steps 5, 6, and 8 are here, in
    /// that order. The catalog closes before the root goes, because a
    /// connection that outlived the key would still hold decrypted pages,
    /// which is the order ADR-0004 fixes.
    ///
    /// Locking twice is not a failure: both `Option`s are already empty.
    pub fn lock(&mut self) -> Result<()> {
        // Step 4: the descriptor records the catalog generation this session
        // leaves behind, §5 of the descriptor specification. The next unlock
        // compares the catalog against it, which is what detects a catalog
        // file rolled back to an older copy. The root is still held here, and
        // the outcome is held rather than propagated, because step 6 below has
        // no precondition and must still run.
        let recorded = match self.catalog.as_ref().map(schema::generation).transpose() {
            Ok(Some(generation)) if generation > self.descriptor.catalog.catalog_generation => {
                self.record_catalog_generation(generation).map(|_| ())
            }
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        };
        // Step 5. The outcome is held rather than propagated, because closing
        // a SQLCipher connection fails on a live system — a busy or unwritable
        // database maps to a status — and step 6 below has no precondition and
        // must still run when it does.
        let closed = match self.catalog.take() {
            Some(catalog) => catalog.close(),
            None => Ok(()),
        };
        // Step 6, and it happens here rather than at drop. `chur_vault_lock`
        // leaves the session in the FFI registry until a separate
        // `chur_session_close`, so a root this call did not take would still be
        // readable by every slot mutator above: `add_recovery_slot` would mint
        // a portable credential for a locked vault, and
        // `begin_android_keystore_slot` would hand the root out. Taking the
        // `Option` drops the `Key`, and `chur_crypto::Secret` zeroizes on drop,
        // which is SEC-032.
        drop(self.root_secret.take());
        // The session is locked, so the §8.1 advisory lock on the descriptor
        // file releases with it and another process may unlock the vault.
        drop(self.descriptor_lock.take());
        // Step 8: every scratch entry, whatever its journal state.
        let scratch = self.root_dir.scratch(&self.object_store_id());
        let cleaned = (|| {
            if scratch.exists() {
                std::fs::remove_dir_all(&scratch).map_err(|_| {
                    chur_core::err!(IoFailure, "the scratch directory could not be cleared")
                })?;
                std::fs::create_dir_all(&scratch).map_err(|_| {
                    chur_core::err!(IoFailure, "the scratch directory could not be recreated")
                })?;
            }
            Ok(())
        })();
        closed?;
        recorded?;
        cleaned
    }

    /// The key slots this vault carries, for the settings screen.
    ///
    /// It returns only the public triple `KEY_SLOTS.md` §2 calls common: the
    /// identity, the family, and the generation. A slot body carries the
    /// wrapped root and never leaves this crate.
    #[must_use]
    pub fn slots(&self) -> Vec<(Id, SlotType, u64)> {
        self.descriptor
            .key_slots
            .iter()
            .map(|entry| (entry.slot_id, entry.slot_type, entry.slot_generation))
            .collect()
    }

    /// Returns the public platform name for one device slot in this session.
    /// A shared name is refused so deleting it cannot disable another slot.
    pub fn platform_slot_identifier(&self, slot_id: &Id) -> Result<Vec<u8>> {
        self.root_secret()?;
        let target = self
            .descriptor
            .key_slots
            .iter()
            .find(|entry| &entry.slot_id == slot_id)
            .ok_or_else(|| chur_core::err!(NotFound, "no slot carries that id"))?;
        let identifier = match target.slot_type {
            SlotType::AndroidKeystore => AndroidKeystoreSlotBody::decode(&target.slot_body)?
                .alias()
                .to_vec(),
            SlotType::AppleKeychain => AppleKeychainSlotBody::decode(&target.slot_body)?
                .keychain_item_id()
                .as_bytes()
                .to_vec(),
            _ => return Err(chur_core::err!(InvalidInput, "slot has no platform key")),
        };
        for other in &self.descriptor.key_slots {
            if other.slot_id == *slot_id || other.slot_type != target.slot_type {
                continue;
            }
            let other_identifier = match other.slot_type {
                SlotType::AndroidKeystore => AndroidKeystoreSlotBody::decode(&other.slot_body)?
                    .alias()
                    .to_vec(),
                SlotType::AppleKeychain => AppleKeychainSlotBody::decode(&other.slot_body)?
                    .keychain_item_id()
                    .as_bytes()
                    .to_vec(),
                _ => continue,
            };
            ensure!(
                other_identifier != identifier,
                Conflict,
                "platform key is shared by another slot"
            );
        }
        Ok(identifier)
    }

    /// Whether the session still holds an open catalog.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.catalog.is_some()
    }

    fn next_slot_generation(&self, slot_type: SlotType) -> u64 {
        self.descriptor
            .key_slots
            .iter()
            .filter(|entry| entry.slot_type == slot_type)
            .map(|entry| entry.slot_generation)
            .max()
            .map_or(1, |current| current + 1)
    }

    /// Refuses a device slot when another identity already holds one.
    ///
    /// `DECOY_VAULT.md` §10 admits one device-slot identity per install. A
    /// device unlock names no identity: it opens the first registry entry whose
    /// slot authenticates, so a device slot in each of two identities would let
    /// the filename order decide which vault a fingerprint opens. The refusal
    /// is [`ChurStatus::PlatformKeyUnavailable`], the status of any device
    /// unlock that is not available, so the message a host shows is the same
    /// as for a device without the factor.
    ///
    /// An identity that already holds a device slot may always add another,
    /// which is what a policy change does. That also keeps the policy change
    /// working on an install where both identities enrolled before this rule.
    /// An entry that cannot be read or does not parse is skipped, as every
    /// unlock skips it.
    fn refuse_device_slot_of_another_identity(&self) -> Result<()> {
        if self.descriptor.key_slots.iter().any(is_device_slot) {
            return Ok(());
        }
        for name in self.root_dir.registry_names()? {
            if name == self.entry_name {
                continue;
            }
            let Ok(bytes) = read_entry(&self.root_dir, &name) else {
                continue;
            };
            let Ok(descriptor) = VaultDescriptor::parse(&bytes) else {
                continue;
            };
            if descriptor.key_slots.iter().any(is_device_slot) {
                bail!(
                    PlatformKeyUnavailable,
                    "device unlock is not available for this vault"
                );
            }
        }
        Ok(())
    }

    /// Runs the slot transaction of `KEY_SLOTS.md` §9.
    ///
    /// Write the new descriptor to a temporary name, fsync it, read it back and
    /// verify it, then install it by an atomic rename. A crash at any point
    /// leaves the previous descriptor installed, which is the one the vault was
    /// already openable with.
    fn commit_slots(&mut self, change: impl FnOnce(&mut Vec<KeySlotDescriptor>)) -> Result<()> {
        // Every slot transaction is authenticated under the root, so this is
        // the funnel all of them pass and the lock is checked once here rather
        // than in each caller. §8 step 6 has already taken the key.
        self.root_secret()?;
        let mut candidate = self.descriptor.clone();
        change(&mut candidate.key_slots);
        candidate.descriptor_generation = next_descriptor_generation(&self.descriptor)?;
        self.commit_descriptor(candidate, sync_directory)
    }

    /// Records a catalog generation in the descriptor.
    ///
    /// §5 of the descriptor specification: the descriptor carries the catalog
    /// generation it was last written against, which is what the unlock-time
    /// check compares against the catalog. A state transition writes a new
    /// descriptor generation rather than mutating authenticated fields in
    /// place, so the rewrite bumps the generation and is authenticated under
    /// the root.
    fn record_catalog_generation(&mut self, generation: u64) -> Result<()> {
        self.root_secret()?;
        let mut candidate = self.descriptor.clone();
        candidate.descriptor_generation = next_descriptor_generation(&self.descriptor)?;
        candidate.catalog.catalog_generation = generation;
        self.commit_descriptor(candidate, sync_directory)
    }

    /// Raises the container-version ceiling of the object store, ADR-0066.
    ///
    /// `VAULT_DESCRIPTOR_V1.md` §6 has the descriptor name the highest
    /// container version its store holds, so a build that cannot read a v2
    /// container refuses the vault as a whole rather than one object at a
    /// time. A writer calls this before the first byte of a container of
    /// `version`; a store whose ceiling already admits it is left alone, so
    /// the rewrite happens once per vault.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::VaultLocked`] once the session is locked, and the
    /// descriptor-installation errors otherwise.
    pub fn admit_container_version(&mut self, version: u16) -> Result<()> {
        if self.descriptor.object_store.container_version_ceiling >= version {
            return Ok(());
        }
        self.root_secret()?;
        let mut candidate = self.descriptor.clone();
        candidate.descriptor_generation = next_descriptor_generation(&self.descriptor)?;
        candidate.object_store.container_version_ceiling = version;
        self.commit_descriptor(candidate, sync_directory)
    }

    /// Retains the replacement's lock and authenticated state before a
    /// directory durability error can return control to an unlocked session.
    fn commit_descriptor(
        &mut self,
        candidate: VaultDescriptor,
        sync: impl FnOnce(&std::path::Path) -> Result<()>,
    ) -> Result<()> {
        let lock = install_locked_descriptor(
            &self.root_dir,
            &self.entry_name,
            &candidate,
            self.root_secret()?,
        )?;
        self.descriptor = candidate;
        self.descriptor_lock = Some(lock);
        sync(&self.root_dir.registry())
    }
}

/// One password candidate, `KEY_SLOTS.md` §8.
struct PasswordCandidate {
    entry_name: RegistryName,
    bytes: Vec<u8>,
    binding: SlotBinding,
    body: PasswordSlotBody,
    params: Argon2Params,
}

/// The candidate list of §8: the highest-generation password slot of each
/// descriptor, in the registry enumeration order.
fn password_candidates(root_dir: &VaultRoot) -> Result<Vec<PasswordCandidate>> {
    let mut candidates = Vec::new();
    for name in root_dir.registry_names()? {
        let bytes = read_entry(root_dir, &name)?;
        let Ok(descriptor) = VaultDescriptor::parse(&bytes) else {
            continue;
        };
        let Some(entry) = descriptor.password_slot() else {
            continue;
        };
        let Ok(body) = PasswordSlotBody::decode(&entry.slot_body) else {
            continue;
        };
        candidates.push(PasswordCandidate {
            entry_name: name,
            binding: entry.binding(descriptor.vault_id),
            params: body.params(),
            body,
            bytes,
        });
    }
    Ok(candidates)
}

/// Whether a slot belongs to a device family, `KEY_SLOTS.md` §4 and §5.
fn is_device_slot(entry: &KeySlotDescriptor) -> bool {
    matches!(
        entry.slot_type,
        SlotType::AndroidKeystore | SlotType::AppleKeychain
    )
}

/// Refuses a new or changed password shorter than
/// `docs/security/PASSWORD_PROFILE.md` §3 allows.
///
/// Only a slot that is being created is checked. An unlock never is, so a
/// slot made before the rule existed still opens. The count is of Unicode
/// scalar values, so a host cannot meet it with bytes alone.
fn check_new_password(canonical: &[u8]) -> Result<()> {
    let characters = core::str::from_utf8(canonical)
        .map_err(|_| {
            Error::new(
                ChurStatus::InvalidInput,
                "password bytes are not valid UTF-8",
            )
        })?
        .chars()
        .count();
    if characters < chur_core::limits::password::NEW_MIN_CHARS {
        bail!(InvalidInput, "a new password needs at least 12 characters");
    }
    Ok(())
}

fn read_entry(root_dir: &VaultRoot, name: &RegistryName) -> Result<Vec<u8>> {
    std::fs::read(root_dir.registry_entry(name))
        .map_err(|_| chur_core::err!(IoFailure, "a registry entry could not be read"))
}

fn seal_password_slot(
    vault_id: &Id,
    canonical: &[u8],
    params: Argon2Params,
    root: &Key,
    generation: u64,
) -> Result<KeySlotDescriptor> {
    let slot_id = random::id()?;
    // The binding is built directly rather than from a placeholder descriptor:
    // a descriptor with an empty body fails the 16-byte minimum of §13, and the
    // binding is exactly the six fields that exist before the body does.
    let binding = SlotBinding::v1(*vault_id, slot_id, SlotType::Password, generation);
    let salt = random::array::<SALT_LEN>()?.to_vec();
    let body = PasswordSlotBody::seal(&binding, canonical, salt, params, Nonce::random()?, root)?;
    KeySlotDescriptor::v1(slot_id, SlotType::Password, generation, body.encode())
}

fn seal_recovery_slot(
    vault_id: &Id,
    secret: &Key,
    root: &Key,
    generation: u64,
) -> Result<KeySlotDescriptor> {
    let slot_id = random::id()?;
    let binding = SlotBinding::v1(*vault_id, slot_id, SlotType::Recovery, generation);
    let body = RecoverySlotBody::seal(&binding, secret, Nonce::random()?, root)?;
    KeySlotDescriptor::v1(slot_id, SlotType::Recovery, generation, body.encode())
}

/// Opens the password slot of a descriptor that is not in the registry.
///
/// A restore holds the package's descriptor before any vault exists, and
/// `docs/format/BACKUP_FORMAT_V1.md` §8 step 2 has it obtain the factor from
/// that descriptor rather than from a registry entry. The one Argon2id
/// derivation this runs is not the constant-cost attempt of
/// `docs/security/KEY_SLOTS.md` §8: it is not an unlock, there is no sibling
/// identity to distinguish, and the file was supplied by the caller.
///
/// # Errors
///
/// Returns [`ChurStatus::VaultIncomplete`] when the descriptor carries no
/// password slot, and [`ChurStatus::AuthenticationFailed`] when the password
/// does not open it.
pub fn open_password_slot_of(descriptor: &VaultDescriptor, password: &[u8]) -> Result<Key> {
    let canonical = password::canonical_bytes(password)?;
    open_password_slot(descriptor, &canonical)
}

/// Opens a recovery slot of a descriptor that is not yet in the registry.
/// A malformed or wrong phrase has the same external result during restore.
pub fn open_recovery_slot_of(descriptor: &VaultDescriptor, phrase: &[u8]) -> Result<Key> {
    let phrase = std::str::from_utf8(phrase).map_err(|_| {
        chur_core::err!(
            AuthenticationFailed,
            "the credential did not open the backup"
        )
    })?;
    let secret = recovery::decode(phrase).map_err(|_| {
        chur_core::err!(
            AuthenticationFailed,
            "the credential did not open the backup"
        )
    })?;
    let mut found = false;
    for entry in descriptor
        .key_slots
        .iter()
        .filter(|entry| entry.slot_type == SlotType::Recovery)
    {
        found = true;
        let binding = entry.binding(descriptor.vault_id);
        if let Ok(root) =
            RecoverySlotBody::decode(&entry.slot_body).and_then(|body| body.open(&binding, &secret))
        {
            return Ok(root);
        }
    }
    ensure!(
        found,
        VaultIncomplete,
        "the descriptor carries no recovery slot"
    );
    bail!(
        AuthenticationFailed,
        "the credential did not open the backup"
    )
}

/// Installs a descriptor body into the registry by atomic rename.
///
/// It is the last step of `VAULT_DESCRIPTOR_V1.md` §9 and of
/// `BACKUP_FORMAT_V1.md` §8, and it is what makes a restored vault openable:
/// until this rename no `.vd` entry names it, so an interrupted restore leaves
/// no vault rather than a partial one.
///
/// The bytes are not re-encoded. They carry the §8 authentication tag the
/// source device computed, and re-encoding here would authenticate whatever
/// this build parsed rather than what the package carried.
///
/// # Errors
///
/// Returns [`ChurStatus::IoFailure`] when the write or the rename fails, and
/// [`ChurStatus::Conflict`] when the registry already holds its two entries.
pub fn install_descriptor(
    root_dir: &VaultRoot,
    entry_name: &RegistryName,
    body: &[u8],
) -> Result<()> {
    ensure!(
        root_dir.registry_names()?.len() < crate::paths::REGISTRY_MAX,
        Conflict,
        "the registry already holds the two identities §11 admits"
    );
    let temporary = root_dir.registry_temporary(entry_name);
    let installed = root_dir.registry_entry(entry_name);
    write_durably(&temporary, body)?;
    let _lock = DescriptorLock::acquire(&temporary)?;
    std::fs::rename(&temporary, &installed)
        .map_err(|_| chur_core::err!(IoFailure, "the descriptor could not be installed"))?;
    sync_directory(&root_dir.registry())
}

/// Refuses a restore that the registry cannot hold as a distinct identity.
///
/// Besides the two-entry bound of `VAULT_DESCRIPTOR_V1.md` §11, an installed
/// identity with the same `vault_id`, or one the credential already opens, is a
/// conflict. `KEY_SLOTS.md` §8 returns the first candidate a password opens, in
/// filename order, so such a pair would make unlock pick one of the two copies
/// at random and leave the other unreachable, the rule
/// [`create_with_params`] applies to a new identity.
///
/// # Errors
///
/// Returns [`ChurStatus::Conflict`] on any of the three conditions.
pub fn ensure_restorable(root_dir: &VaultRoot, vault_id: &Id, credential: &[u8]) -> Result<()> {
    let existing = root_dir.registry_names()?;
    ensure!(
        existing.len() < crate::paths::REGISTRY_MAX,
        Conflict,
        "the registry already holds the two identities §11 admits"
    );
    for name in &existing {
        let bytes = read_entry(root_dir, name)?;
        let Ok(installed) = VaultDescriptor::parse(&bytes) else {
            continue;
        };
        ensure!(
            installed.vault_id != *vault_id
                && open_password_slot_of(&installed, credential).is_err(),
            Conflict,
            "the registry already holds this identity or one this credential opens"
        );
    }
    Ok(())
}

/// Validates and, when needed, migrates a restored catalog before its
/// descriptor is installed into the registry.
///
/// The restore namespace is not openable yet, so it does not need an
/// intermediate installed `MIGRATING` descriptor. The caller must update the
/// unpublished descriptor to catalog v17 before making it active when this
/// function returns `true`.
pub fn prepare_restored_catalog(
    catalog: &mut CatalogDb,
    descriptor: &VaultDescriptor,
) -> Result<bool> {
    ensure!(
        descriptor.state == VaultState::Active,
        VaultIncomplete,
        "the restored descriptor is not active"
    );
    let version = schema::recorded_version(catalog.connection())?
        .ok_or_else(|| chur_core::err!(CatalogCorrupt, "the restored catalog schema is absent"))?;
    match (descriptor.catalog.catalog_format_version, version) {
        (CATALOG_FORMAT_VERSION_V1, CATALOG_FORMAT_VERSION_V1) => {
            schema::migrate_v1_to_v2(catalog, &descriptor.vault_id)?;
            schema::migrate_v2_to_v3(catalog)?;
            schema::migrate_v3_to_v4(catalog)?;
            schema::migrate_v4_to_v5(catalog)?;
            schema::migrate_v5_to_v6(catalog)?;
            schema::migrate_v6_to_v7(catalog)?;
            schema::migrate_v7_to_v8(catalog)?;
            schema::migrate_v8_to_v9(catalog)?;
            schema::migrate_v9_to_v10(catalog)?;
            schema::migrate_v10_to_v11(catalog)?;
            schema::migrate_v11_to_v12(catalog)?;
            schema::migrate_v12_to_v13(catalog)?;
            schema::migrate_v13_to_v14(catalog)?;
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V2, CATALOG_FORMAT_VERSION_V2) => {
            schema::migrate_v2_to_v3(catalog)?;
            schema::migrate_v3_to_v4(catalog)?;
            schema::migrate_v4_to_v5(catalog)?;
            schema::migrate_v5_to_v6(catalog)?;
            schema::migrate_v6_to_v7(catalog)?;
            schema::migrate_v7_to_v8(catalog)?;
            schema::migrate_v8_to_v9(catalog)?;
            schema::migrate_v9_to_v10(catalog)?;
            schema::migrate_v10_to_v11(catalog)?;
            schema::migrate_v11_to_v12(catalog)?;
            schema::migrate_v12_to_v13(catalog)?;
            schema::migrate_v13_to_v14(catalog)?;
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V3, CATALOG_FORMAT_VERSION_V3) => {
            schema::migrate_v3_to_v4(catalog)?;
            schema::migrate_v4_to_v5(catalog)?;
            schema::migrate_v5_to_v6(catalog)?;
            schema::migrate_v6_to_v7(catalog)?;
            schema::migrate_v7_to_v8(catalog)?;
            schema::migrate_v8_to_v9(catalog)?;
            schema::migrate_v9_to_v10(catalog)?;
            schema::migrate_v10_to_v11(catalog)?;
            schema::migrate_v11_to_v12(catalog)?;
            schema::migrate_v12_to_v13(catalog)?;
            schema::migrate_v13_to_v14(catalog)?;
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V4, CATALOG_FORMAT_VERSION_V4) => {
            schema::migrate_v4_to_v5(catalog)?;
            schema::migrate_v5_to_v6(catalog)?;
            schema::migrate_v6_to_v7(catalog)?;
            schema::migrate_v7_to_v8(catalog)?;
            schema::migrate_v8_to_v9(catalog)?;
            schema::migrate_v9_to_v10(catalog)?;
            schema::migrate_v10_to_v11(catalog)?;
            schema::migrate_v11_to_v12(catalog)?;
            schema::migrate_v12_to_v13(catalog)?;
            schema::migrate_v13_to_v14(catalog)?;
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V5, CATALOG_FORMAT_VERSION_V5) => {
            schema::migrate_v5_to_v6(catalog)?;
            schema::migrate_v6_to_v7(catalog)?;
            schema::migrate_v7_to_v8(catalog)?;
            schema::migrate_v8_to_v9(catalog)?;
            schema::migrate_v9_to_v10(catalog)?;
            schema::migrate_v10_to_v11(catalog)?;
            schema::migrate_v11_to_v12(catalog)?;
            schema::migrate_v12_to_v13(catalog)?;
            schema::migrate_v13_to_v14(catalog)?;
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V6, CATALOG_FORMAT_VERSION_V6) => {
            schema::migrate_v6_to_v7(catalog)?;
            schema::migrate_v7_to_v8(catalog)?;
            schema::migrate_v8_to_v9(catalog)?;
            schema::migrate_v9_to_v10(catalog)?;
            schema::migrate_v10_to_v11(catalog)?;
            schema::migrate_v11_to_v12(catalog)?;
            schema::migrate_v12_to_v13(catalog)?;
            schema::migrate_v13_to_v14(catalog)?;
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V7, CATALOG_FORMAT_VERSION_V7) => {
            schema::migrate_v7_to_v8(catalog)?;
            schema::migrate_v8_to_v9(catalog)?;
            schema::migrate_v9_to_v10(catalog)?;
            schema::migrate_v10_to_v11(catalog)?;
            schema::migrate_v11_to_v12(catalog)?;
            schema::migrate_v12_to_v13(catalog)?;
            schema::migrate_v13_to_v14(catalog)?;
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V8, CATALOG_FORMAT_VERSION_V8) => {
            schema::migrate_v8_to_v9(catalog)?;
            schema::migrate_v9_to_v10(catalog)?;
            schema::migrate_v10_to_v11(catalog)?;
            schema::migrate_v11_to_v12(catalog)?;
            schema::migrate_v12_to_v13(catalog)?;
            schema::migrate_v13_to_v14(catalog)?;
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V9, CATALOG_FORMAT_VERSION_V9) => {
            schema::migrate_v9_to_v10(catalog)?;
            schema::migrate_v10_to_v11(catalog)?;
            schema::migrate_v11_to_v12(catalog)?;
            schema::migrate_v12_to_v13(catalog)?;
            schema::migrate_v13_to_v14(catalog)?;
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V10, CATALOG_FORMAT_VERSION_V10) => {
            schema::migrate_v10_to_v11(catalog)?;
            schema::migrate_v11_to_v12(catalog)?;
            schema::migrate_v12_to_v13(catalog)?;
            schema::migrate_v13_to_v14(catalog)?;
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V11, CATALOG_FORMAT_VERSION_V11) => {
            schema::migrate_v11_to_v12(catalog)?;
            schema::migrate_v12_to_v13(catalog)?;
            schema::migrate_v13_to_v14(catalog)?;
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V12, CATALOG_FORMAT_VERSION_V12) => {
            schema::migrate_v12_to_v13(catalog)?;
            schema::migrate_v13_to_v14(catalog)?;
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V13, CATALOG_FORMAT_VERSION_V13) => {
            schema::migrate_v13_to_v14(catalog)?;
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V14, CATALOG_FORMAT_VERSION_V14) => {
            schema::migrate_v14_to_v15(catalog)?;
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V15, CATALOG_FORMAT_VERSION_V15) => {
            schema::migrate_v15_to_v16(catalog)?;
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V16, CATALOG_FORMAT_VERSION_V16) => {
            schema::migrate_v16_to_v17(catalog)?;
            catalog.checkpoint()?;
            Ok(true)
        }
        (CATALOG_FORMAT_VERSION_V17, CATALOG_FORMAT_VERSION_V17) => Ok(false),
        _ => bail!(
            MigrationRequired,
            "the restored descriptor and catalog versions are unsupported"
        ),
    }
}

fn open_password_slot(descriptor: &VaultDescriptor, canonical: &[u8]) -> Result<Key> {
    let Some(entry) = descriptor.password_slot() else {
        bail!(VaultIncomplete, "the descriptor carries no password slot");
    };
    let binding = entry.binding(descriptor.vault_id);
    PasswordSlotBody::decode(&entry.slot_body)?.open(&binding, canonical)
}

fn write_temporary(
    root_dir: &VaultRoot,
    entry_name: &RegistryName,
    descriptor: &VaultDescriptor,
    root: &Key,
) -> Result<()> {
    let bytes = descriptor.encode(root)?;
    write_durably(&root_dir.registry_temporary(entry_name), &bytes)
}

fn install_locked_descriptor(
    root_dir: &VaultRoot,
    entry_name: &RegistryName,
    descriptor: &VaultDescriptor,
    root: &Key,
) -> Result<DescriptorLock> {
    write_temporary(root_dir, entry_name, descriptor, root)?;
    let temporary = root_dir.registry_temporary(entry_name);
    let written = std::fs::read(&temporary)
        .map_err(|_| chur_core::err!(IoFailure, "the descriptor could not be read back"))?;
    let verified = VaultDescriptor::authenticate(&written, Some(root))?;
    ensure!(
        &verified == descriptor,
        VaultCorrupt,
        "the written descriptor is not the one that was built"
    );
    let lock = DescriptorLock::acquire(&temporary)?;
    std::fs::rename(&temporary, root_dir.registry_entry(entry_name))
        .map_err(|_| chur_core::err!(IoFailure, "the descriptor could not be installed"))?;
    Ok(lock)
}

#[cfg(test)]
fn install_authenticated_descriptor(
    root_dir: &VaultRoot,
    entry_name: &RegistryName,
    descriptor: &VaultDescriptor,
    root: &Key,
) -> Result<()> {
    let _lock = install_locked_descriptor(root_dir, entry_name, descriptor, root)?;
    sync_directory(&root_dir.registry())
}

/// Writes a file and fsyncs it, which §9 requires before the verification step.
fn write_durably(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| chur_core::err!(IoFailure, "the descriptor directory is absent"))?;
    }
    let mut file = std::fs::File::create(path)
        .map_err(|_| chur_core::err!(IoFailure, "the descriptor could not be created"))?;
    file.write_all(bytes)
        .map_err(|_| chur_core::err!(IoFailure, "the descriptor could not be written"))?;
    file.sync_all()
        .map_err(|_| chur_core::err!(IoFailure, "the descriptor could not be made durable"))?;
    Ok(())
}

/// Makes a rename durable.
///
/// A rename is atomic but not durable: on a crash the directory entry can be
/// absent even though the file it names is intact, which for §9 would mean a
/// vault that vanished rather than one that was never installed.
fn sync_directory(path: &std::path::Path) -> Result<()> {
    crate::paths::sync_directory(path)
}

/// The commitment the catalog descriptor carries, `VAULT_DESCRIPTOR_V1.md` §5.
///
/// SQLCipher writes a random 16-byte salt at the start of the database and
/// never rewrites it, so those bytes are a stable non-secret identity for this
/// catalog file. Committing to them binds the descriptor to one file: a catalog
/// substituted from another vault, or an older copy restored underneath this
/// one, fails at unlock rather than at the first query that reads a row.
/// The §5 commitment over a catalog file's header.
///
/// `docs/format/VAULT_DESCRIPTOR_V1.md` §5 has the descriptor commit to the
/// catalog it names, so a substituted catalog file fails before the first query
/// reads a row from it. A restore checks the same value before it installs a
/// descriptor, which turns "installs and fails at the next unlock" into "does
/// not install".
///
/// # Errors
///
/// Returns [`ChurStatus::IoFailure`] when the file cannot be opened and
/// [`ChurStatus::CatalogCorrupt`] when it is shorter than a header.
pub fn catalog_header_commitment(path: &std::path::Path) -> Result<commit::Commitment> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)
        .map_err(|_| chur_core::err!(IoFailure, "the catalog file could not be opened"))?;
    let mut header = [0u8; 16];
    file.read_exact(&mut header)
        .map_err(|_| chur_core::err!(CatalogCorrupt, "the catalog file has no header"))?;
    Ok(commit::commit(
        chur_crypto::tag::CATALOG_HEADER_COMMITMENT,
        &[&header],
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use super::*;
    use crate::query::{ObjectQuery, page};

    /// A private directory for one test.
    fn scratch() -> VaultRoot {
        let mut path = std::env::temp_dir();
        path.push(format!("chur-vault-{}", random::id().expect("id").to_hex()));
        std::fs::create_dir_all(&path).expect("create");
        VaultRoot::new(path)
    }

    const PASSWORD: &[u8] = b"correct horse battery staple";

    fn rejection<T>(outcome: Result<T>) -> ChurStatus {
        let Err(error) = outcome else {
            panic!("the vault accepted something the specification forbids");
        };
        error.status()
    }

    fn make(root_dir: &VaultRoot) -> Session {
        create(root_dir, PASSWORD, 1_700_000_000_000)
            .expect("create")
            .activate()
            .expect("activate")
    }

    fn install_v1_state(session: &mut Session) -> VaultDescriptor {
        schema::reset_to_v1(session.catalog().expect("catalog")).expect("reset to v1");
        let mut descriptor = session.descriptor.clone();
        descriptor.descriptor_generation += 1;
        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V1;
        install_authenticated_descriptor(
            &session.root_dir,
            &session.entry_name,
            &descriptor,
            session.root_secret().expect("root"),
        )
        .expect("install v1 descriptor");
        descriptor
    }

    fn install_v2_state(session: &mut Session) -> VaultDescriptor {
        schema::reset_to_v2(session.catalog().expect("catalog")).expect("reset to v2");
        let mut descriptor = session.descriptor.clone();
        descriptor.descriptor_generation += 1;
        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V2;
        install_authenticated_descriptor(
            &session.root_dir,
            &session.entry_name,
            &descriptor,
            session.root_secret().expect("root"),
        )
        .expect("install v2 descriptor");
        descriptor
    }

    fn install_v3_state(session: &mut Session) -> VaultDescriptor {
        schema::reset_to_v3(session.catalog().expect("catalog")).expect("reset to v3");
        let mut descriptor = session.descriptor.clone();
        descriptor.descriptor_generation += 1;
        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V3;
        install_authenticated_descriptor(
            &session.root_dir,
            &session.entry_name,
            &descriptor,
            session.root_secret().expect("root"),
        )
        .expect("install v3 descriptor");
        descriptor
    }

    fn install_v5_state(session: &mut Session) -> VaultDescriptor {
        let catalog = session.catalog().expect("catalog");
        schema::reset_to_v3(catalog).expect("reset to v3");
        schema::migrate_v3_to_v4(catalog).expect("migrate v4");
        schema::migrate_v4_to_v5(catalog).expect("migrate v5");
        let mut descriptor = session.descriptor.clone();
        descriptor.descriptor_generation += 1;
        descriptor.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V5;
        install_authenticated_descriptor(
            &session.root_dir,
            &session.entry_name,
            &descriptor,
            session.root_secret().expect("root"),
        )
        .expect("install v5 descriptor");
        descriptor
    }

    fn migrating_descriptor(
        source: &VaultDescriptor,
        to_catalog_format_version: u16,
        migration_generation: u64,
    ) -> VaultDescriptor {
        let mut descriptor = source.clone();
        descriptor.descriptor_generation += 1;
        descriptor.state = VaultState::Migrating;
        descriptor.migration = Some(MigrationDescriptor {
            from_descriptor_version: DESCRIPTOR_VERSION_V1,
            to_descriptor_version: DESCRIPTOR_VERSION_V1,
            from_catalog_format_version: source.catalog.catalog_format_version,
            to_catalog_format_version,
            migration_generation,
            checkpoint_id: random::id().expect("checkpoint id"),
        });
        descriptor
    }

    #[test]
    fn descriptor_replacement_keeps_its_lock_when_directory_sync_fails() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let installed = root_dir.registry_entry(&session.entry_name);
        let mut candidate = session.descriptor.clone();
        candidate.descriptor_generation += 1;
        let expected = candidate
            .encode(session.root_secret().expect("root"))
            .expect("descriptor");
        let result = session.commit_descriptor(candidate.clone(), |_| {
            assert_eq!(
                rejection(DescriptorLock::acquire(&installed)),
                ChurStatus::Conflict,
                "the replacement is already locked at the directory barrier"
            );
            Err(chur_core::err!(
                IoFailure,
                "injected directory synchronization failure"
            ))
        });
        assert_eq!(rejection(result), ChurStatus::IoFailure);
        assert_eq!(
            session.descriptor, candidate,
            "memory follows the installed authenticated state"
        );
        assert_eq!(
            std::fs::read(&installed).expect("installed descriptor"),
            expected
        );
        assert_eq!(
            rejection(DescriptorLock::acquire(&installed)),
            ChurStatus::Conflict
        );
        assert_eq!(
            rejection(unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000)),
            ChurStatus::Conflict
        );
        drop(session);
        unlock_with_password(&root_dir, PASSWORD, 1_700_000_002_000).expect("unlock after close");
    }

    #[test]
    fn changed_descriptor_bytes_cannot_unwrap_a_prelock_slot_snapshot() {
        let root_dir = scratch();
        std::fs::create_dir_all(root_dir.registry()).expect("registry");
        let name = RegistryName::random().expect("name");
        let installed = root_dir.registry_entry(&name);
        std::fs::write(&installed, b"old slot").expect("old snapshot");
        let expected = std::fs::read(&installed).expect("candidate bytes");
        std::fs::write(&installed, b"new slot").expect("updated snapshot");
        assert_eq!(
            rejection(DescriptorLock::acquire_snapshot(&installed, &expected)),
            ChurStatus::Conflict
        );
        DescriptorLock::acquire_snapshot(&installed, b"new slot").expect("current slot snapshot");
    }

    #[test]
    fn slot_and_password_updates_keep_the_current_descriptor_exclusive() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        session.add_recovery_slot().expect("recovery slot update");
        assert_eq!(
            rejection(unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000)),
            ChurStatus::Conflict
        );
        let replacement = b"new synthetic exclusive session password";
        session
            .replace_password(replacement, Argon2Params::v1_default())
            .expect("password update");
        assert_eq!(
            rejection(unlock_with_password(
                &root_dir,
                replacement,
                1_700_000_002_000
            )),
            ChurStatus::Conflict
        );
        drop(session);
        assert_eq!(
            rejection(unlock_with_password(&root_dir, PASSWORD, 1_700_000_003_000)),
            ChurStatus::AuthenticationFailed
        );
        unlock_with_password(&root_dir, replacement, 1_700_000_004_000)
            .expect("replacement password after close");
    }

    #[cfg(unix)]
    #[test]
    fn an_opened_previous_descriptor_inode_cannot_bypass_its_replacement_lock() {
        let root_dir = scratch();
        std::fs::create_dir_all(root_dir.registry()).expect("registry");
        let name = RegistryName::random().expect("name");
        let installed = root_dir.registry_entry(&name);
        let temporary = root_dir.registry_temporary(&name);
        std::fs::write(&installed, b"previous").expect("old descriptor");
        let old = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&installed)
            .expect("open old inode");
        std::fs::write(&temporary, b"replacement").expect("new descriptor");
        let replacement_lock = DescriptorLock::acquire(&temporary).expect("lock replacement");
        std::fs::rename(&temporary, &installed).expect("install replacement");
        assert_eq!(
            rejection(DescriptorLock::lock_opened(old, &installed)),
            ChurStatus::Conflict,
            "the old file must not grant a lock on the current descriptor"
        );
        drop(replacement_lock);
    }

    #[test]
    fn a_created_session_keeps_the_installed_descriptor_exclusive() {
        let root_dir = scratch();
        let session = make(&root_dir);
        assert_eq!(
            rejection(unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000)),
            ChurStatus::Conflict,
            "an active creation session must hold the descriptor lock"
        );
        drop(session);
        unlock_with_password(&root_dir, PASSWORD, 1_700_000_002_000).expect("unlock after close");
    }

    #[test]
    fn a_created_vault_unlocks_with_its_password() {
        let root_dir = scratch();
        let session = make(&root_dir);
        let vault_id = session.vault_id();
        drop(session);

        let mut reopened =
            unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000).expect("unlock");
        assert_eq!(reopened.vault_id(), vault_id);
        assert!(reopened.is_unlocked());
        page(
            reopened.catalog().expect("catalog"),
            &ObjectQuery::timeline(),
        )
        .expect("query");
    }

    #[test]
    fn a_lock_records_the_catalog_generation_the_session_leaves_behind() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        session
            .catalog()
            .expect("catalog")
            .transaction(schema::bump_generation)
            .expect("bump");
        session.lock().expect("lock");
        assert_eq!(session.descriptor.catalog.catalog_generation, 2);
    }

    #[test]
    fn an_unlock_records_the_generation_a_dead_session_left_behind() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        session
            .catalog()
            .expect("catalog")
            .transaction(schema::bump_generation)
            .expect("bump");
        // The session dies without lock(): the descriptor still records the
        // creation generation, so the unlock tolerates the catalog running
        // ahead and records what it actually holds.
        drop(session);
        let mut session =
            unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000).expect("unlock");
        assert_eq!(session.descriptor.catalog.catalog_generation, 2);
        session.lock().expect("lock");
        assert!(unlock_with_password(&root_dir, PASSWORD, 1_700_000_002_000).is_ok());
    }

    #[test]
    fn a_catalog_older_than_the_descriptor_records_is_refused_at_unlock() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let catalog_path = root_dir.catalog(
            &session.descriptor.object_store.opaque_root_path_id,
            &session.descriptor.catalog.opaque_catalog_path_id,
        );
        // Checkpoint the creation state into the file, then keep it: a valid
        // older copy of the same catalog, whose header commitment matches
        // every later generation. That is why §5 needs catalog_generation and
        // cannot rely on the header.
        session.lock().expect("lock");
        let rolled_back = std::fs::read(&catalog_path).expect("read the catalog");

        let mut session =
            unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000).expect("unlock");
        session
            .catalog()
            .expect("catalog")
            .transaction(schema::bump_generation)
            .expect("bump");
        session.lock().expect("lock");
        assert_eq!(session.descriptor.catalog.catalog_generation, 2);
        drop(session);

        std::fs::write(&catalog_path, rolled_back).expect("restore the old copy");
        let status = rejection(unlock_with_password(&root_dir, PASSWORD, 1_700_000_002_000));
        assert_eq!(status, ChurStatus::VaultCorrupt);
    }

    #[test]
    fn an_unlock_conflicts_while_another_process_holds_the_descriptor() {
        // §8.1: the advisory lock on the descriptor file is taken before any
        // slot unwrap. A holder the unlock cannot displace - another open file
        // description, which is what a second process is - makes every unlock
        // path conflict instead of double-opening the vault.
        let root_dir = scratch();
        let session = make(&root_dir);
        let entry_name = session.entry_name.clone();
        drop(session);

        let held = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root_dir.registry_entry(&entry_name))
            .expect("open the descriptor");
        held.try_lock().expect("hold the descriptor lock");
        let status = rejection(unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000));
        assert_eq!(status, ChurStatus::Conflict);

        // The lock releases with its holder, and the vault unlocks again.
        drop(held);
        assert!(unlock_with_password(&root_dir, PASSWORD, 1_700_000_002_000).is_ok());
    }

    #[test]
    fn a_v15_to_v16_capability_migration_resumes_before_and_after_sql_commit() {
        for sql_committed in [false, true] {
            let root_dir = scratch();
            let mut session = make(&root_dir);
            session
                .catalog()
                .expect("catalog")
                .connection()
                .execute_batch("DROP TABLE playback_positions; UPDATE vault_state SET catalog_format_version = 15")
                .expect("v15 catalog");
            let mut source = session.descriptor.clone();
            source.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V15;
            let migrating = migrating_descriptor(&source, CATALOG_FORMAT_VERSION_V16, 15);
            install_authenticated_descriptor(
                &root_dir,
                &session.entry_name,
                &migrating,
                session.root_secret().expect("root"),
            )
            .expect("authenticated migration");
            if sql_committed {
                schema::migrate_v15_to_v16(session.catalog().expect("catalog"))
                    .expect("SQL commit");
            }
            drop(session);
            let reopened =
                unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000).expect("resume");
            assert_eq!(
                reopened.descriptor.catalog.catalog_format_version,
                CATALOG_FORMAT_VERSION_V17
            );
            assert_eq!(reopened.descriptor.state, VaultState::Active);
            assert!(reopened.descriptor.migration.is_none());
        }
    }

    #[test]
    fn a_v16_to_v17_playback_migration_resumes_before_and_after_sql_commit() {
        for sql_committed in [false, true] {
            let root_dir = scratch();
            let mut session = make(&root_dir);
            session
                .catalog()
                .expect("catalog")
                .connection()
                .execute_batch("DROP TABLE playback_positions; UPDATE vault_state SET catalog_format_version = 16")
                .expect("v16 catalog");
            let mut source = session.descriptor.clone();
            source.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V16;
            let migrating = migrating_descriptor(&source, CATALOG_FORMAT_VERSION_V17, 16);
            install_authenticated_descriptor(
                &root_dir,
                &session.entry_name,
                &migrating,
                session.root_secret().expect("root"),
            )
            .expect("authenticated migration");
            if sql_committed {
                schema::migrate_v16_to_v17(session.catalog().expect("catalog"))
                    .expect("SQL commit");
            }
            drop(session);
            let reopened =
                unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000).expect("resume");
            assert_eq!(
                reopened.descriptor.catalog.catalog_format_version,
                CATALOG_FORMAT_VERSION_V17
            );
            assert_eq!(reopened.descriptor.state, VaultState::Active);
            assert!(reopened.descriptor.migration.is_none());
        }
    }

    #[test]
    fn an_active_v1_vault_migrates_before_unlock_returns() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let source = install_v1_state(&mut session);
        drop(session);

        let reopened = unlock_with_password(&root_dir, PASSWORD, 2).expect("migrate and unlock");
        assert_eq!(
            reopened.descriptor.catalog.catalog_format_version,
            CATALOG_FORMAT_VERSION_V17
        );
        assert_eq!(reopened.descriptor.state, VaultState::Active);
        assert!(reopened.descriptor.migration.is_none());
        assert_eq!(
            reopened.descriptor.descriptor_generation,
            source.descriptor_generation
                + 2 * u64::from(CATALOG_FORMAT_VERSION_V17 - source.catalog.catalog_format_version)
        );
    }

    #[test]
    fn a_v1_to_v2_migration_resumes_then_reaches_v11() {
        for sql_committed in [false, true] {
            let root_dir = scratch();
            let mut session = make(&root_dir);
            let source = install_v1_state(&mut session);
            let migrating = migrating_descriptor(&source, CATALOG_FORMAT_VERSION_V2, 1);
            install_authenticated_descriptor(
                &root_dir,
                &session.entry_name,
                &migrating,
                session.root_secret().expect("root"),
            )
            .expect("install migrating descriptor");
            if sql_committed {
                let vault_id = session.descriptor.vault_id;
                schema::migrate_v1_to_v2(session.catalog().expect("catalog"), &vault_id)
                    .expect("commit catalog v2");
            }
            drop(session);

            let reopened = unlock_with_password(&root_dir, PASSWORD, 2).expect("resume migration");
            assert_eq!(reopened.descriptor.state, VaultState::Active);
            assert_eq!(
                reopened.descriptor.catalog.catalog_format_version,
                CATALOG_FORMAT_VERSION_V17
            );
            assert!(reopened.descriptor.migration.is_none());
            assert_eq!(
                reopened.descriptor.descriptor_generation,
                migrating.descriptor_generation
                    + 1
                    + 2 * u64::from(CATALOG_FORMAT_VERSION_V17 - CATALOG_FORMAT_VERSION_V2)
            );
        }
    }

    #[test]
    fn a_v2_to_v3_migration_resumes_then_reaches_v11() {
        for sql_committed in [false, true] {
            let root_dir = scratch();
            let mut session = make(&root_dir);
            let source = install_v2_state(&mut session);
            let migrating = migrating_descriptor(&source, CATALOG_FORMAT_VERSION_V3, 2);
            install_authenticated_descriptor(
                &root_dir,
                &session.entry_name,
                &migrating,
                session.root_secret().expect("root"),
            )
            .expect("install migrating descriptor");
            if sql_committed {
                schema::migrate_v2_to_v3(session.catalog().expect("catalog"))
                    .expect("commit catalog v3");
            }
            drop(session);

            let reopened = unlock_with_password(&root_dir, PASSWORD, 2).expect("resume migration");
            assert_eq!(reopened.descriptor.state, VaultState::Active);
            assert_eq!(
                reopened.descriptor.catalog.catalog_format_version,
                CATALOG_FORMAT_VERSION_V17
            );
            assert!(reopened.descriptor.migration.is_none());
            assert_eq!(
                reopened.descriptor.descriptor_generation,
                migrating.descriptor_generation
                    + 1
                    + 2 * u64::from(CATALOG_FORMAT_VERSION_V17 - CATALOG_FORMAT_VERSION_V3)
            );
        }
    }

    #[test]
    fn a_v3_to_v4_migration_resumes_on_either_side_of_the_sql_commit() {
        for sql_committed in [false, true] {
            let root_dir = scratch();
            let mut session = make(&root_dir);
            let source = install_v3_state(&mut session);
            let migrating = migrating_descriptor(&source, CATALOG_FORMAT_VERSION_V4, 3);
            install_authenticated_descriptor(
                &root_dir,
                &session.entry_name,
                &migrating,
                session.root_secret().expect("root"),
            )
            .expect("install migrating descriptor");
            if sql_committed {
                schema::migrate_v3_to_v4(session.catalog().expect("catalog"))
                    .expect("commit catalog v4");
            }
            drop(session);

            let reopened = unlock_with_password(&root_dir, PASSWORD, 2).expect("resume migration");
            assert_eq!(reopened.descriptor.state, VaultState::Active);
            assert_eq!(
                reopened.descriptor.catalog.catalog_format_version,
                CATALOG_FORMAT_VERSION_V17
            );
            assert!(reopened.descriptor.migration.is_none());
            assert_eq!(
                reopened.descriptor.descriptor_generation,
                migrating.descriptor_generation
                    + 1
                    + 2 * u64::from(CATALOG_FORMAT_VERSION_V17 - CATALOG_FORMAT_VERSION_V4)
            );
        }
    }

    #[test]
    fn a_v5_to_v6_migration_resumes_on_either_side_of_the_sql_commit() {
        for sql_committed in [false, true] {
            let root_dir = scratch();
            let mut session = make(&root_dir);
            let source = install_v5_state(&mut session);
            let migrating = migrating_descriptor(&source, CATALOG_FORMAT_VERSION_V6, 5);
            install_authenticated_descriptor(
                &root_dir,
                &session.entry_name,
                &migrating,
                session.root_secret().expect("root"),
            )
            .expect("install migrating descriptor");
            if sql_committed {
                schema::migrate_v5_to_v6(session.catalog().expect("catalog"))
                    .expect("commit catalog v6");
            }
            drop(session);

            let reopened = unlock_with_password(&root_dir, PASSWORD, 2).expect("resume migration");
            assert_eq!(reopened.descriptor.state, VaultState::Active);
            assert_eq!(
                reopened.descriptor.catalog.catalog_format_version,
                CATALOG_FORMAT_VERSION_V17
            );
            assert!(reopened.descriptor.migration.is_none());
            assert_eq!(
                reopened.descriptor.descriptor_generation,
                migrating.descriptor_generation
                    + 1
                    + 2 * u64::from(CATALOG_FORMAT_VERSION_V17 - CATALOG_FORMAT_VERSION_V6)
            );
        }
    }

    #[test]
    fn a_wrong_password_is_one_external_result() {
        let root_dir = scratch();
        drop(make(&root_dir));
        assert_eq!(
            rejection(unlock_with_password(&root_dir, b"wrong", 1)),
            ChurStatus::AuthenticationFailed
        );
    }

    #[test]
    fn an_empty_registry_fails_the_same_way_as_a_wrong_password() {
        let root_dir = scratch();
        assert_eq!(
            rejection(unlock_with_password(&root_dir, PASSWORD, 1)),
            ChurStatus::AuthenticationFailed,
            "an absent vault must not be distinguishable from a wrong credential"
        );
    }

    #[test]
    fn a_password_valid_for_a_sibling_identity_fails_like_any_other() {
        let root_dir = scratch();
        drop(make(&root_dir));
        let sibling = create(&root_dir, b"the other identity", 1)
            .expect("create")
            .activate()
            .expect("activate");
        let sibling_id = sibling.vault_id();
        drop(sibling);

        // Each password opens exactly its own identity and neither leaks which.
        let first = unlock_with_password(&root_dir, PASSWORD, 1).expect("unlock");
        let second = unlock_with_password(&root_dir, b"the other identity", 1).expect("unlock");
        assert_ne!(first.vault_id(), second.vault_id());
        assert!(second.vault_id() == sibling_id || first.vault_id() == sibling_id);
        drop(first);
        drop(second);
        assert_eq!(
            rejection(unlock_with_password(&root_dir, b"neither", 1)),
            ChurStatus::AuthenticationFailed
        );
    }

    #[test]
    fn the_registry_admits_only_two_identities() {
        let root_dir = scratch();
        drop(make(&root_dir));
        drop(
            create(&root_dir, b"the second identity", 1)
                .expect("create")
                .activate()
                .expect("activate"),
        );
        assert_eq!(
            rejection(create(&root_dir, b"the third identity", 1)),
            ChurStatus::ResourceLimitExceeded
        );
    }

    #[test]
    fn creation_interrupted_before_activation_leaves_no_openable_vault() {
        let root_dir = scratch();
        let creation = create(&root_dir, PASSWORD, 1).expect("create");
        // The temporary descriptor exists and is not a candidate.
        assert!(root_dir.registry_names().expect("names").is_empty());
        assert_eq!(
            rejection(unlock_with_password(&root_dir, PASSWORD, 1)),
            ChurStatus::AuthenticationFailed
        );
        creation.abandon().expect("abandon");
        assert_eq!(root_dir.sweep_temporary().expect("sweep"), 0);
        assert!(root_dir.registry_names().expect("names").is_empty());
    }

    #[test]
    fn an_abandoned_creation_leaves_no_directory_behind() {
        let root_dir = scratch();
        let creation = create(&root_dir, PASSWORD, 1).expect("create");
        let store = creation.descriptor.object_store.opaque_root_path_id;
        assert!(root_dir.vault(&store).exists());
        creation.abandon().expect("abandon");
        assert!(!root_dir.vault(&store).exists());
    }

    #[test]
    fn a_dropped_creation_is_swept_rather_than_left_as_a_candidate() {
        let root_dir = scratch();
        drop(create(&root_dir, PASSWORD, 1).expect("create"));
        assert!(root_dir.registry_names().expect("names").is_empty());
        assert_eq!(root_dir.sweep_temporary().expect("sweep"), 1);
    }

    #[test]
    fn the_recovery_slot_offered_during_creation_unlocks_the_vault() {
        let root_dir = scratch();
        let mut creation = create(&root_dir, PASSWORD, 1).expect("create");
        let secret = creation.add_recovery_slot().expect("recovery");
        let phrase = recovery::to_phrase(&secret);
        let session = creation.activate().expect("activate");
        let vault_id = session.vault_id();
        drop(session);

        let reopened = unlock_with_recovery(&root_dir, &phrase, 1).expect("recover");
        assert_eq!(reopened.vault_id(), vault_id);
    }

    #[test]
    fn a_recovery_slot_added_after_activation_unlocks_the_vault() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let secret = session.add_recovery_slot().expect("recovery");
        let phrase = recovery::to_phrase(&secret);
        let vault_id = session.vault_id();
        drop(session);
        assert_eq!(
            unlock_with_recovery(&root_dir, &phrase, 1)
                .expect("recover")
                .vault_id(),
            vault_id
        );
    }

    /// `RECOVERY.md` §8: a confirmed new phrase replaces the old one, in the
    /// one descriptor generation that commits it.
    #[test]
    fn a_confirmed_recovery_slot_retires_the_old_phrase() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let old = recovery::to_phrase(&session.add_recovery_slot().expect("recovery"));
        let before = session.descriptor.descriptor_generation;
        let new = recovery::to_phrase(&session.begin_recovery_slot().expect("begin"));
        session.finish_recovery_slot().expect("commit");
        assert_eq!(session.descriptor.descriptor_generation, before + 1);
        let recovery: Vec<u64> = session
            .slots()
            .into_iter()
            .filter(|(_, family, _)| *family == SlotType::Recovery)
            .map(|(_, _, generation)| generation)
            .collect();
        assert_eq!(recovery, vec![2]);
        drop(session);

        assert_eq!(
            rejection(unlock_with_recovery(&root_dir, &old, 1)),
            ChurStatus::AuthenticationFailed
        );
        unlock_with_recovery(&root_dir, &new, 1).expect("the new phrase opens the vault");
    }

    #[test]
    fn a_wrong_recovery_phrase_is_the_same_external_result() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        session.add_recovery_slot().expect("recovery");
        drop(session);
        let other: Key = random::secret::<32>().expect("secret");
        let phrase = recovery::to_phrase(&other);
        assert_eq!(
            rejection(unlock_with_recovery(&root_dir, &phrase, 1)),
            ChurStatus::AuthenticationFailed
        );
    }

    #[test]
    fn an_apple_keychain_slot_unlocks_the_vault() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let item = random::id().expect("id");
        let secret = session.add_apple_keychain_slot(item).expect("slot");
        let vault_id = session.vault_id();
        drop(session);
        assert_eq!(
            unlock_with_apple_keychain(&root_dir, &secret, 1)
                .expect("unlock")
                .vault_id(),
            vault_id
        );
        let other: Key = random::secret::<32>().expect("secret");
        assert_eq!(
            rejection(unlock_with_apple_keychain(&root_dir, &other, 1)),
            ChurStatus::AuthenticationFailed
        );
    }

    /// A stand-in for the Keystore cipher.
    ///
    /// Rust never performs this AEAD and never verifies it, so the algorithm is
    /// not what these tests are about: what they check is that the alias, the
    /// nonce, the wrapped bytes, and the AAD travel out and back unchanged, and
    /// that a wrap performed under one AAD does not open under another. A
    /// keyed hash over the AAD gives that property without adding an AES-GCM
    /// dependency the library itself does not use.
    fn keystore_wrap(aad: &[u8], root: &[u8; 32]) -> ([u8; GCM_NONCE_LEN], [u8; WRAPPED_KEY_LEN]) {
        let nonce = random::array::<GCM_NONCE_LEN>().expect("nonce");
        let mask = commit::commit(b"chur/test/keystore-stand-in", &[&nonce, aad]);
        let mut wrapped = [0u8; WRAPPED_KEY_LEN];
        for (index, byte) in root.iter().enumerate() {
            wrapped[index] = byte ^ mask[index];
        }
        wrapped[32..].copy_from_slice(&mask[..16]);
        (nonce, wrapped)
    }

    fn keystore_unwrap(material: &KeystoreUnlockMaterial) -> Option<Key> {
        let mask = commit::commit(
            b"chur/test/keystore-stand-in",
            &[&material.gcm_nonce, &material.aad],
        );
        if material.wrapped_root_secret[32..] != mask[..16] {
            return None;
        }
        let mut root = [0u8; 32];
        for (index, byte) in root.iter_mut().enumerate() {
            *byte = material.wrapped_root_secret[index] ^ mask[index];
        }
        Some(Key::new(root))
    }

    #[test]
    fn an_android_keystore_slot_unlocks_the_vault() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let vault_id = session.vault_id();
        let enrollment = session.begin_android_keystore_slot().expect("begin");
        let (nonce, wrapped) = keystore_wrap(&enrollment.aad, enrollment.root_secret.expose());
        session
            .finish_android_keystore_slot(nonce, wrapped)
            .expect("finish");
        drop(session);

        let material = android_keystore_material(&root_dir).expect("material");
        assert_eq!(material.len(), 1);
        let root = keystore_unwrap(&material[0]).expect("the wrap opens under the stored AAD");
        assert_eq!(
            unlock_with_android_keystore(&root_dir, &root, 1)
                .expect("unlock")
                .vault_id(),
            vault_id
        );
    }

    #[test]
    fn a_root_that_is_not_the_vault_root_is_the_same_external_result() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let enrollment = session.begin_android_keystore_slot().expect("begin");
        let (nonce, wrapped) = keystore_wrap(&enrollment.aad, enrollment.root_secret.expose());
        session
            .finish_android_keystore_slot(nonce, wrapped)
            .expect("finish");
        drop(session);

        let other: Key = random::secret::<32>().expect("secret");
        assert_eq!(
            rejection(unlock_with_android_keystore(&root_dir, &other, 1)),
            ChurStatus::AuthenticationFailed
        );
    }

    #[test]
    fn a_vault_with_no_keystore_slot_is_never_opened_by_a_root() {
        let root_dir = scratch();
        let session = make(&root_dir);
        drop(session);
        let material = android_keystore_material(&root_dir).expect("material");
        assert!(material.is_empty());
        let any: Key = random::secret::<32>().expect("secret");
        assert_eq!(
            rejection(unlock_with_android_keystore(&root_dir, &any, 1)),
            ChurStatus::AuthenticationFailed
        );
    }

    #[test]
    fn the_stored_aad_is_the_one_the_wrap_received() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let enrollment = session.begin_android_keystore_slot().expect("begin");
        let (nonce, wrapped) = keystore_wrap(&enrollment.aad, enrollment.root_secret.expose());
        session
            .finish_android_keystore_slot(nonce, wrapped)
            .expect("finish");
        drop(session);

        let material = android_keystore_material(&root_dir).expect("material");
        assert_eq!(material[0].aad, enrollment.aad);
        assert_eq!(material[0].alias, enrollment.alias);
        // The AAD binds the slot generation, so a value from a different slot
        // identity cannot open the wrap even with the right nonce.
        let mut forged = KeystoreUnlockMaterial {
            alias: material[0].alias.clone(),
            aad: material[0].aad.clone(),
            gcm_nonce: material[0].gcm_nonce,
            wrapped_root_secret: material[0].wrapped_root_secret,
        };
        forged.aad[0] ^= 0x01;
        assert!(keystore_unwrap(&forged).is_none());
    }

    #[test]
    fn a_wrap_that_was_never_begun_is_refused() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        assert_eq!(
            rejection(
                session.finish_android_keystore_slot([0u8; GCM_NONCE_LEN], [0u8; WRAPPED_KEY_LEN])
            ),
            ChurStatus::Conflict
        );
    }

    #[test]
    fn only_one_identity_can_hold_a_device_slot() {
        let root_dir = scratch();
        let mut first = make(&root_dir);
        let enrollment = first.begin_android_keystore_slot().expect("begin");
        let (nonce, wrapped) = keystore_wrap(&enrollment.aad, enrollment.root_secret.expose());
        first
            .finish_android_keystore_slot(nonce, wrapped)
            .expect("finish");
        // The identity that holds the slot can still replace it, which is what
        // a policy change does.
        let enrollment = first.begin_android_keystore_slot().expect("replace");
        let (nonce, wrapped) = keystore_wrap(&enrollment.aad, enrollment.root_secret.expose());
        first
            .finish_android_keystore_slot(nonce, wrapped)
            .expect("finish the replacement");
        drop(first);

        let mut second = create(&root_dir, b"the other identity", 1)
            .expect("create")
            .activate()
            .expect("activate");
        let before = second.slots().len();
        assert_eq!(
            rejection(second.begin_android_keystore_slot().map(|_| ())),
            ChurStatus::PlatformKeyUnavailable
        );
        let item = random::id().expect("id");
        assert_eq!(
            rejection(second.add_apple_keychain_slot(item).map(|_| ())),
            ChurStatus::PlatformKeyUnavailable
        );
        assert_eq!(second.slots().len(), before);
        drop(second);

        // Every device slot in the registry belongs to the first identity.
        let material = android_keystore_material(&root_dir).expect("material");
        assert_eq!(material.len(), 2);
    }

    #[test]
    fn a_legacy_install_with_two_device_slots_can_still_replace_each() {
        let root_dir = scratch();
        let mut first = make(&root_dir);
        let enrollment = first.begin_android_keystore_slot().expect("begin");
        let (nonce, wrapped) = keystore_wrap(&enrollment.aad, enrollment.root_secret.expose());
        first
            .finish_android_keystore_slot(nonce, wrapped)
            .expect("finish");

        // An install from before the rule: the second identity committed its
        // own device slot while the first already held one.
        let mut second = create(&root_dir, b"the other identity", 1)
            .expect("create")
            .activate()
            .expect("activate");
        let slot_id = random::id().expect("id");
        let generation = second.next_slot_generation(SlotType::AndroidKeystore);
        let binding = SlotBinding::v1(
            second.vault_id(),
            slot_id,
            SlotType::AndroidKeystore,
            generation,
        );
        let alias = random::array::<KEYSTORE_ALIAS_LEN>()
            .expect("alias")
            .to_vec();
        let body =
            AndroidKeystoreSlotBody::new(&binding, alias, [1; GCM_NONCE_LEN], [2; WRAPPED_KEY_LEN])
                .expect("body");
        let legacy = KeySlotDescriptor::v1(
            slot_id,
            SlotType::AndroidKeystore,
            generation,
            body.encode(),
        )
        .expect("slot");
        second
            .commit_slots(|slots| slots.push(legacy))
            .expect("commit the legacy slot");

        // Each identity may still replace its own slot, which a policy change
        // needs; neither is blocked by the other.
        second
            .begin_android_keystore_slot()
            .expect("the second identity replaces its slot");
        first
            .begin_android_keystore_slot()
            .expect("the first identity replaces its slot");
        second
            .add_apple_keychain_slot(random::id().expect("id"))
            .expect("a second family in the same identity");
    }

    #[test]
    fn an_unreadable_entry_does_not_block_an_enrollment() {
        let root_dir = scratch();
        drop(make(&root_dir));
        let mut second = create(&root_dir, b"the other identity", 1)
            .expect("create")
            .activate()
            .expect("activate");
        let other = root_dir
            .registry_names()
            .expect("names")
            .into_iter()
            .find(|name| *name != second.entry_name)
            .expect("the first entry");
        // A directory where the entry file was cannot be read as a file.
        let path = root_dir.registry_entry(&other);
        std::fs::remove_file(&path).expect("remove");
        std::fs::create_dir(&path).expect("directory");
        second.begin_android_keystore_slot().expect("begin");
    }

    #[test]
    fn a_new_or_changed_password_needs_twelve_characters() {
        let root_dir = scratch();
        assert_eq!(
            rejection(create(&root_dir, b"1234a", 1)),
            ChurStatus::InvalidInput
        );
        // Eleven scalar values in more than twelve bytes is still too short.
        assert_eq!(
            rejection(create(
                &root_dir,
                "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}abcde".as_bytes(),
                1
            )),
            ChurStatus::InvalidInput
        );
        let mut session = create(&root_dir, b"123456789012", 1)
            .expect("a 12-digit PIN")
            .activate()
            .expect("activate");
        assert_eq!(
            rejection(session.replace_password(b"short", Argon2Params::v1_default())),
            ChurStatus::InvalidInput
        );
        session
            .replace_password(b"a longer passphrase", Argon2Params::v1_default())
            .expect("change");
        drop(session);
        // An unlock is never held to the rule: a short attempt is only a wrong
        // credential, so a slot made before the rule still opens.
        assert_eq!(
            rejection(unlock_with_password(&root_dir, b"short", 1)),
            ChurStatus::AuthenticationFailed
        );
    }

    #[test]
    fn a_malformed_keystore_slot_does_not_hide_the_others() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let vault_id = session.vault_id();
        let generation = session.next_slot_generation(SlotType::AndroidKeystore);
        let damaged = KeySlotDescriptor::v1(
            random::id().expect("id"),
            SlotType::AndroidKeystore,
            generation,
            vec![0xff; 96],
        )
        .expect("slot");
        session
            .commit_slots(|slots| slots.push(damaged))
            .expect("commit the damaged slot");
        let enrollment = session.begin_android_keystore_slot().expect("begin");
        let (nonce, wrapped) = keystore_wrap(&enrollment.aad, enrollment.root_secret.expose());
        session
            .finish_android_keystore_slot(nonce, wrapped)
            .expect("finish");
        drop(session);

        let material = android_keystore_material(&root_dir).expect("material");
        assert_eq!(material.len(), 1, "the damaged body is skipped");
        let root = keystore_unwrap(&material[0]).expect("the good slot unwraps");
        assert_eq!(
            unlock_with_android_keystore(&root_dir, &root, 1)
                .expect("unlock")
                .vault_id(),
            vault_id
        );
    }

    #[test]
    fn an_identity_with_no_device_slot_does_not_block_another() {
        let root_dir = scratch();
        drop(make(&root_dir));
        let mut second = create(&root_dir, b"the other identity", 1)
            .expect("create")
            .activate()
            .expect("activate");
        let item = random::id().expect("id");
        second.add_apple_keychain_slot(item).expect("slot");
    }

    #[test]
    fn an_abandoned_enrollment_leaves_the_descriptor_alone() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let before = session.slots().len();
        session.begin_android_keystore_slot().expect("begin");
        drop(session);

        assert!(
            android_keystore_material(&root_dir)
                .expect("material")
                .is_empty()
        );
        let reopened = unlock_with_password(&root_dir, PASSWORD, 1).expect("unlock");
        assert_eq!(reopened.slots().len(), before);
    }

    #[test]
    fn the_last_portable_slot_cannot_be_removed() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let item = random::id().expect("id");
        session.add_apple_keychain_slot(item).expect("slot");
        let password_slot = session
            .descriptor
            .password_slot()
            .expect("a password slot")
            .slot_id;
        assert_eq!(
            rejection(session.remove_slot(&password_slot)),
            ChurStatus::Conflict,
            "removing the last portable slot left no verified recovery path"
        );
        session.add_recovery_slot().expect("recovery");
        session.remove_slot(&password_slot).expect("now removable");
    }

    #[test]
    fn a_password_replacement_verifies_before_the_old_slot_goes() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        session
            .replace_password(b"a new password", Argon2Params::v1_default())
            .expect("replace");
        drop(session);
        assert!(
            unlock_with_password(&root_dir, b"a new password", 1)
                .expect("unlock")
                .is_unlocked()
        );
        assert_eq!(
            rejection(unlock_with_password(&root_dir, PASSWORD, 1)),
            ChurStatus::AuthenticationFailed
        );
    }

    #[test]
    fn a_slot_change_advances_the_descriptor_generation() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        assert_eq!(session.descriptor.descriptor_generation, 1);
        session.add_recovery_slot().expect("recovery");
        assert_eq!(session.descriptor.descriptor_generation, 2);
    }

    #[test]
    fn a_v1_store_raises_its_container_ceiling_once_and_keeps_it() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        assert_eq!(session.descriptor.object_store.container_version_ceiling, 2);

        // A vault created before ADR-0066 records a ceiling of 1.
        let mut old = session.descriptor.clone();
        old.descriptor_generation += 1;
        old.object_store.container_version_ceiling = 1;
        session
            .commit_descriptor(old, sync_directory)
            .expect("record a v1 ceiling");
        let generation = session.descriptor.descriptor_generation;

        session.admit_container_version(1).expect("v1 is admitted");
        assert_eq!(session.descriptor.descriptor_generation, generation);
        session
            .admit_container_version(2)
            .expect("raise the ceiling");
        assert_eq!(session.descriptor.object_store.container_version_ceiling, 2);
        assert_eq!(session.descriptor.descriptor_generation, generation + 1);
        session
            .admit_container_version(2)
            .expect("already admitted");
        assert_eq!(session.descriptor.descriptor_generation, generation + 1);
        drop(session);

        let reopened = unlock_with_password(&root_dir, PASSWORD, 2).expect("unlock");
        assert_eq!(
            reopened.descriptor.object_store.container_version_ceiling,
            2
        );
    }

    #[test]
    fn a_substituted_catalog_file_fails_at_unlock() {
        let first = scratch();
        let second = scratch();
        let session = make(&first);
        let store = session.object_store_id();
        let catalog_id = session.descriptor.catalog.opaque_catalog_path_id;
        drop(session);

        let stranger = make(&second);
        let other_store = stranger.object_store_id();
        let other_catalog = stranger.descriptor.catalog.opaque_catalog_path_id;
        drop(stranger);

        std::fs::copy(
            second.catalog(&other_store, &other_catalog),
            first.catalog(&store, &catalog_id),
        )
        .expect("substitute the catalog");
        assert_eq!(
            rejection(unlock_with_password(&first, PASSWORD, 1)),
            ChurStatus::VaultCorrupt,
            "a catalog from another vault opened"
        );
    }

    #[test]
    fn lock_closes_the_catalog_and_clears_the_scratch_directory() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let scratch_dir = root_dir.scratch(&session.object_store_id());
        std::fs::write(scratch_dir.join("aabbccdd"), b"decoded frame").expect("scratch");
        assert!(session.is_unlocked());

        session.lock().expect("lock");
        assert!(!session.is_unlocked());
        assert_eq!(
            rejection(session.catalog()),
            ChurStatus::VaultLocked,
            "the catalog survived the lock"
        );
        let remaining = std::fs::read_dir(&scratch_dir).expect("read").count();
        assert_eq!(remaining, 0, "a scratch entry survived the lock");
    }

    #[test]
    fn failed_generation_recording_still_releases_lock_and_clears_scratch() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let scratch_dir = root_dir.scratch(&session.object_store_id());
        std::fs::write(scratch_dir.join("aabbccdd"), b"decoded frame").expect("scratch");
        session.descriptor.catalog.catalog_generation = 0;
        session.descriptor.descriptor_generation = u64::MAX;

        assert_eq!(rejection(session.lock()), ChurStatus::VaultCorrupt);
        assert!(!session.is_unlocked());
        assert!(session.descriptor_lock.is_none());
        assert_eq!(std::fs::read_dir(&scratch_dir).expect("read").count(), 0);
    }

    #[test]
    fn locking_twice_is_not_a_failure() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        session.lock().expect("lock");
        session.lock().expect("lock again");
    }

    /// A locked session mints no credential and releases no root.
    ///
    /// `PLAINTEXT_LIFECYCLE.md` §8 step 6 zeroizes the root at lock, and step 2
    /// prevents new private operations. `lock` used to do neither: it took the
    /// catalog and left the root, so `is_unlocked()` answered false while every
    /// slot mutator still worked. A recovery secret minted here opens the vault
    /// from any device, and the Keystore enrolment hands out the root itself.
    #[test]
    fn a_locked_session_mints_no_credential() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        session.lock().expect("lock");
        assert!(!session.is_unlocked());
        assert_eq!(
            rejection(session.add_recovery_slot()),
            ChurStatus::VaultLocked,
            "a locked session minted a recovery secret"
        );
        assert_eq!(
            rejection(session.begin_android_keystore_slot()),
            ChurStatus::VaultLocked,
            "a locked session handed out the vault root"
        );
        assert_eq!(
            rejection(session.root_secret()),
            ChurStatus::VaultLocked,
            "a locked session released the root"
        );
    }

    #[test]
    fn a_descriptor_that_fails_the_parser_is_skipped_without_a_credential() {
        let root_dir = scratch();
        drop(make(&root_dir));
        let damaged = RegistryName::random().expect("name");
        std::fs::write(root_dir.registry_entry(&damaged), b"not a descriptor").expect("write");
        // The vault still opens: §11 skips the unparsable entry before any
        // credential is used and attributes its failure to no credential.
        assert!(unlock_with_password(&root_dir, PASSWORD, 1).is_ok());
    }

    #[test]
    fn the_catalog_of_a_new_vault_is_installed_and_empty() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let result = page(
            session.catalog().expect("catalog"),
            &ObjectQuery::timeline(),
        )
        .expect("page");
        assert!(result.objects.is_empty());
        assert_eq!(result.total_count, 0);
    }
    #[test]
    fn an_authenticated_v8_vault_migrates_to_v9_and_keeps_media_tables() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        session.catalog().expect("catalog").transaction(|tx| {
            tx.execute_batch("DROP TABLE IF EXISTS playback_positions; DROP TABLE IF EXISTS own_sync_pending_album_memberships; DROP TABLE IF EXISTS content_index; DROP TABLE private_note_search; DROP TABLE private_note_history_files; DROP TABLE private_note_history_blobs; DROP TABLE private_note_history; DROP TABLE private_note_organization; DROP TABLE private_note_attachments; DROP TABLE private_notes; UPDATE vault_state SET catalog_format_version=8;")
                .expect("historical v8 fixture"); Ok(())
        }).expect("v8 catalog");
        let mut descriptor = session.descriptor.clone();
        descriptor.descriptor_generation += 1;
        descriptor.catalog.catalog_format_version =
            chur_format::constants::CATALOG_FORMAT_VERSION_V8;
        install_authenticated_descriptor(
            &session.root_dir,
            &session.entry_name,
            &descriptor,
            session.root_secret().expect("root"),
        )
        .expect("authenticated v8 descriptor");
        drop(session);
        let mut reopened =
            unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000).expect("v8 migration");
        assert_eq!(
            reopened.descriptor.catalog.catalog_format_version,
            CATALOG_FORMAT_VERSION_V17
        );
        let note = crate::notes::save(
            reopened.catalog().expect("catalog"),
            None,
            0,
            "title",
            "body",
            false,
            crate::notes::NoteFormat::PlainText,
            1_700_000_001_000,
        )
        .expect("save");
        let id = note.id;
        drop(note);
        reopened.lock().expect("lock");
        drop(reopened);
        let reopened =
            unlock_with_password(&root_dir, PASSWORD, 1_700_000_002_000).expect("reopen");
        assert_eq!(
            crate::notes::get(reopened.catalog_ref().expect("catalog"), &id)
                .expect("durable")
                .body,
            "body"
        );
    }
    #[test]
    fn a_v8_to_v9_migration_resumes_on_either_side_of_the_sql_commit() {
        for sql_committed in [false, true] {
            let root_dir = scratch();
            let mut session = make(&root_dir);
            session.catalog().expect("catalog").transaction(|tx| {
                tx.execute_batch("DROP TABLE IF EXISTS playback_positions; DROP TABLE IF EXISTS own_sync_pending_album_memberships; DROP TABLE IF EXISTS content_index; DROP TABLE private_note_search; DROP TABLE private_note_history_files; DROP TABLE private_note_history_blobs; DROP TABLE private_note_history; DROP TABLE private_note_organization; DROP TABLE private_note_attachments; DROP TABLE private_notes; UPDATE vault_state SET catalog_format_version=8;").expect("v8 fixture"); Ok(())
            }).expect("fixture");
            let mut source = session.descriptor.clone();
            source.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V8;
            let migrating = migrating_descriptor(&source, CATALOG_FORMAT_VERSION_V9, 8);
            install_authenticated_descriptor(
                &root_dir,
                &session.entry_name,
                &migrating,
                session.root_secret().expect("root"),
            )
            .expect("migrating descriptor");
            if sql_committed {
                schema::migrate_v8_to_v9(session.catalog().expect("catalog")).expect("SQL commit");
            }
            drop(session);
            let reopened =
                unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000).expect("resume");
            assert_eq!(
                reopened.descriptor.catalog.catalog_format_version,
                CATALOG_FORMAT_VERSION_V17
            );
            assert_eq!(reopened.descriptor.state, VaultState::Active);
            assert!(reopened.descriptor.migration.is_none());
            assert!(
                crate::notes::page(
                    reopened.catalog_ref().expect("catalog"),
                    "",
                    false,
                    50,
                    None
                )
                .expect("notes table")
                .notes
                .is_empty()
            );
        }
    }
    #[test]
    fn a_v13_workspace_migration_resumes_before_and_after_sql_commit() {
        for sql_committed in [false, true] {
            let root_dir = scratch();
            let mut session = make(&root_dir);
            let note = crate::notes::save(
                session.catalog().expect("catalog"),
                None,
                0,
                "Legacy",
                "# exact",
                false,
                crate::notes::NoteFormat::Markdown,
                1_700_000_000_000,
            )
            .expect("note");
            session.catalog().expect("catalog").connection().execute_batch("DROP TABLE IF EXISTS playback_positions; DROP TABLE private_note_history_files; DROP TABLE private_note_history_blobs; DROP TABLE private_note_history; DROP TABLE private_note_organization; UPDATE vault_state SET catalog_format_version=13;").expect("v13 fixture");
            let mut source = session.descriptor.clone();
            source.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V13;
            let migrating = migrating_descriptor(&source, CATALOG_FORMAT_VERSION_V14, 13);
            install_authenticated_descriptor(
                &root_dir,
                &session.entry_name,
                &migrating,
                session.root_secret().expect("root"),
            )
            .expect("descriptor");
            if sql_committed {
                schema::migrate_v13_to_v14(session.catalog().expect("catalog"))
                    .expect("SQL commit");
            }
            drop(session);
            let mut reopened =
                unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000).expect("resume");
            assert_eq!(
                reopened.descriptor.catalog.catalog_format_version,
                CATALOG_FORMAT_VERSION_V17
            );
            assert_eq!(
                crate::notes::get(reopened.catalog_ref().expect("catalog"), &note.id)
                    .expect("note")
                    .body,
                "# exact"
            );
            let n = crate::note_workspace::set_organization(
                reopened.catalog().expect("catalog"),
                &note.id,
                note.revision,
                "Folder",
                &["tag"],
                1_700_000_001_000,
            )
            .expect("organization");
            reopened.lock().expect("lock");
            drop(reopened);
            let reopened = unlock_with_password(&root_dir, PASSWORD, 1_700_000_002_000)
                .expect("reopen encrypted workspace");
            assert_eq!(
                crate::note_workspace::get_organization(
                    reopened.catalog_ref().expect("catalog"),
                    &n.id
                )
                .expect("organization")
                .folder,
                "Folder"
            );
            assert_eq!(
                crate::note_workspace::history(reopened.catalog_ref().expect("catalog"), &n.id)
                    .expect("history")[0]
                    .note
                    .body,
                "# exact"
            );
        }
    }

    #[test]
    fn a_v12_attachment_migration_resumes_before_and_after_sql_commit() {
        for sql_committed in [false, true] {
            let root_dir = scratch();
            let mut session = make(&root_dir);
            let note = crate::notes::save(
                session.catalog().expect("catalog"),
                None,
                0,
                "Legacy",
                "# source",
                false,
                crate::notes::NoteFormat::Markdown,
                1_700_000_000_000,
            )
            .expect("note");
            session.catalog().expect("catalog").connection().execute_batch("DROP TABLE IF EXISTS playback_positions; DROP TABLE private_note_history_files; DROP TABLE private_note_history_blobs; DROP TABLE private_note_history; DROP TABLE private_note_organization; DROP TABLE private_note_attachments; UPDATE vault_state SET catalog_format_version=12;").expect("v12");
            let mut source = session.descriptor.clone();
            source.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V12;
            let migrating = migrating_descriptor(&source, CATALOG_FORMAT_VERSION_V13, 12);
            install_authenticated_descriptor(
                &root_dir,
                &session.entry_name,
                &migrating,
                session.root_secret().expect("root"),
            )
            .expect("descriptor");
            if sql_committed {
                schema::migrate_v12_to_v13(session.catalog().expect("catalog"))
                    .expect("SQL commit");
            }
            drop(session);
            let reopened =
                unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000).expect("resume");
            assert_eq!(
                reopened.descriptor.catalog.catalog_format_version,
                CATALOG_FORMAT_VERSION_V17
            );
            assert_eq!(reopened.descriptor.state, VaultState::Active);
            assert!(reopened.descriptor.migration.is_none());
            let n = crate::notes::get(reopened.catalog_ref().expect("catalog"), &note.id)
                .expect("note");
            assert_eq!(n.body, note.body);
            assert_eq!(n.revision, note.revision);
            assert_eq!(n.attachment_count, 0);
        }
    }

    #[test]
    fn a_v11_note_format_migration_resumes_before_and_after_sql_commit() {
        for sql_committed in [false, true] {
            let root_dir = scratch();
            let mut session = make(&root_dir);
            let note = crate::notes::save(
                session.catalog().expect("catalog"),
                None,
                0,
                "Legacy",
                "# literal source",
                true,
                crate::notes::NoteFormat::PlainText,
                1_700_000_000_000,
            )
            .expect("note");
            session.catalog().expect("catalog").connection().execute_batch("DROP TABLE IF EXISTS playback_positions; DROP TABLE private_note_history_files; DROP TABLE private_note_history_blobs; DROP TABLE private_note_history; DROP TABLE private_note_organization; DROP TABLE private_note_attachments; ALTER TABLE private_notes DROP COLUMN format; UPDATE vault_state SET catalog_format_version=11;").expect("v11 catalog");
            let mut source = session.descriptor.clone();
            source.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V11;
            let migrating = migrating_descriptor(&source, CATALOG_FORMAT_VERSION_V12, 11);
            install_authenticated_descriptor(
                &root_dir,
                &session.entry_name,
                &migrating,
                session.root_secret().expect("root"),
            )
            .expect("authenticated descriptor");
            if sql_committed {
                schema::migrate_v11_to_v12(session.catalog().expect("catalog"))
                    .expect("SQL commit");
            }
            drop(session);
            let reopened = unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000)
                .expect("resume note format migration");
            assert_eq!(
                reopened.descriptor.catalog.catalog_format_version,
                CATALOG_FORMAT_VERSION_V17
            );
            assert_eq!(reopened.descriptor.state, VaultState::Active);
            assert!(reopened.descriptor.migration.is_none());
            let restored = crate::notes::get(reopened.catalog_ref().expect("catalog"), &note.id)
                .expect("legacy note");
            assert_eq!(restored.format, crate::notes::NoteFormat::PlainText);
            assert_eq!(restored.body, "# literal source");
            assert_eq!(restored.revision, note.revision);
        }
    }

    #[test]
    fn a_v10_to_v11_migration_resumes_before_and_after_the_sql_commit() {
        for sql_committed in [false, true] {
            let root_dir = scratch();
            let mut session = make(&root_dir);
            session
                .catalog()
                .expect("catalog")
                .connection()
                .execute_batch(
                    "DROP TABLE IF EXISTS playback_positions; DROP TABLE private_note_history_files; DROP TABLE private_note_history_blobs; DROP TABLE private_note_history; DROP TABLE private_note_organization; DROP TABLE private_note_attachments; ALTER TABLE private_notes DROP COLUMN format; DROP TABLE own_sync_pending_album_memberships;
                 UPDATE vault_state SET catalog_format_version = 10;",
                )
                .expect("v10 catalog");
            let mut source = session.descriptor.clone();
            source.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V10;
            let migrating = migrating_descriptor(&source, CATALOG_FORMAT_VERSION_V11, 10);
            install_authenticated_descriptor(
                &root_dir,
                &session.entry_name,
                &migrating,
                session.root_secret().expect("root"),
            )
            .expect("authenticated migrating descriptor");
            if sql_committed {
                schema::migrate_v10_to_v11(session.catalog().expect("catalog"))
                    .expect("SQL commit");
            }
            drop(session);
            let reopened = unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000)
                .expect("resume album intent migration");
            assert_eq!(
                reopened.descriptor.catalog.catalog_format_version,
                CATALOG_FORMAT_VERSION_V17
            );
            assert_eq!(reopened.descriptor.state, VaultState::Active);
            assert!(reopened.descriptor.migration.is_none());
            let count: i64 = reopened
                .catalog_ref()
                .expect("catalog")
                .connection()
                .query_row(
                    "SELECT count(*) FROM own_sync_pending_album_memberships",
                    [],
                    |row| row.get(0),
                )
                .expect("pending table");
            assert_eq!(count, 0);
        }
    }

    #[test]
    fn restore_prepares_v10_and_preserves_current_v15_without_an_implicit_future_downgrade() {
        let root_dir = scratch();
        let mut session = make(&root_dir);
        let descriptor = session.descriptor.clone();
        assert!(
            !prepare_restored_catalog(session.catalog().expect("catalog"), &descriptor)
                .expect("current restore")
        );
        session
            .catalog()
            .expect("catalog")
            .connection()
            .execute_batch(
                "DROP TABLE IF EXISTS playback_positions; DROP TABLE private_note_history_files; DROP TABLE private_note_history_blobs; DROP TABLE private_note_history; DROP TABLE private_note_organization; DROP TABLE private_note_attachments; ALTER TABLE private_notes DROP COLUMN format; DROP TABLE own_sync_pending_album_memberships;
             UPDATE vault_state SET catalog_format_version = 10;",
            )
            .expect("v10 restore fixture");
        let mut legacy = descriptor.clone();
        legacy.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V10;
        assert!(
            prepare_restored_catalog(session.catalog().expect("catalog"), &legacy)
                .expect("v10 restore migration")
        );
        assert_eq!(
            schema::recorded_version(session.catalog().expect("catalog").connection())
                .expect("version"),
            Some(CATALOG_FORMAT_VERSION_V17)
        );
        session
            .catalog()
            .expect("catalog")
            .connection()
            .execute("UPDATE vault_state SET catalog_format_version = 18", [])
            .expect("future catalog fixture");
        assert_eq!(
            rejection(prepare_restored_catalog(
                session.catalog().expect("catalog"),
                &descriptor
            )),
            ChurStatus::MigrationRequired
        );
        assert_eq!(
            schema::recorded_version(session.catalog().expect("catalog").connection())
                .expect("version"),
            Some(18)
        );
    }

    #[test]
    fn a_v9_to_v10_migration_resumes_before_and_after_the_sql_commit() {
        for sql_committed in [false, true] {
            let root_dir = scratch();
            let mut session = make(&root_dir);
            session.catalog().unwrap().transaction(|tx|{tx.execute_batch("DROP TABLE IF EXISTS playback_positions; DROP TABLE private_note_history_files; DROP TABLE private_note_history_blobs; DROP TABLE private_note_history; DROP TABLE private_note_organization; DROP TABLE private_note_attachments; ALTER TABLE private_notes DROP COLUMN format; DROP TABLE own_sync_pending_album_memberships; DROP TABLE content_index; UPDATE vault_state SET catalog_format_version=9;").unwrap();Ok(())}).unwrap();
            let mut source = session.descriptor.clone();
            source.catalog.catalog_format_version = CATALOG_FORMAT_VERSION_V9;
            let migrating = migrating_descriptor(&source, CATALOG_FORMAT_VERSION_V10, 9);
            install_authenticated_descriptor(
                &root_dir,
                &session.entry_name,
                &migrating,
                session.root_secret().unwrap(),
            )
            .unwrap();
            if sql_committed {
                schema::migrate_v9_to_v10(session.catalog().unwrap()).unwrap();
            }
            drop(session);
            let reopened = unlock_with_password(&root_dir, PASSWORD, 1_700_000_001_000)
                .expect("resume content migration");
            assert_eq!(
                reopened.descriptor.catalog.catalog_format_version,
                CATALOG_FORMAT_VERSION_V17
            );
            assert_eq!(reopened.descriptor.state, VaultState::Active);
            assert!(reopened.descriptor.migration.is_none());
            assert!(
                crate::content_index::candidates(reopened.catalog_ref().unwrap(), None, 100, false)
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

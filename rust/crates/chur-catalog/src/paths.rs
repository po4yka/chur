//! The vault storage layout.
//!
//! `docs/ARCHITECTURE.md` §14.4 gives the shape and states which parts of it
//! are normative: the `registry/` directory, its entry naming, its cap of two,
//! and the order candidates are enumerated in are fixed by
//! `docs/format/VAULT_DESCRIPTOR_V1.md` §11 and ADR-0030. The rest of the names
//! describe responsibilities.
//!
//! Every name below the registry is the lowercase hexadecimal of an opaque
//! random identifier, which is `naming_profile_id` `0x0001`: no user filename,
//! no album, no date, and nothing derived from a key reaches a path.

use std::path::{Path, PathBuf};

use chur_core::{Id, Result, bail, ensure};

/// The suffix of a registry entry, `docs/format/VAULT_DESCRIPTOR_V1.md` §11.
pub const REGISTRY_SUFFIX: &str = ".vd";

/// The suffix of a descriptor being written but not yet installed.
///
/// It is deliberately not `.vd`: §11 enumerates every `.vd` entry as an unlock
/// candidate, and a half-written descriptor must never be one. A crash leaves
/// this file behind and [`VaultRoot::sweep_temporary`] removes it.
pub const REGISTRY_TEMP_SUFFIX: &str = ".vd.tmp";

/// The number of hexadecimal characters in a registry entry name, §11.
pub const REGISTRY_NAME_LEN: usize = 32;

/// The largest number of registry entries, §11: one real identity and one decoy.
pub const REGISTRY_MAX: usize = 2;

/// The root of every Chur private directory.
#[derive(Debug, Clone)]
pub struct VaultRoot {
    base: PathBuf,
}

impl VaultRoot {
    /// Names the root directory. It is created by [`VaultRoot::prepare`].
    #[must_use]
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    /// The root directory.
    #[must_use]
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// The registry directory.
    #[must_use]
    pub fn registry(&self) -> PathBuf {
        self.base.join("registry")
    }

    /// The directory that holds the directory of every vault identity.
    #[must_use]
    pub fn vaults(&self) -> PathBuf {
        self.base.join("vaults")
    }

    /// The directory of one vault identity.
    #[must_use]
    pub fn vault(&self, root_path_id: &Id) -> PathBuf {
        self.vaults().join(hex(root_path_id))
    }

    /// The catalog database of one vault identity.
    #[must_use]
    pub fn catalog(&self, root_path_id: &Id, catalog_path_id: &Id) -> PathBuf {
        self.vault(root_path_id)
            .join(format!("{}.db", hex(catalog_path_id)))
    }

    /// The committed container namespace.
    #[must_use]
    pub fn objects(&self, root_path_id: &Id) -> PathBuf {
        self.vault(root_path_id).join("objects")
    }

    /// The temporary container namespace of `OBJECT_CONTAINER_V1.md` §14.
    #[must_use]
    pub fn incoming(&self, root_path_id: &Id) -> PathBuf {
        self.vault(root_path_id).join("incoming")
    }

    /// Where a container that failed a structural check is held.
    #[must_use]
    pub fn quarantine(&self, root_path_id: &Id) -> PathBuf {
        self.vault(root_path_id).join("quarantine")
    }

    /// The plaintext scratch directory of `PLAINTEXT_LIFECYCLE.md` §5.
    #[must_use]
    pub fn scratch(&self, root_path_id: &Id) -> PathBuf {
        self.vault(root_path_id).join("scratch")
    }

    /// Opaque, disposable inbound records fetched while the vault is locked.
    #[must_use]
    pub fn sync_staging(&self, root_path_id: &Id) -> PathBuf {
        self.vault(root_path_id).join("sync-staging")
    }

    /// Locked ciphertext inbox selected only by the public sync vault identifier.
    #[must_use]
    pub fn sync_inbox(&self, vault_id: &Id) -> PathBuf {
        self.base.join("sync-staging").join(hex(vault_id))
    }

    /// One committed container.
    ///
    /// The first byte of the identifier is a directory level. A vault holds up
    /// to 1000000 objects under `docs/format/CATALOG_SCHEMA_V1.md` §21, and one
    /// directory of a million entries is slow to enumerate on every platform;
    /// 256 subdirectories of about four thousand is not. The identifier is
    /// CSPRNG output, so the level discloses nothing and the split is even.
    #[must_use]
    pub fn container(&self, root_path_id: &Id, container_path_id: &Id) -> PathBuf {
        let name = hex(container_path_id);
        self.objects(root_path_id).join(&name[..2]).join(&name[2..])
    }

    /// One temporary container.
    #[must_use]
    pub fn temporary_container(&self, root_path_id: &Id, temp_path_id: &Id) -> PathBuf {
        self.incoming(root_path_id).join(hex(temp_path_id))
    }

    /// One registry entry.
    #[must_use]
    pub fn registry_entry(&self, entry_name: &RegistryName) -> PathBuf {
        self.registry()
            .join(format!("{}{REGISTRY_SUFFIX}", entry_name.0))
    }

    /// The temporary name of one registry entry.
    #[must_use]
    pub fn registry_temporary(&self, entry_name: &RegistryName) -> PathBuf {
        self.registry()
            .join(format!("{}{REGISTRY_TEMP_SUFFIX}", entry_name.0))
    }

    /// Creates the directories a vault identity needs and claims them.
    ///
    /// The claim is taken after the vault directory exists and before anything
    /// is written into it, so a sweep that holds the claim first makes this
    /// call fail rather than remove what it writes. The caller holds it until
    /// its descriptor is installed or its work is removed; see
    /// [`DirectoryClaim`].
    pub fn prepare(&self, root_path_id: &Id) -> Result<DirectoryClaim> {
        let vault = self.vault(root_path_id);
        for directory in [self.registry(), vault.clone()] {
            std::fs::create_dir_all(&directory).map_err(|_| {
                chur_core::err!(IoFailure, "a vault directory could not be created")
            })?;
        }
        let claim = DirectoryClaim::take(&vault)?;
        for directory in [
            self.objects(root_path_id),
            self.incoming(root_path_id),
            self.quarantine(root_path_id),
            self.scratch(root_path_id),
            self.sync_staging(root_path_id),
        ] {
            std::fs::create_dir_all(&directory).map_err(|_| {
                chur_core::err!(IoFailure, "a vault directory could not be created")
            })?;
        }
        Ok(claim)
    }

    /// The registry entries, in the enumeration order §11 fixes.
    ///
    /// The order is ascending filename bytes, which depends on neither creation
    /// time, nor modification time, nor which candidate is real. A name that is
    /// not 32 lowercase hexadecimal characters plus `.vd` is not an entry and
    /// is skipped without counting toward the cap, because it was never one.
    pub fn registry_names(&self) -> Result<Vec<RegistryName>> {
        let directory = self.registry();
        let listing = match std::fs::read_dir(&directory) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => bail!(IoFailure, "the registry could not be read"),
        };
        let mut names = Vec::new();
        for entry in listing {
            let entry = entry
                .map_err(|_| chur_core::err!(IoFailure, "a registry entry could not be read"))?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let Some(stem) = name.strip_suffix(REGISTRY_SUFFIX) else {
                continue;
            };
            if let Some(parsed) = RegistryName::parse(stem) {
                names.push(parsed);
            }
        }
        names.sort_by(|left, right| left.0.cmp(&right.0));
        ensure!(
            names.len() <= REGISTRY_MAX,
            ResourceLimitExceeded,
            "the registry holds more than the two entries §11 admits"
        );
        Ok(names)
    }

    /// Removes every descriptor that was being written when a process stopped.
    ///
    /// §9 of the descriptor specification requires a crash before `ACTIVE` to
    /// leave nothing openable. A temporary descriptor is never enumerated, so
    /// it is already not openable; this makes it also not present.
    pub fn sweep_temporary(&self) -> Result<usize> {
        let directory = self.registry();
        let listing = match std::fs::read_dir(&directory) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(_) => bail!(IoFailure, "the registry could not be read"),
        };
        // A live creator or restore owns its temporary descriptors.
        let _registry_claim = match DirectoryClaim::take(&directory) {
            Ok(claim) => claim,
            Err(error) if error.status() == chur_core::ChurStatus::Conflict => return Ok(0),
            Err(error) => return Err(error),
        };
        let mut removed = 0;
        for entry in listing {
            let entry = entry
                .map_err(|_| chur_core::err!(IoFailure, "a registry entry could not be read"))?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if name.ends_with(REGISTRY_TEMP_SUFFIX) {
                std::fs::remove_file(entry.path()).map_err(|_| {
                    chur_core::err!(IoFailure, "a temporary descriptor could not be removed")
                })?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// Makes the entries of a directory durable: a rename, a creation, or a removal.
///
/// A rename is atomic but not durable. Until the directory itself is synced, a
/// crash can lose the entry even though the file it names is intact. An error
/// is returned, except the results that mean the platform cannot sync a
/// directory (`EINVAL`, `ENOTSUP`, `EOPNOTSUPP`). There the rename stays atomic
/// and the loss window is the platform's own, and no retry can close it.
///
/// # Errors
///
/// Returns [`chur_core::ChurStatus::IoFailure`] when the directory cannot be
/// opened or the sync fails for any other reason.
pub fn sync_directory(path: &Path) -> Result<()> {
    let directory = std::fs::File::open(path)
        .map_err(|_| chur_core::err!(IoFailure, "a directory could not be opened for a sync"))?;
    match directory.sync_all() {
        Ok(()) => Ok(()),
        Err(error) if sync_is_unsupported(&error) => Ok(()),
        Err(_) => Err(chur_core::err!(
            IoFailure,
            "a directory could not be made durable"
        )),
    }
}

/// The `errno` values that mean "this file system cannot sync a directory".
#[cfg(any(target_os = "linux", target_os = "android"))]
const SYNC_UNSUPPORTED: &[i32] = &[22, 95];
#[cfg(target_vendor = "apple")]
const SYNC_UNSUPPORTED: &[i32] = &[22, 45, 102];
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const SYNC_UNSUPPORTED: &[i32] = &[22];

fn sync_is_unsupported(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::Unsupported
        || error
            .raw_os_error()
            .is_some_and(|code| SYNC_UNSUPPORTED.contains(&code))
}

/// The name of the lock file inside a vault directory, see [`DirectoryClaim`].
const CLAIM_NAME: &str = "lock";

/// The advisory lock on a vault directory whose descriptor is not installed.
///
/// `docs/interop/FFI_CONTRACT.md` §8.1 expects a second process on one root (a
/// split Android process or a second launch) and keeps it off a vault with an
/// exclusive advisory lock on the descriptor file. A creation that waits for
/// its recovery phrase, or a restore that is still writing, has no descriptor
/// to lock, so it holds the same kind of lock on a file inside its directory,
/// from [`VaultRoot::prepare`] until its descriptor is installed or its work is
/// removed. The orphan sweep of `crate::vault` removes only a directory whose
/// claim it can take. The lock lives on the open file description, so a crash
/// releases it, and the file is never read.
#[must_use = "the directory is claimed only while this value lives"]
pub struct DirectoryClaim(#[expect(dead_code)] std::fs::File);

impl DirectoryClaim {
    /// Takes the claim on `directory`, creating its lock file if it is absent.
    ///
    /// A claim that another open file description holds returns `CONFLICT`.
    pub fn take(directory: &Path) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join(CLAIM_NAME))
            .map_err(|_| chur_core::err!(IoFailure, "the vault directory could not be claimed"))?;
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => {
                chur_core::err!(Conflict, "the vault directory is claimed by other work")
            }
            std::fs::TryLockError::Error(_) => {
                chur_core::err!(IoFailure, "the vault directory could not be claimed")
            }
        })?;
        Ok(Self(file))
    }
}

/// The 32 hexadecimal characters of one registry entry, §11.
///
/// The bytes come from the CSPRNG when the descriptor is first written and are
/// unrelated to `vault_id`, to any key, and to creation order, so the name
/// discloses nothing and two identities cannot be told apart by their filenames.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegistryName(String);

impl RegistryName {
    /// Draws a fresh name.
    pub fn random() -> Result<Self> {
        let bytes = chur_crypto::random::array::<16>()?;
        let mut name = String::with_capacity(REGISTRY_NAME_LEN);
        for byte in bytes {
            name.push_str(HEX[usize::from(byte >> 4)]);
            name.push_str(HEX[usize::from(byte & 0x0f)]);
        }
        Ok(Self(name))
    }

    /// Accepts exactly 32 lowercase hexadecimal characters.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        if value.len() != REGISTRY_NAME_LEN {
            return None;
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        Some(Self(value.to_owned()))
    }

    /// The name without its suffix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

const HEX: [&str; 16] = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
];

fn hex(id: &Id) -> String {
    id.to_hex()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use super::*;
    use chur_crypto::random;

    fn scratch_root() -> VaultRoot {
        let mut path = std::env::temp_dir();
        path.push(format!("chur-paths-{}", random::id().expect("id").to_hex()));
        std::fs::create_dir_all(&path).expect("create");
        VaultRoot::new(path)
    }

    #[test]
    fn a_directory_sync_reports_failures_and_tolerates_only_unsupported() {
        let root = scratch_root();
        sync_directory(root.base()).expect("a real directory syncs");
        assert_eq!(
            sync_directory(&root.base().join("absent"))
                .err()
                .map(|error| error.status()),
            Some(chur_core::ChurStatus::IoFailure)
        );
        assert!(sync_is_unsupported(&std::io::Error::from_raw_os_error(22)));
        assert!(sync_is_unsupported(&std::io::Error::from(
            std::io::ErrorKind::Unsupported
        )));
        // EIO and ENOSPC are real failures of the device, not of the platform.
        assert!(!sync_is_unsupported(&std::io::Error::from_raw_os_error(5)));
        assert!(!sync_is_unsupported(&std::io::Error::from_raw_os_error(28)));
        std::fs::remove_dir_all(root.base()).expect("cleanup");
    }

    #[test]
    fn a_container_path_is_sharded_by_its_first_byte() {
        let root = scratch_root();
        let store = random::id().expect("id");
        let container = Id::new([0xab; 16]).expect("id");
        let path = root.container(&store, &container);
        assert!(path.ends_with("ab/ababababababababababababababab"));
    }

    #[test]
    fn no_path_carries_a_name_that_is_not_hexadecimal() {
        let root = scratch_root();
        let store = random::id().expect("id");
        let paths = [
            root.vault(&store),
            root.catalog(&store, &random::id().expect("id")),
            root.container(&store, &random::id().expect("id")),
            root.temporary_container(&store, &random::id().expect("id")),
        ];
        for path in paths {
            for component in path.strip_prefix(root.base()).expect("under the root") {
                let name = component.to_string_lossy();
                let stem = name.strip_suffix(".db").unwrap_or(&name);
                assert!(
                    matches!(stem, "vaults" | "objects" | "incoming")
                        || stem.bytes().all(|byte| byte.is_ascii_hexdigit()),
                    "{name} is neither a fixed label nor hexadecimal"
                );
            }
        }
    }

    #[test]
    fn a_registry_name_is_exactly_thirty_two_lowercase_hexadecimal_characters() {
        let name = RegistryName::random().expect("name");
        assert_eq!(name.as_str().len(), 32);
        assert!(RegistryName::parse(name.as_str()).is_some());
        for bad in [
            "",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789ABCDEF0123456789abcdef",
            "0123456789abcdef0123456789abcdeg",
        ] {
            assert!(RegistryName::parse(bad).is_none(), "{bad} was accepted");
        }
    }

    #[test]
    fn the_registry_enumerates_in_ascending_filename_order() {
        let root = scratch_root();
        std::fs::create_dir_all(root.registry()).expect("create");
        let names = ["ff".repeat(16), "00".repeat(16), "aa".repeat(16)];
        for name in &names {
            std::fs::write(root.registry().join(format!("{name}.vd")), b"x").expect("write");
        }
        let listed: Vec<String> = root
            .registry_names()
            .err()
            .map(|_| Vec::new())
            .unwrap_or_default();
        assert!(listed.is_empty(), "three entries exceed the §11 cap");

        std::fs::remove_file(root.registry().join(format!("{}.vd", names[0]))).expect("remove");
        let listed = root.registry_names().expect("names");
        assert_eq!(
            listed.iter().map(RegistryName::as_str).collect::<Vec<_>>(),
            vec!["00".repeat(16), "aa".repeat(16)]
        );
    }

    #[test]
    fn a_file_that_is_not_an_entry_is_skipped_and_does_not_count() {
        let root = scratch_root();
        std::fs::create_dir_all(root.registry()).expect("create");
        for name in [
            "not-a-descriptor",
            "0123456789abcdef0123456789abcdef.vd.tmp",
            "README",
        ] {
            std::fs::write(root.registry().join(name), b"x").expect("write");
        }
        let real = RegistryName::random().expect("name");
        std::fs::write(root.registry_entry(&real), b"x").expect("write");
        let listed = root.registry_names().expect("names");
        assert_eq!(listed, vec![real]);
    }

    #[test]
    fn a_temporary_descriptor_is_never_a_candidate_and_is_swept() {
        let root = scratch_root();
        std::fs::create_dir_all(root.registry()).expect("create");
        let name = RegistryName::random().expect("name");
        std::fs::write(root.registry_temporary(&name), b"half written").expect("write");
        assert!(root.registry_names().expect("names").is_empty());
        assert_eq!(root.sweep_temporary().expect("sweep"), 1);
        assert!(!root.registry_temporary(&name).exists());
    }

    #[test]
    fn an_absent_registry_enumerates_as_empty_rather_than_failing() {
        let root = VaultRoot::new(std::env::temp_dir().join("chur-absent-registry-probe"));
        assert!(root.registry_names().expect("names").is_empty());
        assert_eq!(root.sweep_temporary().expect("sweep"), 0);
    }
}

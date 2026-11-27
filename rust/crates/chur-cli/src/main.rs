//! Chur command-line foundation.
//!
//! `docs/ARCHITECTURE.md` §9 makes the CLI a first-class component: the storage
//! format must be testable and recoverable independently of Android and iOS UI
//! code. It never prints a plaintext secret by default; the vector generator is
//! the one place that writes key material, and everything it writes is a fixed
//! test-only constant under `test-vectors/`.
//!
//! Subcommands land with their owning format crates. Today the binary can
//! generate and verify the deterministic vector set, inspect a container
//! structurally with no key, and answer the ABI handshake.

mod backup;
mod bench;
mod manifest;
mod output;
mod vault;
mod vectors;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use chur_format::container::{Layout, PublicPreamble};

use crate::manifest::{Generator, Manifest, Outcome, Vector};

/// The default vector directory, relative to the repository root.
const DEFAULT_VECTOR_DIR: &str = "test-vectors/v1";

#[derive(Parser)]
#[command(
    name = "chur-cli",
    about = "Chur vault tooling: vectors, inspection, verification",
    long_about = None,
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate or verify the deterministic test-vector set.
    Vectors {
        #[command(subcommand)]
        action: VectorAction,
    },
    /// Inspect an object container.
    Object {
        #[command(subcommand)]
        action: ObjectAction,
    },
    /// Print the ABI handshake this build answers.
    Abi,
    /// Measure a Phase 0 candidate set.
    Bench {
        #[command(subcommand)]
        action: BenchAction,
    },
    /// Create and restore a portable backup package.
    ///
    /// `docs/format/BACKUP_FORMAT_V1.md` §1 makes the package portable across
    /// Android, iOS, and this binary, so a package written here restores on a
    /// phone and one written on a phone restores here.
    Backup {
        /// The storage root.
        #[arg(long, global = true)]
        root: Option<PathBuf>,
        /// A file holding the password, when `CHUR_PASSWORD` is not set.
        #[arg(long, global = true)]
        password_file: Option<PathBuf>,
        #[command(subcommand)]
        action: BackupAction,
    },
    /// Create, unlock, and operate a vault.
    ///
    /// A password is read from `CHUR_PASSWORD` or `--password-file`, never from
    /// an argument: an argument is in `/proc`, in the shell history, and in
    /// `ps` output for every user on the machine.
    Vault {
        /// The storage root.
        #[arg(long, global = true)]
        root: Option<PathBuf>,
        /// A file holding the password, when `CHUR_PASSWORD` is not set.
        #[arg(long, global = true)]
        password_file: Option<PathBuf>,
        #[command(subcommand)]
        action: VaultAction,
    },
}

#[derive(Subcommand)]
enum BackupAction {
    /// Write a full package of the vault in the storage root.
    Create {
        /// Where to write the package. It must not already exist.
        package: PathBuf,
    },
    /// Restore a package into the storage root.
    ///
    /// The root is not unlocked first: a restore installs an identity rather
    /// than operating one. Set CHUR_RECOVERY_PHRASE to restore with a phrase;
    /// otherwise the password opens the package's portable descriptor.
    Restore {
        /// The package to read.
        package: PathBuf,
    },
    /// Print what a package says about itself without opening it.
    ///
    /// Only the public preamble is read, so this needs no credential and
    /// reveals nothing the file does not already reveal to anyone holding it.
    Inspect {
        /// The package to read.
        package: PathBuf,
    },
}

#[derive(Subcommand)]
enum VaultAction {
    /// Create a vault, `docs/security/PROVISIONING.md` §3.
    Create {
        /// Offer the recovery slot and print the phrase once.
        #[arg(long)]
        recovery: bool,
    },
    /// Report whether the root holds a vault.
    Status,
    /// Import one file.
    Import {
        /// The file to import.
        path: PathBuf,
        /// The IANA media type to record.
        #[arg(long, default_value = "application/octet-stream")]
        content_type: String,
    },
    /// List one query scope, `docs/format/CATALOG_SCHEMA_V1.md` §16.2.
    List {
        /// timeline, favorites, quarantine, trash, album, tag, or search.
        #[arg(long, default_value = "timeline")]
        scope: String,
        /// The album or tag identifier, for those scopes.
        #[arg(long)]
        id: Option<String>,
        /// Optional literal text within the selected scope; required for search, unavailable in Trash.
        #[arg(long)]
        terms: Option<String>,
        /// capture-desc, capture-asc, or import-desc.
        #[arg(long, default_value = "capture-desc")]
        sort: String,
        /// The page size, 1 to 500.
        #[arg(long, default_value_t = 0)]
        limit: u32,
    },
    /// Print one object's detail record.
    Show {
        /// The object identifier.
        object: String,
    },
    /// Write one object's plaintext to a file.
    Export {
        /// The object identifier.
        object: String,
        /// A new destination path. An existing file is preserved.
        destination: PathBuf,
    },
    /// Write a plaintext range to standard output.
    Read {
        /// The object identifier.
        object: String,
        /// The offset in bytes.
        #[arg(long, default_value_t = 0)]
        offset: u64,
        /// The length in bytes.
        #[arg(long)]
        length: u64,
    },
    /// Set or clear the favourite flag.
    Favorite {
        /// The object identifier.
        object: String,
        /// Clear the flag instead of setting it.
        #[arg(long)]
        clear: bool,
    },
    /// Move one object to the thirty-day trash.
    Delete {
        /// The object identifier.
        object: String,
    },
    /// Restore one object from trash.
    Restore {
        /// The object identifier.
        object: String,
    },
    /// Restore every unexpired object from trash.
    RestoreAll,
    /// Permanently erase one object from trash.
    Purge {
        /// The object identifier.
        object: String,
    },
    /// Permanently erase every object in trash.
    EmptyTrash,
    /// Check active-library originals and report known corrupt objects.
    Verify,
    /// Unlock with the recovery phrase in `CHUR_RECOVERY_PHRASE` and set a new
    /// password, `docs/security/RECOVERY.md`.
    Recover,
}

#[derive(Subcommand)]
enum BenchAction {
    /// Time the object-container chunk-size candidates.
    ChunkSizes {
        /// Object plaintext length in bytes.
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        object_bytes: usize,
        /// Samples per candidate.
        #[arg(long, default_value_t = 8)]
        samples: usize,
    },
    /// Time the Argon2id profiles against the interactive target.
    Argon2 {
        /// Samples per profile.
        #[arg(long, default_value_t = 8)]
        samples: usize,
    },
    /// Measure the random-seek cost a player's data source pays.
    RandomSeek {
        /// The synthetic object's plaintext length.
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        object_bytes: usize,
        /// How many seeks to time.
        #[arg(long, default_value_t = 32)]
        samples: usize,
        /// The range one seek asks for.
        #[arg(long, default_value_t = 64 * 1024)]
        range_bytes: usize,
    },
    /// Measure the native half of a lock.
    LockInvalidation {
        /// How many locks to time.
        #[arg(long, default_value_t = 8)]
        samples: usize,
    },
}

#[derive(Subcommand)]
enum VectorAction {
    /// Write the vector set, refusing to overwrite unless `--force` is given.
    Generate {
        /// Directory to write, default `test-vectors/v1`.
        #[arg(long, default_value = DEFAULT_VECTOR_DIR)]
        dir: PathBuf,
        /// Repository commit of the specifications, recorded in the manifest.
        #[arg(long)]
        spec_commit: Option<String>,
        /// Overwrite an existing set.
        #[arg(long)]
        force: bool,
    },
    /// Re-derive the set and compare it byte for byte with what is on disk.
    Verify {
        /// Directory to read, default `test-vectors/v1`.
        #[arg(long, default_value = DEFAULT_VECTOR_DIR)]
        dir: PathBuf,
    },
    /// Print the digest of the vector set for a release evidence package.
    Digest {
        /// Directory to read, default `test-vectors/v1`.
        #[arg(long, default_value = DEFAULT_VECTOR_DIR)]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum ObjectAction {
    /// Report the record layout of a container without any key.
    Inspect {
        /// Path to the container file.
        path: PathBuf,
    },
}

/// Runs one vault subcommand.
///
/// Every command but `create` and `status` unlocks first, which also runs the
/// reconciliation of `OBJECT_CONTAINER_V1.md` §14.4 and the garbage collection
/// of `CATALOG_SCHEMA_V1.md` §14.1, exactly as a session on a device does.
fn run_backup(
    root: Option<PathBuf>,
    password_file: Option<&Path>,
    action: BackupAction,
) -> chur_core::Result<()> {
    // Inspection reads a public preamble, so it runs before any password is
    // asked for. The other two need a credential.
    if let BackupAction::Inspect { package } = &action {
        return backup::inspect(package);
    }
    let root = vault::root_of(root);
    match action {
        BackupAction::Inspect { .. } => Ok(()),
        BackupAction::Create { package } => {
            let password = vault::read_password(password_file)?;
            let mut session = vault::unlock(&root, &password)?;
            backup::create(&mut session, &package)
        }
        BackupAction::Restore { package } => {
            let credential = match std::env::var("CHUR_RECOVERY_PHRASE") {
                Ok(phrase) => zeroize::Zeroizing::new(phrase.into_bytes()),
                Err(_) => vault::read_password(password_file)?,
            };
            backup::restore(&root, &package, &credential)
        }
    }
}

fn run_vault(
    root: Option<PathBuf>,
    password_file: Option<&Path>,
    action: VaultAction,
) -> chur_core::Result<()> {
    let root = vault::root_of(root);
    if let VaultAction::Status = action {
        let directory = chur_catalog::paths::VaultRoot::new(root.clone());
        let entries = directory.registry_names()?;
        println!(
            "{} at {}: {} vault identit{}",
            if entries.is_empty() {
                "no vault"
            } else {
                "vault"
            },
            root.display(),
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" }
        );
        return Ok(());
    }

    let password = vault::read_password(password_file)?;
    if let VaultAction::Create { recovery } = action {
        return vault::create(&root, &password, recovery);
    }
    if let VaultAction::Recover = action {
        // §9 of KEY_SLOTS: the replacement is created and verified before the
        // old slot goes, which `replace_password` does in one descriptor
        // generation.
        let mut session = vault::unlock_with_recovery(&root)?;
        session.replace_password(&password, chur_crypto::password::Argon2Params::v1_default())?;
        println!("vault {} recovered", session.vault_id().to_hex());
        return Ok(());
    }

    let mut session = vault::unlock(&root, &password)?;
    match action {
        VaultAction::Create { .. } | VaultAction::Status | VaultAction::Recover => {
            // Handled above, before the password unlock.
            Ok(())
        }
        VaultAction::Import { path, content_type } => {
            let object_id = vault::import_file(&mut session, &path, &content_type)?;
            println!("{}", object_id.to_hex());
            Ok(())
        }
        VaultAction::List {
            scope,
            id,
            terms,
            sort,
            limit,
        } => {
            let scope = vault::parse_scope(&scope, id.as_deref())?;
            vault::list(&session, scope, terms, vault::parse_sort(&sort)?, limit)
        }
        VaultAction::Show { object } => vault::inspect_object(&session, &vault::parse_id(&object)?),
        VaultAction::Export {
            object,
            destination,
        } => {
            let written = vault::export_object(&session, &vault::parse_id(&object)?, &destination)?;
            println!("{written} bytes written to {}", destination.display());
            Ok(())
        }
        VaultAction::Read {
            object,
            offset,
            length,
        } => vault::read_range(&session, &vault::parse_id(&object)?, offset, length),
        VaultAction::Favorite { object, clear } => {
            let object_id = vault::parse_id(&object)?;
            chur_catalog::store::set_favorite(
                session.catalog()?,
                &object_id,
                !clear,
                vault::now_ms(),
            )
        }
        VaultAction::Delete { object } => vault::delete(&mut session, &vault::parse_id(&object)?),
        VaultAction::Restore { object } => vault::restore(&mut session, &vault::parse_id(&object)?),
        VaultAction::RestoreAll => vault::restore_all(&mut session),
        VaultAction::Purge { object } => vault::purge(&mut session, &vault::parse_id(&object)?),
        VaultAction::EmptyTrash => vault::empty_trash(&mut session),
        VaultAction::Verify => vault::verify(&mut session),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("chur-cli: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::Vectors { action } => match action {
            VectorAction::Generate {
                dir,
                spec_commit,
                force,
            } => generate(&dir, spec_commit.as_deref(), force),
            VectorAction::Verify { dir } => verify(&dir),
            VectorAction::Digest { dir } => digest(&dir),
        },
        Command::Object { action } => match action {
            ObjectAction::Inspect { path } => inspect(&path),
        },
        Command::Abi => {
            abi();
            Ok(())
        }
        Command::Vault {
            root,
            password_file,
            action,
        } => run_vault(root, password_file.as_deref(), action)
            .map_err(|error| format!("vault: {error}")),
        Command::Backup {
            root,
            password_file,
            action,
        } => run_backup(root, password_file.as_deref(), action)
            .map_err(|error| format!("backup: {error}")),
        Command::Bench { action } => match action {
            BenchAction::ChunkSizes {
                object_bytes,
                samples,
            } => bench::chunk_sizes(object_bytes, samples)
                .map_err(|error| format!("chunk-size benchmark: {error}")),
            BenchAction::Argon2 { samples } => {
                bench::argon2(samples).map_err(|error| format!("Argon2id benchmark: {error}"))
            }
            BenchAction::RandomSeek {
                object_bytes,
                samples,
                range_bytes,
            } => bench::random_seek(object_bytes, samples, range_bytes)
                .map_err(|error| format!("random-seek benchmark: {error}")),
            BenchAction::LockInvalidation { samples } => bench::lock_invalidation(samples)
                .map_err(|error| format!("lock-invalidation benchmark: {error}")),
        },
    }
}

// ---------------------------------------------------------------------------
// Vector generation
// ---------------------------------------------------------------------------

fn generator_metadata(spec_commit: Option<&str>) -> Result<(String, Generator), String> {
    let commit = match spec_commit {
        Some(value) => value.to_owned(),
        None => head_commit()?,
    };
    Ok((
        commit.clone(),
        Generator {
            name: "chur-cli".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            commit,
            toolchain: option_env!("RUSTUP_TOOLCHAIN")
                .unwrap_or("unknown")
                .to_owned(),
        },
    ))
}

fn head_commit() -> Result<String, String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("could not run git to read HEAD: {error}"))?;
    if !output.status.success() {
        return Err("git rev-parse HEAD failed; pass --spec-commit".to_owned());
    }
    let commit = String::from_utf8(output.stdout)
        .map_err(|_| "git printed a non-UTF-8 commit".to_owned())?
        .trim()
        .to_owned();
    if commit.len() != 40 || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("git printed an unexpected commit: {commit}"));
    }
    Ok(commit)
}

fn build_manifest(
    spec_commit: String,
    generator: Generator,
) -> Result<(Manifest, Vec<Vector>), String> {
    let vectors = vectors::build_all().map_err(|error| format!("building vectors: {error}"))?;
    let manifest = Manifest {
        manifest_version: 1,
        spec_commit,
        generator,
        vectors: vectors.iter().map(|vector| vector.entry.clone()).collect(),
    };
    check_set(&manifest, &vectors)?;
    Ok((manifest, vectors))
}

/// The rules `TEST_VECTORS.md` §1, §2, and §9 place on the set as a whole.
fn check_set(manifest: &Manifest, vectors: &[Vector]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    let mut files = BTreeSet::new();
    for vector in vectors {
        let entry = &vector.entry;
        if !seen.insert(entry.vector_id.clone()) {
            return Err(format!("duplicate vector id {}", entry.vector_id));
        }
        check_vector_id(&entry.vector_id)?;
        if manifest::format_directory(&vector.format_word).is_none() {
            return Err(format!(
                "{} names the unallocated format word {}",
                entry.vector_id, vector.format_word
            ));
        }
        if !entry
            .vector_id
            .starts_with(&format!("{}-v", vector.format_word))
        {
            return Err(format!(
                "{} does not begin with its format word {}",
                entry.vector_id, vector.format_word
            ));
        }
        match entry.outcome {
            Outcome::Accept => {
                if entry.expected.is_empty() {
                    return Err(format!("{} accepts but expects nothing", entry.vector_id));
                }
                if entry.error_code.is_some() {
                    return Err(format!(
                        "{} accepts but names an error code",
                        entry.vector_id
                    ));
                }
            }
            Outcome::Reject => {
                if entry.error_code.is_none() {
                    return Err(format!(
                        "{} rejects but names no error code",
                        entry.vector_id
                    ));
                }
                if !entry.expected.is_empty() {
                    return Err(format!(
                        "{} rejects but carries expectations",
                        entry.vector_id
                    ));
                }
            }
        }
        match &entry.error_code {
            Some(code)
                if !chur_core::ChurStatus::ALL
                    .iter()
                    .any(|status| status.name() == code) =>
            {
                return Err(format!(
                    "{} names an unregistered error code {code}",
                    entry.vector_id
                ));
            }
            _ => {}
        }
        for (path, _) in &vector.files {
            if !files.insert(path.clone()) {
                return Err(format!("two vectors write {}", path.display()));
            }
        }
    }
    if manifest.vectors.len() != vectors.len() {
        return Err("manifest and vector list disagree in length".to_owned());
    }
    if !manifest
        .vectors
        .windows(2)
        .all(|pair| pair[0].vector_id < pair[1].vector_id)
    {
        return Err("manifest vectors are not sorted by vector_id".to_owned());
    }
    Ok(())
}

/// The §9 grammar: `format "-v" version "-" case`, all lowercase ASCII words.
fn check_vector_id(vector_id: &str) -> Result<(), String> {
    let allowed = vector_id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !allowed {
        return Err(format!(
            "{vector_id} is not lowercase ASCII words joined by '-'"
        ));
    }
    let mut parts = vector_id.split("-v");
    let format = parts.next().unwrap_or_default();
    let rest = parts.collect::<Vec<_>>().join("-v");
    let Some((version, case)) = rest.split_once('-') else {
        return Err(format!("{vector_id} has no version and case"));
    };
    if format.is_empty() || case.is_empty() || version.is_empty() {
        return Err(format!("{vector_id} has an empty grammar part"));
    }
    if !version.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("{vector_id} has a non-numeric version"));
    }
    Ok(())
}

fn render_manifest(manifest: &Manifest) -> Result<String, String> {
    let mut text = serde_json::to_string_pretty(manifest)
        .map_err(|error| format!("rendering manifest.json: {error}"))?;
    text.push('\n');
    Ok(text)
}

fn generate(dir: &Path, spec_commit: Option<&str>, force: bool) -> Result<(), String> {
    let manifest_path = dir.join("manifest.json");
    if manifest_path.exists() && !force {
        return Err(format!(
            "{} exists; pass --force to overwrite",
            manifest_path.display()
        ));
    }
    let (spec_commit, generator) = generator_metadata(spec_commit)?;
    let (manifest, vectors) = build_manifest(spec_commit, generator)?;

    for vector in &vectors {
        for (relative, bytes) in &vector.files {
            let path = dir.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| format!("creating {}: {error}", parent.display()))?;
            }
            std::fs::write(&path, bytes)
                .map_err(|error| format!("writing {}: {error}", path.display()))?;
        }
    }
    std::fs::create_dir_all(dir).map_err(|error| format!("creating {}: {error}", dir.display()))?;
    std::fs::write(&manifest_path, render_manifest(&manifest)?)
        .map_err(|error| format!("writing {}: {error}", manifest_path.display()))?;

    let fixtures: usize = vectors.iter().map(|vector| vector.files.len()).sum();
    println!(
        "wrote {} vectors and {fixtures} fixtures to {}",
        vectors.len(),
        dir.display()
    );
    Ok(())
}

fn verify(dir: &Path) -> Result<(), String> {
    let manifest_path = dir.join("manifest.json");
    let on_disk_text = std::fs::read_to_string(&manifest_path)
        .map_err(|error| format!("reading {}: {error}", manifest_path.display()))?;
    let on_disk: Manifest = serde_json::from_str(&on_disk_text)
        .map_err(|error| format!("parsing {}: {error}", manifest_path.display()))?;

    if on_disk.manifest_version != 1 {
        return Err(format!(
            "manifest_version is {}, not 1",
            on_disk.manifest_version
        ));
    }
    if on_disk.spec_commit.len() != 40
        || !on_disk.spec_commit.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err("spec_commit is not a 40-character hexadecimal commit".to_owned());
    }

    // Regenerating and comparing is what §8 asks for: a generator update must
    // reproduce historical vectors byte for byte. `spec_commit` and `generator`
    // are provenance, not vector bytes, so the rebuilt manifest carries the
    // recorded values and everything else must match.
    let (rebuilt, vectors) =
        build_manifest(on_disk.spec_commit.clone(), on_disk.generator.clone())?;
    if rebuilt.vectors != on_disk.vectors {
        let recorded: BTreeSet<&str> = on_disk
            .vectors
            .iter()
            .map(|entry| entry.vector_id.as_str())
            .collect();
        let produced: BTreeSet<&str> = rebuilt
            .vectors
            .iter()
            .map(|entry| entry.vector_id.as_str())
            .collect();
        for missing in recorded.difference(&produced) {
            eprintln!("  only on disk:  {missing}");
        }
        for added in produced.difference(&recorded) {
            eprintln!("  only rebuilt:  {added}");
        }
        for entry in &rebuilt.vectors {
            match on_disk
                .vectors
                .iter()
                .find(|candidate| candidate.vector_id == entry.vector_id)
            {
                Some(other) if other != entry => {
                    eprintln!("  changed:       {}", entry.vector_id);
                }
                _ => {}
            }
        }
        return Err("the rebuilt vector set does not match the recorded one".to_owned());
    }
    // A superseded vector keeps its bytes under §8 and names the vector that
    // carries the current rule, which must exist and be current itself.
    for entry in &on_disk.vectors {
        if let Some(target) = &entry.superseded_by {
            let current = on_disk
                .vectors
                .iter()
                .find(|candidate| &candidate.vector_id == target);
            match current {
                Some(found) if found.superseded_by.is_none() => {}
                _ => {
                    return Err(format!(
                        "{} is superseded by {target}, which is absent or superseded itself",
                        entry.vector_id
                    ));
                }
            }
        }
    }
    if render_manifest(&rebuilt)? != on_disk_text {
        return Err("manifest.json is not the rendering of its own entries".to_owned());
    }

    let mut expected_files = BTreeMap::new();
    for vector in &vectors {
        for (relative, bytes) in &vector.files {
            expected_files.insert(relative.clone(), bytes.clone());
        }
    }
    for (relative, bytes) in &expected_files {
        let path = dir.join(relative);
        let found =
            std::fs::read(&path).map_err(|error| format!("reading {}: {error}", path.display()))?;
        if &found != bytes {
            return Err(format!(
                "{} does not match the rebuilt fixture",
                path.display()
            ));
        }
    }

    // §1: a fixture no entry references fails the suite.
    let mut stray = Vec::new();
    for group in walk(dir)? {
        let relative = group
            .strip_prefix(dir)
            .map_err(|_| "fixture path escaped the vector directory".to_owned())?;
        if relative == Path::new("manifest.json") || relative == Path::new("README.md") {
            continue;
        }
        if !expected_files.contains_key(relative) {
            stray.push(relative.to_path_buf());
        }
    }
    if !stray.is_empty() {
        for path in &stray {
            eprintln!("  unreferenced:  {}", path.display());
        }
        return Err(format!(
            "{} fixture files are referenced by no entry",
            stray.len()
        ));
    }

    println!(
        "verified {} vectors and {} fixtures in {}",
        on_disk.vectors.len(),
        expected_files.len(),
        dir.display()
    );
    Ok(())
}

/// Prints the digest `TEST_VECTORS.md` §8 has release CI archive.
///
/// The formula is fixed here rather than in a shell pipeline, so the value does
/// not depend on how a platform's `find` orders entries or how its checksum
/// tool formats a line:
///
/// SHA-256 over every file under the directory, in ascending order of its path
/// relative to that directory, feeding for each file the relative path as UTF-8
/// with `/` separators, then the file bytes.
fn digest(dir: &Path) -> Result<(), String> {
    let mut hasher = Sha256Digest::new();
    let mut count = 0usize;
    for path in walk(dir)? {
        let relative = path
            .strip_prefix(dir)
            .map_err(|_| "a fixture path escaped the vector directory".to_owned())?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes =
            std::fs::read(&path).map_err(|error| format!("reading {}: {error}", path.display()))?;
        hasher.update(relative.as_bytes());
        hasher.update(&bytes);
        count += 1;
    }
    println!(
        "{}  {count} files  {}",
        hex::encode(hasher.finalize()),
        dir.display()
    );
    Ok(())
}

/// A SHA-256 accumulator over the dependency the workspace already carries.
///
/// The digest is SHA-256 rather than the BLAKE3-256 of suite `0x0001`: it is
/// release metadata for a human to compare, not a protocol commitment, and
/// `TEST_VECTORS.md` §2 keeps the manifest outside the canonical encoding for
/// the same reason.
struct Sha256Digest(sha2::Sha256);

impl Sha256Digest {
    fn new() -> Self {
        use sha2::Digest as _;
        Self(sha2::Sha256::new())
    }

    fn update(&mut self, bytes: &[u8]) {
        use sha2::Digest as _;
        self.0.update(bytes);
    }

    fn finalize(self) -> [u8; 32] {
        use sha2::Digest as _;
        self.0.finalize().into()
    }
}

fn walk(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = std::fs::read_dir(&current)
            .map_err(|error| format!("reading {}: {error}", current.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("reading {}: {error}", current.display()))?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

fn inspect(path: &Path) -> Result<(), String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
    let preamble = PublicPreamble::decode(
        bytes
            .get(..PublicPreamble::LEN)
            .ok_or_else(|| "file is shorter than a container preamble".to_owned())?,
    )
    .map_err(|error| format!("preamble: {error}"))?;
    let layout = Layout::parse(&bytes).map_err(|error| format!("layout: {error}"))?;

    println!("path                     {}", path.display());
    println!("file length              {}", bytes.len());
    println!(
        "manifest record length   {}",
        preamble.manifest_record_length()
    );
    println!("first chunk offset       {}", layout.first_chunk_offset());
    println!(
        "container version        {}",
        layout.container_version().value()
    );
    println!("chunk records            {}", layout.chunk_count());
    // In a v2 container the chunk headers include the bucket padding, so this
    // is the stored stream length; the object size is inside the sealed final
    // commit and needs the object key.
    println!(
        "stored chunk plaintext   {}",
        layout.declared_plaintext_length()
    );
    println!(
        "last chunk plaintext     {}",
        layout.last_chunk_plaintext_length()
    );
    println!("final commit present     {}", layout.has_final_commit());
    let commitment = layout
        .ordered_chunk_commitment(&bytes)
        .map_err(|error| format!("ordered commitment: {error}"))?;
    println!("ordered commitment       {}", manifest::hex_of(&commitment));
    println!();
    println!("No key was used. Nothing above is authenticated: a structural scan");
    println!("proves framing, and only an AEAD proves authenticity.");
    Ok(())
}

// ---------------------------------------------------------------------------
// ABI
// ---------------------------------------------------------------------------

fn abi() {
    println!("abi version              1.0");
    println!("object format range      1..=1");
    println!("key slot format range    1..=1");
    println!("capabilities             0x0000000000000000");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use super::*;

    fn built() -> (Manifest, Vec<Vector>) {
        build_manifest(
            "0".repeat(40),
            Generator {
                name: "chur-cli".to_owned(),
                version: "0.1.0".to_owned(),
                commit: "0".repeat(40),
                toolchain: "test".to_owned(),
            },
        )
        .unwrap()
    }

    #[test]
    fn the_set_satisfies_its_own_rules() {
        let (manifest, vectors) = built();
        check_set(&manifest, &vectors).unwrap();
        assert!(vectors.len() >= 50, "the set is smaller than expected");
    }

    #[test]
    fn generation_is_deterministic() {
        let first = built();
        let second = built();
        assert_eq!(
            render_manifest(&first.0).unwrap(),
            render_manifest(&second.0).unwrap()
        );
        let files_of = |vectors: &[Vector]| -> Vec<(PathBuf, Vec<u8>)> {
            vectors
                .iter()
                .flat_map(|vector| vector.files.clone())
                .collect()
        };
        assert_eq!(files_of(&first.1), files_of(&second.1));
    }

    #[test]
    fn every_hkdf_label_has_a_vector() {
        let (_, vectors) = built();
        for label in chur_crypto::kdf::Label::ALL {
            let slug = label.as_str().replace('/', "-").replace("chur-v1-", "");
            let id = format!("key-derivation-v1-{slug}");
            assert!(
                vectors.iter().any(|vector| vector.entry.vector_id == id),
                "no vector for {}",
                label.as_str()
            );
        }
    }

    #[test]
    fn every_key_slot_family_has_a_vector() {
        let (_, vectors) = built();
        for prefix in [
            "password-slot-v1-",
            "recovery-slot-v1-",
            "keystore-slot-v1-",
            "keychain-slot-v1-",
        ] {
            assert!(
                vectors
                    .iter()
                    .any(|vector| vector.entry.vector_id.starts_with(prefix)),
                "no vector for {prefix}"
            );
        }
    }

    #[test]
    fn every_vector_id_matches_the_grammar() {
        let (_, vectors) = built();
        for vector in &vectors {
            check_vector_id(&vector.entry.vector_id).unwrap();
        }
        assert!(check_vector_id("Object-v1-case").is_err());
        assert!(check_vector_id("object-1-case").is_err());
        assert!(check_vector_id("object-vx-case").is_err());
        assert!(check_vector_id("object-v1-").is_err());
    }

    #[test]
    fn a_rejected_vector_files_its_fixtures_under_negative() {
        let (_, vectors) = built();
        for vector in &vectors {
            for (path, _) in &vector.files {
                let under_negative = path.starts_with("negative");
                assert_eq!(
                    under_negative,
                    vector.entry.outcome == Outcome::Reject,
                    "{} files {} in the wrong directory",
                    vector.entry.vector_id,
                    path.display()
                );
            }
        }
    }

    #[test]
    fn every_named_specification_exists() {
        let (_, vectors) = built();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("..");
        for vector in &vectors {
            let path = root.join(&vector.entry.spec);
            assert!(
                path.exists(),
                "{} names a specification that does not exist: {}",
                vector.entry.vector_id,
                vector.entry.spec
            );
        }
    }
}

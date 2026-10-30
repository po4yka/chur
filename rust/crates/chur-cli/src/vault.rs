//! The vault subcommands.
//!
//! `docs/ARCHITECTURE.md` §9 makes the CLI a first-class component: the storage
//! format must be testable and recoverable independently of Android and iOS UI
//! code. These subcommands are that, for the whole Phase 1 flow: create a
//! vault, unlock it, import, list, read, export, verify, and delete.
//!
//! A password reaches the process through an environment variable or a file
//! rather than an argument. `docs/security/PLAINTEXT_LIFECYCLE.md` §10 forbids
//! a private value in a diagnostic, and an argument is in `/proc`, in the shell
//! history, and in `ps` output for every user on the machine.

use std::io::Write;
use std::path::{Path, PathBuf};

use chur_catalog::paths::VaultRoot;
use chur_catalog::query::{ObjectQuery, Page, Scope, Sort, page};
use chur_catalog::vault::{self, Session};
use chur_catalog::{deletion, store};
use chur_core::{ChurStatus, Error, Id, Result, bail};
use chur_format::constants::{IntegritySummary, MediaClass, ObjectState, StreamKind};
use chur_media::import::{CanonicalMedia, SourceCapability};
use chur_media::{export, import, integrity, reader};
use zeroize::Zeroizing;

/// Reads the password from the environment or a file.
///
/// `CHUR_PASSWORD` is read first, then `--password-file`. Neither is an
/// argument, for the reason in the module comment.
pub fn read_password(file: Option<&Path>) -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(value) = std::env::var("CHUR_PASSWORD") {
        return Ok(Zeroizing::new(value.into_bytes()));
    }
    let Some(path) = file else {
        bail!(
            InvalidInput,
            "set CHUR_PASSWORD or pass --password-file; a password is never an argument"
        );
    };
    let mut bytes = Zeroizing::new(
        std::fs::read(path)
            .map_err(|_| chur_core::err!(IoFailure, "the password file could not be read"))?,
    );
    // A trailing newline is what an editor and `echo` both leave, and a user who
    // typed the password into a file did not intend it.
    if bytes.ends_with(b"\n") {
        bytes.pop();
    }
    if bytes.ends_with(b"\r") {
        bytes.pop();
    }
    Ok(bytes)
}

/// The time that trash retention is judged against, `CATALOG_SCHEMA_V18.md`.
fn trusted_now(session: &mut Session) -> Result<u64> {
    chur_catalog::trusted_time::now(session.catalog()?, now_ms())
}

/// The device clock in milliseconds, `CATALOG_SCHEMA_V1.md` §8.1. Retention does not use it directly.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Creates a vault and prints the recovery phrase when one is requested.
pub fn create(root: &Path, password: &[u8], recovery: bool) -> Result<()> {
    let directory = VaultRoot::new(root.to_path_buf());
    let mut creation = vault::create(&directory, password, now_ms())?;
    if recovery {
        let secret = creation.add_recovery_slot()?;
        let phrase = chur_crypto::recovery::to_phrase(&secret);
        // The one place this binary prints a secret, and only because
        // `docs/security/RECOVERY.md` §2 requires the user to see it exactly
        // once. It goes to standard output so a caller can redirect it; it is
        // never logged and never shown again.
        println!("recovery phrase (shown once, store it offline):");
        println!("{}", phrase.as_str());
    }
    let session = creation.activate()?;
    println!("vault {} created", session.vault_id().to_hex());
    Ok(())
}

/// Unlocks a vault with a password.
pub fn unlock(root: &Path, password: &[u8]) -> Result<Session> {
    let directory = VaultRoot::new(root.to_path_buf());
    let session = vault::unlock_with_password(&directory, password, now_ms())?;
    after_unlock(session)
}

/// Unlocks a vault with the recovery phrase, `docs/security/RECOVERY.md`.
///
/// The phrase is read from `CHUR_RECOVERY_PHRASE` for the same reason a
/// password is never an argument.
pub fn unlock_with_recovery(root: &Path) -> Result<Session> {
    let Ok(phrase) = std::env::var("CHUR_RECOVERY_PHRASE") else {
        bail!(
            InvalidInput,
            "set CHUR_RECOVERY_PHRASE; a recovery phrase is never an argument"
        );
    };
    let phrase = Zeroizing::new(phrase);
    let directory = VaultRoot::new(root.to_path_buf());
    let session = vault::unlock_with_recovery(&directory, &phrase, now_ms())?;
    after_unlock(session)
}

/// The work every unlock does before the caller sees the session.
///
/// It runs the same startup work as `chur_vault_unlock`, except the
/// sync-staging sweep, which belongs to the native host's sync surface and
/// which the command line does not use. A failure locks the session before it
/// returns, as the native unlock does, so the lock path still removes the
/// scratch directory and closes the catalog.
fn after_unlock(mut session: Session) -> Result<Session> {
    match startup_work(&mut session) {
        Ok(()) => Ok(session),
        Err(error) => {
            let _ = session.lock();
            Err(error)
        }
    }
}

fn startup_work(session: &mut Session) -> Result<()> {
    // `CATALOG_SCHEMA_V1.md` §14.1: garbage collection runs at the first unlock
    // of a session, and `OBJECT_CONTAINER_V1.md` §14.4 reconciles the journal
    // and deletes temporary containers that no journal record names. They run
    // here rather than at each call site, so no unlock path can skip them.
    let killed = import::reconcile(session)?;
    let orphans = import::sweep_orphan_temporaries(session)?;
    // `PLAINTEXT_LIFECYCLE.md` §5, and the catalog snapshot of a killed backup.
    export::clear_scratch(session)?;
    chur_media::backup::clear_snapshot(session)?;
    let swept = collect_deletions(session)?;
    let trusted = trusted_now(session)?;
    let expired = chur_catalog::trash::pending(session.catalog_ref()?, Some(trusted))?;
    for id in &expired {
        purge(session, id)?;
    }
    if killed > 0 || orphans > 0 || swept > 0 || !expired.is_empty() {
        println!(
            "recovered: {killed} dead import(s), {orphans} orphan temporary container(s), {swept} pending deletion(s), {} expired trash item(s)",
            expired.len()
        );
    }
    Ok(())
}

/// Completes every deletion left half-finished, §14.1.
pub fn collect_deletions(session: &mut Session) -> Result<usize> {
    let store_id = session.object_store_id();
    let root = session.root_dir().clone();
    let pending = deletion::sweep(session.catalog_ref()?)?;
    let count = pending.len();
    for entry in pending {
        if !entry.erased {
            let secret = session.root_secret()?.duplicate();
            let vault_id = session.vault_id();
            deletion::erase_with_sync(
                session.catalog()?,
                &secret,
                vault_id,
                &entry.object_id,
                now_ms(),
            )?;
        }
        for container in &entry.containers {
            chur_media::store::unlink_container(&root, &store_id, container)?;
        }
        deletion::finish(session.catalog()?, &entry.object_id)?;
        deletion::discard_tombstone(session.catalog()?, &entry.object_id)?;
    }
    session.catalog()?.checkpoint()?;
    Ok(count)
}

/// Imports one file.
pub fn import_file(session: &mut Session, path: &Path, content_type: &str) -> Result<Id> {
    let mut file = std::fs::File::open(path)
        .map_err(|_| chur_core::err!(IoFailure, "the source could not be opened"))?;
    let length = file
        .metadata()
        .map(|metadata| metadata.len())
        .map_err(|_| chur_core::err!(IoFailure, "the source length could not be read"))?;
    let capability = SourceCapability {
        requested_object_id: None,
        seekable: true,
        known_length: Some(length),
        content_type_hint: content_type.to_owned(),
        original_filename: path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned),
        // The CLI has no provider metadata, so §8.1's substitution applies: the
        // capture time is set to the import time and the row records that it
        // was substituted.
        capture_time_ms: None,
    };
    // §1 of the media pipeline puts codec probing on the platform and the CLI
    // has no decoder, so the class comes from the caller's declared type and
    // the dimensions stay zero. An image imported here is an image with no
    // dimensions, which §5.1 of the container format permits, rather than a
    // guess at a size nothing measured.
    let media = CanonicalMedia {
        media_class: class_of(content_type),
        width: 0,
        height: 0,
        duration_ms: 0,
    };
    let now = now_ms();
    let running = import::begin(session, capability, media, now)?;
    // One refill loop lives in `chur_media::import`, so the memory bound and
    // the cancellation behaviour are properties of that code rather than of
    // each caller. The CLI never cancels, so it passes `Uninterrupted`.
    import::stream_into(
        running,
        session,
        &mut file,
        content_type,
        now,
        &mut chur_media::progress::Uninterrupted,
    )
}

/// Prints one page of a scope.
pub fn list(
    session: &Session,
    scope: Scope,
    terms: Option<String>,
    sort: Sort,
    limit: u32,
) -> Result<()> {
    let result = page(
        session.catalog_ref()?,
        &ObjectQuery {
            scope,
            terms,
            kinds: 0,
            sort,
            cursor: None,
            limit,
        },
    )?;
    print_page(session, &result)
}

fn print_page(session: &Session, result: &Page) -> Result<()> {
    println!(
        "{} object(s) of {} at catalog generation {}",
        result.objects.len(),
        result.total_count,
        result.catalog_generation
    );
    for object in &result.objects {
        let metadata = store::active_metadata(session.catalog_ref()?, &object.object_id)?;
        println!(
            "  {}  {:>12}  {:<10}  {}{}",
            object.object_id.to_hex(),
            object.plaintext_size,
            summary_name(object.integrity_summary),
            metadata.original_filename.as_deref().unwrap_or("(no name)"),
            if object.favorite { "  *" } else { "" }
        );
    }
    Ok(())
}

fn summary_name(value: u8) -> &'static str {
    match IntegritySummary::from_value(value) {
        Some(IntegritySummary::Unverified) => "unverified",
        Some(IntegritySummary::Verifying) => "verifying",
        Some(IntegritySummary::RangeVerified) => "range",
        Some(IntegritySummary::CompleteVerified) => "verified",
        Some(IntegritySummary::Incomplete) => "incomplete",
        Some(IntegritySummary::Quarantined) => "quarantined",
        Some(IntegritySummary::Unsupported) => "unsupported",
        Some(IntegritySummary::MigrationRequired) => "migrate",
        _ => "unknown",
    }
}

/// Exports one object to a path.
pub fn export_object(session: &Session, object_id: &Id, destination: &Path) -> Result<u64> {
    let mut file = std::fs::File::create(destination)
        .map_err(|_| chur_core::err!(IoFailure, "the destination could not be created"))?;
    let written = export::export_stream(
        session,
        object_id,
        StreamKind::Original,
        &mut file,
        &mut chur_media::progress::Uninterrupted,
    )?;
    file.flush()
        .map_err(|_| chur_core::err!(IoFailure, "the destination could not be flushed"))?;
    Ok(written)
}

/// Scans every object and prints its verdict.
pub fn verify(session: &mut Session) -> Result<()> {
    let objects: Vec<Id> = {
        let mut all = Vec::new();
        let mut query = ObjectQuery::timeline();
        loop {
            let result = page(session.catalog_ref()?, &query)?;
            all.extend(result.objects.iter().map(|row| row.object_id));
            let Some(cursor) = result.next_cursor else {
                break;
            };
            query.cursor = Some(cursor);
        }
        all
    };
    let mut verified = 0usize;
    let mut problems = 0usize;
    for object_id in &objects {
        let outcome = integrity::scan_object(session, object_id, now_ms())?;
        let name = if outcome.state == ObjectState::Corrupt {
            problems += 1;
            "corrupt"
        } else if outcome.integrity_summary == IntegritySummary::CompleteVerified {
            verified += 1;
            "verified"
        } else {
            problems += 1;
            summary_name(outcome.integrity_summary.value())
        };
        println!("  {}  {name}", object_id.to_hex());
    }
    println!(
        "{verified} verified, {problems} with a problem, {} scanned",
        objects.len()
    );
    if problems > 0 {
        bail!(ObjectCorrupt, "at least one object did not verify");
    }
    Ok(())
}

/// Prints one object's detail record.
pub fn inspect_object(session: &Session, object_id: &Id) -> Result<()> {
    let catalog = session.catalog_ref()?;
    let object = store::object(catalog, object_id)?;
    let metadata = store::active_metadata(catalog, object_id)?;
    let streams = store::streams(catalog, object_id)?;
    let tags = store::object_tags(catalog, object_id)?;
    println!("object            {}", object.object_id.to_hex());
    println!("state             {:?}", object.state);
    println!(
        "integrity         {}",
        summary_name(object.integrity_summary.value())
    );
    println!("media kind        {:?}", object.media_kind);
    println!("plaintext size    {}", object.plaintext_size);
    println!(
        "capture time      {}{}",
        object.capture_time_ms,
        if object.capture_time_substituted {
            " (substituted from import time)"
        } else {
            ""
        }
    );
    println!("import time       {}", object.import_time_ms);
    println!("content type      {}", metadata.content_type);
    println!(
        "filename          {}",
        metadata.original_filename.as_deref().unwrap_or("(none)")
    );
    println!("favourite         {}", object.favorite);
    println!("thumbnail ready   {}", object.thumbnail_ready);
    if !tags.is_empty() {
        let names: Vec<&str> = tags.iter().map(|tag| tag.name.as_str()).collect();
        println!("tags              {}", names.join(", "));
    }
    for stream in streams {
        println!(
            "stream            {:?} revision {} chunk {} ciphertext {}",
            stream.stream_kind, stream.stream_revision, stream.chunk_size, stream.ciphertext_size
        );
    }
    Ok(())
}

/// Reads a plaintext range and writes it to standard output.
pub fn read_range(session: &Session, object_id: &Id, offset: u64, length: u64) -> Result<()> {
    let mut handle = reader::open(session, object_id, StreamKind::Original)?;
    let bytes = handle.read_range(offset, length)?;
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|_| chur_core::err!(IoFailure, "standard output rejected a write"))
}

/// Moves one active object to trash.
pub fn delete(session: &mut Session, object_id: &Id) -> Result<()> {
    let trusted = trusted_now(session)?;
    chur_catalog::trash::set(session.catalog()?, &[*object_id], false, trusted)
}

/// Restores one trashed object.
pub fn restore(session: &mut Session, object_id: &Id) -> Result<()> {
    let trusted = trusted_now(session)?;
    chur_catalog::trash::set(session.catalog()?, &[*object_id], true, trusted)
}

/// Restores every unexpired trash entry atomically.
pub fn restore_all(session: &mut Session) -> Result<()> {
    let ids = chur_catalog::trash::pending(session.catalog_ref()?, None)?;
    if ids.is_empty() {
        return Ok(());
    }
    let trusted = trusted_now(session)?;
    chur_catalog::trash::set(session.catalog()?, &ids, true, trusted)
}

/// Permanently erases one object and rolls its garbage collection forward.
pub fn purge(session: &mut Session, object_id: &Id) -> Result<()> {
    if !matches!(
        store::object(session.catalog_ref()?, object_id)?.state,
        ObjectState::Trashed | ObjectState::Corrupt
    ) {
        bail!(
            InvalidInput,
            "only a trashed or corrupt object can be purged"
        );
    }
    deletion::begin(session.catalog()?, object_id)?;
    collect_deletions(session).map(|_| ())
}

/// Permanently erases all objects in trash.
pub fn empty_trash(session: &mut Session) -> Result<()> {
    let ids = chur_catalog::trash::pending(session.catalog_ref()?, None)?;
    for id in ids {
        purge(session, &id)?;
    }
    Ok(())
}

/// Parses a 32-character hexadecimal identifier.
pub fn parse_id(value: &str) -> Result<Id> {
    let bytes = hex::decode(value).map_err(|_| {
        Error::new(
            ChurStatus::InvalidInput,
            "the identifier is not hexadecimal",
        )
    })?;
    Id::from_slice(&bytes)
}

/// Turns a scope name and an optional identifier into a query scope.
pub fn parse_scope(name: &str, id: Option<&str>) -> Result<Scope> {
    Ok(match name {
        "timeline" => Scope::Timeline,
        "favorites" => Scope::Favorites,
        "quarantine" => Scope::Quarantine,
        "trash" => Scope::Trash,
        "album" => Scope::Album(parse_id(id.ok_or_else(|| {
            chur_core::err!(InvalidInput, "the album scope names an album")
        })?)?),
        "tag" => Scope::Tag(parse_id(id.ok_or_else(|| {
            chur_core::err!(InvalidInput, "the tag scope names a tag")
        })?)?),
        "search" => Scope::Search,
        _ => bail!(InvalidInput, "the scope name is not one §16.2 allocates"),
    })
}

/// Turns a sort name into a query sort.
pub fn parse_sort(name: &str) -> Result<Sort> {
    Ok(match name {
        "capture-desc" => Sort::CaptureDesc,
        "capture-asc" => Sort::CaptureAsc,
        "import-desc" => Sort::ImportDesc,
        _ => bail!(InvalidInput, "the sort name is not one §16.2 allocates"),
    })
}

/// The media class a content type implies, for a CLI import.
///
/// It is deliberately coarse: `MEDIA_PIPELINE.md` §1 puts codec probing on the
/// platform, and the CLI has no decoder, so an import here is opaque unless the
/// caller names a class.
#[must_use]
pub fn class_of(content_type: &str) -> MediaClass {
    match content_type.split('/').next() {
        Some("image") => MediaClass::Image,
        Some("video") => MediaClass::Video,
        Some("audio") => MediaClass::Audio,
        _ => MediaClass::Opaque,
    }
}

/// The storage root a command operates on.
#[must_use]
pub fn root_of(value: Option<PathBuf>) -> PathBuf {
    value.unwrap_or_else(|| PathBuf::from("chur-vault"))
}

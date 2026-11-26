//! Independent encrypted selection archives and authenticated logical import.
#![expect(unsafe_code, reason = "the bounded C ABI validates caller pointers")]
use crate::{
    api::{self, Status},
    operation::{Operation, OperationKind, Shared, Stage},
    panic::guard_status_for,
    registry::{self, Entry, Handle, Kind},
};
use chur_catalog::{
    schema, store,
    transfer::{self, Plan},
    vault::{self, Session},
};
use chur_core::{Id, Result, ensure};
use chur_crypto::random;
use chur_format::constants::{ObjectState, StreamKind};
use chur_media::{backup, derived, import, progress::Progress, reader};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

struct Request {
    password: Zeroizing<Vec<u8>>,
    objects: Vec<Id>,
    albums: Vec<Id>,
    notes: Vec<(Id, u64)>,
    max_output_bytes: u64,
}
struct Decoder<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| chur_core::err!(InvalidInput, "the archive request is malformed"))?;
        ensure!(
            end <= self.bytes.len(),
            InvalidInput,
            "the archive request is truncated"
        );
        let b = &self.bytes[self.at..end];
        self.at = end;
        Ok(b)
    }
    fn count(&mut self, max: usize) -> Result<usize> {
        let n = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| chur_core::err!(InvalidInput, "the archive count is malformed"))?,
        ) as usize;
        ensure!(
            n <= max,
            ResourceLimitExceeded,
            "the archive request exceeds its bound"
        );
        Ok(n)
    }
}
fn decode(bytes: &[u8], export: bool) -> Result<Request> {
    let mut d = Decoder { bytes, at: 0 };
    ensure!(
        d.take(1)? == [1],
        UnsupportedVersion,
        "the archive request version is unsupported"
    );
    let n = d.count(1024)?;
    let password = chur_crypto::password::canonical_bytes(d.take(n)?)?;
    let mut r = Request {
        password,
        objects: Vec::new(),
        albums: Vec::new(),
        notes: Vec::new(),
        max_output_bytes: i64::MAX as u64,
    };
    if export {
        let n = d.count(1000)?;
        for _ in 0..n {
            r.objects.push(Id::from_slice(d.take(16)?)?)
        }
        let n = d.count(1000)?;
        for _ in 0..n {
            r.albums.push(Id::from_slice(d.take(16)?)?)
        }
        let n = d.count(1000)?;
        for _ in 0..n {
            let id = Id::from_slice(d.take(16)?)?;
            let revision =
                u64::from_be_bytes(d.take(8)?.try_into().map_err(|_| {
                    chur_core::err!(InvalidInput, "the note revision is malformed")
                })?);
            ensure!(revision > 0, InvalidInput, "the note revision is invalid");
            r.notes.push((id, revision));
        }
    }
    if export {
        r.max_output_bytes = u64::from_be_bytes(
            d.take(8)?
                .try_into()
                .map_err(|_| chur_core::err!(InvalidInput, "the archive capacity is malformed"))?,
        );
        ensure!(
            r.max_output_bytes > 0 && r.max_output_bytes <= i64::MAX as u64,
            InvalidInput,
            "the archive capacity is invalid"
        );
    }
    ensure!(
        d.at == bytes.len(),
        InvalidInput,
        "the archive request has trailing bytes"
    );
    Ok(r)
}
pub(crate) struct CancelOnly<'a>(pub(crate) &'a Shared);
impl Progress for CancelOnly<'_> {
    fn cancelled(&self) -> bool {
        self.0.cancelled()
    }
    fn advance(&mut self, _: u64) {}
}
fn check(shared: &Shared) -> Result<()> {
    ensure!(
        !shared.cancelled(),
        Cancelled,
        "the encrypted archive operation was cancelled"
    );
    Ok(())
}

enum Access {
    Shared { handle: Handle, entry: Arc<Entry> },
    Local(Box<Session>),
}
impl Access {
    fn with<T>(&mut self, f: impl FnOnce(&mut Session) -> Result<T>) -> Result<T> {
        match self {
            Self::Local(s) => f(s),
            Self::Shared { entry, .. } => {
                let Entry::Session { session, .. } = entry.as_ref() else {
                    return Err(chur_core::err!(
                        InvalidInput,
                        "the archive owner is not a session"
                    ));
                };
                let mut s = registry::lock(session);
                f(&mut s)
            }
        }
    }
    fn unchanged(&mut self, generation: u64) -> Result<()> {
        self.with(|s| {
            ensure!(
                schema::generation(s.catalog_ref()?)? == generation,
                Conflict,
                "the archive source changed"
            );
            Ok(())
        })
    }
    fn open(&mut self, id: &Id, kind: StreamKind) -> Result<Lease> {
        match self {
            Self::Local(s) => Ok(Lease::Local(Box::new(reader::open(s, id, kind)?))),
            Self::Shared { handle, entry } => {
                let Entry::Session { session, .. } = entry.as_ref() else {
                    return Err(chur_core::err!(
                        InvalidInput,
                        "the archive owner is not a session"
                    ));
                };
                let s = registry::lock(session);
                let _lifecycle = registry::reader_lifecycle();
                let opened = reader::open(&s, id, kind)?;
                let handle = registry::insert(Entry::Reader {
                    session: *handle,
                    root: std::fs::canonicalize(s.root_dir().base()).map_err(|_| {
                        chur_core::err!(IoFailure, "the archive source root could not be resolved")
                    })?,
                    store_id: s.object_store_id(),
                    object_id: *id,
                    reader: Mutex::new(Some(opened)),
                })?;
                let entry = registry::get(handle, Kind::Reader)?;
                Ok(Lease::Registered { handle, entry })
            }
        }
    }
}
impl Drop for Access {
    fn drop(&mut self) {
        if let Self::Local(s) = self {
            let _ = s.lock();
        }
    }
}
enum Lease {
    Local(Box<reader::ObjectReader>),
    Registered { handle: Handle, entry: Arc<Entry> },
}
impl Lease {
    fn with<T>(&mut self, f: impl FnOnce(&mut reader::ObjectReader) -> Result<T>) -> Result<T> {
        match self {
            Self::Local(r) => f(r),
            Self::Registered { entry, .. } => {
                let Entry::Reader { reader, .. } = entry.as_ref() else {
                    return Err(chur_core::err!(
                        InvalidInput,
                        "the archive reader is invalid"
                    ));
                };
                let mut r = registry::lock(reader);
                f(r.as_mut()
                    .ok_or_else(|| chur_core::err!(Cancelled, "the archive reader was revoked"))?)
            }
        }
    }
    fn verify(&mut self, shared: &Shared) -> Result<()> {
        let handle = match self {
            Self::Registered { handle, .. } => Some(*handle),
            _ => None,
        };
        self.with(|r| {
            r.verify_complete_with(&|| {
                shared.cancelled()
                    || handle.is_some_and(|h| registry::get(h, Kind::Reader).is_err())
            })?;
            Ok(())
        })
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Self::Registered { handle, .. } = self {
            let _ = registry::close(*handle);
        }
    }
}

/// Removes encrypted operation staging left by a stopped process, before publishing a new session.
pub(crate) fn sweep_staging(session: &Session) -> Result<()> {
    let parent = session
        .root_dir()
        .vault(&session.object_store_id())
        .join("archive-staging");
    match std::fs::symlink_metadata(&parent) {
        Ok(m) => {
            ensure!(
                m.is_dir() && !m.file_type().is_symlink(),
                IoFailure,
                "the archive staging directory is invalid"
            );
            std::fs::remove_dir_all(parent).map_err(|_| {
                chur_core::err!(
                    IoFailure,
                    "abandoned encrypted archive staging could not be removed"
                )
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(chur_core::err!(
            IoFailure,
            "the archive staging directory could not be read"
        )),
    }
}
struct Staging {
    path: PathBuf,
    root: chur_catalog::paths::VaultRoot,
}
impl Staging {
    fn new(owner: &mut Access) -> Result<Self> {
        let parent = owner.with(|s| {
            Ok(s.root_dir()
                .vault(&s.object_store_id())
                .join("archive-staging"))
        })?;
        match std::fs::create_dir(&parent) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let m = std::fs::symlink_metadata(&parent).map_err(|_| {
                    chur_core::err!(IoFailure, "the archive staging directory could not be read")
                })?;
                ensure!(
                    m.is_dir() && !m.file_type().is_symlink(),
                    IoFailure,
                    "the archive staging directory is invalid"
                );
            }
            Err(_) => {
                return Err(chur_core::err!(
                    IoFailure,
                    "the archive staging directory could not be created"
                ));
            }
        }
        let path = parent.join(random::id()?.to_hex());
        std::fs::create_dir(&path).map_err(|_| {
            chur_core::err!(IoFailure, "encrypted archive staging could not be created")
        })?;
        Ok(Self {
            root: chur_catalog::paths::VaultRoot::new(path.clone()),
            path,
        })
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn copy(
    source: &mut Access,
    target: &mut Access,
    plan: Plan,
    shared: &Shared,
    now: u64,
) -> Result<()> {
    shared.set_total((plan.objects.len() + plan.notes.len()) as u64);
    shared.advance(0, Stage::Running);
    let mut completed = 0u64;
    let mut objects = BTreeMap::new();
    let mut tags = BTreeMap::new();
    for id in &plan.objects {
        check(shared)?;
        source.unchanged(plan.generation)?;
        let (object, metadata, object_tags, streams) = source.with(|s| {
            let db = s.catalog_ref()?;
            let object = store::object(db, id)?;
            ensure!(
                object.state == ObjectState::Active,
                NotFound,
                "the selected original is not active"
            );
            Ok((
                object,
                store::active_metadata(db, id)?,
                store::object_tags(db, id)?,
                store::streams(db, id)?,
            ))
        })?;
        let mut lease = source.open(id, StreamKind::Original)?;
        lease.verify(shared)?;
        let capability = import::SourceCapability {
            requested_object_id: None,
            seekable: true,
            known_length: Some(object.plaintext_size),
            content_type_hint: metadata.content_type.clone(),
            original_filename: metadata.original_filename.clone(),
            capture_time_ms: metadata.capture_time_ms,
        };
        let media = import::CanonicalMedia {
            media_class: object.media_kind,
            width: object.width,
            height: object.height,
            duration_ms: object.duration_ms,
        };
        let mut writing = target.with(|s| import::begin(s, capability, media, now))?;
        let copied = (|| {
            let mut offset = 0;
            while offset < object.plaintext_size {
                check(shared)?;
                source.unchanged(plan.generation)?;
                let take = u64::from(writing.chunk_size()).min(object.plaintext_size - offset);
                let bytes = lease.with(|r| r.read_range(offset, take))?;
                target.with(|s| writing.write(s, &bytes))?;
                offset += take;
            }
            check(shared)?;
            source.unchanged(plan.generation)?;
            Ok(())
        })();
        if let Err(error) = copied {
            let _ = target.with(|s| writing.abandon(s));
            return Err(error);
        }
        let transaction = writing.transaction_id();
        let committed = target.with(|s| {
            writing.commit_with_display_checked(
                s,
                &metadata.content_type,
                now,
                import::CopiedDisplay {
                    caption: metadata.caption.clone(),
                    favorite: object.favorite,
                    capture_time: Some((object.capture_time_ms, object.capture_time_substituted)),
                },
                &|| shared.cancelled(),
            )
        });
        let new_id = match committed {
            Ok(id) => id,
            Err(error) => {
                if target
                    .with(|s| import::reconcile_one(s, &transaction))
                    .unwrap_or(false)
                {
                    completed += 1;
                    shared.advance(completed, Stage::Running);
                }
                return Err(error);
            }
        };
        drop(lease);
        // The original and its display metadata are now committed, as in normal batch import.
        completed += 1;
        shared.advance(completed, Stage::Running);
        objects.insert(*id, new_id);
        for tag in object_tags {
            check(shared)?;
            let new_tag = if let Some(id) = tags.get(&tag.tag_id) {
                *id
            } else {
                let new = target.with(|s| transfer::copy_tag(s.catalog()?, &tag))?;
                tags.insert(tag.tag_id, new);
                new
            };
            target.with(|s| store::set_object_tag(s.catalog()?, &new_tag, &new_id, true))?;
        }
        // Derived display assets are independently authenticated and rebound to the fresh object.
        let mut kinds = std::collections::BTreeSet::new();
        for stream in streams {
            let kind = stream.stream_kind;
            if !matches!(
                kind,
                StreamKind::ThumbnailSmall
                    | StreamKind::GridPreview
                    | StreamKind::ScreenPreview
                    | StreamKind::VideoPoster
                    | StreamKind::AudioWaveform
            ) || !kinds.insert(kind.value())
            {
                continue;
            }
            check(shared)?;
            source.unchanged(plan.generation)?;
            let mut derivative = source.open(id, kind)?;
            derivative.verify(shared)?;
            let (width, height) = derivative.with(|r| Ok(r.dimensions()))?;
            let bytes = derivative.with(|r| {
                ensure!(
                    r.size() <= 32 * 1024 * 1024,
                    ResourceLimitExceeded,
                    "the archive display asset exceeds its memory bound"
                );
                r.read_range(0, r.size())
            })?;
            target.with(|s| derived::put(s, &new_id, kind, width, height, &bytes, now))?;
        }
    }
    for (id, revision) in &plan.notes {
        check(shared)?;
        source.unchanged(plan.generation)?;
        let note = source.with(|s| chur_catalog::notes::get(s.catalog_ref()?, id))?;
        ensure!(
            note.revision == *revision && note.deleted_ms.is_none(),
            Conflict,
            "the selected note changed"
        );
        let attachments =
            source.with(|s| chur_catalog::note_attachments::all(s.catalog_ref()?, id))?;
        let workspace =
            source.with(|s| chur_catalog::note_workspace::archive(s.catalog_ref()?, id))?;
        target
            .with(|s| transfer::copy_note(s.catalog()?, &note, &attachments, Some(&workspace)))?;
        completed += 1;
        shared.advance(completed, Stage::Running);
    }
    let mut albums = BTreeMap::new();
    for selected in &plan.albums {
        check(shared)?;
        let new = target.with(|s| transfer::copy_album(s.catalog()?, &selected.listing.album))?;
        albums.insert(selected.listing.album.album_id, new);
    }
    for selected in &plan.albums {
        check(shared)?;
        let Some(new) = albums.get(&selected.listing.album.album_id) else {
            continue;
        };
        if let Some(parent) = selected.listing.parent_id.and_then(|p| albums.get(&p)) {
            target.with(|s| store::move_album(s.catalog()?, new, Some(parent), None))?;
        }
        for object in &selected.members {
            check(shared)?;
            if let Some(id) = objects.get(object) {
                target.with(|s| store::set_album_membership(s.catalog()?, new, id, true, now))?;
            }
        }
    }
    source.unchanged(plan.generation)?;
    check(shared)
}

fn authenticate_all(source: &mut Access, shared: &Shared) -> Result<()> {
    source.with(|s| {
        store::for_each_stream_ordered(s.catalog_ref()?, |id, stream| {
            check(shared)?;
            let key = chur_media::keys::object_key(s, id)?;
            let file = chur_media::store::ContainerFile::open(
                s.root_dir(),
                &s.object_store_id(),
                &stream.container_path_id,
            )?;
            let identity = chur_format::container::StreamIdentity {
                object_id: *id,
                stream_id: stream.stream_id,
                stream_kind: stream.stream_kind,
                stream_revision: stream.stream_revision,
            };
            let mut r = chur_format::container::StreamReader::open(file, &key, &identity)?;
            r.verify_complete_with(&|| shared.cancelled())?;
            ensure!(
                r.read_final_commit()?.ordered_chunk_commitment() == &stream.final_commitment,
                ObjectCorrupt,
                "the archive container contradicts its catalog"
            );
            Ok(())
        })
    })
}
pub(crate) struct BoundedOutput<'a> {
    pub(crate) file: &'a mut std::fs::File,
    pub(crate) limit: u64,
    pub(crate) position: u64,
    pub(crate) exceeded: bool,
}
impl std::io::Write for BoundedOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .position
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.limit)
        {
            self.exceeded = true;
            return Err(std::io::Error::other("archive output capacity exceeded"));
        }
        let n = std::io::Write::write(self.file, bytes)?;
        self.position += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(self.file)
    }
}
impl std::io::Seek for BoundedOutput<'_> {
    fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
        let position = std::io::Seek::seek(self.file, from)?;
        if position > self.limit {
            self.exceeded = true;
            return Err(std::io::Error::other("archive output capacity exceeded"));
        }
        self.position = position;
        Ok(position)
    }
}

fn run_export(
    mut source: Access,
    request: Request,
    mut output: std::fs::File,
    shared: &Shared,
) -> Result<Option<Id>> {
    check(shared)?;
    let plan = source.with(|s| {
        transfer::select(
            s.catalog_ref()?,
            &request.objects,
            &request.albums,
            &request.notes,
        )
    })?;
    let generation = plan.generation;
    let staging = Staging::new(&mut source)?;
    let mut target = Access::Local(Box::new(
        vault::create(&staging.root, &request.password, api::now_ms())?.activate()?,
    ));
    drop(request.password);
    copy(&mut source, &mut target, plan, shared, api::now_ms())?;
    check(shared)?;
    let done = shared.snapshot().processed;
    shared.advance(done, Stage::Committing);
    let mut bounded = BoundedOutput {
        file: &mut output,
        limit: request.max_output_bytes,
        position: 0,
        exceeded: false,
    };
    let outcome = target.with(|s| {
        s.checkpoint_catalog()?;
        let length = std::fs::metadata(s.catalog_path())
            .map_err(|_| chur_core::err!(IoFailure, "the archive catalog size could not be read"))?
            .len();
        ensure!(
            length <= 4 * 1_073_741_824,
            ResourceLimitExceeded,
            "the archive catalog exceeds its verification bound"
        );
        backup::create(s, &mut bounded, api::now_ms(), &mut CancelOnly(shared)).map(|_| ())
    });
    if bounded.exceeded {
        return Err(chur_core::err!(
            ResourceLimitExceeded,
            "the encrypted archive exceeds its output capacity"
        ));
    }
    outcome?;
    output.sync_all().map_err(|_| {
        chur_core::err!(IoFailure, "the encrypted archive could not be synchronized")
    })?;
    source.unchanged(generation)?;
    check(shared)?;
    Ok(None)
}
fn run_import(
    mut target: Access,
    request: Request,
    mut input: std::fs::File,
    shared: &Shared,
) -> Result<Option<Id>> {
    check(shared)?;
    let staging = Staging::new(&mut target)?;
    backup::restore_limited(
        &staging.root,
        &mut input,
        &request.password,
        &mut CancelOnly(shared),
        4 * 1_073_741_824,
    )?;
    check(shared)?;
    let mut source = Access::Local(Box::new(vault::unlock_with_password(
        &staging.root,
        &request.password,
        api::now_ms(),
    )?));
    drop(request.password);
    authenticate_all(&mut source, shared)?;
    let plan = source.with(|s| transfer::all(s.catalog_ref()?))?;
    check(shared)?;
    copy(&mut source, &mut target, plan, shared, api::now_ms())?;
    check(shared)?;
    Ok(None)
}

unsafe fn begin(
    session: Handle,
    request: *const u8,
    length: u32,
    fd: core::ffi::c_int,
    out: *mut Handle,
    export: bool,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: the exported caller provides a live writable handle and readable bounded request.
        unsafe { api::write_out(out, 0)? };
        let bytes = unsafe { api::borrow_bytes(request, length)? };
        let request = decode(bytes, export)?;
        let entry = registry::get(session, Kind::Session)?;
        let mut descriptor = unsafe { api::duplicate_descriptor(fd)? };
        if export {
            crate::provider_io::require_archive_output(&mut descriptor)?;
        } else {
            crate::provider_io::require_regular(&descriptor)?;
        }
        let owner = Access::Shared {
            handle: session,
            entry,
        };
        let kind = if export {
            OperationKind::Export
        } else {
            OperationKind::Import
        };
        let operation = Operation::spawn(kind, 0, move |shared| {
            if export {
                run_export(owner, request, descriptor, shared)
            } else {
                run_import(owner, request, descriptor, shared)
            }
        })?;
        let handle = registry::insert(Entry::Operation {
            owner: session,
            operation,
        })?;
        unsafe { api::write_out(out, handle) }
    })
}
/// Starts an independent password-protected encrypted selection archive.
/// # Safety
/// Request is a nonoverlapping readable range of `length` bytes (at most 65536),
/// descriptor is writable and seekable, and out is a live writable handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chur_selective_export_begin(
    session: Handle,
    request: *const u8,
    length: u32,
    descriptor: core::ffi::c_int,
    out: *mut Handle,
) -> Status {
    unsafe { begin(session, request, length, descriptor, out, true) }
}
/// Authenticates the complete archive before copying logical items into the active vault.
/// # Safety
/// As export, with a readable seekable descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chur_selective_import_begin(
    session: Handle,
    request: *const u8,
    length: u32,
    descriptor: core::ffi::c_int,
    out: *mut Handle,
) -> Status {
    unsafe { begin(session, request, length, descriptor, out, false) }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use chur_format::constants::MediaClass;
    use std::io::{Read, Seek, SeekFrom, Write};
    const PASSWORD: &[u8] = b"archive fixture source password";
    fn root() -> chur_catalog::paths::VaultRoot {
        let path = std::env::temp_dir().join(format!(
            "chur-selective-{}",
            random::id().expect("id").to_hex()
        ));
        std::fs::create_dir(&path).expect("directory");
        chur_catalog::paths::VaultRoot::new(path)
    }
    fn session(root: &chur_catalog::paths::VaultRoot) -> Session {
        vault::create(root, PASSWORD, 1)
            .expect("create")
            .activate()
            .expect("activate")
    }
    fn original(s: &mut Session, width: u32, height: u32) -> Id {
        import::import_bytes(
            s,
            import::SourceCapability {
                requested_object_id: None,
                seekable: true,
                known_length: Some(4),
                content_type_hint: "image/jpeg".into(),
                original_filename: Some("selected.jpg".into()),
                capture_time_ms: None,
            },
            import::CanonicalMedia {
                media_class: MediaClass::Image,
                width,
                height,
                duration_ms: 0,
            },
            "image/jpeg",
            &Zeroizing::new(vec![1, 2, 3, 4]),
            30,
        )
        .expect("original")
    }
    #[test]
    fn copied_display_asset_uses_authenticated_non_square_dimensions_and_fresh_keys() {
        let source_root = root();
        let target_root = root();
        let mut source = session(&source_root);
        let mut target = session(&target_root);
        let id = original(&mut source, 4000, 1000);
        let bytes = Zeroizing::new(vec![9, 8, 7, 6, 5]);
        derived::put(
            &mut source,
            &id,
            StreamKind::ThumbnailSmall,
            128,
            32,
            &bytes,
            31,
        )
        .expect("derivative");
        let source_tag = random::id().expect("source tag");
        let destination_tag = random::id().expect("target tag");
        store::put_tag(
            source.catalog().expect("catalog"),
            &chur_catalog::model::Tag {
                tag_id: source_tag,
                name: "existing tag".into(),
                created_ms: 10,
            },
        )
        .expect("source tag");
        store::set_object_tag(source.catalog().expect("catalog"), &source_tag, &id, true)
            .expect("source membership");
        store::put_tag(
            target.catalog().expect("catalog"),
            &chur_catalog::model::Tag {
                tag_id: destination_tag,
                name: "existing tag".into(),
                created_ms: 5,
            },
        )
        .expect("target tag");
        store::set_favorite(source.catalog().expect("catalog"), &id, true, 32).expect("favorite");
        let old_key = chur_media::keys::object_key(&source, &id).expect("source key");
        let plan = transfer::select(source.catalog_ref().expect("catalog"), &[id], &[], &[])
            .expect("plan");
        let operation = Operation::spawn(OperationKind::Export, 0, move |shared| {
            let mut source = Access::Local(Box::new(source));
            let mut target = Access::Local(Box::new(target));
            copy(&mut source, &mut target, plan, shared, 40)?;
            target.with(|s| {
                let plan = transfer::all(s.catalog_ref()?)?;
                assert_eq!(plan.objects.len(), 1);
                let fresh = plan.objects[0];
                assert_ne!(fresh, id);
                let object = store::object(s.catalog_ref()?, &fresh)?;
                assert_eq!(object.capture_time_ms, 30);
                assert!(object.capture_time_substituted);
                assert_eq!(object.import_time_ms, 40);
                assert!(object.favorite);
                let mut favorites = chur_catalog::query::ObjectQuery::timeline();
                favorites.scope = chur_catalog::query::Scope::Favorites;
                assert_eq!(
                    chur_catalog::query::page(s.catalog_ref()?, &favorites)?
                        .objects
                        .len(),
                    1
                );
                let copied_tags = store::tags(s.catalog_ref()?)?;
                assert_eq!(copied_tags.len(), 1);
                assert_eq!(copied_tags[0].tag_id, destination_tag);
                assert_eq!(copied_tags[0].created_ms, 5);
                assert_eq!(
                    store::object_tags(s.catalog_ref()?, &fresh)?[0].tag_id,
                    destination_tag
                );
                let fresh_key = chur_media::keys::object_key(s, &fresh)?;
                assert_ne!(fresh_key.expose(), old_key.expose());
                let mut asset = reader::open(s, &fresh, StreamKind::ThumbnailSmall)?;
                assert_eq!(asset.dimensions(), (128, 32));
                assert_eq!(
                    asset.read_range(0, asset.size())?.as_slice(),
                    &[9, 8, 7, 6, 5]
                );
                Ok(())
            })?;
            assert_eq!(shared.snapshot().processed, 1);
            Ok(None)
        })
        .expect("operation");
        operation.join();
        assert_eq!(operation.poll().status, 0);
        drop(operation);
        std::fs::remove_dir_all(source_root.base()).expect("cleanup");
        std::fs::remove_dir_all(target_root.base()).expect("cleanup");
    }
    #[test]
    fn encrypted_archive_capacity_is_enforced_before_write_and_staging_is_removed() {
        let source_root = root();
        let mut source = session(&source_root);
        let id = original(&mut source, 1, 1);
        let staging_path = source
            .root_dir()
            .vault(&source.object_store_id())
            .join("archive-staging");
        let output_path = source_root.base().join("explicit-output.churbak-partial");
        let output = std::fs::File::create(&output_path).expect("output");
        let request = Request {
            password: Zeroizing::new(b"fresh archive password".to_vec()),
            objects: vec![id],
            albums: Vec::new(),
            notes: Vec::new(),
            max_output_bytes: 64,
        };
        let operation = Operation::spawn(OperationKind::Export, 0, move |shared| {
            run_export(Access::Local(Box::new(source)), request, output, shared)
        })
        .expect("operation");
        operation.join();
        assert_eq!(
            operation.poll().status,
            chur_core::ChurStatus::ResourceLimitExceeded as i32
        );
        assert_eq!(operation.poll().processed, 1);
        assert!(
            std::fs::metadata(&output_path)
                .expect("output metadata")
                .len()
                <= 64
        );
        assert_eq!(
            std::fs::read_dir(staging_path)
                .expect("staging parent")
                .count(),
            0
        );
        drop(operation);
        std::fs::remove_dir_all(source_root.base()).expect("cleanup");
    }
    #[test]
    fn checked_target_commit_cancels_and_reconciles_only_its_own_incomplete_item() {
        let root = root();
        let mut s = session(&root);
        let mut writing = import::begin(
            &mut s,
            import::SourceCapability {
                requested_object_id: None,
                seekable: true,
                known_length: Some(4),
                content_type_hint: "application/octet-stream".into(),
                original_filename: Some("partial".into()),
                capture_time_ms: None,
            },
            import::CanonicalMedia::opaque(),
            1,
        )
        .expect("begin");
        let transaction = writing.transaction_id();
        let id = writing.object_id();
        writing.write(&mut s, &[1, 2, 3, 4]).expect("chunk");
        let result = writing.commit_with_display_checked(
            &mut s,
            "application/octet-stream",
            2,
            import::CopiedDisplay {
                caption: None,
                favorite: false,
                capture_time: None,
            },
            &|| true,
        );
        assert!(result.is_err());
        assert!(!import::reconcile_one(&mut s, &transaction).expect("reconcile"));
        assert!(store::object(s.catalog_ref().expect("catalog"), &id).is_err());
        assert!(
            chur_catalog::journal::live(s.catalog_ref().expect("catalog"))
                .expect("journal")
                .is_empty()
        );
        s.lock().expect("lock");
        std::fs::remove_dir_all(root.base()).expect("cleanup");
    }
    #[test]
    fn bounded_writer_refuses_oversized_chunks_without_advancing_the_file() {
        let root = root();
        let path = root.base().join("bounded");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .expect("file");
        {
            let mut writer = BoundedOutput {
                file: &mut file,
                limit: 4,
                position: 0,
                exceeded: false,
            };
            writer.write_all(&[1, 2]).expect("small");
            assert!(writer.write_all(&[3, 4, 5]).is_err());
            assert!(writer.exceeded);
            assert_eq!(writer.position, 2);
        }
        file.seek(SeekFrom::Start(0)).expect("seek");
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).expect("read");
        assert_eq!(contents, vec![1, 2]);
        std::fs::remove_dir_all(root.base()).expect("cleanup");
    }
    #[test]
    fn descriptor_custody_prevents_another_unlock_from_sweeping_live_staging() {
        let root = root();
        let mut owner = Access::Local(Box::new(session(&root)));
        let stage = Staging::new(&mut owner).expect("stage");
        let second = vault::unlock_with_password(&root, PASSWORD, 2);
        match second {
            Ok(_) => panic!("a second unlock bypassed descriptor custody"),
            Err(error) => assert_eq!(error.status(), chur_core::ChurStatus::Conflict),
        }
        assert!(stage.path.is_dir());
        drop(stage);
        let orphan = owner
            .with(|s| {
                Ok(s.root_dir()
                    .vault(&s.object_store_id())
                    .join("archive-staging")
                    .join("orphan"))
            })
            .expect("path");
        std::fs::create_dir(&orphan).expect("orphan");
        owner.with(|s| s.lock()).expect("lock");
        drop(owner);
        let mut reopened = vault::unlock_with_password(&root, PASSWORD, 3).expect("reopen");
        sweep_staging(&reopened).expect("sweep");
        assert!(!orphan.exists());
        reopened.lock().expect("lock");
        std::fs::remove_dir_all(root.base()).expect("cleanup");
    }
    #[cfg(unix)]
    #[test]
    fn packaging_cancel_keeps_item_progress_and_removes_its_encrypted_staging() {
        use std::os::{fd::OwnedFd, unix::net::UnixStream};
        let source_root = root();
        let mut source = session(&source_root);
        let bytes = Zeroizing::new(vec![17; 8 * 1024 * 1024]);
        let id = import::import_bytes(
            &mut source,
            import::SourceCapability {
                requested_object_id: None,
                seekable: true,
                known_length: Some(bytes.len() as u64),
                content_type_hint: "application/octet-stream".into(),
                original_filename: Some("large opaque fixture".into()),
                capture_time_ms: None,
            },
            import::CanonicalMedia::opaque(),
            "application/octet-stream",
            &bytes,
            1,
        )
        .expect("original");
        drop(bytes);
        let staging = source
            .root_dir()
            .vault(&source.object_store_id())
            .join("archive-staging");
        let (mut receive, send) = UnixStream::pair().expect("pipe");
        receive
            .set_read_timeout(Some(std::time::Duration::from_secs(60)))
            .expect("timeout");
        let owned: OwnedFd = send.into();
        let output = std::fs::File::from(owned);
        let request = Request {
            password: Zeroizing::new(b"independent archive password".to_vec()),
            objects: vec![id],
            albums: Vec::new(),
            notes: Vec::new(),
            max_output_bytes: i64::MAX as u64,
        };
        let operation = Operation::spawn(OperationKind::Export, 0, move |shared| {
            run_export(Access::Local(Box::new(source)), request, output, shared)
        })
        .expect("operation");
        let mut prefix = [0; 4];
        receive.read_exact(&mut prefix).expect("archive prefix");
        assert_eq!(&prefix, b"CHUR");
        assert!(!operation.poll().terminal);
        assert_eq!(operation.poll().processed, 1);
        operation.cancel();
        let mut buffer = [0; 16384];
        loop {
            match receive.read(&mut buffer) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) => panic!("archive drain failed: {error}"),
            }
        }
        operation.join();
        assert_eq!(
            operation.poll().status,
            chur_core::ChurStatus::Cancelled as i32
        );
        assert_eq!(operation.poll().processed, 1);
        assert_eq!(operation.poll().total, 1);
        assert_eq!(std::fs::read_dir(staging).expect("staging").count(), 0);
        drop(operation);
        std::fs::remove_dir_all(source_root.base()).expect("cleanup");
    }
    #[cfg(unix)]
    #[test]
    fn orphan_sweep_does_not_follow_a_link_outside_its_private_namespace() {
        let source_root = root();
        let outside = root();
        let marker = outside.base().join("keep");
        std::fs::write(&marker, b"preserve").expect("marker");
        let mut source = session(&source_root);
        let parent = source
            .root_dir()
            .vault(&source.object_store_id())
            .join("archive-staging");
        std::fs::create_dir(&parent).expect("parent");
        std::os::unix::fs::symlink(outside.base(), parent.join("outside-link")).expect("link");
        source.lock().expect("lock");
        drop(source);
        let mut reopened = vault::unlock_with_password(&source_root, PASSWORD, 2).expect("reopen");
        sweep_staging(&reopened).expect("sweep");
        assert_eq!(std::fs::read(&marker).expect("outside intact"), b"preserve");
        reopened.lock().expect("lock");
        std::fs::remove_dir_all(source_root.base()).expect("cleanup");
        std::fs::remove_dir_all(outside.base()).expect("cleanup");
    }
    #[test]
    fn selective_archive_and_import_omit_derived_content_but_offer_fresh_sources_for_ocr() {
        use chur_catalog::{
            content_index,
            query::{ObjectQuery, Scope, page},
        };
        let source_root = root();
        let target_root = root();
        let restored_root = root();
        let mut source = session(&source_root);
        let target = session(&target_root);
        let source_vault = source.vault_id();
        let target_vault = target.vault_id();
        let object_id = original(&mut source, 800, 600);
        let source_stream = store::object(source.catalog_ref().unwrap(), &object_id)
            .unwrap()
            .primary_stream_id;
        let text = "Уникальныйраспознанныйтекст OCR_SELECTIVE_CANARY_714829";
        content_index::put(
            source.catalog().unwrap(),
            &object_id,
            &source_stream,
            1,
            1,
            text,
        )
        .unwrap();
        let query = ObjectQuery {
            scope: Scope::Search,
            terms: Some("уникальныйраспознанныйтекст".into()),
            ..ObjectQuery::timeline()
        };
        assert_eq!(
            page(source.catalog_ref().unwrap(), &query)
                .unwrap()
                .objects
                .len(),
            1
        );
        let archive = source_root.base().join("selected.churbak");
        let output = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&archive)
            .unwrap();
        let password = b"independent selective content fixture";
        let export_request = Request {
            password: Zeroizing::new(password.to_vec()),
            objects: vec![object_id],
            albums: Vec::new(),
            notes: Vec::new(),
            max_output_bytes: i64::MAX as u64,
        };
        let export_operation = Operation::spawn(OperationKind::Export, 0, move |shared| {
            run_export(
                Access::Local(Box::new(source)),
                export_request,
                output,
                shared,
            )
        })
        .unwrap();
        export_operation.join();
        assert_eq!(export_operation.poll().status, 0);
        drop(export_operation);
        let encrypted = std::fs::read(&archive).unwrap();
        let canary = b"OCR_SELECTIVE_CANARY_714829";
        assert!(!encrypted.windows(canary.len()).any(|bytes| bytes == canary));
        let mut restore_input = std::fs::File::open(&archive).unwrap();
        backup::restore(
            &restored_root,
            &mut restore_input,
            password,
            &mut chur_media::progress::Uninterrupted,
        )
        .unwrap();
        let restored =
            vault::unlock_with_password(&restored_root, password, api::now_ms()).unwrap();
        assert_ne!(restored.vault_id(), source_vault);
        assert!(
            page(restored.catalog_ref().unwrap(), &query)
                .unwrap()
                .objects
                .is_empty()
        );
        let exported_candidates =
            content_index::candidates(restored.catalog_ref().unwrap(), None, 100, false).unwrap();
        assert_eq!(exported_candidates.len(), 1);
        assert_ne!(exported_candidates[0].object_id, object_id);
        assert_ne!(exported_candidates[0].primary_stream_id, source_stream);
        let archive_object = exported_candidates[0].object_id;
        drop(restored);
        let input = std::fs::File::open(&archive).unwrap();
        let import_request = Request {
            password: Zeroizing::new(password.to_vec()),
            objects: Vec::new(),
            albums: Vec::new(),
            notes: Vec::new(),
            max_output_bytes: i64::MAX as u64,
        };
        let import_operation = Operation::spawn(OperationKind::Import, 0, move |shared| {
            run_import(
                Access::Local(Box::new(target)),
                import_request,
                input,
                shared,
            )
        })
        .unwrap();
        import_operation.join();
        assert_eq!(import_operation.poll().status, 0);
        drop(import_operation);
        let reopened = vault::unlock_with_password(&target_root, PASSWORD, api::now_ms()).unwrap();
        assert_eq!(reopened.vault_id(), target_vault);
        assert!(
            page(reopened.catalog_ref().unwrap(), &query)
                .unwrap()
                .objects
                .is_empty()
        );
        let imported_candidates =
            content_index::candidates(reopened.catalog_ref().unwrap(), None, 100, false).unwrap();
        assert_eq!(imported_candidates.len(), 1);
        assert_ne!(imported_candidates[0].object_id, object_id);
        assert_ne!(imported_candidates[0].object_id, archive_object);
        assert_ne!(imported_candidates[0].primary_stream_id, source_stream);
        let mut original_reader = reader::open(
            &reopened,
            &imported_candidates[0].object_id,
            StreamKind::Original,
        )
        .unwrap();
        assert_eq!(
            original_reader
                .read_range(0, original_reader.size())
                .unwrap()
                .as_slice(),
            &[1, 2, 3, 4]
        );
        drop(original_reader);
        drop(reopened);
        std::fs::remove_dir_all(source_root.base()).unwrap();
        std::fs::remove_dir_all(target_root.base()).unwrap();
        std::fs::remove_dir_all(restored_root.base()).unwrap();
    }
    #[test]
    fn encrypted_selective_note_archive_and_import_recover_historical_files() {
        use chur_catalog::{note_attachments as files, note_workspace as workspace, notes};
        let source_root = root();
        let restored_root = root();
        let target_root = root();
        let mut source = session(&source_root);
        let n = notes::save(
            source.catalog().unwrap(),
            None,
            0,
            "Private note",
            "# exact source",
            false,
            notes::NoteFormat::Markdown,
            api::now_ms(),
        )
        .unwrap();
        let aid = random::id().unwrap();
        let bytes = b"SELECTIVE_HISTORICAL_FILE_CANARY";
        let n = files::put(
            source.catalog().unwrap(),
            &n.id,
            n.revision,
            files::AttachmentData {
                attachment: files::Attachment {
                    id: aid,
                    name: "history.bin".into(),
                    mime_type: "application/octet-stream".into(),
                    size: bytes.len() as u64,
                },
                data: Zeroizing::new(bytes.to_vec()),
            },
            api::now_ms(),
        )
        .unwrap();
        let n = workspace::set_organization(
            source.catalog().unwrap(),
            &n.id,
            n.revision,
            "Folder",
            &["tag"],
            api::now_ms(),
        )
        .unwrap();
        let n = files::remove(
            source.catalog().unwrap(),
            &n.id,
            n.revision,
            &aid,
            api::now_ms(),
        )
        .unwrap();
        let path = source_root.base().join("note-selection.churbak");
        let output = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let password = b"independent historical note archive password";
        let request = Request {
            password: Zeroizing::new(password.to_vec()),
            objects: Vec::new(),
            albums: Vec::new(),
            notes: vec![(n.id, n.revision)],
            max_output_bytes: i64::MAX as u64,
        };
        let operation = Operation::spawn(OperationKind::Export, 0, move |shared| {
            run_export(Access::Local(Box::new(source)), request, output, shared)
        })
        .unwrap();
        operation.join();
        assert_eq!(operation.poll().status, 0);
        drop(operation);
        assert!(
            !std::fs::read(&path)
                .unwrap()
                .windows(bytes.len())
                .any(|w| w == bytes)
        );
        let mut input = std::fs::File::open(&path).unwrap();
        backup::restore(
            &restored_root,
            &mut input,
            password,
            &mut chur_media::progress::Uninterrupted,
        )
        .unwrap();
        let mut restored =
            vault::unlock_with_password(&restored_root, password, api::now_ms()).unwrap();
        let copied = notes::page(restored.catalog_ref().unwrap(), "", false, 50, None)
            .unwrap()
            .notes
            .remove(0)
            .note;
        assert_ne!(copied.id, n.id);
        assert_eq!(copied.attachment_count, 0);
        assert_eq!(
            workspace::get_organization(restored.catalog_ref().unwrap(), &copied.id)
                .unwrap()
                .folder,
            "Folder"
        );
        let revision = workspace::history(restored.catalog_ref().unwrap(), &copied.id)
            .unwrap()
            .into_iter()
            .find(|r| r.note.attachment_count == 1)
            .unwrap()
            .note
            .revision;
        workspace::restore(
            restored.catalog().unwrap(),
            &copied.id,
            copied.revision,
            revision,
            api::now_ms(),
        )
        .unwrap();
        assert_eq!(
            &*files::read(restored.catalog_ref().unwrap(), &copied.id, &aid).unwrap(),
            bytes
        );
        restored.lock().unwrap();
        drop(restored);
        let target = session(&target_root);
        let input = std::fs::File::open(&path).unwrap();
        let request = Request {
            password: Zeroizing::new(password.to_vec()),
            objects: Vec::new(),
            albums: Vec::new(),
            notes: Vec::new(),
            max_output_bytes: i64::MAX as u64,
        };
        let operation = Operation::spawn(OperationKind::Import, 0, move |shared| {
            run_import(Access::Local(Box::new(target)), request, input, shared)
        })
        .unwrap();
        operation.join();
        assert_eq!(operation.poll().status, 0);
        drop(operation);
        let mut target =
            vault::unlock_with_password(&target_root, PASSWORD, api::now_ms()).unwrap();
        let copied = notes::page(target.catalog_ref().unwrap(), "", false, 50, None)
            .unwrap()
            .notes
            .remove(0)
            .note;
        let revision = workspace::history(target.catalog_ref().unwrap(), &copied.id)
            .unwrap()
            .into_iter()
            .find(|r| r.note.attachment_count == 1)
            .unwrap()
            .note
            .revision;
        workspace::restore(
            target.catalog().unwrap(),
            &copied.id,
            copied.revision,
            revision,
            api::now_ms(),
        )
        .unwrap();
        assert_eq!(
            &*files::read(target.catalog_ref().unwrap(), &copied.id, &aid).unwrap(),
            bytes
        );
        assert_eq!(
            workspace::get_organization(target.catalog_ref().unwrap(), &copied.id)
                .unwrap()
                .tags,
            vec!["tag"]
        );
        target.lock().unwrap();
        drop(target);
        std::fs::remove_dir_all(source_root.base()).unwrap();
        std::fs::remove_dir_all(restored_root.base()).unwrap();
        std::fs::remove_dir_all(target_root.base()).unwrap();
    }
}

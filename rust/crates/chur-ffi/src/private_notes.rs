//! Bounded private-note control records and cancellable plaintext export.
#![expect(
    unsafe_code,
    reason = "the C ABI validates caller pointers for each call"
)]
use crate::{
    api::{self, Status},
    operation::{Operation, OperationKind, Stage},
    panic::guard_status_for,
    registry::{self, Entry, Handle, Kind},
};
use chur_catalog::notes;
use chur_core::{Id, Result, ensure};
use zeroize::Zeroizing;
const CAPACITY: usize = 1024 * 1024;
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| chur_core::err!(InvalidInput, "the note request is malformed"))?;
        ensure!(
            end <= self.bytes.len(),
            InvalidInput,
            "the note request is truncated"
        );
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn number(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| chur_core::err!(InvalidInput, "the note number is malformed"),
        )?))
    }
    fn string(&mut self, max: usize) -> Result<&'a str> {
        let len = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| chur_core::err!(InvalidInput, "the note length is malformed"))?,
        ) as usize;
        ensure!(
            len <= max,
            ResourceLimitExceeded,
            "the note text exceeds its bound"
        );
        core::str::from_utf8(self.take(len)?)
            .map_err(|_| chur_core::err!(InvalidInput, "the note text is not UTF-8"))
    }
    fn count(&mut self) -> Result<usize> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| chur_core::err!(InvalidInput, "the attachment count is malformed"))?,
        ) as usize)
    }
    fn finished(&self) -> Result<()> {
        ensure!(
            self.at == self.bytes.len(),
            InvalidInput,
            "the request has trailing bytes"
        );
        Ok(())
    }
    fn end(self) -> Result<()> {
        ensure!(
            self.at == self.bytes.len(),
            InvalidInput,
            "the note request has trailing bytes"
        );
        Ok(())
    }
}
fn string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}
fn encode(out: &mut Vec<u8>, n: &notes::Note, text: &str, size: u64) {
    out.extend_from_slice(n.id.as_bytes());
    out.extend_from_slice(&n.revision.to_be_bytes());
    out.extend_from_slice(&n.created_ms.to_be_bytes());
    out.extend_from_slice(&n.updated_ms.to_be_bytes());
    out.extend_from_slice(&n.deleted_ms.unwrap_or(u64::MAX).to_be_bytes());
    out.push(u8::from(n.pinned));
    out.push(n.format as u8);
    out.extend_from_slice(&n.attachment_count.to_be_bytes());
    out.extend_from_slice(&size.to_be_bytes());
    string(out, &n.title);
    string(out, text);
}
fn with_catalog<T>(
    session: Handle,
    body: impl FnOnce(&mut chur_catalog::CatalogDb) -> Result<T>,
) -> Result<T> {
    let entry = registry::get(session, Kind::Session)?;
    let Entry::Session {
        session: guarded, ..
    } = entry.as_ref()
    else {
        return Err(chur_core::err!(InvalidInput, "the handle is not a session"));
    };
    let mut guard = registry::lock(guarded);
    body(guard.catalog()?)
}
/// The caller provides a readable bounded request and a writable output buffer.
/// All output pointers must remain valid for this synchronous call.
unsafe fn control(
    session: Handle,
    request: *const u8,
    len: usize,
    destination: *mut u8,
    capacity: usize,
    written: *mut usize,
    body: impl FnOnce(&mut chur_catalog::CatalogDb, &mut Reader<'_>, &mut Vec<u8>) -> Result<()>,
) -> Status {
    guard_status_for(session, || {
        // SAFETY: the exported function delegates its documented pointer contract.
        unsafe { api::write_out(written, 0)? };
        ensure!(
            len <= CAPACITY,
            ResourceLimitExceeded,
            "the note request exceeds its bound"
        );
        ensure!(
            capacity >= CAPACITY,
            ResourceLimitExceeded,
            "the note output buffer is too small"
        );
        ensure!(
            len == 0 || !request.is_null(),
            InvalidInput,
            "the note request pointer is null"
        );
        // SAFETY: len is bounded to 1 MiB, the pointer is non-null for a nonempty
        // request, and the caller guarantees readable, unaliased bytes for the call.
        let input = if len == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(request, len) }
        };
        // SAFETY: capacity was checked above; only the fixed record bound is borrowed.
        let output = unsafe { api::borrow_bytes_mut(destination, CAPACITY)? };
        let mut reader = Reader {
            bytes: input,
            at: 0,
        };
        let mut record = Zeroizing::new(Vec::with_capacity(CAPACITY));
        with_catalog(session, |db| {
            notes::purge_expired(db, api::now_ms())?;
            body(db, &mut reader, &mut record)
        })?;
        reader.end()?;
        ensure!(
            record.len() <= capacity,
            ResourceLimitExceeded,
            "the note output exceeds its bound"
        );
        output[..record.len()].copy_from_slice(&record);
        unsafe { api::write_out(written, record.len()) }
    })
}
/// Lists bounded summaries. Request: trash u8, limit u64, terms u32+UTF8, cursor u32+bytes.
/// # Safety
/// Request and output pointers follow `control`'s synchronous contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chur_private_notes_query(
    session: Handle,
    request: *const u8,
    len: usize,
    destination: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> Status {
    unsafe {
        control(
            session,
            request,
            len,
            destination,
            capacity,
            written,
            |db, r, out| {
                let trash = r.byte()?;
                ensure!(trash <= 1, InvalidInput, "the note trash flag is invalid");
                let limit = u16::try_from(r.number()?)
                    .map_err(|_| chur_core::err!(InvalidInput, "the note page limit is invalid"))?;
                let terms = r.string(256)?;
                let n = u32::from_be_bytes(
                    r.take(4)?
                        .try_into()
                        .map_err(|_| chur_core::err!(InvalidInput, "the cursor is malformed"))?,
                ) as usize;
                ensure!(
                    n == 0 || n == 65,
                    InvalidInput,
                    "the note cursor is malformed"
                );
                let cursor = r.take(n)?;
                ensure!(
                    r.at == r.bytes.len(),
                    InvalidInput,
                    "the request has trailing bytes"
                );
                let page = notes::page(
                    db,
                    terms,
                    trash == 1,
                    limit,
                    if n == 0 { None } else { Some(cursor) },
                )?;
                out.extend_from_slice(&(page.notes.len() as u32).to_be_bytes());
                for item in page.notes {
                    encode(out, &item.note, &item.note.body, item.export_size);
                }
                let cursor = page.next_cursor.unwrap_or_default();
                out.extend_from_slice(&(cursor.len() as u32).to_be_bytes());
                out.extend_from_slice(&cursor);
                Ok(())
            },
        )
    }
}
/// Gets one note. Request is exactly its sixteen-byte id.
/// # Safety
/// Request and output pointers follow `control`'s synchronous contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chur_private_note_get(
    session: Handle,
    request: *const u8,
    len: usize,
    destination: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> Status {
    unsafe {
        control(
            session,
            request,
            len,
            destination,
            capacity,
            written,
            |db, r, out| {
                let id = Id::from_slice(r.take(16)?)?;
                ensure!(
                    r.at == r.bytes.len(),
                    InvalidInput,
                    "the request has trailing bytes"
                );
                let n = notes::get(db, &id)?;
                encode(
                    out,
                    &n,
                    &n.body,
                    chur_catalog::note_attachments::export_size(db, &n)?,
                );
                Ok(())
            },
        )
    }
}
/// Saves under CAS. Request: id16 (zero creates), expected u64, pinned u8, format u8, title/body u32+UTF8.
/// # Safety
/// Request and output pointers follow `control`'s synchronous contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chur_private_note_save(
    session: Handle,
    request: *const u8,
    len: usize,
    destination: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> Status {
    unsafe {
        control(
            session,
            request,
            len,
            destination,
            capacity,
            written,
            |db, r, out| {
                let bytes = r.take(16)?;
                let id = if bytes.iter().all(|b| *b == 0) {
                    None
                } else {
                    Some(Id::from_slice(bytes)?)
                };
                let expected = r.number()?;
                let pin = r.byte()?;
                ensure!(pin <= 1, InvalidInput, "the pin flag is invalid");
                let format = notes::NoteFormat::try_from(r.byte()?)?;
                let title = r.string(256)?;
                let body = r.string(262144)?;
                ensure!(
                    r.at == r.bytes.len(),
                    InvalidInput,
                    "the request has trailing bytes"
                );
                let n = notes::save(
                    db,
                    id,
                    expected,
                    title,
                    body,
                    pin == 1,
                    format,
                    api::now_ms(),
                )?;
                encode(
                    out,
                    &n,
                    &n.body,
                    chur_catalog::note_attachments::export_size(db, &n)?,
                );
                Ok(())
            },
        )
    }
}
/// Changes one note. Request: id16, expected u64, action u8 (1..5). Purge returns an empty record.
/// # Safety
/// Request and output pointers follow `control`'s synchronous contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chur_private_note_change(
    session: Handle,
    request: *const u8,
    len: usize,
    destination: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> Status {
    unsafe {
        control(
            session,
            request,
            len,
            destination,
            capacity,
            written,
            |db, r, out| {
                let id = Id::from_slice(r.take(16)?)?;
                let expected = r.number()?;
                let action = r.byte()?;
                ensure!(
                    r.at == r.bytes.len(),
                    InvalidInput,
                    "the request has trailing bytes"
                );
                if let Some(n) = notes::change(db, &id, expected, action, api::now_ms())? {
                    encode(
                        out,
                        &n,
                        &n.body,
                        chur_catalog::note_attachments::export_size(db, &n)?,
                    );
                }
                Ok(())
            },
        )
    }
}
/// Executes one bounded attachment command. 1=list(id16), 2=put(id16,revision u64,file),
/// 3=read(id16,attachment16), 4=remove(id16,revision u64,attachment16),
/// 5=import(format u8,title/body strings,count u32,files). A file is id16,name/MIME
/// strings,data u32+bytes. List returns count u32 and id/name/MIME/size u64 records;
/// put/remove/import return the normal private-note record; read returns raw bytes.
/// # Safety
/// All input/output pointers remain readable/writable and non-overlapping for this synchronous call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chur_private_note_attachments(
    session: Handle,
    request: *const u8,
    len: usize,
    destination: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> Status {
    guard_status_for(session, || {
        unsafe { api::write_out(written, 0)? };
        ensure!(
            len <= chur_catalog::note_attachments::TOTAL_MAX + 524288,
            ResourceLimitExceeded,
            "the attachment request exceeds its bound"
        );
        ensure!(
            capacity <= chur_catalog::note_attachments::FILE_MAX + 1048576,
            ResourceLimitExceeded,
            "the attachment output exceeds its bound"
        );
        let request_length = u32::try_from(len).map_err(|_| {
            chur_core::err!(
                ResourceLimitExceeded,
                "the attachment request length is out of range"
            )
        })?;
        let input = unsafe { api::borrow_large(request, request_length)? };
        let mut r = Reader {
            bytes: input,
            at: 0,
        };
        let command = r.byte()?;
        ensure!(
            capacity
                >= if command == 3 || command == 10 {
                    chur_catalog::note_attachments::FILE_MAX
                } else {
                    CAPACITY
                },
            ResourceLimitExceeded,
            "the attachment output buffer is too small"
        );
        let output = unsafe { api::borrow_bytes_mut(destination, capacity)? };
        let mut out = Zeroizing::new(Vec::with_capacity(capacity));
        with_catalog(session, |db| {
            use chur_catalog::note_attachments as files;
            notes::purge_expired(db, api::now_ms())?;
            match command {
                1 => {
                    let id = Id::from_slice(r.take(16)?)?;
                    r.finished()?;
                    let all = files::list(db, &id)?;
                    out.extend_from_slice(&(all.len() as u32).to_be_bytes());
                    for a in all {
                        out.extend_from_slice(a.id.as_bytes());
                        string(&mut out, &a.name);
                        string(&mut out, &a.mime_type);
                        out.extend_from_slice(&a.size.to_be_bytes());
                    }
                }
                2 => {
                    let id = Id::from_slice(r.take(16)?)?;
                    let revision = r.number()?;
                    let item = attachment(&mut r)?;
                    r.finished()?;
                    let n = files::put(db, &id, revision, item, api::now_ms())?;
                    encode(&mut out, &n, &n.body, files::export_size(db, &n)?);
                }
                3 => {
                    let id = Id::from_slice(r.take(16)?)?;
                    let attachment = Id::from_slice(r.take(16)?)?;
                    r.finished()?;
                    out.extend_from_slice(&files::read(db, &id, &attachment)?);
                }
                4 => {
                    let id = Id::from_slice(r.take(16)?)?;
                    let revision = r.number()?;
                    let attachment = Id::from_slice(r.take(16)?)?;
                    r.finished()?;
                    let n = files::remove(db, &id, revision, &attachment, api::now_ms())?;
                    encode(&mut out, &n, &n.body, files::export_size(db, &n)?);
                }
                5 => {
                    let format = notes::NoteFormat::try_from(r.byte()?)?;
                    let title = r.string(256)?;
                    let body = r.string(262144)?;
                    let count = r.count()?;
                    ensure!(
                        count <= files::COUNT_MAX,
                        ResourceLimitExceeded,
                        "the attachment count exceeds its bound"
                    );
                    let mut all = Vec::with_capacity(count);
                    for _ in 0..count {
                        all.push(attachment(&mut r)?);
                    }
                    r.finished()?;
                    let n = files::import(db, title, body, format, &all, api::now_ms())?;
                    encode(&mut out, &n, &n.body, files::export_size(db, &n)?);
                }
                6 => {
                    let id = Id::from_slice(r.take(16)?)?;
                    r.finished()?;
                    encode_organization(
                        &mut out,
                        &chur_catalog::note_workspace::get_organization(db, &id)?,
                    );
                }
                7 => {
                    let id = Id::from_slice(r.take(16)?)?;
                    let expected = r.number()?;
                    let folder = r.string(64)?;
                    let count = r.count()?;
                    ensure!(
                        count <= 16,
                        ResourceLimitExceeded,
                        "the note has too many tags"
                    );
                    let mut tags = Vec::with_capacity(count);
                    for _ in 0..count {
                        tags.push(r.string(64)?);
                    }
                    r.finished()?;
                    let n = chur_catalog::note_workspace::set_organization(
                        db,
                        &id,
                        expected,
                        folder,
                        &tags,
                        api::now_ms(),
                    )?;
                    encode(&mut out, &n, &n.body, files::export_size(db, &n)?);
                }
                8 => {
                    let id = Id::from_slice(r.take(16)?)?;
                    r.finished()?;
                    let versions = chur_catalog::note_workspace::history(db, &id)?;
                    out.extend_from_slice(&(versions.len() as u32).to_be_bytes());
                    for v in versions {
                        out.extend_from_slice(&v.note.revision.to_be_bytes());
                        out.extend_from_slice(&v.note.updated_ms.to_be_bytes());
                        string(&mut out, &v.note.title);
                        out.push(v.note.format as u8);
                        out.extend_from_slice(&v.note.attachment_count.to_be_bytes());
                    }
                }
                9 => {
                    let id = Id::from_slice(r.take(16)?)?;
                    let expected = r.number()?;
                    let revision = r.number()?;
                    r.finished()?;
                    let n = chur_catalog::note_workspace::restore(
                        db,
                        &id,
                        expected,
                        revision,
                        api::now_ms(),
                    )?;
                    encode(&mut out, &n, &n.body, files::export_size(db, &n)?);
                }
                10 => {
                    let id = Id::from_slice(r.take(16)?)?;
                    let revision = r.number()?;
                    let attachment = Id::from_slice(r.take(16)?)?;
                    r.finished()?;
                    out.extend_from_slice(&chur_catalog::note_workspace::read_revision_file(
                        db,
                        &id,
                        revision,
                        &attachment,
                    )?);
                }
                11 => {
                    let id = Id::from_slice(r.take(16)?)?;
                    let revision = r.number()?;
                    r.finished()?;
                    let v = chur_catalog::note_workspace::get_revision(db, &id, revision)?;
                    encode(&mut out, &v.note, &v.note.body, v.note.export_size());
                    encode_organization(&mut out, &v.organization);
                    out.extend_from_slice(&(v.attachments.len() as u32).to_be_bytes());
                    for a in v.attachments {
                        out.extend_from_slice(a.id.as_bytes());
                        string(&mut out, &a.name);
                        string(&mut out, &a.mime_type);
                        out.extend_from_slice(&a.size.to_be_bytes());
                    }
                }
                12 => {
                    let trash = r.byte()?;
                    ensure!(trash <= 1, InvalidInput, "the note trash flag is invalid");
                    let limit = u16::try_from(r.number()?).map_err(|_| {
                        chur_core::err!(InvalidInput, "the note page limit is invalid")
                    })?;
                    let terms = r.string(256)?;
                    let len = r.count()?;
                    ensure!(
                        len == 0 || len == 65,
                        InvalidInput,
                        "the note cursor is malformed"
                    );
                    let cursor = r.take(len)?;
                    let folder = r.string(64)?;
                    let tag = r.string(64)?;
                    r.finished()?;
                    let page = notes::page_filtered(
                        db,
                        terms,
                        trash == 1,
                        limit,
                        if len == 0 { None } else { Some(cursor) },
                        folder,
                        tag,
                    )?;
                    out.extend_from_slice(&(page.notes.len() as u32).to_be_bytes());
                    for item in &page.notes {
                        encode(&mut out, &item.note, &item.note.body, item.export_size);
                    }
                    let cursor = page.next_cursor.unwrap_or_default();
                    out.extend_from_slice(&(cursor.len() as u32).to_be_bytes());
                    out.extend_from_slice(&cursor);
                    for item in &page.notes {
                        encode_organization(
                            &mut out,
                            &chur_catalog::note_workspace::get_organization(db, &item.note.id)?,
                        );
                    }
                }
                _ => {
                    return Err(chur_core::err!(
                        InvalidInput,
                        "the attachment command is unknown"
                    ));
                }
            }
            Ok(())
        })?;
        ensure!(
            out.len() <= capacity,
            ResourceLimitExceeded,
            "the attachment output buffer is too small"
        );
        output[..out.len()].copy_from_slice(&out);
        unsafe { api::write_out(written, out.len()) }
    })
}
fn encode_organization(out: &mut Vec<u8>, org: &chur_catalog::note_workspace::Organization) {
    string(out, &org.folder);
    out.extend_from_slice(&(org.tags.len() as u32).to_be_bytes());
    for tag in &org.tags {
        string(out, tag);
    }
}
fn attachment(r: &mut Reader<'_>) -> Result<chur_catalog::note_attachments::AttachmentData> {
    let id = Id::from_slice(r.take(16)?)?;
    let name = r.string(240)?;
    let mime_type = r.string(128)?;
    let len = r.count()?;
    ensure!(
        len <= chur_catalog::note_attachments::FILE_MAX,
        ResourceLimitExceeded,
        "the attachment exceeds its byte bound"
    );
    let data = Zeroizing::new(r.take(len)?.to_vec());
    Ok(chur_catalog::note_attachments::AttachmentData {
        attachment: chur_catalog::note_attachments::Attachment {
            id,
            name: name.to_owned(),
            mime_type: mime_type.to_owned(),
            size: len as u64,
        },
        data,
    })
}

/// Starts an owned cancellable export: package with files; otherwise exact Markdown/plain text.
/// # Safety
/// `id` reads sixteen bytes, `out` writes one handle, and `fd` is an open writable descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chur_private_note_export_begin(
    session: Handle,
    id: *const u8,
    expected: u64,
    fd: core::ffi::c_int,
    out: *mut Handle,
) -> Status {
    unsafe { begin_export(session, id, expected, None, fd, out) }
}
/// Exports one file from the checked saved revision without returning plaintext to the host.
/// Trash retains files until purge/expiry, under the same rules as complete note export.
/// # Safety
/// Identifiers read sixteen bytes, `out` writes one handle, and `fd` is an open writable descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chur_private_note_attachment_export_begin(
    session: Handle,
    id: *const u8,
    attachment_id: *const u8,
    expected: u64,
    fd: core::ffi::c_int,
    out: *mut Handle,
) -> Status {
    unsafe { begin_export(session, id, expected, Some(attachment_id), fd, out) }
}
unsafe fn begin_export(
    session: Handle,
    id: *const u8,
    expected: u64,
    attachment_id: Option<*const u8>,
    fd: core::ffi::c_int,
    out: *mut Handle,
) -> Status {
    guard_status_for(session, || {
        unsafe { api::write_out(out, 0)? };
        let id = Id::from_slice(unsafe { api::borrow_bytes(id, 16)? })?;
        let attachment_id = attachment_id
            .map(|id| Id::from_slice(unsafe { api::borrow_bytes(id, 16)? }))
            .transpose()?;
        // Validate the descriptor before retaining a plaintext snapshot.
        let destination = unsafe { api::duplicate_descriptor(fd)? };
        let bytes = with_catalog(session, |db| {
            notes::purge_expired(db, api::now_ms())?;
            let n = notes::get(db, &id)?;
            ensure!(n.revision == expected, Conflict, "the private note changed");
            match attachment_id {
                Some(attachment) => chur_catalog::note_attachments::read(db, &id, &attachment),
                None => chur_catalog::note_attachments::export_bytes(db, &n),
            }
        })?;
        let operation =
            Operation::spawn(OperationKind::Export, bytes.len() as u64, move |shared| {
                use std::io::Write;
                let mut destination = crate::provider_io::ProviderIo::new(destination, shared)?;
                let mut done = 0;
                for chunk in bytes.chunks(4096) {
                    ensure!(
                        !shared.cancelled(),
                        Cancelled,
                        "the private note export was cancelled"
                    );
                    destination.write_all(chunk).map_err(|_| {
                        chur_core::err!(IoFailure, "the private note export could not be written")
                    })?;
                    done += chunk.len() as u64;
                    shared.advance(done, Stage::Running);
                }
                ensure!(
                    !shared.cancelled(),
                    Cancelled,
                    "the private note export was cancelled"
                );
                destination.flush().map_err(|_| {
                    chur_core::err!(IoFailure, "the private note export could not be flushed")
                })?;
                ensure!(
                    !shared.cancelled(),
                    Cancelled,
                    "the private note export was cancelled"
                );
                shared.advance(done, Stage::Committing);
                Ok(None)
            })?;
        let handle = registry::insert(Entry::Operation {
            owner: session,
            operation,
        })?;
        unsafe { api::write_out(out, handle) }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::records::{ChurCreateRequestV1, ChurRuntimeConfigV1};
    use std::os::fd::AsRawFd;

    #[test]
    fn trashed_note_exports_exact_utf8_but_stale_expired_and_purged_notes_do_not() {
        let root = std::env::temp_dir().join(format!(
            "chur-note-export-{}",
            chur_crypto::random::id().unwrap().to_hex()
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.to_str().unwrap().as_bytes();
        let config = ChurRuntimeConfigV1 {
            root_path: path.as_ptr(),
            root_path_length: path.len() as u32,
        };
        let password = b"private note export fixture password";
        let request = ChurCreateRequestV1 {
            password: password.as_ptr(),
            password_length: password.len() as u32,
            memory_kib: 0,
            iterations: 0,
            parallelism: 0,
        };
        let mut runtime = 0;
        let mut creation = 0;
        let mut session = 0;
        unsafe {
            assert_eq!(api::chur_runtime_open(&config, &mut runtime), 0);
            assert_eq!(
                crate::product::chur_vault_create_begin(runtime, &request, &mut creation),
                0
            );
            assert_eq!(
                crate::product::chur_vault_creation_activate(creation, &mut session),
                0
            );
        }
        let now = api::now_ms();
        let note = with_catalog(session, |db| {
            let note = notes::save(
                db,
                None,
                0,
                "Заметка",
                "Текст\nwith emoji 🗒",
                false,
                notes::NoteFormat::PlainText,
                now,
            )?;
            Ok(notes::change(db, &note.id, note.revision, 3, now)?.unwrap())
        })
        .unwrap();
        let destination = root.join("note.txt");
        let output = std::fs::File::create(&destination).unwrap();
        let mut operation = 0;
        assert_eq!(
            unsafe {
                chur_private_note_export_begin(
                    session,
                    note.id.as_bytes().as_ptr(),
                    note.revision,
                    output.as_raw_fd(),
                    &mut operation,
                )
            },
            0
        );
        let entry = registry::get(operation, Kind::Operation).unwrap();
        let Entry::Operation {
            operation: worker, ..
        } = entry.as_ref()
        else {
            panic!("operation")
        };
        worker.join();
        assert_eq!(worker.poll().status, 0);
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            "Заметка\n\nТекст\nwith emoji 🗒".as_bytes()
        );
        assert_eq!(unsafe { api::chur_operation_close(operation) }, 0);
        drop(entry);
        drop(output);

        let markdown = with_catalog(session, |db| {
            notes::save(
                db,
                None,
                0,
                "Omitted title",
                "# Source\n\n- [x] exact\n",
                false,
                notes::NoteFormat::Markdown,
                now,
            )
        })
        .unwrap();
        let markdown_path = root.join("note.md");
        let markdown_output = std::fs::File::create(&markdown_path).unwrap();
        let mut markdown_operation = 0;
        assert_eq!(
            unsafe {
                chur_private_note_export_begin(
                    session,
                    markdown.id.as_bytes().as_ptr(),
                    markdown.revision,
                    markdown_output.as_raw_fd(),
                    &mut markdown_operation,
                )
            },
            0
        );
        let markdown_entry = registry::get(markdown_operation, Kind::Operation).unwrap();
        let Entry::Operation {
            operation: markdown_worker,
            ..
        } = markdown_entry.as_ref()
        else {
            panic!("operation")
        };
        markdown_worker.join();
        assert_eq!(markdown_worker.poll().status, 0);
        assert_eq!(
            std::fs::read(&markdown_path).unwrap(),
            markdown.body.as_bytes()
        );
        assert_eq!(
            std::fs::metadata(&markdown_path).unwrap().len(),
            markdown.export_size()
        );
        assert_eq!(unsafe { api::chur_operation_close(markdown_operation) }, 0);
        drop(markdown_entry);
        drop(markdown_output);

        let expired = with_catalog(session, |db| {
            let old = now - chur_catalog::trash::RETENTION_MS - 1;
            let note = notes::save(
                db,
                None,
                0,
                "expired",
                "body",
                false,
                notes::NoteFormat::PlainText,
                old,
            )?;
            Ok(notes::change(db, &note.id, note.revision, 3, old)?.unwrap())
        })
        .unwrap();
        let purged = with_catalog(session, |db| {
            let note = notes::save(
                db,
                None,
                0,
                "purged",
                "body",
                false,
                notes::NoteFormat::PlainText,
                now,
            )?;
            let note = notes::change(db, &note.id, note.revision, 3, now)?.unwrap();
            notes::change(db, &note.id, note.revision, 5, now)?;
            Ok(note)
        })
        .unwrap();
        for (note, revision, status) in [
            (&note, note.revision - 1, chur_core::ChurStatus::Conflict),
            (&expired, expired.revision, chur_core::ChurStatus::NotFound),
            (&purged, purged.revision, chur_core::ChurStatus::NotFound),
        ] {
            let output = std::fs::File::create(&destination).unwrap();
            let mut operation = 99;
            assert_eq!(
                unsafe {
                    chur_private_note_export_begin(
                        session,
                        note.id.as_bytes().as_ptr(),
                        revision,
                        output.as_raw_fd(),
                        &mut operation,
                    )
                },
                status as i32
            );
            assert_eq!(operation, 0);
            assert_eq!(output.metadata().unwrap().len(), 0);
        }
        let attachment_id = chur_crypto::random::id().unwrap();
        let file_bytes = b"%PDF-1.7\nexact private attachment\0bytes";
        let attachment = || chur_catalog::note_attachments::AttachmentData {
            attachment: chur_catalog::note_attachments::Attachment {
                id: attachment_id,
                name: "document.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                size: file_bytes.len() as u64,
            },
            data: Zeroizing::new(file_bytes.to_vec()),
        };
        let attached = with_catalog(session, |db| {
            chur_catalog::note_attachments::put(
                db,
                &markdown.id,
                markdown.revision,
                attachment(),
                now,
            )
        })
        .unwrap();
        let file_path = root.join("attachment.pdf");
        let file_output = std::fs::File::create(&file_path).unwrap();
        let mut file_operation = 0;
        assert_eq!(
            unsafe {
                chur_private_note_attachment_export_begin(
                    session,
                    attached.id.as_bytes().as_ptr(),
                    attachment_id.as_bytes().as_ptr(),
                    attached.revision,
                    file_output.as_raw_fd(),
                    &mut file_operation,
                )
            },
            0
        );
        let file_entry = registry::get(file_operation, Kind::Operation).unwrap();
        let Entry::Operation {
            operation: worker, ..
        } = file_entry.as_ref()
        else {
            panic!("operation")
        };
        worker.join();
        assert_eq!(worker.poll().status, 0);
        assert_eq!(std::fs::read(&file_path).unwrap(), file_bytes);
        assert_eq!(unsafe { api::chur_operation_close(file_operation) }, 0);
        drop(file_entry);
        drop(file_output);

        let expired_file = with_catalog(session, |db| {
            let old = now - chur_catalog::trash::RETENTION_MS - 1;
            let n = notes::save(
                db,
                None,
                0,
                "expired file",
                "body",
                false,
                notes::NoteFormat::Markdown,
                old,
            )?;
            let n = chur_catalog::note_attachments::put(db, &n.id, n.revision, attachment(), old)?;
            Ok(notes::change(db, &n.id, n.revision, 3, old)?.unwrap())
        })
        .unwrap();
        for (n, revision, status) in [
            (
                &attached,
                attached.revision - 1,
                chur_core::ChurStatus::Conflict,
            ),
            (
                &expired_file,
                expired_file.revision,
                chur_core::ChurStatus::NotFound,
            ),
            (&purged, purged.revision, chur_core::ChurStatus::NotFound),
        ] {
            let output = std::fs::File::create(&file_path).unwrap();
            let mut operation = 99;
            assert_eq!(
                unsafe {
                    chur_private_note_attachment_export_begin(
                        session,
                        n.id.as_bytes().as_ptr(),
                        attachment_id.as_bytes().as_ptr(),
                        revision,
                        output.as_raw_fd(),
                        &mut operation,
                    )
                },
                status as i32
            );
            assert_eq!(operation, 0);
            assert_eq!(output.metadata().unwrap().len(), 0);
        }
        assert_eq!(unsafe { api::chur_session_close(session) }, 0);
        assert_eq!(unsafe { api::chur_runtime_close(runtime) }, 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn undersized_or_null_output_never_reaches_a_mutation() {
        let mut written = 999usize;
        let mut called = false;
        // SAFETY: the zero-length request/output are not dereferenced and written is live.
        let status = unsafe {
            control(
                0,
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
                0,
                &mut written,
                |_, _, _| {
                    called = true;
                    Ok(())
                },
            )
        };
        assert_eq!(status, chur_core::ChurStatus::ResourceLimitExceeded as i32);
        assert!(!called);
        assert_eq!(written, 0);
        // A claimed sufficient capacity with no memory is refused before opening a catalog.
        let status = unsafe {
            control(
                0,
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
                CAPACITY,
                &mut written,
                |_, _, _| {
                    called = true;
                    Ok(())
                },
            )
        };
        assert_eq!(status, chur_core::ChurStatus::InvalidInput as i32);
        assert!(!called);
    }
}

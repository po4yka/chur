//! Encrypt host-owned sources into an independent CHURBAK1 archive.
#![expect(unsafe_code, reason = "the bounded C ABI validates caller pointers")]

use crate::{
    api::{self, Status},
    operation::{Operation, OperationKind, Shared, Stage},
    panic::guard_status_for,
    registry::{self, Entry, Handle, Kind},
    selective::{BoundedOutput, CancelOnly},
};
use chur_catalog::{
    paths::{DirectoryClaim, VaultRoot},
    vault,
};
use chur_core::{Result, ensure};
use chur_media::{backup, import};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const INPUT_LIMIT: u64 = 4 * 1_073_741_824;
const REQUEST_LIMIT: u32 = 128 * 1024;
const NAMESPACE: &str = "external-archives";
struct Source {
    name: String,
    mime: String,
    length: Option<u64>,
}
struct Request {
    password: Zeroizing<Vec<u8>>,
    limit: u64,
    sources: Vec<Source>,
}
struct Decoder<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or_else(|| {
            chur_core::err!(InvalidInput, "the external archive request is malformed")
        })?;
        ensure!(
            end <= self.bytes.len(),
            InvalidInput,
            "the external archive request is truncated"
        );
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| chur_core::err!(InvalidInput, "invalid archive field"),
        )?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| chur_core::err!(InvalidInput, "invalid archive field"),
        )?))
    }
    fn field(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        ensure!(
            n <= max,
            ResourceLimitExceeded,
            "the external archive field exceeds its bound"
        );
        self.take(n)
    }
}
fn decode(bytes: &[u8]) -> Result<Request> {
    let mut d = Decoder { bytes, at: 0 };
    ensure!(
        d.take(1)? == [1],
        UnsupportedVersion,
        "the external archive request version is unsupported"
    );
    let password = chur_crypto::password::canonical_bytes(d.field(1024)?)?;
    let limit = d.u64()?;
    ensure!(
        limit > 0 && limit <= i64::MAX as u64,
        InvalidInput,
        "the archive output capacity is invalid"
    );
    let count = d.u32()?;
    ensure!(
        (1..=32).contains(&count),
        ResourceLimitExceeded,
        "the archive source count is outside its bound"
    );
    let mut sources = Vec::with_capacity(count as usize);
    let mut known = 0u64;
    for _ in 0..count {
        let name = std::str::from_utf8(d.field(1024)?)
            .map_err(|_| chur_core::err!(InvalidInput, "the source name is not UTF-8"))?
            .to_owned();
        ensure!(
            !name.is_empty()
                && name != "."
                && name != ".."
                && !name
                    .chars()
                    .any(|c| c == '/' || c == '\\' || c.is_control()),
            InvalidInput,
            "the source name is not a basename"
        );
        let raw = std::str::from_utf8(d.field(255)?)
            .map_err(|_| chur_core::err!(InvalidInput, "the source media type is not UTF-8"))?;
        let token = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b))
        };
        let mime = match raw.split_once('/') {
            Some((a, b))
                if raw.len() <= chur_core::limits::media::CONTENT_TYPE_MAX
                    && token(a)
                    && token(b) =>
            {
                raw.to_ascii_lowercase()
            }
            _ => "application/octet-stream".to_owned(),
        };
        let length = match d.take(1)?[0] {
            0 => None,
            1 => Some(d.u64()?),
            _ => {
                return Err(chur_core::err!(
                    InvalidInput,
                    "the source length flag is invalid"
                ));
            }
        };
        if let Some(n) = length {
            known = known.checked_add(n).ok_or_else(|| {
                chur_core::err!(
                    ResourceLimitExceeded,
                    "the source lengths exceed their bound"
                )
            })?;
        }
        ensure!(
            known <= INPUT_LIMIT,
            ResourceLimitExceeded,
            "the source lengths exceed their bound"
        );
        sources.push(Source { name, mime, length });
    }
    ensure!(
        d.at == bytes.len(),
        InvalidInput,
        "the external archive request has trailing bytes"
    );
    Ok(Request {
        password,
        limit,
        sources,
    })
}
fn directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| chur_core::err!(IoFailure, "the archive staging directory is unavailable"))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        IoFailure,
        "the archive staging directory is invalid"
    );
    Ok(())
}
struct Claim {
    parent: PathBuf,
    _claim: DirectoryClaim,
}
impl Claim {
    fn take(root: &Path, create: bool) -> Result<Option<Self>> {
        directory(root)?;
        ensure!(
            std::fs::canonicalize(root).ok().as_deref() == Some(root),
            IoFailure,
            "the runtime root changed"
        );
        let parent = root.join(NAMESPACE);
        match std::fs::symlink_metadata(&parent) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !create {
                    return Ok(None);
                }
                std::fs::create_dir(&parent).map_err(|_| {
                    chur_core::err!(
                        IoFailure,
                        "the archive staging directory could not be created"
                    )
                })?;
            }
            Err(_) => {
                return Err(chur_core::err!(
                    IoFailure,
                    "the archive staging directory is unavailable"
                ));
            }
            Ok(_) => {}
        }
        directory(&parent)?;
        let lock = parent.join("lock");
        match std::fs::symlink_metadata(&lock) {
            Ok(m) => ensure!(
                m.is_file() && !m.file_type().is_symlink(),
                IoFailure,
                "the archive staging claim is invalid"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(chur_core::err!(
                    IoFailure,
                    "the archive staging claim is unavailable"
                ));
            }
        }
        let claim = DirectoryClaim::take(&parent)?;
        Ok(Some(Self {
            parent,
            _claim: claim,
        }))
    }
    fn sweep(&self) -> Result<()> {
        directory(&self.parent)?;
        for entry in std::fs::read_dir(&self.parent)
            .map_err(|_| chur_core::err!(IoFailure, "archive staging could not be read"))?
        {
            let entry = entry
                .map_err(|_| chur_core::err!(IoFailure, "archive staging could not be read"))?;
            let name = entry.file_name();
            if name == "lock" {
                continue;
            }
            let Some(name) = name.to_str() else { continue };
            if name.len() != 32
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                continue;
            }
            let kind = entry
                .file_type()
                .map_err(|_| chur_core::err!(IoFailure, "archive staging could not be read"))?;
            if kind.is_dir() {
                std::fs::remove_dir_all(entry.path())
            } else {
                std::fs::remove_file(entry.path())
            }
            .map_err(|_| {
                chur_core::err!(
                    IoFailure,
                    "abandoned encrypted staging could not be removed"
                )
            })?;
        }
        Ok(())
    }
}
/// Sweep encrypted staging after a process exit; never sweep a live operation.
pub(crate) fn sweep_staging(root: &Path) -> Result<()> {
    match Claim::take(root, false) {
        Ok(Some(claim)) => claim.sweep(),
        Ok(None) => Ok(()),
        Err(e) if e.status() == chur_core::ChurStatus::Conflict => Ok(()),
        Err(e) => Err(e),
    }
}
struct Staging {
    path: PathBuf,
    claim: Claim,
}
impl Staging {
    fn new(claim: Claim) -> Result<Self> {
        claim.sweep()?;
        let path = claim.parent.join(chur_crypto::random::id()?.to_hex());
        std::fs::create_dir(&path)
            .map_err(|_| chur_core::err!(IoFailure, "encrypted staging could not be created"))?;
        Ok(Self { path, claim })
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        if directory(&self.claim.parent).is_ok()
            && self.path.parent() == Some(self.claim.parent.as_path())
            && directory(&self.path).is_ok()
        {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
fn check(shared: &Shared) -> Result<()> {
    ensure!(
        !shared.cancelled(),
        Cancelled,
        "the external archive operation was cancelled"
    );
    Ok(())
}
fn run(
    request: Request,
    inputs: Vec<File>,
    mut output: File,
    claim: Claim,
    shared: &Shared,
) -> Result<Option<chur_core::Id>> {
    check(shared)?;
    let staging = Staging::new(claim)?;
    let root = VaultRoot::new(staging.path.clone());
    let mut session = vault::create(&root, &request.password, api::now_ms())?.activate()?;
    drop(request.password);
    let result = (|| {
        let mut aggregate = 0u64;
        for (source, input) in request.sources.into_iter().zip(inputs) {
            check(shared)?;
            let mut input = crate::provider_io::ProviderIo::new(input, shared)?;
            let capability = import::SourceCapability {
                requested_object_id: None,
                seekable: false,
                known_length: source.length,
                content_type_hint: source.mime.clone(),
                original_filename: Some(source.name),
                capture_time_ms: None,
            };
            let mut writing = import::begin(
                &mut session,
                capability,
                import::CanonicalMedia::opaque(),
                api::now_ms(),
            )?;
            let mut buffer = Zeroizing::new(vec![0; writing.chunk_size() as usize]);
            let mut source_bytes = 0u64;
            loop {
                check(shared)?;
                // Fill full encrypted chunks even when a provider returns short reads.
                let capacity = (INPUT_LIMIT - aggregate + 1).min(buffer.len() as u64) as usize;
                let mut n = 0;
                while n < capacity {
                    check(shared)?;
                    let read = input.read(&mut buffer[n..capacity]).map_err(|_| {
                        chur_core::err!(IoFailure, "an external source could not be read")
                    })?;
                    check(shared)?;
                    if read == 0 {
                        break;
                    }
                    n += read;
                }
                if n == 0 {
                    break;
                }
                aggregate += n as u64;
                source_bytes += n as u64;
                ensure!(
                    aggregate <= INPUT_LIMIT,
                    ResourceLimitExceeded,
                    "the external sources exceed their input bound"
                );
                ensure!(
                    source.length.is_none_or(|size| source_bytes <= size),
                    InvalidInput,
                    "an external source length changed"
                );
                writing.write(&mut session, &buffer[..n])?;
                shared.advance(aggregate, Stage::Running);
            }
            ensure!(
                source.length.is_none_or(|size| source_bytes == size),
                InvalidInput,
                "an external source length changed"
            );
            writing.commit_with_display_checked(
                &mut session,
                &source.mime,
                api::now_ms(),
                import::CopiedDisplay {
                    caption: None,
                    favorite: false,
                    capture_time: None,
                },
                &|| shared.cancelled(),
            )?;
        }
        shared.set_total(aggregate);
        shared.advance(aggregate, Stage::Committing);
        check(shared)?;
        session.checkpoint_catalog()?;
        let mut bounded = BoundedOutput {
            file: &mut output,
            limit: request.limit,
            position: 0,
            exceeded: false,
        };
        let written = backup::create(
            &mut session,
            &mut bounded,
            api::now_ms(),
            &mut CancelOnly(shared),
        );
        ensure!(
            !bounded.exceeded,
            ResourceLimitExceeded,
            "the external archive exceeds its output capacity"
        );
        written?;
        output.sync_all().map_err(|_| {
            chur_core::err!(IoFailure, "the external archive could not be synchronized")
        })?;
        check(shared)?;
        Ok(None)
    })();
    // Close SQLCipher before the staging guard removes its encrypted files.
    let locked = session.lock();
    drop(session);
    result.and_then(|value| locked.map(|()| value))
}

/// Encrypts external file descriptors without adding objects to an installed vault.
///
/// # Safety
/// Request points to `length` readable bytes (at most 128 KiB), source_fds to
/// `source_count` readable i32 values (1..32), and out to a writable handle.
/// All ranges are non-overlapping. Source and destination descriptors remain
/// open during this call; the caller holds their offset leases until terminal.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chur_external_archive_begin(
    runtime: Handle,
    request: *const u8,
    length: u32,
    source_fds: *const i32,
    source_count: u32,
    destination_fd: i32,
    out: *mut Handle,
) -> Status {
    guard_status_for(runtime, || {
        // SAFETY: caller's pointer contract; bounds are checked before slicing.
        unsafe { api::write_out(out, 0)? };
        ensure!(
            length <= REQUEST_LIMIT,
            ResourceLimitExceeded,
            "the external archive request exceeds its bound"
        );
        let request = decode(unsafe { api::borrow_large(request, length)? })?;
        ensure!(
            source_count as usize == request.sources.len() && !source_fds.is_null(),
            InvalidInput,
            "the source descriptor count does not match"
        );
        let fds = unsafe { std::slice::from_raw_parts(source_fds, source_count as usize) };
        let entry = registry::get(runtime, Kind::Runtime)?;
        let Entry::Runtime(guarded) = entry.as_ref() else {
            return Err(chur_core::err!(
                InvalidInput,
                "the archive owner is not a runtime"
            ));
        };
        let claim = Claim::take(registry::lock(guarded).root().base(), true)?
            .ok_or_else(|| chur_core::err!(InternalFailure, "the staging claim is absent"))?;
        let mut inputs = Vec::with_capacity(fds.len());
        for &fd in fds {
            inputs.push(unsafe { api::duplicate_descriptor(fd)? });
        }
        let mut output = unsafe { api::duplicate_descriptor(destination_fd)? };
        crate::provider_io::require_archive_output(&mut output)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let destination = output.metadata().map_err(|_| {
                chur_core::err!(IoFailure, "the archive destination is unavailable")
            })?;
            for input in &inputs {
                let source = input
                    .metadata()
                    .map_err(|_| chur_core::err!(IoFailure, "an external source is unavailable"))?;
                ensure!(
                    source.dev() != destination.dev() || source.ino() != destination.ino(),
                    InvalidInput,
                    "an archive destination cannot be a source"
                );
            }
        }
        let total = request
            .sources
            .iter()
            .try_fold(0u64, |sum, s| s.length.and_then(|n| sum.checked_add(n)))
            .unwrap_or(0);
        let operation = Operation::spawn(OperationKind::Export, total, move |shared| {
            run(request, inputs, output, claim, shared)
        })?;
        let handle = registry::insert(Entry::Operation {
            owner: runtime,
            operation,
        })?;
        unsafe { api::write_out(out, handle) }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    const PASSWORD: &[u8] = b"independent external archive password";
    fn scratch() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "chur-external-{}",
            chur_crypto::random::id().unwrap().to_hex()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::canonicalize(root).unwrap()
    }
    fn wire(files: &[(&str, &str, Option<u64>)], limit: u64) -> Vec<u8> {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&(PASSWORD.len() as u32).to_be_bytes());
        bytes.extend_from_slice(PASSWORD);
        bytes.extend_from_slice(&limit.to_be_bytes());
        bytes.extend_from_slice(&(files.len() as u32).to_be_bytes());
        for (name, mime, length) in files {
            for text in [*name, *mime] {
                bytes.extend_from_slice(&(text.len() as u32).to_be_bytes());
                bytes.extend_from_slice(text.as_bytes());
            }
            bytes.push(u8::from(length.is_some()));
            if let Some(n) = length {
                bytes.extend_from_slice(&n.to_be_bytes());
            }
        }
        bytes
    }
    fn runtime(root: &Path) -> Handle {
        let bytes = root.to_str().unwrap().as_bytes();
        let config = crate::records::ChurRuntimeConfigV1 {
            root_path: bytes.as_ptr(),
            root_path_length: bytes.len() as u32,
        };
        let mut runtime = 0;
        assert_eq!(unsafe { api::chur_runtime_open(&config, &mut runtime) }, 0);
        runtime
    }
    fn operation(handle: Handle) -> std::sync::Arc<Entry> {
        registry::get(handle, Kind::Operation).unwrap()
    }
    fn join(handle: Handle) -> crate::operation::Progress {
        let entry = operation(handle);
        let Entry::Operation { operation, .. } = entry.as_ref() else {
            panic!("operation")
        };
        operation.join();
        operation.poll()
    }
    fn begin(runtime: Handle, request: &[u8], sources: &[i32], output: &File) -> (i32, Handle) {
        let mut handle = 99;
        let status = unsafe {
            chur_external_archive_begin(
                runtime,
                request.as_ptr(),
                request.len() as u32,
                sources.as_ptr(),
                sources.len() as u32,
                output.as_raw_fd(),
                &mut handle,
            )
        };
        (status, handle)
    }
    fn stages(root: &Path) -> usize {
        std::fs::read_dir(root.join(NAMESPACE))
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name() != "lock")
            .count()
    }
    #[test]
    fn request_rejects_unsafe_names_lengths_flags_and_trailing_bytes() {
        assert!(decode(&wire(&[("safe.txt", "", Some(0))], 1)).is_ok());
        for name in ["", ".", "..", "../private", "x/y", "x\\y", "line\nbreak"] {
            assert!(decode(&wire(&[(name, "", None)], 1)).is_err());
        }
        assert!(decode(&wire(&[("safe", "", Some(INPUT_LIMIT + 1))], 1)).is_err());
        assert!(
            decode(&wire(
                &[("safe", "", Some(INPUT_LIMIT)), ("other", "", Some(1))],
                1
            ))
            .is_err()
        );
        assert!(decode(&wire(&[("safe", "", None)], 0)).is_err());
        let mut request = wire(&[("safe", "", None)], 1);
        request.push(0);
        assert!(decode(&request).is_err());
        let mut request = wire(&[("safe", "", None)], 1);
        *request.last_mut().unwrap() = 2;
        assert!(decode(&request).is_err());
        assert_eq!(
            decode(&wire(&[("safe", "unknown", None)], 1))
                .unwrap()
                .sources[0]
                .mime,
            "application/octet-stream"
        );
    }
    #[test]
    fn request_normalizes_media_types_to_the_catalog_bound() {
        let maximum = chur_core::limits::media::CONTENT_TYPE_MAX;
        let accepted = format!("application/{}", "x".repeat(maximum - 12));
        let oversized = format!("{accepted}x");
        for (hint, expected) in [
            (accepted.to_uppercase(), accepted.as_str()),
            (oversized, "application/octet-stream"),
            ("not a MIME".into(), "application/octet-stream"),
        ] {
            let request = decode(&wire(&[("document", &hint, Some(0))], 1)).unwrap();
            assert_eq!(request.sources[0].mime, expected);
        }
    }
    #[test]
    fn restart_sweep_keeps_live_work_and_removes_only_abandoned_encrypted_stages() {
        let root = scratch();
        let stage = Staging::new(Claim::take(&root, true).unwrap().unwrap()).unwrap();
        let path = stage.path.clone();
        std::fs::write(path.join("ciphertext"), [1, 2, 3]).unwrap();
        sweep_staging(&root).unwrap();
        assert!(path.is_dir());
        drop(stage);
        assert!(!path.exists());
        let stale = root.join(NAMESPACE).join("a".repeat(32));
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("encrypted"), [4, 5]).unwrap();
        sweep_staging(&root).unwrap();
        assert!(!stale.exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn staging_rejects_parent_and_claim_symlinks_without_touching_foreign_files() {
        let root = scratch();
        let outside = scratch();
        let marker = outside.join("keep");
        std::fs::write(&marker, b"preserve").unwrap();
        std::os::unix::fs::symlink(&outside, root.join(NAMESPACE)).unwrap();
        assert!(sweep_staging(&root).is_err());
        assert!(Claim::take(&root, true).is_err());
        std::fs::remove_file(root.join(NAMESPACE)).unwrap();
        std::fs::create_dir(root.join(NAMESPACE)).unwrap();
        std::os::unix::fs::symlink(&marker, root.join(NAMESPACE).join("lock")).unwrap();
        assert!(Claim::take(&root, true).is_err());
        assert_eq!(std::fs::read(&marker).unwrap(), b"preserve");
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
    #[test]
    fn bad_descriptor_and_source_destination_alias_fail_before_start() {
        let root = scratch();
        let runtime = runtime(&root);
        let output = File::create(root.join("output")).unwrap();
        let request = wire(&[("empty", "", Some(0))], 1024 * 1024);
        let (status, handle) = begin(runtime, &request, &[-1], &output);
        assert_ne!(status, 0);
        assert_eq!(handle, 0);
        let (status, handle) = begin(runtime, &request, &[output.as_raw_fd()], &output);
        assert_eq!(status, chur_core::ChurStatus::InvalidInput as i32);
        assert_eq!(handle, 0);
        assert_eq!(output.metadata().unwrap().len(), 0);
        assert_eq!(unsafe { api::chur_runtime_close(runtime) }, 0);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn external_archive_restores_exact_opaque_files_with_empty_and_unknown_types() {
        let root = scratch();
        let runtime = runtime(&root);
        let contents = [
            Vec::new(),
            b"arbitrary\0document\xff".to_vec(),
            vec![17; 1_100_000],
            b"PK\x03\x04DOCX original bytes\0\xff".to_vec(),
        ];
        let names = ["empty.txt", "данные.bin", "duplicate.bin", "document.docx"];
        let mut files = Vec::new();
        for (i, bytes) in contents.iter().enumerate() {
            let path = root.join(format!("input{i}"));
            std::fs::write(&path, bytes).unwrap();
            files.push(File::open(path).unwrap());
        }
        let fds: Vec<_> = files.iter().map(AsRawFd::as_raw_fd).collect();
        let request = wire(
            &[
                (names[0], "text/plain", Some(0)),
                (names[1], "", None),
                (names[2], "not a MIME", Some(contents[2].len() as u64)),
                (
                    names[3],
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    Some(contents[3].len() as u64),
                ),
            ],
            16 * 1024 * 1024,
        );
        let archive_path = root.join("result.churbak");
        let output = File::create(&archive_path).unwrap();
        let (status, handle) = begin(runtime, &request, &fds, &output);
        assert_eq!(status, 0);
        // Duplicates own the worker lifetime; caller descriptors can close after begin.
        drop(files);
        drop(output);
        let progress = join(handle);
        assert_eq!(progress.status, 0);
        assert_eq!(
            progress.processed,
            contents.iter().map(|b| b.len() as u64).sum::<u64>()
        );
        assert_eq!(progress.total, progress.processed);
        assert_eq!(stages(&root), 0);
        assert!(
            !root.join("registry").exists(),
            "no primary descriptor created"
        );
        let restore_root = root.join("restored");
        let restore = VaultRoot::new(restore_root.clone());
        let wrong = backup::restore(
            &restore,
            &mut File::open(&archive_path).unwrap(),
            b"wrong archive password",
            &mut chur_media::progress::Uninterrupted,
        );
        assert!(wrong.is_err());
        backup::restore(
            &restore,
            &mut File::open(&archive_path).unwrap(),
            PASSWORD,
            &mut chur_media::progress::Uninterrupted,
        )
        .unwrap();
        let mut session = vault::unlock_with_password(&restore, PASSWORD, 20).unwrap();
        let plan = chur_catalog::transfer::all(session.catalog_ref().unwrap()).unwrap();
        assert_eq!(plan.objects.len(), contents.len());
        for id in &plan.objects {
            let metadata =
                chur_catalog::store::active_metadata(session.catalog_ref().unwrap(), id).unwrap();
            let name = metadata.original_filename.unwrap();
            let i = names
                .iter()
                .position(|candidate| *candidate == name)
                .unwrap();
            let mut reader = chur_media::reader::open(
                &session,
                id,
                chur_format::constants::StreamKind::Original,
            )
            .unwrap();
            assert_eq!(
                reader.read_range(0, reader.size()).unwrap().as_slice(),
                contents[i]
            );
            if i > 0 {
                assert_eq!(metadata.content_type, "application/octet-stream");
            }
        }
        for (index, original) in contents.iter().enumerate() {
            assert_eq!(
                std::fs::read(root.join(format!("input{index}"))).unwrap(),
                *original
            );
        }
        session.lock().unwrap();
        assert_eq!(unsafe { api::chur_operation_close(handle) }, 0);
        assert_eq!(unsafe { api::chur_runtime_close(runtime) }, 0);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn output_capacity_and_changed_provider_lengths_remove_staging_without_source_changes() {
        let root = scratch();
        let runtime = runtime(&root);
        let source = root.join("source");
        std::fs::write(&source, b"original").unwrap();
        for (index, length, limit, expected) in [
            (0, Some(8), 1, chur_core::ChurStatus::ResourceLimitExceeded),
            (1, Some(1), 1024 * 1024, chur_core::ChurStatus::InvalidInput),
            (2, Some(9), 1024 * 1024, chur_core::ChurStatus::InvalidInput),
        ] {
            let input = File::open(&source).unwrap();
            let output = File::create(root.join(format!("output{index}"))).unwrap();
            let request = wire(&[("source", "", length)], limit);
            let (status, handle) = begin(runtime, &request, &[input.as_raw_fd()], &output);
            assert_eq!(status, 0);
            assert_eq!(join(handle).status, expected as i32);
            assert_eq!(output.metadata().unwrap().len(), 0);
            assert_eq!(stages(&root), 0);
            assert_eq!(std::fs::read(&source).unwrap(), b"original");
            assert_eq!(unsafe { api::chur_operation_close(handle) }, 0);
        }
        assert_eq!(unsafe { api::chur_runtime_close(runtime) }, 0);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn runtime_close_cancels_unknown_length_pipe_and_cleans_staging() {
        use std::os::{fd::OwnedFd, unix::net::UnixStream};
        let root = scratch();
        let runtime = runtime(&root);
        let (input, mut producer) = UnixStream::pair().unwrap();
        let input = File::from(OwnedFd::from(input));
        let output = File::create(root.join("output")).unwrap();
        let request = wire(&[("pipe.bin", "", None)], 16 * 1024 * 1024);
        let (status, handle) = begin(runtime, &request, &[input.as_raw_fd()], &output);
        assert_eq!(status, 0);
        producer.write_all(&vec![9; 1_048_576]).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let entry = operation(handle);
            let Entry::Operation { operation, .. } = entry.as_ref() else {
                panic!("operation")
            };
            if operation.poll().processed > 0 {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let (send, receive) = std::sync::mpsc::channel();
        let closing = std::thread::spawn(move || {
            send.send(unsafe { api::chur_runtime_close(runtime) })
                .unwrap();
        });
        let closed = receive.recv_timeout(std::time::Duration::from_secs(3));
        // Keep the provider open until after the timed result. Cleanup must not need EOF.
        drop(producer);
        closing.join().unwrap();
        assert_eq!(closed.unwrap(), 0);
        assert_eq!(output.metadata().unwrap().len(), 0);
        assert_eq!(stages(&root), 0);
        assert!(registry::get(handle, Kind::Operation).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}

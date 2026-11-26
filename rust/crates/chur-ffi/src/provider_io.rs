//! Cancel-aware I/O for descriptors supplied by a platform provider.
//!
//! A duplicate shares file status flags with the host descriptor. The host must
//! give the operation exclusive I/O and flag access until it ends (FFI §13).
//! The Android broker creates the native pipe; a provider must not retain a
//! duplicate of this endpoint that could clear O_NONBLOCK.

use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::time::{Duration, Instant};

use chur_core::Result;

use crate::operation::Shared;

const CANCEL_POLL_MS: i32 = 50;
const STALL_LIMIT: Duration = Duration::from_secs(30);

/// Do not enter a provider FUSE callback while a native operation owns keys.
/// Even fstat/fstatfs can call the provider, so inspect kernel proc records first.
#[cfg(target_os = "android")]
pub(crate) fn reject_provider_filesystem(file: &File) -> Result<()> {
    let target = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| chur_core::err!(IoFailure, "the descriptor identity is unavailable"))?;
    let target = target.to_string_lossy();
    if target.starts_with("pipe:[") || target.starts_with("socket:[") {
        return Ok(());
    }
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
        .map_err(|_| chur_core::err!(IoFailure, "the descriptor mount is unavailable"))?;
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|_| chur_core::err!(IoFailure, "the process mounts are unavailable"))?;
    chur_core::ensure!(
        trusted_mount(&info, &mounts),
        InvalidInput,
        "provider files require a platform pipe or a local staged copy"
    );
    Ok(())
}

#[cfg(any(target_os = "android", test))]
fn trusted_mount(info: &str, mounts: &str) -> bool {
    let Some(id) = info.lines().find_map(|line| line.strip_prefix("mnt_id:")) else {
        return false;
    };
    let id = id.trim();
    // Anonymous pipes and sockets have a kernel mount that is not in mountinfo.
    // Their proc fdinfo mnt_id is not sufficient to classify the type. The caller
    // checks their kernel-generated fd symlink before calling this helper.
    mounts
        .lines()
        .find_map(|line| {
            let (fields, filesystem) = line.split_once(" - ")?;
            if fields.split_whitespace().next()? != id {
                return None;
            }
            let kind = filesystem.split_whitespace().next()?;
            Some(kind != "fuse" && kind != "fuseblk" && !kind.starts_with("fuse."))
        })
        .unwrap_or(false)
}

/// Reject streams on APIs that require regular seekable archive files.
pub(crate) fn require_regular(file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|_| chur_core::err!(IoFailure, "the provider descriptor is unavailable"))?;
    chur_core::ensure!(
        metadata.is_file(),
        InvalidInput,
        "this operation requires a regular file"
    );
    Ok(())
}

/// An archive starts at byte zero and must occupy the whole destination.
pub(crate) fn require_archive_output(file: &mut File) -> Result<()> {
    require_regular(file)?;
    chur_core::ensure!(
        file.stream_position().is_ok_and(|position| position == 0)
            && file.metadata().is_ok_and(|m| m.len() == 0),
        InvalidInput,
        "the archive destination must be empty and at offset zero"
    );
    Ok(())
}

/// Owns the duplicated descriptor; cancellation never closes it from another thread.
pub(crate) struct ProviderIo<'a> {
    file: File,
    shared: &'a Shared,
    stream: bool,
}

impl<'a> ProviderIo<'a> {
    pub(crate) fn new(file: File, shared: &'a Shared) -> Result<Self> {
        let kind = file
            .metadata()
            .map_err(|_| chur_core::err!(IoFailure, "the provider descriptor is unavailable"))?
            .file_type();
        let stream = kind.is_fifo() || kind.is_socket();
        chur_core::ensure!(
            kind.is_file() || stream,
            InvalidInput,
            "the provider descriptor is not a file or stream"
        );
        if stream {
            // SAFETY: `file` owns a live descriptor; F_GETFL takes no extra argument.
            #[expect(unsafe_code, reason = "query flags on an owned provider descriptor")]
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            chur_core::ensure!(flags >= 0, IoFailure, "the provider flags are unavailable");
            // SAFETY: the descriptor is live and F_SETFL takes an integer bitmask.
            // O_NONBLOCK applies to all duplicates. FFI §13 excludes concurrent
            // host I/O/flag changes; do not race a restore of the previous flags.
            #[expect(
                unsafe_code,
                reason = "enable bounded reads and writes on a provider stream"
            )]
            let changed =
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
            chur_core::ensure!(
                changed == 0,
                IoFailure,
                "the provider cannot use nonblocking I/O"
            );
        }
        Ok(Self {
            file,
            shared,
            stream,
        })
    }

    fn check(&self) -> io::Result<()> {
        if self.shared.cancelled() {
            // Interrupted would make Read::read_exact/Write::write_all retry forever.
            return Err(io::Error::other("the provider operation was cancelled"));
        }
        Ok(())
    }

    fn transfer(
        &mut self,
        events: libc::c_short,
        mut action: impl FnMut(&mut File) -> io::Result<usize>,
    ) -> io::Result<usize> {
        let started = Instant::now();
        loop {
            self.check()?;
            match action(&mut self.file) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if self.stream && error.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
            if started.elapsed() >= STALL_LIMIT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the provider stream stalled",
                ));
            }
            let mut descriptor = libc::pollfd {
                fd: self.file.as_raw_fd(),
                events,
                revents: 0,
            };
            // SAFETY: the pointer covers one initialized pollfd for this call,
            // and its descriptor stays owned by self for the whole wait.
            #[expect(
                unsafe_code,
                reason = "bounded readiness wait on an owned provider stream"
            )]
            let ready = unsafe { libc::poll(&mut descriptor, 1, CANCEL_POLL_MS) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
            // Retry the nonblocking syscall even on HUP/ERR to obtain EOF/EPIPE.
        }
    }
}

impl Read for ProviderIo<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.transfer(libc::POLLIN, |file| file.read(buffer))
    }
}

impl Write for ProviderIo<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.transfer(libc::POLLOUT, |file| file.write(buffer))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::trusted_mount;

    #[test]
    fn provider_fuse_mounts_and_unknown_mounts_are_rejected() {
        let info = "pos:\t0\nflags:\t0100002\nmnt_id:\t42\n";
        for kind in ["fuse", "fuseblk", "fuse.appfuse"] {
            assert!(!trusted_mount(
                info,
                &format!("42 1 0:1 / /provider rw - {kind} provider rw\n")
            ));
        }
        assert!(trusted_mount(
            info,
            "42 1 0:1 / /data rw - ext4 /dev/block/data rw\n"
        ));
        assert!(!trusted_mount(
            info,
            "43 1 0:1 / /data rw - ext4 /dev/block/data rw\n"
        ));
        assert!(!trusted_mount("", ""));
    }
}

//! Publish a complete CLI output in the destination directory.

use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::Path;

use chur_core::{Result, err};

/// Writes to a private file and publishes it only if the final name is free.
pub fn write_new<T>(destination: &Path, write: impl FnOnce(&mut File) -> Result<T>) -> Result<T> {
    let directory = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = directory.join(format!(
        ".chur-{}.partial",
        chur_crypto::random::id()?.to_hex()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| err!(IoFailure, "the temporary output could not be created"))?;
    let result = (|| {
        let value = write(&mut file)?;
        file.sync_all()
            .map_err(|_| err!(IoFailure, "the output could not be made durable"))?;
        std::fs::hard_link(&temporary, destination).map_err(|error| {
            if error.kind() == ErrorKind::AlreadyExists {
                err!(Conflict, "the destination already exists")
            } else {
                err!(IoFailure, "the output could not be published")
            }
        })?;
        Ok(value)
    })();
    drop(file);
    std::fs::remove_file(temporary)
        .map_err(|_| err!(IoFailure, "the temporary output could not be removed"))?;
    chur_catalog::paths::sync_directory(directory)?;
    result
}

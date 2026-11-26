//! The `backup` command group.
//!
//! `docs/format/BACKUP_FORMAT_V1.md` §1 makes the package portable across
//! Android, iOS, and the CLI, and `docs/ROADMAP.md` Phase 2 makes a restore on
//! all three an exit criterion. All three run one implementation; what differs
//! is the file it is pointed at, which is why this module is thin.
//!
//! Nothing here prints private content. A summary is a set of counts and one
//! identifier, which §9 already lists among the things the outer package
//! reveals to anyone holding it.

use std::path::Path;

use chur_catalog::paths::VaultRoot;
use chur_catalog::vault::Session;
use chur_core::Result;
use chur_media::backup;
use chur_media::progress::Uninterrupted;

use crate::vault::now_ms;

/// Writes a full package of the unlocked vault, §5 and §7.
///
/// Publish the durable package only while the destination name is free.
pub fn create(session: &mut Session, destination: &Path) -> Result<()> {
    let summary = crate::output::write_new(destination, |file| {
        backup::create(session, file, now_ms(), &mut Uninterrupted)
    })?;

    println!(
        "backup {} of vault {}",
        summary.backup_id.to_hex(),
        summary.vault_id.to_hex()
    );
    println!(
        "{} record(s), {} stream(s), {} portable slot(s), {} byte(s)",
        summary.record_count, summary.stream_count, summary.slot_count, summary.package_length
    );
    Ok(())
}

/// Restores a package into a storage root, §8.
///
/// The root is not unlocked first. A restore installs an identity rather than
/// operating one, and §8 step 2 obtains the factor from the package's own
/// portable descriptor, so a restore into an empty root is the ordinary case.
pub fn restore(root: &Path, package: &Path, password: &[u8]) -> Result<()> {
    let directory = VaultRoot::new(root.to_path_buf());
    let mut file = std::fs::File::open(package)
        .map_err(|_| chur_core::err!(NotFound, "the package could not be opened"))?;
    let summary = backup::restore(&directory, &mut file, password, &mut Uninterrupted)?;
    println!(
        "restored vault {} from backup {}",
        summary.vault_id.to_hex(),
        summary.backup_id.to_hex()
    );
    println!(
        "{} stream(s), created at {} ms",
        summary.stream_count, summary.created_time_ms
    );
    Ok(())
}

/// Reports what a package says about itself without opening it, §2.1.
///
/// Only the public preamble is read. §9 lists what the outer package reveals to
/// anyone holding it, and this prints that and nothing more: no identity, no
/// counts, and no times, because every one of those is inside the sealed
/// manifest and §10 requires a restore to show decrypted metadata only after
/// authentication.
pub fn inspect(package: &Path) -> Result<()> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(package)
        .map_err(|_| chur_core::err!(NotFound, "the package could not be opened"))?;
    let mut head = vec![0u8; chur_format::backup::PREAMBLE_LEN];
    file.read_exact(&mut head)
        .map_err(|_| chur_core::err!(VaultCorrupt, "the file is shorter than a preamble"))?;

    match chur_format::backup::framing_of(&head)? {
        chur_format::backup::Framing::Native => {}
        chur_format::backup::Framing::AgeBinary | chur_format::backup::Framing::AgeArmored => {
            println!("age-wrapped package; unwrap it with the age tool first");
            return Ok(());
        }
    }
    let preamble = chur_format::backup::PublicPreamble::decode(&head)?;
    let length = std::fs::metadata(package)
        .map(|metadata| metadata.len())
        .map_err(|_| chur_core::err!(IoFailure, "the package length could not be read"))?;
    println!("Chur backup package v{}", preamble.backup_version());
    println!("records        {}", preamble.record_count());
    println!("length         {length}");
    println!("everything else is sealed and needs a credential");
    Ok(())
}

//! The `backup` commands driven as a subprocess.
//!
//! `docs/ROADMAP.md` Phase 2 makes "backup restore succeeds across Android,
//! iOS, and CLI" an exit criterion. This is the CLI third of it, and it runs
//! the binary rather than the library: an exit status and a printed line are
//! what a user and a script see, and neither is exercised by a library test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BINARY: &str = env!("CARGO_BIN_EXE_chur-cli");
const PASSWORD: &str = "correct horse battery staple";

fn scratch() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "chur-cli-backup-{}",
        chur_crypto::random::id().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn run(group: &str, root: &Path, arguments: &[&str]) -> Output {
    Command::new(BINARY)
        .arg(group)
        .arg("--root")
        .arg(root)
        .args(arguments)
        .env("CHUR_PASSWORD", PASSWORD)
        .env_remove("CHUR_RECOVERY_PHRASE")
        .output()
        .expect("the binary ran")
}

fn expect_ok(output: &Output, what: &str) -> String {
    assert!(
        output.status.success(),
        "{what} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn expect_failure(output: &Output) -> String {
    assert!(
        !output.status.success(),
        "a command the specification refuses returned success"
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The whole path: create a vault, import a file, write a package, restore it
/// into a second root, and export the same bytes out of the restored vault.
#[test]
fn a_package_written_by_the_cli_restores_through_the_cli() {
    let scratch = scratch();
    let source = scratch.join("source");
    let restored = scratch.join("restored");
    let file = scratch.join("photo.jpg");
    let bytes: Vec<u8> = (0..300_000u32).map(|index| (index % 251) as u8).collect();
    std::fs::write(&file, &bytes).unwrap();

    expect_ok(&run("vault", &source, &["create"]), "create");
    let imported = expect_ok(
        &run(
            "vault",
            &source,
            &[
                "import",
                file.to_str().unwrap(),
                "--content-type",
                "image/jpeg",
            ],
        ),
        "import",
    );
    let object = imported.trim().to_owned();

    let package = scratch.join("vault.churbak");
    let neighbor = package.with_extension("churbak.partial");
    std::fs::write(&neighbor, b"unrelated existing file").unwrap();
    let written = expect_ok(
        &run("backup", &source, &["create", package.to_str().unwrap()]),
        "backup create",
    );
    assert!(written.contains("1 stream(s)"), "summary was: {written}");
    assert!(package.exists());
    assert_eq!(
        std::fs::read(&neighbor).unwrap(),
        b"unrelated existing file"
    );
    let saved = std::fs::read(&package).unwrap();
    assert!(
        !run("backup", &source, &["create", package.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(std::fs::read(&package).unwrap(), saved);

    let shown = expect_ok(
        &run("backup", &source, &["inspect", package.to_str().unwrap()]),
        "backup inspect",
    );
    assert!(shown.contains("Chur backup package v2"));
    assert!(shown.contains("records        5"), "inspect was: {shown}");

    let report = expect_ok(
        &run("backup", &restored, &["restore", package.to_str().unwrap()]),
        "backup restore",
    );
    assert!(report.contains("restored vault"), "restore was: {report}");
    assert!(report.contains("1 stream(s)"));

    let status = expect_ok(&run("vault", &restored, &["status"]), "status");
    assert!(status.contains("1 vault identity"), "status was: {status}");

    let destination = scratch.join("exported.jpg");
    expect_ok(
        &run(
            "vault",
            &restored,
            &["export", &object, destination.to_str().unwrap()],
        ),
        "export",
    );
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
}

#[test]
fn a_recovery_phrase_restores_a_cli_backup() {
    let scratch = scratch();
    let source = scratch.join("source");
    let restored = scratch.join("restored");
    let created = expect_ok(&run("vault", &source, &["create", "--recovery"]), "create");
    let phrase = created.lines().nth(1).expect("recovery phrase");
    let package = scratch.join("vault.churbak");
    expect_ok(
        &run("backup", &source, &["create", package.to_str().unwrap()]),
        "backup create",
    );

    let output = Command::new(BINARY)
        .arg("backup")
        .arg("--root")
        .arg(&restored)
        .arg("restore")
        .arg(&package)
        .env("CHUR_RECOVERY_PHRASE", phrase)
        .env("CHUR_PASSWORD", "wrong password")
        .output()
        .expect("the binary ran");
    expect_ok(&output, "recovery restore");
    let status = expect_ok(&run("vault", &restored, &["status"]), "status");
    assert!(status.contains("1 vault identity"));
}

/// A package is never written over an existing file. §7 finalizes atomically,
/// and overwriting would destroy a good package to make room for one that may
/// fail halfway.
#[test]
fn a_package_is_never_written_over_an_existing_file() {
    let scratch = scratch();
    let source = scratch.join("source");
    expect_ok(&run("vault", &source, &["create"]), "create");

    let package = scratch.join("taken.churbak");
    std::fs::write(&package, b"not a package").unwrap();
    let message = expect_failure(&run(
        "backup",
        &source,
        &["create", package.to_str().unwrap()],
    ));
    assert!(message.contains("backup:"), "message was: {message}");
    assert_eq!(std::fs::read(&package).unwrap(), b"not a package");
}

/// §10: a restore shows decrypted metadata only after authentication. Inspect
/// needs no credential, so it must print nothing that a credential would have
/// unsealed — not the identity, not the counts, and not the creation time.
#[test]
fn inspect_prints_only_what_the_package_already_reveals() {
    let scratch = scratch();
    let source = scratch.join("source");
    let file = scratch.join("photo.jpg");
    std::fs::write(&file, vec![7u8; 4_096]).unwrap();
    expect_ok(&run("vault", &source, &["create"]), "create");
    expect_ok(
        &run(
            "vault",
            &source,
            &[
                "import",
                file.to_str().unwrap(),
                "--content-type",
                "image/jpeg",
            ],
        ),
        "import",
    );
    let package = scratch.join("vault.churbak");
    let written = expect_ok(
        &run("backup", &source, &["create", package.to_str().unwrap()]),
        "backup create",
    );
    let vault_id = written
        .lines()
        .next()
        .unwrap()
        .rsplit(' ')
        .next()
        .unwrap()
        .to_owned();

    // Inspect runs with no password at all, which is the point.
    let output = Command::new(BINARY)
        .arg("backup")
        .arg("inspect")
        .arg(&package)
        .env_remove("CHUR_PASSWORD")
        .output()
        .expect("the binary ran");
    let shown = expect_ok(&output, "inspect without a credential");
    assert!(!shown.contains(&vault_id), "inspect printed the vault id");
    assert!(shown.contains("sealed and needs a credential"));
}

/// A wrong credential restores nothing and leaves the destination empty.
#[test]
fn a_wrong_credential_leaves_the_destination_empty() {
    let scratch = scratch();
    let source = scratch.join("source");
    let restored = scratch.join("restored");
    expect_ok(&run("vault", &source, &["create"]), "create");
    let package = scratch.join("vault.churbak");
    expect_ok(
        &run("backup", &source, &["create", package.to_str().unwrap()]),
        "backup create",
    );

    let output = Command::new(BINARY)
        .arg("backup")
        .arg("--root")
        .arg(&restored)
        .arg("restore")
        .arg(&package)
        .env("CHUR_PASSWORD", "some other password entirely")
        .output()
        .expect("the binary ran");
    expect_failure(&output);

    let status = expect_ok(&run("vault", &restored, &["status"]), "status");
    assert!(status.contains("no vault"), "status was: {status}");
}

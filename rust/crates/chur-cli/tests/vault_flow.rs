//! The vault subcommands, driven as a user drives them.
//!
//! `docs/ARCHITECTURE.md` §9 makes the CLI the way the storage format stays
//! testable and recoverable independently of Android and iOS. This test runs
//! the real binary over a real directory: create, import, list, export,
//! recover, corrupt, and verify.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BINARY: &str = env!("CARGO_BIN_EXE_chur-cli");
const PASSWORD: &str = "correct horse battery staple";

fn scratch() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "chur-cli-flow-{}",
        chur_crypto::random::id().unwrap().to_hex()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

/// Runs one subcommand with the password in the environment, never an argument.
fn run(root: &Path, password: &str, arguments: &[&str]) -> Output {
    Command::new(BINARY)
        .arg("vault")
        .arg("--root")
        .arg(root)
        .args(arguments)
        .env("CHUR_PASSWORD", password)
        .env_remove("CHUR_RECOVERY_PHRASE")
        .output()
        .expect("the binary ran")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn expect_ok(output: &Output, what: &str) -> String {
    assert!(
        output.status.success(),
        "{what} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout(output)
}

#[test]
fn the_whole_vault_flow_runs_from_the_command_line() {
    let base = scratch();
    let root = base.join("v");
    let source = base.join("source.bin");
    // Three chunks and a short fourth, so the short-last-chunk case is in the
    // round trip rather than only in the unit tests.
    let bytes: Vec<u8> = (0..262_144u32 * 3 + 4_321)
        .map(|value| (value.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    std::fs::write(&source, &bytes).unwrap();

    // Before creation the root holds no vault, and that is not an error.
    let status = expect_ok(&run(&root, PASSWORD, &["status"]), "status");
    assert!(status.contains("no vault"), "{status}");

    let created = expect_ok(&run(&root, PASSWORD, &["create", "--recovery"]), "create");
    let phrase = created
        .lines()
        .nth(1)
        .expect("the recovery phrase is the second line")
        .to_owned();
    assert_eq!(phrase.split_whitespace().count(), 24, "a 24-word phrase");

    let status = expect_ok(&run(&root, PASSWORD, &["status"]), "status");
    assert!(status.contains("1 vault identity"), "{status}");

    let object = expect_ok(
        &run(
            &root,
            PASSWORD,
            &[
                "import",
                source.to_str().unwrap(),
                "--content-type",
                "image/jpeg",
            ],
        ),
        "import",
    )
    .trim()
    .to_owned();
    assert_eq!(
        object.len(),
        32,
        "an object identifier is 32 hex characters"
    );

    let listed = expect_ok(&run(&root, PASSWORD, &["list"]), "list");
    assert!(listed.contains(&object), "{listed}");
    assert!(listed.contains("verified"), "{listed}");

    let shown = expect_ok(&run(&root, PASSWORD, &["show", &object]), "show");
    assert!(shown.contains("media kind        Image"), "{shown}");
    assert!(shown.contains("substituted from import time"), "{shown}");

    // The export is byte-identical, which is the whole point of the format.
    let destination = base.join("out.bin");
    expect_ok(
        &run(
            &root,
            PASSWORD,
            &["export", &object, destination.to_str().unwrap()],
        ),
        "export",
    );
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);

    // A range read returns the same bytes as the file at that offset.
    let read = run(
        &root,
        PASSWORD,
        &["read", &object, "--offset", "262100", "--length", "200"],
    );
    assert!(read.status.success());
    assert_eq!(read.stdout, bytes[262_100..262_300]);

    expect_ok(&run(&root, PASSWORD, &["favorite", &object]), "favorite");
    let favorites = expect_ok(
        &run(&root, PASSWORD, &["list", "--scope", "favorites"]),
        "list favorites",
    );
    assert!(favorites.contains(&object), "{favorites}");

    expect_ok(&run(&root, PASSWORD, &["verify"]), "verify");

    // Recovery rotates the password in one descriptor generation, so the old
    // one stops working and the new one starts.
    let recovered = Command::new(BINARY)
        .arg("vault")
        .arg("--root")
        .arg(&root)
        .arg("recover")
        .env("CHUR_PASSWORD", "a replacement password")
        .env("CHUR_RECOVERY_PHRASE", &phrase)
        .output()
        .expect("the binary ran");
    expect_ok(&recovered, "recover");
    assert!(!run(&root, PASSWORD, &["list"]).status.success());
    expect_ok(
        &run(&root, "a replacement password", &["list"]),
        "list after recovery",
    );

    // A flipped ciphertext bit is proven corruption: verify fails, and §16.2
    // takes the row out of every scope.
    let container = find_container(&root);
    let mut damaged = std::fs::read(&container).unwrap();
    let at = damaged.len() / 2;
    damaged[at] ^= 0x01;
    std::fs::write(&container, &damaged).unwrap();

    let verified = run(&root, "a replacement password", &["verify"]);
    assert!(!verified.status.success(), "a damaged object verified");
    assert!(
        stdout(&verified).contains("corrupt"),
        "{}",
        stdout(&verified)
    );
    let repeated = run(&root, "a replacement password", &["verify"]);
    assert!(!repeated.status.success());
    assert!(stdout(&repeated).contains("1 with a problem"));
    let listed = expect_ok(
        &run(&root, "a replacement password", &["list"]),
        "list after corruption",
    );
    assert!(listed.starts_with("0 object(s)"), "{listed}");
    expect_ok(
        &run(&root, "a replacement password", &["purge", &object]),
        "purge corrupt object",
    );
    assert!(
        !container.exists(),
        "purge must collect the corrupt ciphertext"
    );
    assert!(
        !run(&root, "a replacement password", &["show", &object])
            .status
            .success()
    );
}

#[test]
fn a_password_is_never_an_argument() {
    let base = scratch();
    let root = base.join("v");
    // With neither the environment variable nor a file, the command refuses
    // rather than falling back to a prompt or an argument.
    let output = Command::new(BINARY)
        .arg("vault")
        .arg("--root")
        .arg(&root)
        .arg("create")
        .env_remove("CHUR_PASSWORD")
        .output()
        .expect("the binary ran");
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("never an argument"),
        "the refusal does not say why: {message}"
    );
}

#[test]
fn a_password_file_is_accepted_without_its_trailing_line_ending() {
    let base = scratch();
    let root = base.join("v");
    let file = base.join("password");
    std::fs::write(&file, format!("{PASSWORD}\r\n")).unwrap();

    let create = Command::new(BINARY)
        .arg("vault")
        .arg("--root")
        .arg(&root)
        .arg("--password-file")
        .arg(&file)
        .arg("create")
        .env_remove("CHUR_PASSWORD")
        .output()
        .expect("the binary ran");
    expect_ok(&create, "create with a password file");

    // The same password without CRLF opens it, proving the line ending was trimmed.
    expect_ok(&run(&root, PASSWORD, &["status"]), "status");
    expect_ok(&run(&root, PASSWORD, &["list"]), "list");
}

/// The first committed container under a vault root.
fn find_container(root: &Path) -> PathBuf {
    fn walk(directory: &Path, found: &mut Option<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if found.is_none()
                && path
                    .parent()
                    .and_then(Path::parent)
                    .and_then(|parent| parent.file_name())
                    .is_some_and(|name| name == "objects")
            {
                *found = Some(path);
            }
        }
    }
    let mut found = None;
    walk(root, &mut found);
    found.expect("a committed container")
}

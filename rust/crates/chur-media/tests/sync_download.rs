//! Ciphertext-only sync download validation before local publication.

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU64, Ordering};

use chur_catalog::paths::VaultRoot;
use chur_core::{ChurStatus, Id, Result};
use chur_crypto::{Key, Nonce};
use chur_format::constants::StreamKind;
use chur_format::container::{
    CanonicalManifest, ContainerReader, ContainerWriter, MediaProperties, ReadAt, StreamIdentity,
};
use chur_media::{store, sync_download};

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).expect("id")
}

struct TestRoot(std::path::PathBuf);

impl TestRoot {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "chur-sync-download-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("test root");
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Bytes(Vec<u8>);

impl ReadAt for Bytes {
    fn length(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset)
            .map_err(|_| chur_core::err!(ObjectIncomplete, "offset is too large"))?;
        let end = start
            .checked_add(buffer.len())
            .filter(|end| *end <= self.0.len())
            .ok_or_else(|| chur_core::err!(ObjectIncomplete, "range is absent"))?;
        buffer.copy_from_slice(&self.0[start..end]);
        Ok(())
    }
}

struct Interrupted {
    bytes: Bytes,
    reads: usize,
}

impl ReadAt for Interrupted {
    fn length(&self) -> u64 {
        self.bytes.length()
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        if self.reads == 1 {
            return Err(chur_core::err!(
                NetworkFailure,
                "test transport was interrupted"
            ));
        }
        self.reads += 1;
        self.bytes.read_at(offset, buffer)
    }
}

#[test]
fn only_a_complete_authentic_download_can_be_published() {
    let root = TestRoot::new();
    let vault_root = VaultRoot::new(&root.0);
    let key = Key::new([1; 32]);
    let identity = StreamIdentity {
        object_id: id(2),
        stream_id: id(3),
        stream_kind: StreamKind::Original,
        stream_revision: 1,
    };
    let manifest = CanonicalManifest::new(
        identity,
        None,
        1_048_576,
        [4; 16],
        1,
        MediaProperties::opaque(),
    )
    .expect("manifest");
    let mut writer =
        ContainerWriter::start(Vec::new(), &key, manifest, Nonce::new([5; 24])).expect("writer");
    writer.write_chunk(&vec![7; 1_048_576]).expect("full chunk");
    writer.write_chunk(b"private bytes").expect("last chunk");
    let bytes = writer.finish(Nonce::new([6; 24]), 1).expect("container");
    let final_commit = ContainerReader::open(&bytes, &key, &identity)
        .expect("reader")
        .read_final_commit()
        .expect("final commit");
    let expected = sync_download::Expectation::new(
        identity.object_id,
        identity.stream_id,
        bytes.len() as u64,
        *final_commit.ordered_chunk_commitment(),
    )
    .expect("expectation");
    let mut interrupted = Interrupted {
        bytes: Bytes(bytes.clone()),
        reads: 0,
    };
    assert!(
        sync_download::stage(
            &vault_root,
            &id(7),
            &id(8),
            &mut interrupted,
            &key,
            &expected,
        )
        .is_err()
    );
    assert!(store::temporary_exists(&vault_root, &id(7), &id(8)));
    let mut source = Bytes(bytes.clone());
    let verified = sync_download::stage(&vault_root, &id(7), &id(8), &mut source, &key, &expected)
        .expect("verified download");
    assert_eq!(verified.plaintext_size(), 1_048_589);
    verified
        .commit(&vault_root, &id(7), &id(9))
        .expect("publish");
    assert_eq!(
        store::read_container(&vault_root, &id(7), &id(9)).expect("stored"),
        bytes
    );

    // Every content-derived rejection of a full-length file must leave nothing to resume from,
    // so the next sync restarts at offset 0 instead of re-verifying the same bad bytes.
    // Header offsets: magic 0..8, version 8..10, encoding profile 10..12, suite 12..14.
    let middle = bytes.len() / 2;
    for (case, (position, status)) in [
        (middle, None),
        (8, Some(ChurStatus::UnsupportedVersion)),
        (12, Some(ChurStatus::UnsupportedSuite)),
    ]
    .into_iter()
    .enumerate()
    {
        let temp = id(10 + case as u8);
        let mut damaged = bytes.clone();
        damaged[position] ^= 0xff;
        let error = sync_download::stage(
            &vault_root,
            &id(7),
            &temp,
            &mut Bytes(damaged),
            &key,
            &expected,
        )
        .err()
        .expect("damaged container is rejected");
        if let Some(status) = status {
            assert_eq!(error.status(), status);
        }
        assert!(
            !store::temporary_exists(&vault_root, &id(7), &temp),
            "case {case} {:?}",
            error.status()
        );
        assert!(!store::container_exists(&vault_root, &id(7), &temp));
        assert_eq!(
            sync_download::staged_offset(&vault_root, &id(7), &temp, &expected).expect("offset"),
            0
        );
    }
}

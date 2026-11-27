//! Every reject vector of `test-vectors/v1`, run through the reader.
//!
//! `vectors verify` proves that the generator still produces the recorded
//! bytes. It does not prove that the reader still refuses them: a format change
//! can make a reader accept an input that a frozen vector says it rejects. This
//! test reads the manifest from disk and runs each reject vector's inputs
//! through the parser its owning specification names, then compares the status
//! with the vector's `error_code`.
//!
//! A vector marked `superseded_by` keeps its bytes under
//! `docs/format/TEST_VECTORS.md` §8 and is skipped; the vector it names is run
//! instead. A reject vector with no reader case here fails the test, so a new
//! negative vector cannot be added without a reader check.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use chur_core::{ChurStatus, Id, Result};
use chur_crypto::secret::Key;
use chur_format::backup::{
    BackupManifest, CatalogExportPosition, PublicPreamble, RecordCommitter, RecordHeader,
    RecordType, open_catalog_export,
};
use chur_format::catalog_export::{ChunkSource, ExportReader};
use chur_format::codec::Reader;
use chur_format::constants::{BACKUP_VERSION_V1, StreamKind};
use chur_format::container::{ContainerReader, StreamIdentity};
use chur_format::descriptor::VaultDescriptor;
use chur_format::envelope::{CollectionKeyEnvelope, ObjectKeyEnvelope};
use chur_format::slot::PasswordSlotBody;
use chur_sync_protocol::checkpoint::Checkpoint;
use chur_sync_protocol::grant::CollectionGrant;
use chur_sync_protocol::membership::{EnrollmentRecord, RevocationRecord};
use chur_sync_protocol::operation::Operation;
use serde_json::Value;
use zeroize::Zeroizing;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../test-vectors/v1")
}

struct Case<'a> {
    inputs: &'a serde_json::Map<String, Value>,
}

impl Case<'_> {
    fn bytes(&self, role: &str) -> Vec<u8> {
        match &self.inputs[role] {
            Value::String(text) => hex::decode(text).expect("hexadecimal input"),
            Value::Object(reference) => {
                let file = reference["file"].as_str().expect("file reference");
                std::fs::read(vectors_dir().join(file)).expect("fixture file")
            }
            other => panic!("input {role} is not bytes: {other}"),
        }
    }

    fn fixed<const N: usize>(&self, role: &str) -> [u8; N] {
        self.bytes(role).try_into().expect("fixed-length input")
    }

    fn key(&self, role: &str) -> Key {
        Key::new(self.fixed(role))
    }

    fn id(&self, role: &str) -> Id {
        Id::new(self.fixed(role)).expect("identifier input")
    }

    fn number(&self, role: &str) -> u64 {
        match &self.inputs[role] {
            Value::Number(number) => number.as_u64().expect("unsigned number"),
            Value::String(text) => text.parse().expect("decimal number"),
            other => panic!("input {role} is not a number: {other}"),
        }
    }

    fn text(&self, role: &str) -> &str {
        self.inputs[role].as_str().expect("text input")
    }

    fn flag(&self, role: &str) -> bool {
        self.inputs[role].as_bool().expect("boolean input")
    }
}

struct OneChunk(Option<Vec<u8>>);

impl ChunkSource for OneChunk {
    fn next_chunk(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.0.take().map(Zeroizing::new))
    }
}

/// The identity every container vector is sealed for.
fn container_identity() -> StreamIdentity {
    StreamIdentity {
        object_id: Id::new([0x33; 16]).unwrap(),
        stream_id: Id::new([0x34; 16]).unwrap(),
        stream_kind: StreamKind::Original,
        stream_revision: 1,
    }
}

fn open_container(container: &[u8], object_key: &Key) -> Result<()> {
    ContainerReader::open(container, object_key, &container_identity())
        .and_then(|reader| reader.verify_complete())
        .map(|_| ())
}

/// Runs one reject vector and returns what the reader said.
fn run(vector_id: &str, case: &Case<'_>) -> Result<()> {
    let unused_key = Key::new([0x77; 32]);
    match vector_id {
        "canonical-encoding-v1-all-zero-identifier" => {
            Id::new(case.fixed("identifier")).map(|_| ())
        }
        "canonical-encoding-v1-boolean-byte-two" => {
            let bytes = case.bytes("encoded");
            Reader::new(&bytes, ChurStatus::NonCanonicalEncoding)
                .bool()
                .map(|_| ())
        }
        "canonical-encoding-v1-invalid-utf8-string" => {
            let bytes = case.bytes("encoded");
            Reader::new(&bytes, ChurStatus::NonCanonicalEncoding)
                .string(64)
                .map(|_| ())
        }
        "canonical-encoding-v1-declared-length-over-the-limit" => {
            let bytes = case.bytes("encoded");
            let limit = u32::try_from(case.number("parser_limit")).unwrap();
            Reader::new(&bytes, ChurStatus::NonCanonicalEncoding)
                .variable(limit)
                .map(|_| ())
        }
        "password-slot-v1-memory-below-the-floor" | "password-slot-v1-trailing-byte" => {
            PasswordSlotBody::decode(&case.bytes("slot_body")).map(|_| ())
        }
        "recovery-slot-v1-checksum-mismatch" | "recovery-slot-v1-twenty-three-words" => {
            chur_crypto::recovery::decode(case.text("phrase")).map(|_| ())
        }
        "vault-descriptor-v1-wrong-magic" | "vault-descriptor-v1-truncated-tag" => {
            VaultDescriptor::parse(&case.bytes("descriptor")).map(|_| ())
        }
        "vault-descriptor-v1-wrong-candidate-root" => VaultDescriptor::authenticate(
            &case.bytes("descriptor"),
            Some(&case.key("candidate_root")),
        )
        .map(|_| ()),
        "collection-envelope-v1-foreign-vault-identity" => {
            CollectionKeyEnvelope::decode(&case.bytes("envelope"))
                .and_then(|envelope| envelope.open(&case.key("vault_root_secret")))
                .map(|_| ())
        }
        "object-key-envelope-v1-unsupported-suite" => {
            ObjectKeyEnvelope::decode(&case.bytes("envelope")).map(|_| ())
        }
        "object-v1-missing-final-commit"
        | "object-v2-non-zero-padding-byte"
        | "object-v2-padding-past-bucket"
        | "object-v2-padding-short-of-bucket" => {
            open_container(&case.bytes("container"), &case.key("object_key"))
        }
        // The key is never reached: each of these fails the keyless walk of
        // the record headers first.
        "object-v1-trailing-byte-after-final-commit"
        | "object-v1-non-zero-preamble-reserved"
        | "object-v1-forged-chunk-plaintext-length"
        | "object-v1-unsupported-suite" => open_container(&case.bytes("container"), &unused_key),
        "backup-v1-wrong-magic"
        | "backup-v1-unsupported-suite"
        | "backup-v1-non-zero-reserved"
        | "backup-v2-unsupported-version" => {
            PublicPreamble::decode(&case.bytes("preamble")).map(|_| ())
        }
        "backup-v1-record-count-below-minimum" => {
            PublicPreamble::new(BACKUP_VERSION_V1, case.number("record_count")).map(|_| ())
        }
        "backup-v1-unallocated-record-type" | "backup-v1-unsupported-record-version" => {
            RecordHeader::decode(&case.bytes("header")).map(|_| ())
        }
        // The vector's package is version 1, which its identifier names.
        "backup-v1-manifest-contradicts-the-preamble" => {
            BackupManifest::decode_in_package(&case.bytes("manifest_plaintext"), BACKUP_VERSION_V1)
                .map(|_| ())
        }
        "backup-v1-final-commit-does-not-open-as-a-manifest" => BackupManifest::open(
            &case.bytes("record"),
            &case.key("manifest_key"),
            &case.id("vault_id"),
            BACKUP_VERSION_V1,
        )
        .map(|_| ()),
        "backup-v2-catalog-export-spliced-from-another-backup"
        | "backup-v2-catalog-export-reordered" => {
            let position = CatalogExportPosition {
                vault_id: case.id("vault_id"),
                backup_id: case.id("backup_id"),
                record_index: case.number("record_index"),
                chunk_index: u32::try_from(case.number("chunk_index")).unwrap(),
                is_final: case.flag("is_final"),
            };
            open_catalog_export(&case.bytes("record"), &case.key("manifest_key"), &position)
                .map(|_| ())
        }
        "backup-v2-catalog-export-truncated" => {
            let (mut reader, header) = ExportReader::new(OneChunk(Some(case.bytes("stream"))))?;
            for _ in 0..header.table_count {
                let table = reader.table()?;
                for _ in 0..table.row_count * table.columns.len() as u64 {
                    reader.value()?;
                }
            }
            reader.finish()
        }
        "backup-v2-descriptor-altered" => {
            let mut records = RecordCommitter::new();
            records.add(0, RecordType::Manifest, &case.bytes("manifest_record"));
            records.add(1, RecordType::Descriptor, &case.bytes("descriptor_record"));
            records.add(
                2,
                RecordType::CatalogExport,
                &case.bytes("catalog_export_record"),
            );
            records.add(4, RecordType::Envelope, &case.bytes("envelope_record"));
            let sealed: [u8; 32] = case.fixed("sealed_record_commitment");
            if chur_crypto::secret::constant_time_eq(&records.finish(), &sealed) {
                Ok(())
            } else {
                Err(chur_core::Error::new(
                    ChurStatus::VaultCorrupt,
                    "the record commitment does not match",
                ))
            }
        }
        "operation-v1-version-two" | "operation-v1-truncated-signature" => {
            Operation::decode(&case.bytes("record")).map(|_| ())
        }
        "operation-v1-modified-signature" => Operation::decode(&case.bytes("record"))
            .and_then(|operation| operation.verify_signature(&case.fixed("signing_public_key"))),
        "operation-v1-hpke-suite-two" => {
            EnrollmentRecord::decode(&case.bytes("record")).map(|_| ())
        }
        "operation-v1-compacted-checkpoint" => {
            Checkpoint::decode(&case.bytes("record")).map(|_| ())
        }
        "operation-v1-self-issued-revocation" => {
            RevocationRecord::decode(&case.bytes("record")).map(|_| ())
        }
        "collection-grant-v1-modified-signature" => CollectionGrant::decode(&case.bytes("record"))
            .and_then(|grant| {
                grant.verify_sender_signature(&case.fixed("sender_signing_public_key"))
            }),
        "collection-grant-v1-unknown-hpke-profile" => {
            CollectionGrant::decode(&case.bytes("record")).map(|_| ())
        }
        _ => panic!("reject vector {vector_id} has no reader case in this test"),
    }
}

#[test]
fn every_current_reject_vector_is_rejected_by_the_reader_as_declared() {
    let text = std::fs::read_to_string(vectors_dir().join("manifest.json")).expect("manifest");
    let manifest: Value = serde_json::from_str(&text).expect("manifest JSON");
    let mut ran = 0;
    let mut superseded = 0;
    let mut failures = Vec::new();
    for vector in manifest["vectors"].as_array().expect("vector list") {
        if vector["outcome"] != "reject" {
            continue;
        }
        let vector_id = vector["vector_id"].as_str().expect("vector id");
        if vector.get("superseded_by").is_some() {
            superseded += 1;
            continue;
        }
        let expected = vector["error_code"].as_str().expect("error code");
        let case = Case {
            inputs: vector["inputs"].as_object().expect("inputs"),
        };
        match run(vector_id, &case) {
            Ok(()) => failures.push(format!("{vector_id}: accepted, expected {expected}")),
            Err(error) if error.status().name() == expected => {}
            Err(error) => failures.push(format!(
                "{vector_id}: {} rather than {expected}",
                error.status().name()
            )),
        }
        ran += 1;
    }
    assert!(failures.is_empty(), "{failures:#?}");
    assert!(ran >= 40, "only {ran} reject vectors ran");
    assert_eq!(superseded, 1, "one historical vector is superseded");
}

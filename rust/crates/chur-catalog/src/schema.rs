//! The physical catalog schema and its migrations.
//!
//! `docs/format/CATALOG_SCHEMA_V1.md` §1 lists the logical entities and §18
//! fixes how a schema version moves: versions are values of the
//! `catalog_format_version` namespace, they begin at `0x0001`, and they
//! increase by one with no gap and no branch. This module holds one migration
//! step per version and applies them in order.
//!
//! The DDL carries no user label, which §16.5 asks for: a table or index named
//! after an album would put a private word in a page an attacker can see the
//! size of.

use chur_core::{Id, Result, bail, ensure, err, limits::catalog as limits};
use chur_format::{
    constants::{
        CATALOG_FORMAT_VERSION_V1, CATALOG_FORMAT_VERSION_V2, CATALOG_FORMAT_VERSION_V3,
        CATALOG_FORMAT_VERSION_V4, CATALOG_FORMAT_VERSION_V5, CATALOG_FORMAT_VERSION_V6,
        CATALOG_FORMAT_VERSION_V7, CATALOG_FORMAT_VERSION_V8, CATALOG_FORMAT_VERSION_V9,
        CATALOG_FORMAT_VERSION_V10, CATALOG_FORMAT_VERSION_V11, CATALOG_FORMAT_VERSION_V12,
        CATALOG_FORMAT_VERSION_V13, CATALOG_FORMAT_VERSION_V14, CATALOG_FORMAT_VERSION_V15,
        CATALOG_FORMAT_VERSION_V16, CATALOG_FORMAT_VERSION_V17, CATALOG_FORMAT_VERSION_V18,
    },
    envelope::ObjectKeyEnvelope,
};
use rusqlite::Connection;

use crate::db::{CatalogDb, as_sqlite_integer, from_sqlite_integer, map_sqlite};

/// One schema step: the version it produces and the statements that produce it.
#[cfg(test)]
struct Step {
    version: u16,
}

/// Every schema step, in ascending version order with no gap.
#[cfg(test)]
const STEPS: &[Step] = &[
    Step {
        version: CATALOG_FORMAT_VERSION_V1,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V2,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V3,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V4,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V5,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V6,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V7,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V8,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V9,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V10,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V11,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V12,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V13,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V14,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V15,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V16,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V17,
    },
    Step {
        version: CATALOG_FORMAT_VERSION_V18,
    },
];

/// The v1 schema.
///
/// Column widths follow the canonical model rather than SQLite's affinities: an
/// identifier is a 16-byte `BLOB` and never text, a time is the `u64`
/// milliseconds of `docs/format/CANONICAL_ENCODING_V1.md` §9 stored as a signed
/// integer, and every enumerated value is the byte allocated in §15.4.
const V1_DDL: &str = r#"
-- §2. Exactly one row. The CHECK is what makes that structural rather than a
-- convention a later statement can break.
CREATE TABLE vault_state (
    only_row                  INTEGER PRIMARY KEY CHECK (only_row = 1),
    catalog_format_version    INTEGER NOT NULL,
    catalog_generation        INTEGER NOT NULL,
    active_migration_target   INTEGER,
    object_store_checkpoint   INTEGER NOT NULL,
    integrity_checkpoint_ms   INTEGER NOT NULL,
    capability_flags          INTEGER NOT NULL
) STRICT;

-- §3.
CREATE TABLE collections (
    collection_id     BLOB PRIMARY KEY,
    current_epoch     INTEGER NOT NULL,
    policy_type       INTEGER NOT NULL,
    created_revision  INTEGER NOT NULL,
    status            INTEGER NOT NULL
) STRICT;

-- §4. `body` is the encoded CollectionKeyEnvelopeV1 of the format crate; the
-- catalog stores it whole rather than splitting it into columns, so no second
-- encoder exists for a record CANONICAL_ENCODING_V1.md §13 reserves for Rust.
CREATE TABLE collection_key_envelopes (
    collection_id     BLOB NOT NULL REFERENCES collections(collection_id),
    collection_epoch  INTEGER NOT NULL,
    generation        INTEGER NOT NULL,
    status            INTEGER NOT NULL,
    body              BLOB NOT NULL,
    PRIMARY KEY (collection_id, collection_epoch, generation)
) STRICT;

-- §5. `state` and `integrity_summary` are the two independent enums of §5.1.
-- The projection columns of §16.1 live here so a page is a range scan.
CREATE TABLE objects (
    object_id                 BLOB PRIMARY KEY,
    object_generation         INTEGER NOT NULL,
    collection_id             BLOB NOT NULL REFERENCES collections(collection_id),
    primary_stream_id         BLOB NOT NULL,
    media_kind                INTEGER NOT NULL,
    capture_time_ms           INTEGER NOT NULL,
    import_time_ms            INTEGER NOT NULL,
    capture_time_substituted  INTEGER NOT NULL,
    plaintext_size            INTEGER NOT NULL,
    width                     INTEGER NOT NULL,
    height                    INTEGER NOT NULL,
    duration_ms               INTEGER NOT NULL,
    favorite                  INTEGER NOT NULL,
    state                     INTEGER NOT NULL,
    integrity_summary         INTEGER NOT NULL,
    thumbnail_ready           INTEGER NOT NULL,
    active_metadata_revision  INTEGER NOT NULL,
    -- The FTS5 rowid of this object. FTS5 keys on an INTEGER rowid and an
    -- object is keyed on 16 opaque bytes, so a search hit could not be joined
    -- back to its row without a column holding the mapping. UNIQUE is what
    -- turns a collision into a refused insert rather than a wrong page.
    search_key                INTEGER NOT NULL UNIQUE
) STRICT;

-- §6. No active row points at a temporary uncommitted container, which the
-- import journal enforces by holding the temp path itself.
CREATE TABLE object_streams (
    stream_id                 BLOB PRIMARY KEY,
    object_id                 BLOB NOT NULL REFERENCES objects(object_id),
    stream_kind               INTEGER NOT NULL,
    stream_revision           INTEGER NOT NULL,
    source_content_revision   INTEGER NOT NULL,
    container_path_id         BLOB NOT NULL,
    container_version         INTEGER NOT NULL,
    suite_id                  INTEGER NOT NULL,
    ciphertext_size           INTEGER NOT NULL,
    plaintext_size            INTEGER NOT NULL,
    chunk_size                INTEGER NOT NULL,
    complete_verified_ms      INTEGER,
    final_commitment          BLOB NOT NULL
) STRICT;

-- §7. Uniqueness prevents an ambiguous active generation.
CREATE TABLE object_key_envelopes (
    object_id     BLOB NOT NULL REFERENCES objects(object_id),
    generation    INTEGER NOT NULL,
    status        INTEGER NOT NULL,
    body          BLOB NOT NULL,
    PRIMARY KEY (object_id, generation)
) STRICT;

-- §8. The queryable columns are the revision, protected by SQLCipher only.
-- `record` is reserved for a sealed canonical revision; v1 writers store it
-- empty.
CREATE TABLE metadata_revisions (
    object_id           BLOB NOT NULL REFERENCES objects(object_id),
    revision            INTEGER NOT NULL,
    active              INTEGER NOT NULL,
    record              BLOB NOT NULL,
    original_filename   TEXT,
    caption             TEXT,
    content_type        TEXT NOT NULL,
    capture_time_ms     INTEGER,
    width               INTEGER NOT NULL,
    height              INTEGER NOT NULL,
    duration_ms         INTEGER NOT NULL,
    PRIMARY KEY (object_id, revision)
) STRICT;

-- §10. The binding to source_content_revision is what stops a stale derivative
-- from being presented as current.
CREATE TABLE derived_assets (
    object_id                BLOB NOT NULL REFERENCES objects(object_id),
    kind                     INTEGER NOT NULL,
    source_content_revision  INTEGER NOT NULL,
    asset_revision           INTEGER NOT NULL,
    generator_profile        INTEGER NOT NULL,
    stream_id                BLOB NOT NULL,
    PRIMARY KEY (object_id, kind, source_content_revision)
) STRICT;

-- §9.
CREATE TABLE albums (
    album_id          BLOB PRIMARY KEY,
    name              TEXT NOT NULL,
    created_ms        INTEGER NOT NULL,
    revision          INTEGER NOT NULL
) STRICT;

-- §9 and §16.3: capture_time_ms is duplicated here so an album page never joins
-- before sorting.
CREATE TABLE album_memberships (
    album_id          BLOB NOT NULL REFERENCES albums(album_id),
    object_id         BLOB NOT NULL REFERENCES objects(object_id),
    capture_time_ms   INTEGER NOT NULL,
    added_ms          INTEGER NOT NULL,
    revision          INTEGER NOT NULL,
    PRIMARY KEY (album_id, object_id)
) STRICT;

-- §9 and §16.3: the same duplication, for the same reason.
CREATE TABLE favorites (
    object_id         BLOB PRIMARY KEY REFERENCES objects(object_id),
    capture_time_ms   INTEGER NOT NULL,
    added_ms          INTEGER NOT NULL
) STRICT;

CREATE TABLE tags (
    tag_id     BLOB PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE object_tags (
    tag_id            BLOB NOT NULL REFERENCES tags(tag_id),
    object_id         BLOB NOT NULL REFERENCES objects(object_id),
    capture_time_ms   INTEGER NOT NULL,
    PRIMARY KEY (tag_id, object_id)
) STRICT;

-- §11. The journal record of OBJECT_CONTAINER_V1.md §14.1. It shares the
-- catalog transaction domain, so a chunk-index reservation and the state that
-- activates the object cannot disagree after a crash.
CREATE TABLE import_transactions (
    transaction_id       BLOB PRIMARY KEY,
    temp_path_id         BLOB NOT NULL,
    object_id            BLOB NOT NULL,
    stream_id            BLOB NOT NULL,
    stream_kind          INTEGER NOT NULL,
    stream_revision      INTEGER NOT NULL,
    envelope_generation  INTEGER NOT NULL,
    -- NULL once §14.4 step 1 has destroyed it, which is the moment the
    -- ContentKey and every byte written under it become unrecoverable. The
    -- column is the envelope itself rather than a reference, because
    -- object_key_envelopes references an object row that does not exist until
    -- the transaction commits.
    envelope_body        BLOB,
    nonce_prefix         BLOB NOT NULL,
    chunk_size           INTEGER NOT NULL,
    manifest_length      INTEGER NOT NULL,
    reserved_index       INTEGER,
    expected_length      INTEGER,
    source_seekable      INTEGER NOT NULL,
    stage                INTEGER NOT NULL,
    opened_ms            INTEGER NOT NULL
) STRICT;

-- §12. Opaque cleanup state with no private filename.
CREATE TABLE scratch_entries (
    entry_id     BLOB PRIMARY KEY,
    path_id      BLOB NOT NULL,
    object_id    BLOB,
    byte_length  INTEGER NOT NULL,
    created_ms   INTEGER NOT NULL
) STRICT;

-- §13. Stable codes, never a secret error string.
CREATE TABLE integrity_records (
    object_id     BLOB NOT NULL REFERENCES objects(object_id),
    stream_id     BLOB NOT NULL,
    checked_ms    INTEGER NOT NULL,
    scope         INTEGER NOT NULL,
    range_start   INTEGER NOT NULL,
    range_end     INTEGER NOT NULL,
    outcome       INTEGER NOT NULL,
    PRIMARY KEY (object_id, stream_id, checked_ms)
) STRICT;

-- §14. Written before physical garbage collection so recovery cannot resurrect
-- a removed object.
CREATE TABLE tombstones (
    collection_id BLOB NOT NULL CHECK (length(collection_id) = 16),
    object_id     BLOB NOT NULL CHECK (length(object_id) = 16),
    authored_ms   INTEGER NOT NULL,
    object_generation INTEGER NOT NULL,
    PRIMARY KEY (collection_id, object_id)
) STRICT;

-- Object content keys use disposable, object-bound requests. Private request
-- keys and pending local envelopes are mutable SQLCipher state, never log data.
CREATE TABLE object_receive_dispatch (
    collection_id BLOB NOT NULL CHECK (length(collection_id) = 16),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    ticket INTEGER NOT NULL CHECK (ticket > 0),
    PRIMARY KEY (collection_id, object_id)
) STRICT;
CREATE INDEX object_receive_dispatch_order ON object_receive_dispatch(collection_id, ticket);

CREATE TABLE object_key_requests (
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    collection_id BLOB NOT NULL CHECK (length(collection_id) = 16),
    prekey_id BLOB NOT NULL UNIQUE CHECK (length(prekey_id) = 16),
    private_key BLOB NOT NULL CHECK (length(private_key) = 32),
    record BLOB NOT NULL CHECK (length(record) = 226),
    PRIMARY KEY (collection_id, object_id)
) STRICT;
CREATE INDEX object_key_requests_by_collection ON object_key_requests(collection_id);
CREATE TABLE pending_object_keys (
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    collection_id BLOB NOT NULL CHECK (length(collection_id) = 16),
    request_record BLOB NOT NULL CHECK (length(request_record) = 226),
    grant_record BLOB NOT NULL CHECK (length(grant_record) = 346),
    envelope BLOB NOT NULL CHECK (length(envelope) = 142),
    PRIMARY KEY (collection_id, object_id)
) STRICT;
CREATE TABLE issued_object_key_grants (
    prekey_id BLOB PRIMARY KEY CHECK (length(prekey_id) = 16),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    request_record BLOB NOT NULL CHECK (length(request_record) = 226),
    grant_record BLOB NOT NULL CHECK (length(grant_record) = 346)
) STRICT;

-- Local pairing state stays in the encrypted catalog and is excluded from portable snapshots.
CREATE TABLE device_pairing_pending (
    only_row INTEGER PRIMARY KEY CHECK(only_row = 1),
    request BLOB NOT NULL,
    identity_envelope BLOB,
    approval BLOB,
    credentials BLOB,
    finalized INTEGER NOT NULL CHECK(finalized IN (0, 1))
) STRICT;
CREATE TABLE device_pairing_revocations (
    device_id BLOB PRIMARY KEY REFERENCES sync_devices(device_id),
    checkpoint BLOB NOT NULL,
    revocation BLOB NOT NULL,
    operation BLOB NOT NULL
) STRICT;
CREATE TABLE device_pairing_approvals (
    request_id BLOB PRIMARY KEY,
    request BLOB NOT NULL,
    checkpoint BLOB NOT NULL,
    enrollment BLOB NOT NULL,
    operation BLOB NOT NULL,
    approval BLOB NOT NULL
) STRICT;


-- §16.3. The five indexes that cover a scope under a sort, then the four that
-- serve lookups which are not query scopes.
CREATE INDEX objects_by_capture ON objects (state, capture_time_ms, object_id);
CREATE INDEX objects_by_import ON objects (state, import_time_ms, object_id);
CREATE INDEX memberships_by_capture
    ON album_memberships (album_id, capture_time_ms, object_id);
CREATE INDEX favorites_by_capture ON favorites (capture_time_ms, object_id);
CREATE INDEX object_tags_by_capture ON object_tags (tag_id, capture_time_ms, object_id);
CREATE INDEX streams_by_object ON object_streams (object_id, stream_kind);
CREATE INDEX assets_by_object ON derived_assets (object_id, kind, source_content_revision);
CREATE INDEX envelopes_by_object ON object_key_envelopes (object_id, status);
CREATE INDEX imports_by_stage ON import_transactions (stage);
CREATE INDEX tombstones_by_authored ON tombstones (authored_ms);

-- §16.4. The FTS5 table lives in the same database, so its pages carry the same
-- at-rest encryption. It is contentless: the catalog already holds the
-- filename, the caption, and the tag names in ordinary columns, so a second
-- copy inside the index would be a second source of truth for private text.
-- `contentless_delete=1` is what makes a row replaceable by its rowid alone; a
-- plain contentless table can only be appended to, and reindexing a revised
-- object would leave the old terms matching for ever.
CREATE VIRTUAL TABLE object_search USING fts5(
    filename,
    caption,
    tag_names,
    content='',
    contentless_delete=1,
    tokenize='unicode61 remove_diacritics 2',
    prefix='2 3'
);
"#;

/// Catalog v2 adds only encrypted synchronization state.
const V2_DDL: &str = r#"
CREATE TABLE sync_state (
    only_row                         INTEGER PRIMARY KEY CHECK (only_row = 1),
    membership_generation           INTEGER NOT NULL CHECK (membership_generation >= 0),
    membership_commitment           BLOB NOT NULL CHECK (length(membership_commitment) = 32),
    latest_own_checkpoint_commitment BLOB
        CHECK (latest_own_checkpoint_commitment IS NULL OR length(latest_own_checkpoint_commitment) = 32)
) STRICT;

CREATE TABLE sync_membership_records (
    membership_generation INTEGER PRIMARY KEY CHECK (membership_generation >= 0),
    record_kind            INTEGER NOT NULL CHECK (record_kind IN (1, 2)),
    device_id              BLOB NOT NULL CHECK (length(device_id) = 16),
    commitment             BLOB NOT NULL UNIQUE CHECK (length(commitment) = 32),
    record                 BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 16777216)
) STRICT;

CREATE TABLE sync_devices (
    device_id              BLOB PRIMARY KEY CHECK (length(device_id) = 16),
    signing_public_key     BLOB NOT NULL CHECK (length(signing_public_key) = 32),
    hpke_public_key        BLOB NOT NULL CHECK (length(hpke_public_key) = 32),
    status                 INTEGER NOT NULL CHECK (status IN (1, 2)),
    membership_generation  INTEGER NOT NULL CHECK (membership_generation >= 0),
    revoked_sequence       INTEGER CHECK (revoked_sequence IS NULL OR revoked_sequence >= 0),
    revoked_digest         BLOB CHECK (revoked_digest IS NULL OR length(revoked_digest) = 32),
    CHECK ((status = 1 AND revoked_sequence IS NULL AND revoked_digest IS NULL)
        OR (status = 2 AND revoked_sequence IS NOT NULL AND revoked_digest IS NOT NULL))
) STRICT;

CREATE TABLE sync_signing_keys (
    device_id              BLOB NOT NULL REFERENCES sync_devices(device_id),
    membership_generation  INTEGER NOT NULL CHECK (membership_generation >= 0),
    public_key             BLOB NOT NULL CHECK (length(public_key) = 32),
    PRIMARY KEY (device_id, membership_generation)
) STRICT;

CREATE TABLE sync_identity_envelopes (
    device_id          BLOB NOT NULL REFERENCES sync_devices(device_id),
    identity_generation INTEGER NOT NULL CHECK (identity_generation >= 0),
    active             INTEGER NOT NULL CHECK (active IN (0, 1)),
    recovery_only      INTEGER NOT NULL CHECK (recovery_only IN (0, 1)),
    body               BLOB NOT NULL CHECK (length(body) BETWEEN 1 AND 16777216),
    PRIMARY KEY (device_id, identity_generation)
) STRICT;

CREATE TABLE sync_operations (
    device_id       BLOB NOT NULL REFERENCES sync_devices(device_id),
    device_sequence INTEGER NOT NULL CHECK (device_sequence >= 0),
    operation_id    BLOB NOT NULL CHECK (length(operation_id) = 16),
    digest          BLOB NOT NULL CHECK (length(digest) = 32),
    record          BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 16777216),
    PRIMARY KEY (device_id, device_sequence)
) STRICT;

CREATE TABLE sync_heads (
    device_id         BLOB PRIMARY KEY REFERENCES sync_devices(device_id),
    accepted_sequence INTEGER CHECK (accepted_sequence IS NULL OR accepted_sequence >= 0),
    accepted_digest   BLOB CHECK (accepted_digest IS NULL OR length(accepted_digest) = 32),
    floor_sequence    INTEGER CHECK (floor_sequence IS NULL OR floor_sequence >= 0),
    floor_digest      BLOB CHECK (floor_digest IS NULL OR length(floor_digest) = 32),
    CHECK ((accepted_sequence IS NULL) = (accepted_digest IS NULL)),
    CHECK ((floor_sequence IS NULL) = (floor_digest IS NULL))
) STRICT;

CREATE TABLE sync_forks (
    device_id          BLOB PRIMARY KEY REFERENCES sync_devices(device_id),
    state              INTEGER NOT NULL CHECK (state IN (1, 2)),
    accepted_record    BLOB NOT NULL CHECK (length(accepted_record) BETWEEN 1 AND 16777216),
    conflicting_record BLOB NOT NULL CHECK (length(conflicting_record) BETWEEN 1 AND 16777216)
) STRICT;

CREATE TABLE sync_checkpoints (
    issuer_device_id BLOB PRIMARY KEY REFERENCES sync_devices(device_id),
    commitment       BLOB NOT NULL UNIQUE CHECK (length(commitment) = 32),
    record           BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 16777216),
    accepted_at_ms   INTEGER NOT NULL CHECK (accepted_at_ms >= 0),
    own              INTEGER NOT NULL CHECK (own IN (0, 1))
) STRICT;

CREATE TABLE sync_rotations (
    collection_id         BLOB PRIMARY KEY REFERENCES collections(collection_id),
    target_epoch          INTEGER NOT NULL CHECK (target_epoch >= 0),
    owner_device_id       BLOB NOT NULL REFERENCES sync_devices(device_id),
    membership_generation INTEGER NOT NULL CHECK (membership_generation >= 0),
    accepted_at_ms        INTEGER NOT NULL CHECK (accepted_at_ms >= 0),
    collection_envelope   BLOB NOT NULL CHECK (length(collection_envelope) = 126),
    completed             INTEGER NOT NULL CHECK (completed IN (0, 1))
) STRICT;

CREATE TABLE sync_object_envelope_epochs (
    object_id           BLOB PRIMARY KEY REFERENCES objects(object_id),
    collection_id       BLOB NOT NULL REFERENCES collections(collection_id),
    collection_epoch    INTEGER NOT NULL CHECK (collection_epoch >= 0),
    envelope_generation INTEGER NOT NULL CHECK (envelope_generation >= 0)
) STRICT;

CREATE UNIQUE INDEX sync_operations_by_id ON sync_operations (operation_id);
CREATE INDEX sync_operations_by_digest ON sync_operations (device_id, digest);
CREATE INDEX sync_membership_by_device
    ON sync_membership_records (device_id, membership_generation);
CREATE INDEX sync_old_epoch_objects
    ON sync_object_envelope_epochs (collection_id, collection_epoch, object_id);
CREATE UNIQUE INDEX sync_active_identity_envelope
    ON sync_identity_envelopes (device_id) WHERE active = 1;
"#;

/// Catalog v3 adds only durable collection-sharing state.
const V3_DDL: &str = r#"
CREATE TABLE sharing_collections (
    collection_id         BLOB PRIMARY KEY CHECK (length(collection_id) = 16),
    source_vault_id       BLOB NOT NULL CHECK (length(source_vault_id) = 16),
    initial_epoch         INTEGER NOT NULL CHECK (initial_epoch >= 1),
    membership_generation INTEGER NOT NULL CHECK (membership_generation >= 0),
    membership_commitment BLOB NOT NULL CHECK (length(membership_commitment) = 32),
    current_epoch         INTEGER NOT NULL CHECK (current_epoch >= initial_epoch)
) STRICT;

CREATE TABLE sharing_membership_records (
    collection_id              BLOB NOT NULL REFERENCES sharing_collections(collection_id),
    membership_generation      INTEGER NOT NULL CHECK (membership_generation >= 1),
    commitment                 BLOB NOT NULL CHECK (length(commitment) = 32),
    issuer_signing_public_key  BLOB NOT NULL CHECK (length(issuer_signing_public_key) = 32),
    recipient_identity_vault_id BLOB NOT NULL CHECK (length(recipient_identity_vault_id) = 16),
    recipient_device_id        BLOB NOT NULL CHECK (length(recipient_device_id) = 16),
    record                     BLOB NOT NULL CHECK (length(record) = 292),
    PRIMARY KEY (collection_id, membership_generation),
    UNIQUE (collection_id, commitment)
) STRICT;

CREATE TABLE sharing_recipient_pins (
    collection_id               BLOB NOT NULL REFERENCES sharing_collections(collection_id),
    recipient_identity_vault_id BLOB NOT NULL CHECK (length(recipient_identity_vault_id) = 16),
    recipient_device_id         BLOB NOT NULL CHECK (length(recipient_device_id) = 16),
    signing_public_key          BLOB NOT NULL CHECK (length(signing_public_key) = 32),
    hpke_public_key             BLOB NOT NULL CHECK (length(hpke_public_key) = 32),
    verification                INTEGER NOT NULL CHECK (verification IN (1, 2)),
    PRIMARY KEY (collection_id, recipient_identity_vault_id, recipient_device_id)
) STRICT;

CREATE TABLE sharing_grants (
    grant_id                    BLOB PRIMARY KEY CHECK (length(grant_id) = 16),
    collection_id               BLOB NOT NULL REFERENCES sharing_collections(collection_id),
    recipient_identity_vault_id BLOB NOT NULL CHECK (length(recipient_identity_vault_id) = 16),
    recipient_device_id         BLOB NOT NULL CHECK (length(recipient_device_id) = 16),
    membership_generation       INTEGER NOT NULL CHECK (membership_generation >= 1),
    collection_epoch            INTEGER NOT NULL CHECK (collection_epoch >= 1),
    record                      BLOB NOT NULL CHECK (length(record) = 309)
) STRICT;

CREATE INDEX sharing_membership_by_recipient
    ON sharing_membership_records (
        collection_id, recipient_identity_vault_id, recipient_device_id, membership_generation
    );
CREATE INDEX sharing_grants_by_collection
    ON sharing_grants (collection_id, membership_generation, collection_epoch, grant_id);
"#;

/// Catalog v4 adds only durable collection-operation streams.
const V4_DDL: &str = r#"
CREATE TABLE sharing_operation_streams (
    key_selector      BLOB PRIMARY KEY CHECK (length(key_selector) = 16),
    collection_id     BLOB NOT NULL REFERENCES sharing_collections(collection_id),
    collection_epoch  INTEGER NOT NULL CHECK (collection_epoch >= 1),
    UNIQUE (collection_id, collection_epoch)
) STRICT;

CREATE TABLE sharing_operations (
    key_selector              BLOB NOT NULL REFERENCES sharing_operation_streams(key_selector),
    issuer_identity_vault_id  BLOB NOT NULL CHECK (length(issuer_identity_vault_id) = 16),
    issuer_device_id          BLOB NOT NULL CHECK (length(issuer_device_id) = 16),
    device_sequence           INTEGER NOT NULL CHECK (device_sequence >= 1),
    operation_id              BLOB NOT NULL CHECK (length(operation_id) = 16),
    digest                    BLOB NOT NULL CHECK (length(digest) = 32),
    record                    BLOB NOT NULL CHECK (length(record) BETWEEN 1 AND 16777216),
    PRIMARY KEY (key_selector, issuer_identity_vault_id, issuer_device_id, device_sequence),
    UNIQUE (key_selector, operation_id)
) STRICT;

CREATE TABLE sharing_operation_forks (
    key_selector              BLOB NOT NULL REFERENCES sharing_operation_streams(key_selector),
    issuer_identity_vault_id  BLOB NOT NULL CHECK (length(issuer_identity_vault_id) = 16),
    issuer_device_id          BLOB NOT NULL CHECK (length(issuer_device_id) = 16),
    state                     INTEGER NOT NULL CHECK (state IN (1, 2)),
    accepted_record           BLOB NOT NULL CHECK (length(accepted_record) BETWEEN 1 AND 16777216),
    conflicting_record        BLOB NOT NULL CHECK (length(conflicting_record) BETWEEN 1 AND 16777216),
    PRIMARY KEY (key_selector, issuer_identity_vault_id, issuer_device_id)
) STRICT;

CREATE INDEX sharing_operations_by_participant
    ON sharing_operations (
        key_selector, issuer_identity_vault_id, issuer_device_id, device_sequence
    );
"#;

/// Catalog v5 adds only the durable grant-acceptance freeze.
///
/// [`COLLECTION_MEMBERSHIP.md`](../../../docs/sync/COLLECTION_MEMBERSHIP.md) §5
/// freezes grant acceptance for a collection whose grant identifier arrives
/// again with different bytes, and a freeze that one reopen forgets protects
/// nobody. The column is client state about a detected security conflict; it
/// carries no canonical meaning and never enters an authenticated record.
const V5_DDL: &str = r#"
ALTER TABLE sharing_collections
    ADD COLUMN grants_frozen INTEGER NOT NULL DEFAULT 0 CHECK (grants_frozen IN (0, 1));
"#;

/// Catalog v6 indexes accepted object operations without storing plaintext.
/// Existing v5 streams stay unindexed until their accepted encrypted records
/// are decrypted and checked after unlock. New empty streams start ready.
const V6_DDL: &str = r#"
ALTER TABLE sharing_operation_streams
    ADD COLUMN object_index_ready INTEGER NOT NULL DEFAULT 0
    CHECK (object_index_ready IN (0, 1));
ALTER TABLE sharing_operation_streams
    ADD COLUMN log_revision INTEGER NOT NULL DEFAULT 0 CHECK (log_revision >= 0);

CREATE TABLE sharing_object_operations (
    key_selector  BLOB NOT NULL REFERENCES sharing_operation_streams(key_selector),
    object_id     BLOB NOT NULL CHECK (length(object_id) = 16),
    operation_id  BLOB NOT NULL CHECK (length(operation_id) = 16),
    kind          INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 6),
    PRIMARY KEY (key_selector, object_id, operation_id),
    UNIQUE (key_selector, operation_id),
    FOREIGN KEY (key_selector, operation_id)
        REFERENCES sharing_operations(key_selector, operation_id)
) STRICT;

CREATE UNIQUE INDEX sharing_object_single_create_commit
    ON sharing_object_operations (key_selector, object_id, kind)
    WHERE kind IN (1, 2);

CREATE TABLE sharing_object_projection (
    key_selector  BLOB NOT NULL REFERENCES sharing_operation_streams(key_selector),
    object_id     BLOB NOT NULL CHECK (length(object_id) = 16),
    revision      INTEGER NOT NULL CHECK (revision >= 1),
    dirty         INTEGER NOT NULL CHECK (dirty IN (0, 1)),
    PRIMARY KEY (key_selector, object_id)
) STRICT;

CREATE INDEX sharing_object_dirty
    ON sharing_object_projection (key_selector, dirty, object_id);
"#;

/// Logical album structure and deterministic manual order. Existing members
/// retain capture-time order until the user rearranges them.
const V7_DDL: &str = r#"
ALTER TABLE albums ADD COLUMN parent_album_id BLOB;
ALTER TABLE albums ADD COLUMN sort_position INTEGER NOT NULL DEFAULT 0;
ALTER TABLE album_memberships ADD COLUMN sort_position INTEGER NOT NULL DEFAULT 0;
CREATE INDEX albums_siblings ON albums(parent_album_id, sort_position, album_id);
CREATE INDEX album_memberships_manual ON album_memberships(album_id, sort_position, object_id);
UPDATE albums SET sort_position = (
    SELECT count(*) FROM albums previous
     WHERE previous.name < albums.name
        OR (previous.name = albums.name AND previous.album_id < albums.album_id)
);
UPDATE album_memberships SET sort_position = (
    SELECT count(*) FROM album_memberships previous
     WHERE previous.album_id = album_memberships.album_id
       AND (previous.capture_time_ms > album_memberships.capture_time_ms
         OR (previous.capture_time_ms = album_memberships.capture_time_ms
           AND previous.object_id > album_memberships.object_id))
);
"#;

const V8_DDL: &str = r#"
CREATE TABLE trash_entries (
    object_id BLOB PRIMARY KEY REFERENCES objects(object_id),
    deleted_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL
) STRICT;
CREATE INDEX trash_entries_expiry ON trash_entries(expires_ms, object_id);
CREATE INDEX trash_entries_recent ON trash_entries(deleted_ms DESC, object_id DESC);
"#;

/// Private local notes; these tables are never part of media synchronization.
const V9_DDL: &str = r#"
CREATE TABLE private_notes (
 note_id BLOB NOT NULL UNIQUE CHECK(length(note_id)=16),
 revision INTEGER NOT NULL CHECK(revision>0),
 title TEXT NOT NULL CHECK(length(CAST(title AS BLOB))<=256),
 body TEXT NOT NULL CHECK(length(CAST(body AS BLOB))<=262144),
 created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL,
 pinned INTEGER NOT NULL CHECK(pinned IN (0,1)),
 deleted_ms INTEGER, expires_ms INTEGER,
 CHECK((deleted_ms IS NULL)=(expires_ms IS NULL))
) STRICT;
CREATE INDEX private_notes_order ON private_notes(pinned DESC,updated_ms DESC,note_id DESC);
CREATE INDEX private_notes_expiry ON private_notes(expires_ms);
CREATE VIRTUAL TABLE private_note_search USING fts5(title,body,tokenize='unicode61');
INSERT INTO private_note_search(private_note_search,rank) VALUES('secure-delete',1);
"#;

/// Local derived text and a combined metadata/content FTS index, all SQLCipher pages.
const V10_DDL: &str = r#"
CREATE TABLE content_index (
 object_id BLOB PRIMARY KEY REFERENCES objects(object_id) CHECK(length(object_id)=16),
 primary_stream_id BLOB NOT NULL CHECK(length(primary_stream_id)=16),
 engine_version INTEGER NOT NULL CHECK(engine_version=1),
 status INTEGER NOT NULL CHECK(status IN (1,2)),
 body TEXT NOT NULL CHECK(length(CAST(body AS BLOB))<=262144)
) STRICT;
DROP TABLE object_search;
CREATE VIRTUAL TABLE object_search USING fts5(
 filename,caption,tag_names,content_body,
 content='',contentless_delete=1,tokenize='unicode61 remove_diacritics 2',prefix='2 3'
);
INSERT INTO object_search(object_search,rank) VALUES('secure-delete',1);
INSERT INTO object_search(rowid,filename,caption,tag_names,content_body)
 SELECT o.search_key,COALESCE(m.original_filename,''),COALESCE(m.caption,''),
 COALESCE((SELECT group_concat(t.name,' ') FROM object_tags ot JOIN tags t ON t.tag_id=ot.tag_id WHERE ot.object_id=o.object_id),''),''
 FROM objects o JOIN metadata_revisions m ON m.object_id=o.object_id AND m.active=1 WHERE o.state=1;
"#;

/// Durable local additions that have not yet entered the signed operation log.
const V11_DDL: &str = r#"
CREATE TABLE own_sync_pending_album_memberships (
    album_id BLOB NOT NULL REFERENCES albums(album_id) ON DELETE CASCADE
        CHECK(length(album_id) = 16),
    object_id BLOB NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE
        CHECK(length(object_id) = 16),
    PRIMARY KEY (album_id, object_id)
) STRICT;
CREATE INDEX own_sync_pending_album_memberships_object
    ON own_sync_pending_album_memberships(object_id, album_id);
INSERT INTO own_sync_pending_album_memberships(album_id, object_id)
    SELECT album_id, object_id FROM album_memberships;
"#;

/// Explicit body interpretation; all existing notes remain literal text.
const V12_DDL: &str = "ALTER TABLE private_notes ADD COLUMN format INTEGER NOT NULL DEFAULT 0 CHECK(format IN (0,1));";

/// Note-owned attachments never leave the SQLCipher catalog except explicit exports.
const V13_DDL: &str = r#"
CREATE TABLE private_note_attachments (
 note_id BLOB NOT NULL REFERENCES private_notes(note_id) ON DELETE CASCADE CHECK(length(note_id)=16),
 attachment_id BLOB NOT NULL CHECK(length(attachment_id)=16),
 name TEXT NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 240),
 mime_type TEXT NOT NULL CHECK(mime_type IN ('image/png','image/jpeg','image/gif','image/webp','application/pdf','application/octet-stream')),
 data BLOB NOT NULL CHECK(length(data)<=8388608),
 PRIMARY KEY(note_id,attachment_id)
) STRICT;
"#;
/// Organization and bounded historical snapshots live entirely inside SQLCipher.
const V14_DDL: &str = r#"
CREATE TABLE private_note_organization (
 note_id BLOB PRIMARY KEY REFERENCES private_notes(note_id) ON DELETE CASCADE,
 folder TEXT NOT NULL CHECK(length(CAST(folder AS BLOB))<=64),
 tags TEXT NOT NULL CHECK(length(CAST(tags AS BLOB))<=4096)
) STRICT;
CREATE TABLE private_note_history (
 note_id BLOB NOT NULL REFERENCES private_notes(note_id) ON DELETE CASCADE,
 revision INTEGER NOT NULL CHECK(revision>0),
 title TEXT NOT NULL CHECK(length(CAST(title AS BLOB))<=256),
 body TEXT NOT NULL CHECK(length(CAST(body AS BLOB))<=262144),
 format INTEGER NOT NULL CHECK(format IN (0,1)),
 updated_ms INTEGER NOT NULL CHECK(updated_ms>=0),
 pinned INTEGER NOT NULL CHECK(pinned IN (0,1)),
 folder TEXT NOT NULL CHECK(length(CAST(folder AS BLOB))<=64),
 tags TEXT NOT NULL CHECK(length(CAST(tags AS BLOB))<=4096),
 PRIMARY KEY(note_id,revision)
) STRICT;
CREATE TABLE private_note_history_blobs (
 note_id BLOB NOT NULL REFERENCES private_notes(note_id) ON DELETE CASCADE,
 blob_id BLOB NOT NULL CHECK(length(blob_id)=16),
 data BLOB NOT NULL CHECK(length(data)<=8388608),
 PRIMARY KEY(note_id,blob_id)
) STRICT;
CREATE TABLE private_note_history_files (
 note_id BLOB NOT NULL,
 revision INTEGER NOT NULL,
 attachment_id BLOB NOT NULL CHECK(length(attachment_id)=16),
 name TEXT NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 240),
 mime_type TEXT NOT NULL,
 blob_id BLOB NOT NULL,
 PRIMARY KEY(note_id,revision,attachment_id),
 FOREIGN KEY(note_id,revision) REFERENCES private_note_history(note_id,revision) ON DELETE CASCADE,
 FOREIGN KEY(note_id,blob_id) REFERENCES private_note_history_blobs(note_id,blob_id)
) STRICT;
"#;
/// Atomically adds organization and historical recovery after descriptor authentication.
pub fn migrate_v13_to_v14(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V13),
        MigrationRequired,
        "the catalog is not version thirteen"
    );
    db.transaction(|tx| {
  tx.execute("UPDATE vault_state SET active_migration_target=14 WHERE only_row=1",[]).map_err(|e|map_sqlite(e,"the note workspace migration target could not be written"))?;
  tx.execute_batch(V14_DDL).map_err(|e|map_sqlite(e,"the note workspace migration failed"))?;
  tx.execute("UPDATE vault_state SET catalog_format_version=14,active_migration_target=NULL WHERE only_row=1",[]).map_err(|e|map_sqlite(e,"the note workspace version could not be written"))?;
  Ok(())
 })
}

/// Adds bounded encrypted attachment storage after the authenticated descriptor transition.
pub fn migrate_v12_to_v13(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V12),
        MigrationRequired,
        "the catalog is not version twelve"
    );
    db.transaction(|tx| {
 tx.execute("UPDATE vault_state SET active_migration_target=13 WHERE only_row=1",[]).map_err(|e|map_sqlite(e,"the attachment migration target could not be written"))?;
 tx.execute_batch(V13_DDL).map_err(|e|map_sqlite(e,"the attachment schema migration failed"))?;
 tx.execute("UPDATE vault_state SET catalog_format_version=13,active_migration_target=NULL WHERE only_row=1",[]).map_err(|e|map_sqlite(e,"the attachment schema version could not be written"))?; Ok(())
 })
}

/// Adds the body discriminator after an authenticated v11 transition.
pub fn migrate_v11_to_v12(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V11),
        MigrationRequired,
        "the catalog is not version eleven"
    );
    db.transaction(|tx| {
        tx.execute("UPDATE vault_state SET active_migration_target=12 WHERE only_row=1", []).map_err(|e| map_sqlite(e, "the note format migration target could not be written"))?;
        tx.execute_batch(V12_DDL).map_err(|e| map_sqlite(e, "the note format migration failed"))?;
        tx.execute("UPDATE vault_state SET catalog_format_version=12,active_migration_target=NULL WHERE only_row=1", []).map_err(|e| map_sqlite(e, "the note format catalog version could not be written"))?;
        Ok(())
    })
}

/// Retains the existing album snapshot after an authenticated v10 transition.
///
/// # Errors
///
/// Returns `MigrationRequired` if the catalog is not v10. Database errors roll
/// back the table, pending additions, and recorded version together.
pub fn migrate_v10_to_v11(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V10),
        MigrationRequired,
        "the catalog is not version ten"
    );
    db.transaction(|transaction| {
        transaction.execute(
            "UPDATE vault_state SET active_migration_target = ?1 WHERE only_row = 1",
            [i64::from(CATALOG_FORMAT_VERSION_V11)],
        ).map_err(|error| map_sqlite(error, "the album intent migration target could not be written"))?;
        transaction.execute_batch(V11_DDL)
            .map_err(|error| map_sqlite(error, "the album intent migration failed"))?;
        transaction.execute(
            "UPDATE vault_state SET catalog_format_version = ?1, active_migration_target = NULL WHERE only_row = 1",
            [i64::from(CATALOG_FORMAT_VERSION_V11)],
        ).map_err(|error| map_sqlite(error, "the album intent catalog version could not be written"))?;
        Ok(())
    })
}

/// Adds encrypted local content search after the authenticated v9 transition.
pub fn migrate_v9_to_v10(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V9),
        MigrationRequired,
        "the catalog is not version nine"
    );
    db.transaction(|tx| {
        tx.execute(
            "UPDATE vault_state SET active_migration_target=10 WHERE only_row=1", [],
        ).map_err(|error|map_sqlite(error,"the content migration target could not be written"))?;
        tx.execute_batch(V10_DDL)
            .map_err(|error|map_sqlite(error,"the content index migration failed"))?;
        tx.execute(
            "UPDATE vault_state SET catalog_format_version=10,active_migration_target=NULL WHERE only_row=1", [],
        ).map_err(|error|map_sqlite(error,"the content catalog version could not be written"))?;
        Ok(())
    })
}

/// Removes obsolete network enrollment state while preserving vault data and device membership.
/// An authenticated migration is required; old approval payloads are intentionally invalidated.
pub fn migrate_v14_to_v15(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V14),
        MigrationRequired,
        "the catalog is not version fourteen"
    );
    db.transaction(|tx| {
        tx.execute_batch("DELETE FROM device_pairing_pending;
            DROP TABLE device_pairing_approvals;
            CREATE TABLE device_pairing_approvals (
                request_id BLOB PRIMARY KEY, request BLOB NOT NULL, checkpoint BLOB NOT NULL,
                enrollment BLOB NOT NULL, operation BLOB NOT NULL, approval BLOB NOT NULL
            ) STRICT;
            UPDATE vault_state SET catalog_format_version = 15, active_migration_target = NULL WHERE only_row = 1;")
            .map_err(|error| map_sqlite(error, "peer-only catalog migration failed"))?;
        Ok(())
    })
}

/// Records support for compatible-video streams without rewriting media or catalog rows.
pub fn migrate_v15_to_v16(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V15),
        MigrationRequired,
        "the catalog is not version fifteen"
    );
    db.transaction(|tx| {
        tx.execute_batch(
            "UPDATE vault_state SET active_migration_target = 16 WHERE only_row = 1;
             UPDATE vault_state SET catalog_format_version = 16, active_migration_target = NULL WHERE only_row = 1;",
        )
        .map_err(|error| map_sqlite(error, "the compatible-video catalog capability could not be recorded"))?;
        Ok(())
    })
}

const V17_DDL: &str = r#"
CREATE TABLE playback_positions (
    object_id                BLOB PRIMARY KEY REFERENCES objects(object_id) ON DELETE CASCADE,
    object_generation        INTEGER NOT NULL CHECK (object_generation >= 1),
    source_content_revision  INTEGER NOT NULL CHECK (source_content_revision >= 1),
    position_ms              INTEGER NOT NULL CHECK (position_ms >= 0),
    duration_ms              INTEGER NOT NULL CHECK (duration_ms BETWEEN 1 AND 14400000),
    CHECK (position_ms <= duration_ms)
) STRICT;
"#;

/// Adds local encrypted resume positions after descriptor authentication.
pub fn migrate_v16_to_v17(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V16),
        MigrationRequired,
        "the catalog is not version sixteen"
    );
    db.transaction(|tx| {
        tx.execute("UPDATE vault_state SET active_migration_target = 17 WHERE only_row = 1", [])
            .map_err(|error| map_sqlite(error, "the playback migration target could not be written"))?;
        tx.execute_batch(V17_DDL).map_err(|error| map_sqlite(error, "the playback position schema could not be created"))?;
        tx.execute("UPDATE vault_state SET catalog_format_version = 17, active_migration_target = NULL WHERE only_row = 1", [])
            .map_err(|error| map_sqlite(error, "the playback position schema version could not be written"))?;
        Ok(())
    })
}

const V18_DDL: &str = r#"
-- CATALOG_SCHEMA_V18.md: the trusted-time high-water mark. No row until the
-- first retention sweep initializes it from the device clock.
CREATE TABLE trusted_time (
    only_row    INTEGER PRIMARY KEY CHECK (only_row = 1),
    trusted_ms  INTEGER NOT NULL CHECK (trusted_ms >= 0)
) STRICT;
"#;

/// Adds the persisted trusted-time mark after descriptor authentication.
pub fn migrate_v17_to_v18(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V17),
        MigrationRequired,
        "the catalog is not version seventeen"
    );
    db.transaction(|tx| {
        tx.execute("UPDATE vault_state SET active_migration_target = 18 WHERE only_row = 1", [])
            .map_err(|error| map_sqlite(error, "the trusted-time migration target could not be written"))?;
        tx.execute_batch(V18_DDL).map_err(|error| map_sqlite(error, "the trusted-time schema could not be created"))?;
        tx.execute("UPDATE vault_state SET catalog_format_version = 18, active_migration_target = NULL WHERE only_row = 1", [])
            .map_err(|error| map_sqlite(error, "the trusted-time schema version could not be written"))?;
        Ok(())
    })
}

/// Creates the current schema or opens it without performing an implicit migration.
///
/// `docs/format/CATALOG_SCHEMA_V1.md` §18 forbids skipping an untested step, so
/// Existing v1 catalogs return `MigrationRequired`: the authenticated vault
/// descriptor must enter `MIGRATING` before their pages change.
pub fn open_at_current_version(db: &mut CatalogDb, now_ms: u64) -> Result<u16> {
    let present = recorded_version(db.connection())?;
    let Some(present) = present else {
        install(db, now_ms)?;
        return Ok(CATALOG_FORMAT_VERSION_V18);
    };
    if present != CATALOG_FORMAT_VERSION_V18 {
        bail!(
            MigrationRequired,
            "the catalog requires an authenticated schema migration"
        );
    }
    Ok(CATALOG_FORMAT_VERSION_V18)
}

/// The version the database records, or `None` when the schema is absent.
pub(crate) fn recorded_version(connection: &Connection) -> Result<Option<u16>> {
    let present: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'vault_state'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the catalog schema could not be read"))?;
    if present == 0 {
        return Ok(None);
    }
    let version: i64 = connection
        .query_row(
            "SELECT catalog_format_version FROM vault_state WHERE only_row = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the catalog format version could not be read"))?;
    u16::try_from(version)
        .map(Some)
        .map_err(|_| err!(CatalogCorrupt, "the catalog format version is out of range"))
}

/// Installs the current schema and its single `vault_state` row.
fn install(db: &mut CatalogDb, now_ms: u64) -> Result<()> {
    install_export_version(db, CATALOG_FORMAT_VERSION_V18, now_ms)
}

/// Installs the exact known schema declared by a portable catalog export.
/// Restore performs authenticated migrations only after it verifies these rows.
pub(crate) fn install_export_version(db: &mut CatalogDb, version: u16, now_ms: u64) -> Result<()> {
    ensure!(
        matches!(
            version,
            CATALOG_FORMAT_VERSION_V15
                | CATALOG_FORMAT_VERSION_V16
                | CATALOG_FORMAT_VERSION_V17
                | CATALOG_FORMAT_VERSION_V18
        ),
        UnsupportedVersion,
        "the portable catalog schema is unsupported"
    );
    let checkpoint = as_sqlite_integer(now_ms, "the install time is out of range")?;
    db.transaction(|transaction| {
        transaction
            .execute_batch(V1_DDL)
            .map_err(|error| map_sqlite(error, "the catalog schema could not be created"))?;
        transaction
            .execute_batch(V2_DDL)
            .map_err(|error| map_sqlite(error, "the sync catalog schema could not be created"))?;
        transaction.execute_batch(V3_DDL).map_err(|error| {
            map_sqlite(error, "the sharing catalog schema could not be created")
        })?;
        transaction.execute_batch(V4_DDL).map_err(|error| {
            map_sqlite(
                error,
                "the collection operation catalog schema could not be created",
            )
        })?;
        transaction
            .execute_batch(V5_DDL)
            .map_err(|error| map_sqlite(error, "the grant freeze schema could not be created"))?;
        transaction.execute_batch(V6_DDL).map_err(|error| {
            map_sqlite(error, "the shared-object index schema could not be created")
        })?;
        transaction.execute_batch(V7_DDL).map_err(|error| {
            map_sqlite(error, "the album organization schema could not be created")
        })?;
        transaction
            .execute_batch(V8_DDL)
            .map_err(|error| map_sqlite(error, "the trash schema could not be created"))?;
        transaction
            .execute_batch(V9_DDL)
            .map_err(|error| map_sqlite(error, "the private notes schema could not be created"))?;
        transaction
            .execute_batch(V10_DDL)
            .map_err(|e| map_sqlite(e, "the content index schema could not be created"))?;
        transaction
            .execute_batch(V11_DDL)
            .map_err(|error| map_sqlite(error, "the album intent schema could not be created"))?;
        transaction
            .execute_batch(V12_DDL)
            .map_err(|e| map_sqlite(e, "the note format schema could not be created"))?;
        transaction
            .execute_batch(V13_DDL)
            .map_err(|e| map_sqlite(e, "the attachment schema could not be created"))?;
        transaction
            .execute_batch(V14_DDL)
            .map_err(|e| map_sqlite(e, "the note workspace schema could not be created"))?;
        if version >= CATALOG_FORMAT_VERSION_V17 {
            transaction.execute_batch(V17_DDL).map_err(|error| {
                map_sqlite(error, "the playback position schema could not be created")
            })?;
        }
        if version >= CATALOG_FORMAT_VERSION_V18 {
            transaction.execute_batch(V18_DDL).map_err(|error| {
                map_sqlite(error, "the trusted-time schema could not be created")
            })?;
        }
        transaction
            .execute(
                "INSERT INTO vault_state (
                     only_row, catalog_format_version, catalog_generation,
                     active_migration_target, object_store_checkpoint,
                     integrity_checkpoint_ms, capability_flags
                 ) VALUES (1, ?1, 1, NULL, 0, ?2, 0)",
                rusqlite::params![i64::from(version), checkpoint],
            )
            .map_err(|error| map_sqlite(error, "the catalog state row could not be written"))?;
        Ok(())
    })
}

/// Adds private local notes after an authenticated v8 descriptor transition.
pub fn migrate_v8_to_v9(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V8),
        MigrationRequired,
        "the catalog is not version eight"
    );
    db.transaction(|tx| {
        tx.execute("UPDATE vault_state SET active_migration_target=?1 WHERE only_row=1", [i64::from(CATALOG_FORMAT_VERSION_V9)]).map_err(|error|map_sqlite(error,"the note migration target could not be written"))?;
        tx.execute_batch(V9_DDL).map_err(|error| map_sqlite(error, "the private notes migration failed"))?;
        tx.execute("UPDATE vault_state SET catalog_format_version=?1,active_migration_target=NULL WHERE only_row=1", [i64::from(CATALOG_FORMAT_VERSION_V9)])
          .map_err(|error| map_sqlite(error,"the catalog version could not be written"))?;
        Ok(())
    })
}

#[cfg(test)]
const RESET_V7_DDL: &str = "
DROP TABLE IF EXISTS trusted_time;
DROP TABLE IF EXISTS playback_positions;
DROP TABLE IF EXISTS own_sync_pending_album_memberships;
DROP TABLE IF EXISTS content_index;
DROP TABLE IF EXISTS private_note_search;
DROP TABLE IF EXISTS private_note_history_files;
DROP TABLE IF EXISTS private_note_history_blobs;
DROP TABLE IF EXISTS private_note_history;
DROP TABLE IF EXISTS private_note_organization;
DROP TABLE IF EXISTS private_note_attachments;
DROP TABLE IF EXISTS private_notes;
DROP TABLE trash_entries;
DROP INDEX albums_siblings;
DROP INDEX album_memberships_manual;
ALTER TABLE album_memberships DROP COLUMN sort_position;
ALTER TABLE albums DROP COLUMN sort_position;
ALTER TABLE albums DROP COLUMN parent_album_id;
";

#[cfg(test)]
pub(crate) fn reset_to_v1(db: &mut CatalogDb) -> Result<()> {
    db.transaction(|transaction| {
        transaction
            .execute_batch(RESET_V7_DDL)
            .map_err(|error| map_sqlite(error, "the v7 test columns could not be removed"))?;
        transaction
            .execute_batch(
                "DROP TABLE sharing_object_projection;
                 DROP TABLE sharing_object_operations;
                 DROP TABLE sharing_operation_forks;
                 DROP TABLE sharing_operations;
                 DROP TABLE sharing_operation_streams;
                 DROP TABLE sharing_grants;
                 DROP TABLE sharing_recipient_pins;
                 DROP TABLE sharing_membership_records;
                 DROP TABLE sharing_collections;
                 DROP TABLE sync_rotations;
                 DROP TABLE sync_object_envelope_epochs;
                 DROP TABLE sync_checkpoints;
                 DROP TABLE sync_forks;
                 DROP TABLE sync_heads;
                 DROP TABLE sync_operations;
                 DROP TABLE sync_identity_envelopes;
                 DROP TABLE sync_signing_keys;
                 DROP TABLE sync_devices;
                 DROP TABLE sync_membership_records;
                 DROP TABLE sync_state;
                 UPDATE vault_state SET catalog_format_version = 1 WHERE only_row = 1;",
            )
            .map_err(|error| map_sqlite(error, "the test catalog could not be reset to v1"))?;
        Ok(())
    })
}

#[cfg(test)]
pub(crate) fn reset_to_v2(db: &mut CatalogDb) -> Result<()> {
    db.transaction(|transaction| {
        transaction
            .execute_batch(RESET_V7_DDL)
            .map_err(|error| map_sqlite(error, "the v7 test columns could not be removed"))?;
        transaction
            .execute_batch(
                "DROP TABLE sharing_object_projection;
                 DROP TABLE sharing_object_operations;
                 DROP TABLE sharing_operation_forks;
                 DROP TABLE sharing_operations;
                 DROP TABLE sharing_operation_streams;
                 DROP TABLE sharing_grants;
                 DROP TABLE sharing_recipient_pins;
                 DROP TABLE sharing_membership_records;
                 DROP TABLE sharing_collections;
                 UPDATE vault_state SET catalog_format_version = 2 WHERE only_row = 1;",
            )
            .map_err(|error| map_sqlite(error, "the test catalog could not be reset to v2"))?;
        Ok(())
    })
}

#[cfg(test)]
pub(crate) fn reset_to_v3(db: &mut CatalogDb) -> Result<()> {
    db.transaction(|transaction| {
        transaction
            .execute_batch(RESET_V7_DDL)
            .map_err(|error| map_sqlite(error, "the v7 test columns could not be removed"))?;
        transaction
            .execute_batch(
                "DROP TABLE sharing_object_projection;
                 DROP TABLE sharing_object_operations;
                 DROP TABLE sharing_operation_forks;
                 DROP TABLE sharing_operations;
                 DROP TABLE sharing_operation_streams;
                 DROP TABLE sharing_grants;
                 DROP TABLE sharing_recipient_pins;
                 DROP TABLE sharing_membership_records;
                 DROP TABLE sharing_collections;
                 UPDATE vault_state SET catalog_format_version = 3 WHERE only_row = 1;",
            )
            .map_err(|error| map_sqlite(error, "the test catalog could not be reset to v3"))?;
        // The v3 sharing tables come back in their canonical shape, without
        // anything a later version added.
        transaction
            .execute_batch(V3_DDL)
            .map_err(|error| map_sqlite(error, "the v3 sharing state could not be rebuilt"))?;
        Ok(())
    })
}

/// Applies the only supported migration after the descriptor entered `MIGRATING`.
///
/// The version is written in the same transaction as the step's statements, so
/// a crash leaves the database at the version whose schema is actually present.
pub(crate) fn migrate_v1_to_v2(db: &mut CatalogDb, vault_id: &Id) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V1),
        MigrationRequired,
        "the catalog is not at the supported migration source"
    );
    db.transaction(|transaction| {
        transaction
            .execute(
                "UPDATE vault_state SET active_migration_target = ?1 WHERE only_row = 1",
                [i64::from(CATALOG_FORMAT_VERSION_V2)],
            )
            .map_err(|error| map_sqlite(error, "the migration target could not be recorded"))?;
        transaction
            .execute_batch(V2_DDL)
            .map_err(|error| map_sqlite(error, "a migration step failed"))?;
        backfill_object_envelope_epochs(transaction, vault_id)?;
        transaction
            .execute(
                "UPDATE vault_state
                    SET catalog_format_version = ?1, active_migration_target = NULL
                  WHERE only_row = 1",
                [i64::from(CATALOG_FORMAT_VERSION_V2)],
            )
            .map_err(|error| map_sqlite(error, "the migrated version could not be recorded"))?;
        Ok(())
    })
}

/// Applies the v2-to-v3 sharing-state migration after the descriptor entered
/// `MIGRATING`.
pub(crate) fn migrate_v2_to_v3(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V2),
        MigrationRequired,
        "the catalog is not at the supported migration source"
    );
    db.transaction(|transaction| {
        transaction
            .execute(
                "UPDATE vault_state SET active_migration_target = ?1 WHERE only_row = 1",
                [i64::from(CATALOG_FORMAT_VERSION_V3)],
            )
            .map_err(|error| map_sqlite(error, "the migration target could not be recorded"))?;
        transaction
            .execute_batch(V3_DDL)
            .map_err(|error| map_sqlite(error, "a migration step failed"))?;
        transaction
            .execute(
                "UPDATE vault_state
                    SET catalog_format_version = ?1, active_migration_target = NULL
                  WHERE only_row = 1",
                [i64::from(CATALOG_FORMAT_VERSION_V3)],
            )
            .map_err(|error| map_sqlite(error, "the migrated version could not be recorded"))?;
        Ok(())
    })
}

/// Applies the v3-to-v4 collection-operation migration after the descriptor
/// entered `MIGRATING`.
pub(crate) fn migrate_v3_to_v4(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V3),
        MigrationRequired,
        "the catalog is not at the supported migration source"
    );
    db.transaction(|transaction| {
        transaction
            .execute(
                "UPDATE vault_state SET active_migration_target = ?1 WHERE only_row = 1",
                [i64::from(CATALOG_FORMAT_VERSION_V4)],
            )
            .map_err(|error| map_sqlite(error, "the migration target could not be recorded"))?;
        transaction
            .execute_batch(V4_DDL)
            .map_err(|error| map_sqlite(error, "a migration step failed"))?;
        transaction
            .execute(
                "UPDATE vault_state
                    SET catalog_format_version = ?1, active_migration_target = NULL
                  WHERE only_row = 1",
                [i64::from(CATALOG_FORMAT_VERSION_V4)],
            )
            .map_err(|error| map_sqlite(error, "the migrated version could not be recorded"))?;
        Ok(())
    })
}

pub(crate) fn migrate_v4_to_v5(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V4),
        MigrationRequired,
        "the catalog is not at the supported migration source"
    );
    db.transaction(|transaction| {
        transaction
            .execute(
                "UPDATE vault_state SET active_migration_target = ?1 WHERE only_row = 1",
                [i64::from(CATALOG_FORMAT_VERSION_V5)],
            )
            .map_err(|error| map_sqlite(error, "the migration target could not be recorded"))?;
        transaction
            .execute_batch(V5_DDL)
            .map_err(|error| map_sqlite(error, "a migration step failed"))?;
        transaction
            .execute(
                "UPDATE vault_state
                    SET catalog_format_version = ?1, active_migration_target = NULL
                  WHERE only_row = 1",
                [i64::from(CATALOG_FORMAT_VERSION_V5)],
            )
            .map_err(|error| map_sqlite(error, "the migrated version could not be recorded"))?;
        Ok(())
    })
}

/// Adds the protected object-operation index. Old accepted streams are
/// backfilled after unlock, when their collection keys are available.
pub(crate) fn migrate_v5_to_v6(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V5),
        MigrationRequired,
        "the catalog is not at the supported migration source"
    );
    db.transaction(|transaction| {
        transaction
            .execute(
                "UPDATE vault_state SET active_migration_target = ?1 WHERE only_row = 1",
                [i64::from(CATALOG_FORMAT_VERSION_V6)],
            )
            .map_err(|error| map_sqlite(error, "the migration target could not be recorded"))?;
        transaction
            .execute_batch(V6_DDL)
            .map_err(|error| map_sqlite(error, "a migration step failed"))?;
        transaction
            .execute(
                "UPDATE vault_state
                    SET catalog_format_version = ?1, active_migration_target = NULL
                  WHERE only_row = 1",
                [i64::from(CATALOG_FORMAT_VERSION_V6)],
            )
            .map_err(|error| map_sqlite(error, "the migrated version could not be recorded"))?;
        Ok(())
    })
}

/// Adds album hierarchy and ordering under the authenticated migration gate.
pub(crate) fn migrate_v6_to_v7(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V6),
        MigrationRequired,
        "the catalog is not at the supported migration source"
    );
    db.transaction(|transaction| {
        transaction
            .execute(
                "UPDATE vault_state SET active_migration_target = ?1 WHERE only_row = 1",
                [i64::from(CATALOG_FORMAT_VERSION_V7)],
            )
            .map_err(|error| map_sqlite(error, "the migration target could not be recorded"))?;
        transaction
            .execute_batch(V7_DDL)
            .map_err(|error| map_sqlite(error, "the album organization migration failed"))?;
        transaction
            .execute(
                "UPDATE vault_state SET catalog_format_version = ?1,
                active_migration_target = NULL WHERE only_row = 1",
                [i64::from(CATALOG_FORMAT_VERSION_V7)],
            )
            .map_err(|error| map_sqlite(error, "the migrated version could not be recorded"))?;
        Ok(())
    })
}

/// Adds the recoverable trash under the authenticated migration gate.
pub(crate) fn migrate_v7_to_v8(db: &mut CatalogDb) -> Result<()> {
    ensure!(
        recorded_version(db.connection())? == Some(CATALOG_FORMAT_VERSION_V7),
        MigrationRequired,
        "the catalog is not at the supported migration source"
    );
    db.transaction(|transaction| {
        transaction.execute(
            "UPDATE vault_state SET active_migration_target = ?1 WHERE only_row = 1",
            [i64::from(CATALOG_FORMAT_VERSION_V8)],
        ).map_err(|error| map_sqlite(error, "the migration target could not be recorded"))?;
        transaction.execute_batch(V8_DDL)
            .map_err(|error| map_sqlite(error, "the trash migration failed"))?;
        transaction.execute(
            "UPDATE vault_state SET catalog_format_version = ?1, active_migration_target = NULL WHERE only_row = 1",
            [i64::from(CATALOG_FORMAT_VERSION_V8)],
        ).map_err(|error| map_sqlite(error, "the migrated version could not be recorded"))?;
        Ok(())
    })
}

fn backfill_object_envelope_epochs(
    transaction: &rusqlite::Transaction<'_>,
    vault_id: &Id,
) -> Result<()> {
    let mut select = transaction
        .prepare(
            "SELECT e.object_id, o.collection_id, e.generation, e.body
               FROM object_key_envelopes e
               JOIN objects o ON o.object_id = e.object_id
              WHERE e.status = 1
                AND e.generation = (
                    SELECT max(candidate.generation)
                      FROM object_key_envelopes candidate
                     WHERE candidate.object_id = e.object_id AND candidate.status = 1
                )",
        )
        .map_err(|error| map_sqlite(error, "active object envelopes could not be read"))?;
    let mut rows = select
        .query([])
        .map_err(|error| map_sqlite(error, "active object envelopes could not be read"))?;
    while let Some(row) = rows
        .next()
        .map_err(|error| map_sqlite(error, "an active object envelope could not be read"))?
    {
        let object_bytes: Vec<u8> = row
            .get(0)
            .map_err(|error| map_sqlite(error, "an object id could not be read"))?;
        let collection_bytes: Vec<u8> = row
            .get(1)
            .map_err(|error| map_sqlite(error, "a collection id could not be read"))?;
        let generation: i64 = row
            .get(2)
            .map_err(|error| map_sqlite(error, "an envelope generation could not be read"))?;
        let body: Vec<u8> = row
            .get(3)
            .map_err(|error| map_sqlite(error, "an object envelope could not be read"))?;
        let object_id = crate::row::id(&object_bytes, "an object id is malformed")?;
        let collection_id = crate::row::id(&collection_bytes, "a collection id is malformed")?;
        let generation = from_sqlite_integer(generation, "an envelope generation is negative")?;
        let envelope = ObjectKeyEnvelope::decode(&body)
            .map_err(|_| err!(CatalogCorrupt, "an active object envelope is malformed"))?;
        ensure!(
            envelope.vault_id() == vault_id
                && envelope.object_id() == &object_id
                && envelope.collection_id() == &collection_id
                && envelope.envelope_generation() == generation,
            CatalogCorrupt,
            "an active object envelope contradicts its catalog row"
        );
        transaction
            .execute(
                "INSERT INTO sync_object_envelope_epochs
                    (object_id, collection_id, collection_epoch, envelope_generation)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    object_id.as_bytes().as_slice(),
                    collection_id.as_bytes().as_slice(),
                    as_sqlite_integer(
                        envelope.collection_epoch(),
                        "an envelope collection epoch is too large"
                    )?,
                    as_sqlite_integer(generation, "an envelope generation is too large")?,
                ],
            )
            .map_err(|error| map_sqlite(error, "an envelope epoch could not be projected"))?;
    }
    Ok(())
}

/// The catalog generation, which every query page reports so a caller can tell
/// that its cursor crossed a write.
pub fn generation(db: &CatalogDb) -> Result<u64> {
    let value: i64 = db
        .connection()
        .query_row(
            "SELECT catalog_generation FROM vault_state WHERE only_row = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite(error, "the catalog generation could not be read"))?;
    from_sqlite_integer(value, "the catalog generation is negative")
}

/// Advances the catalog generation inside a transaction that already changed a
/// row a query page can return.
pub fn bump_generation(transaction: &rusqlite::Transaction<'_>) -> Result<()> {
    transaction
        .execute(
            "UPDATE vault_state SET catalog_generation = catalog_generation + 1 WHERE only_row = 1",
            [],
        )
        .map_err(|error| map_sqlite(error, "the catalog generation could not be advanced"))?;
    Ok(())
}

/// Rejects a page `limit` outside the bounds of §16.2.
pub fn check_query_limit(limit: u32) -> Result<u32> {
    if limit == 0 {
        return Ok(limits::QUERY_LIMIT_DEFAULT);
    }
    if !(limits::QUERY_LIMIT_MIN..=limits::QUERY_LIMIT_MAX).contains(&limit) {
        bail!(ResourceLimitExceeded, "the page limit is outside §16.2");
    }
    Ok(limit)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

    use rusqlite::OptionalExtension;

    use super::*;
    use crate::db::{CatalogKey, CatalogLocation};
    use chur_crypto::{Key, Nonce, random};
    use chur_format::envelope::ObjectKeyEnvelope;

    fn open() -> CatalogDb {
        let root: Key = random::secret::<32>().expect("root");
        let vault = random::id().expect("id");
        let key = CatalogKey::derive(&root, &vault).expect("key");
        CatalogDb::open(&CatalogLocation::Memory, &key).expect("open")
    }

    fn install_v1(db: &mut CatalogDb) {
        db.transaction(|transaction| {
            transaction.execute_batch(V1_DDL).expect("v1 schema");
            transaction
                .execute(
                    "INSERT INTO vault_state (
                         only_row, catalog_format_version, catalog_generation,
                         active_migration_target, object_store_checkpoint,
                         integrity_checkpoint_ms, capability_flags
                     ) VALUES (1, 1, 1, NULL, 0, 1, 0)",
                    [],
                )
                .expect("v1 state");
            Ok(())
        })
        .expect("install v1");
    }

    fn v10_with_album_memberships() -> CatalogDb {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("current schema");
        db.connection().execute_batch(
            "DROP TABLE own_sync_pending_album_memberships;
             UPDATE vault_state SET catalog_format_version = 10;
             INSERT INTO collections VALUES (zeroblob(16), 1, 1, 1, 1);
             INSERT INTO albums (album_id,name,created_ms,revision) VALUES
                 (x'01010101010101010101010101010101','First',1,1),
                 (x'02020202020202020202020202020202','Second',1,1);
             INSERT INTO objects VALUES
                 (x'03030303030303030303030303030303',1,zeroblob(16),zeroblob(16),1,1,1,0,1,1,1,0,0,1,0,0,1,1),
                 (x'04040404040404040404040404040404',1,zeroblob(16),zeroblob(16),1,1,1,0,1,1,1,0,0,1,0,0,1,2);
             INSERT INTO album_memberships (album_id,object_id,capture_time_ms,added_ms,revision)
                 VALUES (x'01010101010101010101010101010101',x'03030303030303030303030303030303',1,1,1),
                        (x'02020202020202020202020202020202',x'04040404040404040404040404040404',1,1,1);"
        ).expect("real v10 fixture");
        db
    }

    #[test]
    fn v10_migration_retains_membership_snapshot_and_cascades_only_pending_intents() {
        let mut db = v10_with_album_memberships();
        let before_generation = generation(&db).expect("generation");
        migrate_v10_to_v11(&mut db).expect("migrate");
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V11)
        );
        assert_eq!(generation(&db).expect("generation"), before_generation);
        let counts: (i64, i64) = db
            .connection()
            .query_row(
                "SELECT (SELECT count(*) FROM album_memberships),
                    (SELECT count(*) FROM own_sync_pending_album_memberships)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("memberships and pending additions");
        assert_eq!(counts, (2, 2));
        assert!(db.connection().execute(
            "INSERT INTO own_sync_pending_album_memberships VALUES (zeroblob(16),zeroblob(16))", [],
        ).is_err(), "foreign keys must reject absent albums and objects");
        assert!(
            db.connection()
                .execute(
                    "INSERT INTO own_sync_pending_album_memberships VALUES (x'01',x'03')",
                    [],
                )
                .is_err(),
            "pending identifiers must have exactly sixteen bytes"
        );
        db.connection()
            .execute_batch(
                "DELETE FROM album_memberships;
             DELETE FROM albums WHERE name = 'First';
             DELETE FROM objects WHERE search_key = 2;",
            )
            .expect("remove parents after their ordinary memberships");
        let pending: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM own_sync_pending_album_memberships",
                [],
                |row| row.get(0),
            )
            .expect("cascaded additions");
        assert_eq!(pending, 0);
        assert_eq!(
            crate::store::albums(&db).expect("remaining album")[0]
                .album
                .name,
            "Second"
        );
    }

    #[test]
    fn v10_migration_rolls_back_ddl_and_seed_when_version_commit_fails() {
        let mut db = v10_with_album_memberships();
        db.connection()
            .execute_batch(
                "CREATE TEMP TRIGGER refuse_v11_version BEFORE UPDATE ON vault_state
             WHEN NEW.catalog_format_version = 11
             BEGIN SELECT RAISE(ABORT, 'version commit refused'); END;",
            )
            .expect("database write failure");
        migrate_v10_to_v11(&mut db).expect_err("the final version write must fail");
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V10)
        );
        let state: (i64, Option<i64>) = db.connection().query_row(
            "SELECT (SELECT count(*) FROM sqlite_schema WHERE name = 'own_sync_pending_album_memberships'),
                    active_migration_target FROM vault_state WHERE only_row = 1",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).expect("rolled back schema and marker");
        assert_eq!(state, (0, None));
        db.connection()
            .execute_batch("DROP TRIGGER refuse_v11_version")
            .expect("clear failure");
        migrate_v10_to_v11(&mut db).expect("retry complete migration");
    }

    #[test]
    fn v11_note_format_migration_preserves_literal_source_and_rolls_back_on_failure() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("current");
        db.connection().execute_batch("ALTER TABLE private_notes DROP COLUMN format; UPDATE vault_state SET catalog_format_version=11; INSERT INTO private_notes(note_id,revision,title,body,created_ms,updated_ms,pinned) VALUES(x'01010101010101010101010101010101',7,'Legacy','# literal text',1,2,1);").expect("v11 rows");
        let generation = generation(&db).expect("generation");
        db.connection().execute_batch("CREATE TRIGGER refuse_v12 BEFORE UPDATE OF catalog_format_version ON vault_state WHEN NEW.catalog_format_version=12 BEGIN SELECT RAISE(ABORT,'fixture failure'); END;").expect("failure trigger");
        assert!(migrate_v11_to_v12(&mut db).is_err());
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V11)
        );
        let (format_columns, marker):(i64, Option<i64>) = db.connection().query_row("SELECT (SELECT count(*) FROM pragma_table_info('private_notes') WHERE name='format'),active_migration_target FROM vault_state", [], |r| Ok((r.get(0)?,r.get(1)?))).expect("rollback");
        assert_eq!((format_columns, marker), (0, None));
        db.connection()
            .execute_batch("DROP TRIGGER refuse_v12")
            .expect("clear failure");
        migrate_v11_to_v12(&mut db).expect("real migration");
        let id = Id::from_slice(&[1; 16]).expect("id");
        let note = crate::notes::get(&db, &id).expect("legacy note");
        assert_eq!(note.format, crate::notes::NoteFormat::PlainText);
        assert_eq!(note.body, "# literal text");
        assert_eq!(note.revision, 7);
        assert!(note.pinned);
        assert_eq!(
            generation,
            self::generation(&db).expect("generation retained")
        );
    }

    #[test]
    fn v13_workspace_migration_rolls_back_and_preserves_current_notes() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("current");
        let n = crate::notes::save(
            &mut db,
            None,
            0,
            "Legacy",
            "# exact",
            false,
            crate::notes::NoteFormat::Markdown,
            2,
        )
        .expect("note");
        db.connection().execute_batch("DROP TABLE private_note_history_files; DROP TABLE private_note_history_blobs; DROP TABLE private_note_history; DROP TABLE private_note_organization; UPDATE vault_state SET catalog_format_version=13; CREATE TRIGGER refuse_v14 BEFORE UPDATE OF catalog_format_version ON vault_state WHEN NEW.catalog_format_version=14 BEGIN SELECT RAISE(ABORT,'version refused'); END;").expect("v13 fixture");
        assert!(migrate_v13_to_v14(&mut db).is_err());
        let state:(i64,Option<i64>,i64)=db.connection().query_row("SELECT catalog_format_version,active_migration_target,(SELECT count(*) FROM sqlite_schema WHERE name LIKE 'private_note_history%') FROM vault_state",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).expect("rollback state");
        assert_eq!(state, (13, None, 0));
        db.connection()
            .execute_batch("DROP TRIGGER refuse_v14")
            .expect("clear injected failure");
        migrate_v13_to_v14(&mut db).expect("complete migration");
        assert_eq!(
            crate::notes::get(&db, &n.id).expect("preserved").body,
            "# exact"
        );
        assert!(
            crate::note_workspace::history(&db, &n.id)
                .expect("new empty history")
                .is_empty()
        );
        assert!(
            crate::note_workspace::get_organization(&db, &n.id)
                .expect("new organization")
                .folder
                .is_empty()
        );
    }

    #[test]
    fn peer_only_migration_removes_network_columns_and_rolls_back_failed_transitions() {
        let mut db = open();
        open_at_current_version(&mut db, 1_700_000_000_000).expect("install");
        db.connection().execute_batch("ALTER TABLE device_pairing_approvals ADD COLUMN server_url TEXT;
            ALTER TABLE device_pairing_approvals ADD COLUMN transport_token BLOB;
            INSERT INTO device_pairing_approvals VALUES (zeroblob(16), X'01', X'02', X'03', X'04', X'05', 'obsolete', zeroblob(32));
            UPDATE vault_state SET catalog_format_version = 14;
            CREATE TRIGGER fail_peer_migration BEFORE UPDATE OF catalog_format_version ON vault_state
                WHEN NEW.catalog_format_version = 15 BEGIN SELECT RAISE(ABORT, 'migration interrupted'); END;")
            .expect("old enrollment fixture");
        assert!(migrate_v14_to_v15(&mut db).is_err());
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V14)
        );
        let columns: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM pragma_table_info('device_pairing_approvals')",
                [],
                |row| row.get(0),
            )
            .expect("columns");
        assert_eq!(columns, 8, "failed transaction retains its old schema");
        db.connection()
            .execute_batch("DROP TRIGGER fail_peer_migration")
            .expect("remove interruption");
        migrate_v14_to_v15(&mut db).expect("peer migration");
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V15)
        );
        let (columns, approvals): (i64, i64) = db.connection().query_row("SELECT (SELECT count(*) FROM pragma_table_info('device_pairing_approvals')), (SELECT count(*) FROM device_pairing_approvals)", [], |row| Ok((row.get(0)?, row.get(1)?))).expect("new schema");
        assert_eq!((columns, approvals), (6, 0));
    }

    #[test]
    fn compatible_video_capability_migration_is_atomic_and_preserves_rows() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("install");
        db.connection().execute_batch(
            "UPDATE vault_state SET catalog_format_version = 15;
             INSERT INTO tags (tag_id, name, created_ms) VALUES (zeroblob(16), 'catalog-canary', 1);
             CREATE TRIGGER fail_video_capability BEFORE UPDATE OF catalog_format_version ON vault_state
                 WHEN NEW.catalog_format_version = 16 BEGIN SELECT RAISE(ABORT, 'interrupted'); END;",
        ).expect("v15 fixture");
        assert!(migrate_v15_to_v16(&mut db).is_err());
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V15)
        );
        let target: Option<u16> = db
            .connection()
            .query_row(
                "SELECT active_migration_target FROM vault_state WHERE only_row = 1",
                [],
                |row| row.get(0),
            )
            .expect("target");
        assert_eq!(
            target, None,
            "a failed transaction must not retain its target"
        );
        db.connection()
            .execute_batch("DROP TRIGGER fail_video_capability")
            .expect("retry");
        migrate_v15_to_v16(&mut db).expect("capability migration");
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V16)
        );
        let name: String = db
            .connection()
            .query_row(
                "SELECT name FROM tags WHERE tag_id = zeroblob(16)",
                [],
                |row| row.get(0),
            )
            .expect("preserved tag");
        assert_eq!(name, "catalog-canary");
        assert_eq!(generation(&db).expect("generation"), 1);
        assert_eq!(
            migrate_v15_to_v16(&mut db)
                .expect_err("wrong source version")
                .status(),
            chur_core::ChurStatus::MigrationRequired
        );
    }

    #[test]
    fn playback_position_migration_rolls_back_ddl_and_version_together() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("install");
        db.connection().execute_batch("DROP TABLE trusted_time; DROP TABLE playback_positions;
            UPDATE vault_state SET catalog_format_version = 16;
            CREATE TRIGGER fail_playback_migration BEFORE UPDATE OF catalog_format_version ON vault_state
            WHEN NEW.catalog_format_version = 17 BEGIN SELECT RAISE(ABORT, 'interrupted'); END;").expect("v16 fixture");
        assert!(migrate_v16_to_v17(&mut db).is_err());
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V16)
        );
        let tables: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='playback_positions'",
                [],
                |row| row.get(0),
            )
            .expect("rolled back DDL");
        assert_eq!(tables, 0);
        db.connection()
            .execute_batch("DROP TRIGGER fail_playback_migration")
            .expect("retry");
        migrate_v16_to_v17(&mut db).expect("migrate");
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V17)
        );
        assert_eq!(generation(&db).expect("generation"), 1);
        assert_eq!(
            migrate_v16_to_v17(&mut db)
                .expect_err("wrong source version")
                .status(),
            chur_core::ChurStatus::MigrationRequired
        );
    }

    #[test]
    fn trusted_time_migration_rolls_back_ddl_and_version_together() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("install");
        db.connection().execute_batch("DROP TABLE trusted_time;
            UPDATE vault_state SET catalog_format_version = 17;
            CREATE TRIGGER fail_trusted_time_migration BEFORE UPDATE OF catalog_format_version ON vault_state
            WHEN NEW.catalog_format_version = 18 BEGIN SELECT RAISE(ABORT, 'interrupted'); END;").expect("v17 fixture");
        assert!(migrate_v17_to_v18(&mut db).is_err());
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V17)
        );
        let tables = |db: &CatalogDb| -> i64 {
            db.connection()
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name='trusted_time'",
                    [],
                    |row| row.get(0),
                )
                .expect("table count")
        };
        assert_eq!(tables(&db), 0);
        db.connection()
            .execute_batch("DROP TRIGGER fail_trusted_time_migration")
            .expect("retry");
        migrate_v17_to_v18(&mut db).expect("migrate");
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V18)
        );
        assert_eq!(tables(&db), 1);
        let rows: i64 = db
            .connection()
            .query_row("SELECT count(*) FROM trusted_time", [], |row| row.get(0))
            .expect("rows");
        assert_eq!(rows, 0);
        assert_eq!(generation(&db).expect("generation"), 1);
        assert_eq!(
            migrate_v17_to_v18(&mut db)
                .expect_err("wrong source version")
                .status(),
            chur_core::ChurStatus::MigrationRequired
        );
    }

    #[test]
    fn a_new_catalog_installs_version_eighteen() {
        let mut db = open();
        assert_eq!(
            open_at_current_version(&mut db, 1_700_000_000_000).expect("install"),
            CATALOG_FORMAT_VERSION_V18
        );
        let sharing_tables: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                  WHERE type = 'table' AND name LIKE 'sharing_%'",
                [],
                |row| row.get(0),
            )
            .expect("sharing tables");
        assert_eq!(sharing_tables, 9);
        let frozen: i64 = db
            .connection()
            .query_row(
                "SELECT grants_frozen FROM sharing_collections LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| map_sqlite(error, "the freeze column could not be read"))
            .expect("freeze column readable")
            .unwrap_or(0);
        assert_eq!(frozen, 0);
        assert_eq!(generation(&db).expect("generation"), 1);
    }

    #[test]
    fn opening_an_installed_catalog_is_idempotent() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("install");
        open_at_current_version(&mut db, 2).expect("reopen");
        assert_eq!(generation(&db).expect("generation"), 1);
    }

    #[test]
    fn a_non_current_version_is_migration_required_and_not_changed() {
        let mut db = open();
        install_v1(&mut db);
        let Err(error) = open_at_current_version(&mut db, 1) else {
            panic!("a v1 catalog migrated without an authenticated descriptor");
        };
        assert_eq!(error.status(), chur_core::ChurStatus::MigrationRequired);
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V1)
        );
    }

    #[test]
    fn the_state_row_cannot_be_duplicated() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("install");
        let outcome = db.connection().execute(
            "INSERT INTO vault_state (
                 only_row, catalog_format_version, catalog_generation,
                 active_migration_target, object_store_checkpoint,
                 integrity_checkpoint_ms, capability_flags
             ) VALUES (2, 1, 1, NULL, 0, 0, 0)",
            [],
        );
        assert!(outcome.is_err(), "a second vault_state row was accepted");
    }

    #[test]
    fn the_schema_steps_ascend_by_one_from_one() {
        for (index, step) in STEPS.iter().enumerate() {
            let expected = u16::try_from(index + 1).expect("a schema step index fits a u16");
            assert_eq!(step.version, expected, "§18 forbids a gap or a branch");
        }
        assert_eq!(
            STEPS.last().map(|step| step.version),
            Some(CATALOG_FORMAT_VERSION_V18)
        );
    }

    #[test]
    fn v6_migration_orders_existing_albums_and_preserves_names() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("install");
        db.transaction(|transaction| {
            transaction
                .execute_batch(RESET_V7_DDL)
                .expect("v6 structure");
            transaction
                .execute(
                    "UPDATE vault_state SET catalog_format_version = 6 WHERE only_row = 1",
                    [],
                )
                .expect("v6 version");
            for (id, name) in [(1u8, "Zulu"), (2u8, "Alpha")] {
                transaction
                    .execute(
                        "INSERT INTO albums (album_id, name, created_ms, revision)
                     VALUES (?1, ?2, 1, 1)",
                        rusqlite::params![vec![id; 16], name],
                    )
                    .expect("album");
            }
            Ok(())
        })
        .expect("v6 fixture");
        migrate_v6_to_v7(&mut db).expect("migrate");
        let rows: Vec<(String, i64)> = db
            .connection()
            .prepare("SELECT name, sort_position FROM albums ORDER BY sort_position")
            .expect("query")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("rows")
            .map(|row| row.expect("row"))
            .collect();
        assert_eq!(rows, vec![("Alpha".to_owned(), 0), ("Zulu".to_owned(), 1)]);
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V7)
        );
    }

    #[test]
    fn v7_migration_adds_trash_without_touching_existing_albums() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("install");
        let album_id = vec![7u8; 16];
        db.transaction(|tx| {
            tx.execute("INSERT INTO albums (album_id, name, created_ms, revision) VALUES (?1, 'Saved', 1, 1)",
                [album_id.as_slice()]).expect("album");
            tx.execute_batch("DROP TABLE trash_entries; UPDATE vault_state SET catalog_format_version = 7 WHERE only_row = 1;")
                .expect("v7 fixture");
            Ok(())
        }).expect("fixture");
        migrate_v7_to_v8(&mut db).expect("migrate");
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V8)
        );
        let album: String = db
            .connection()
            .query_row(
                "SELECT name FROM albums WHERE album_id = ?1",
                [album_id.as_slice()],
                |row| row.get(0),
            )
            .expect("album preserved");
        assert_eq!(album, "Saved");
    }

    #[test]
    fn v4_migration_installs_the_grant_acceptance_freeze() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("install");
        reset_to_v1(&mut db).expect("reset to v1");
        let vault_id = Id::new([7; 16]).expect("id");
        migrate_v1_to_v2(&mut db, &vault_id).expect("migrate v2");
        migrate_v2_to_v3(&mut db).expect("migrate v3");
        migrate_v3_to_v4(&mut db).expect("migrate v4");
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V4)
        );

        migrate_v4_to_v5(&mut db).expect("migrate v5");

        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V5)
        );
        // The freeze defaults to unfrozen and rejects anything else, so a
        // collection cannot enter the state by accident.
        let outcome = db.connection().execute(
            "INSERT INTO sharing_collections (
                 collection_id, source_vault_id, initial_epoch,
                 membership_generation, membership_commitment, current_epoch,
                 grants_frozen
             ) VALUES (x'01010101010101010101010101010101',
                       x'02020202020202020202020202020202', 1, 0,
                       x'0303030303030303030303030303030303030303030303030303030303030303', 1, 1)",
            [],
        );
        assert!(outcome.is_ok(), "a frozen collection row was rejected");
        let outcome = db.connection().execute(
            "INSERT INTO sharing_collections (
                 collection_id, source_vault_id, initial_epoch,
                 membership_generation, membership_commitment, current_epoch,
                 grants_frozen
             ) VALUES (x'04040404040404040404040404040404',
                       x'02020202020202020202020202020202', 1, 0, x'03', 1, 2)",
            [],
        );
        assert!(outcome.is_err(), "a non-boolean freeze value was accepted");
    }

    #[test]
    fn v2_migration_installs_empty_sharing_state() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("install");
        reset_to_v2(&mut db).expect("reset to v2");

        migrate_v2_to_v3(&mut db).expect("migrate");

        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V3)
        );
        let sharing_tables: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                  WHERE type = 'table' AND name LIKE 'sharing_%'",
                [],
                |row| row.get(0),
            )
            .expect("sharing tables");
        assert_eq!(sharing_tables, 4);
    }

    #[test]
    fn v3_migration_installs_empty_collection_operation_state() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("install");
        reset_to_v3(&mut db).expect("reset to v3");

        migrate_v3_to_v4(&mut db).expect("migrate");

        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V4)
        );
        let operation_tables: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                  WHERE type = 'table' AND name IN (
                    'sharing_operation_streams', 'sharing_operations',
                    'sharing_operation_forks'
                  )",
                [],
                |row| row.get(0),
            )
            .expect("operation tables");
        assert_eq!(operation_tables, 3);
    }

    #[test]
    fn v5_migration_installs_an_empty_object_index() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("install");
        reset_to_v3(&mut db).expect("reset to v3");
        migrate_v3_to_v4(&mut db).expect("migrate v4");
        migrate_v4_to_v5(&mut db).expect("migrate v5");

        migrate_v5_to_v6(&mut db).expect("migrate v6");

        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V6)
        );
        let object_tables: i64 = db
            .connection()
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                  WHERE type = 'table' AND name IN (
                    'sharing_object_operations', 'sharing_object_projection'
                  )",
                [],
                |row| row.get(0),
            )
            .expect("object tables");
        assert_eq!(object_tables, 2);
    }

    #[test]
    fn v3_sharing_constraints_reject_malformed_rows() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("schema");
        let collection = [1u8; 16];
        db.connection()
            .execute(
                "INSERT INTO sharing_collections (
                     collection_id, source_vault_id, initial_epoch,
                     membership_generation, membership_commitment, current_epoch
                 ) VALUES (?1, ?2, 1, 0, ?3, 1)",
                rusqlite::params![collection, [2u8; 16], [0u8; 32]],
            )
            .expect("collection");

        assert!(
            db.connection()
                .execute(
                    "INSERT INTO sharing_recipient_pins VALUES (?1, ?2, ?3, ?4, ?5, 3)",
                    rusqlite::params![collection, [3u8; 16], [4u8; 16], [5u8; 32], [6u8; 32],],
                )
                .is_err(),
            "an invalid verification state was accepted"
        );
        assert!(
            db.connection()
                .execute(
                    "INSERT INTO sharing_grants VALUES (?1, ?2, ?3, ?4, 1, 1, ?5)",
                    rusqlite::params![[7u8; 16], collection, [3u8; 16], [4u8; 16], [8u8; 308],],
                )
                .is_err(),
            "a short grant record was accepted"
        );
    }

    #[test]
    fn v1_migration_projects_the_highest_active_object_envelope() {
        let mut db = open();
        install_v1(&mut db);
        let vault_id = random::id().expect("vault");
        let collection_id = random::id().expect("collection");
        let object_id = random::id().expect("object");
        let stream_id = random::id().expect("stream");
        let collection_key: Key = random::secret::<32>().expect("collection key");
        let object_key: Key = random::secret::<32>().expect("object key");
        let envelope = ObjectKeyEnvelope::seal(
            &collection_key,
            vault_id,
            collection_id,
            7,
            object_id,
            3,
            Nonce::new([4; 24]),
            &object_key,
        )
        .expect("envelope");
        db.transaction(|transaction| {
            transaction
                .execute(
                    "INSERT INTO collections VALUES (?1, 7, 1, 1, 1)",
                    [collection_id.as_bytes().as_slice()],
                )
                .expect("collection");
            transaction
                .execute(
                    "INSERT INTO objects VALUES (
                         ?1, 1, ?2, ?3, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1
                     )",
                    rusqlite::params![
                        object_id.as_bytes().as_slice(),
                        collection_id.as_bytes().as_slice(),
                        stream_id.as_bytes().as_slice(),
                    ],
                )
                .expect("object");
            transaction
                .execute(
                    "INSERT INTO object_key_envelopes VALUES (?1, 3, 1, ?2)",
                    rusqlite::params![object_id.as_bytes().as_slice(), envelope.encode()],
                )
                .expect("envelope row");
            Ok(())
        })
        .expect("v1 rows");

        migrate_v1_to_v2(&mut db, &vault_id).expect("migrate");
        let projection: (i64, i64) = db
            .connection()
            .query_row(
                "SELECT collection_epoch, envelope_generation
                   FROM sync_object_envelope_epochs WHERE object_id = ?1",
                [object_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("projection");
        assert_eq!(projection, (7, 3));
        assert_eq!(
            recorded_version(db.connection()).expect("version"),
            Some(CATALOG_FORMAT_VERSION_V2)
        );
    }

    #[test]
    fn v2_sync_constraints_reject_malformed_rows() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("schema");
        assert!(
            db.connection()
                .execute(
                    "INSERT INTO sync_devices VALUES (?1, ?2, ?3, 1, 1, NULL, NULL)",
                    rusqlite::params![vec![1u8; 15], vec![2u8; 32], vec![3u8; 32]],
                )
                .is_err(),
            "a short device id was accepted"
        );
        let device = [1u8; 16];
        db.connection()
            .execute(
                "INSERT INTO sync_devices VALUES (?1, ?2, ?3, 1, 1, NULL, NULL)",
                rusqlite::params![device, [2u8; 32], [3u8; 32]],
            )
            .expect("device");
        assert!(
            db.connection()
                .execute(
                    "INSERT INTO sync_heads VALUES (?1, 1, NULL, NULL, NULL)",
                    [device],
                )
                .is_err(),
            "a partial accepted head was accepted"
        );
        db.connection()
            .execute(
                "INSERT INTO sync_identity_envelopes VALUES (?1, 1, 1, 0, ?2)",
                rusqlite::params![device, [4u8]],
            )
            .expect("identity envelope");
        assert!(
            db.connection()
                .execute(
                    "INSERT INTO sync_identity_envelopes VALUES (?1, 2, 1, 0, ?2)",
                    rusqlite::params![device, [5u8]],
                )
                .is_err(),
            "a second active identity envelope was accepted"
        );
    }

    #[test]
    fn the_generation_advances_once_per_transaction_that_asks() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("install");
        db.transaction(bump_generation).expect("bump");
        assert_eq!(generation(&db).expect("generation"), 2);
    }

    #[test]
    fn a_page_limit_is_bounded_and_zero_means_the_default() {
        assert_eq!(check_query_limit(0).expect("default"), 200);
        assert_eq!(check_query_limit(1).expect("minimum"), 1);
        assert_eq!(check_query_limit(500).expect("maximum"), 500);
        let Err(error) = check_query_limit(501) else {
            panic!("a page limit above §16.2 was accepted");
        };
        assert_eq!(error.status(), chur_core::ChurStatus::ResourceLimitExceeded);
    }

    #[test]
    fn the_search_index_tokenizes_with_the_registered_profile() {
        let mut db = open();
        open_at_current_version(&mut db, 1).expect("install");
        db.connection()
            .execute(
                "INSERT INTO object_search (rowid, filename, caption, tag_names)
                 VALUES (1, 'Ärger.jpg', 'a caption', 'holiday')",
                [],
            )
            .expect("index a row");
        // remove_diacritics 2 folds the umlaut, and the prefix index answers a
        // two-character as-you-type query.
        for query in ["arger", "ar*", "holiday", "caption"] {
            let hits: i64 = db
                .connection()
                .query_row(
                    "SELECT count(*) FROM object_search WHERE object_search MATCH ?1",
                    [query],
                    |row| row.get(0),
                )
                .expect("search");
            assert_eq!(hits, 1, "query {query} did not match");
        }
    }
}

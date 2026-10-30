//! Chur private catalog.
//!
//! The catalog stores queryable private metadata, object and collection
//! relationships, key envelopes, journals, integrity state, and durable sync
//! state inside a Rust-owned encrypted database. Room and DataStore never
//! open or mirror it.
//!
//! Normative sources:
//!
//! - `docs/format/CATALOG_SCHEMA_V1.md` (logical entities, transactions)
//! - `docs/format/CATALOG_SCHEMA_V2.md` (encrypted synchronization state)
//! - `docs/format/CATALOG_SCHEMA_V3.md` (collection-sharing state)
//! - `docs/format/CATALOG_SCHEMA_V4.md` (collection operation streams)
//! - ADR-0004 (SQLCipher accessed directly from Rust)
//!
//! Two representations exist and no third: the physical SQLCipher schema of
//! [`schema`], and the canonical serialization of
//! `docs/format/CANONICAL_ENCODING_V1.md` when a portable backup exports it.

pub mod catalog_export;
pub mod content_index;
pub mod db;
pub mod deletion;
pub mod device_pairing;
pub mod journal;
pub mod model;
pub mod note_attachments;
pub mod note_workspace;
pub mod notes;
pub mod object_grants;
pub mod own_sync;
pub mod paths;
pub mod playback;
pub mod query;
mod receive_queue;
pub(crate) mod row;
pub mod schema;
pub mod sharing;
pub mod sharing_log;
pub mod sharing_publication;
pub mod sharing_receive;
pub mod sharing_service;
pub mod store;
pub mod sync_engine;
pub mod sync_keys;
pub mod sync_log;
pub mod sync_membership;
pub mod sync_receive;
pub mod sync_rotation;
pub mod sync_staging;
pub mod transfer;
pub mod trash;
pub mod trusted_time;
pub mod vault;

pub use db::{CatalogDb, CatalogKey, CatalogLocation};

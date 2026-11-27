//! Chur cryptographic primitives.
//!
//! Rust is the only owner of key material, derivation, wrapping, and AEAD use
//! (ADR-0001). Every construction here is testable from a CLI without any
//! Android or iOS dependency, and every one of them is a v1 suite `0x0001`
//! construction: XChaCha20-Poly1305 for AEAD, BLAKE3-256 for commitments,
//! HKDF-SHA-256 for derivation, and Argon2id for the password factor.
//!
//! Normative sources:
//!
//! - `docs/CRYPTOGRAPHY.md` (profile v1, primitives, HKDF construction, secrets)
//! - `docs/security/KEY_HIERARCHY.md` §3 (label and context registry)
//! - `docs/security/PASSWORD_PROFILE.md` (canonical password bytes, Argon2id)
//! - `docs/format/CANONICAL_ENCODING_V1.md` §7 (domain tags, canonical tuples)
//! - `docs/security/SECURITY_INVARIANTS.md` (SEC-001 to SEC-010)

pub mod aead;
pub mod commit;
pub mod kdf;
pub mod password;
pub mod random;
pub mod recovery;
pub mod secret;
pub mod sha256;
pub mod tuple;

pub use aead::Nonce;
pub use commit::{Commitment, Committer};
pub use kdf::{Context, Label};
pub use secret::{Key, Secret};
pub use tuple::{Tuple, tag};

/// Transcript-bound ephemeral peer session keys.
pub mod peer;

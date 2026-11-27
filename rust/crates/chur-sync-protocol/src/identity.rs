//! Portable device identity and verification fingerprints from
//! `docs/sync/DEVICE_IDENTITY.md`.

use chur_core::limits::NONCE_LEN;
use chur_core::{ChurStatus, Error, Id, Result, ensure};
use chur_crypto::aead::{self, Nonce};
use chur_crypto::kdf::{self, Context, Label};
use chur_crypto::secret::Key;
use chur_crypto::tuple::{Tuple, tag};
use chur_crypto::{commit, random};
use chur_format::codec::{Reader, Writer};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::membership::EnrollmentRecord;
use crate::operation::{DeviceSigningKey, PROTOCOL_VERSION_V1};

const HEX: &[u8; 16] = b"0123456789abcdef";
const ENCODING_PROFILE_V1: u16 = 1;
const SIGNING_SUITE_V1: u16 = 1;
const HPKE_SUITE_V1: u16 = 1;
const PRIVATE_IDENTITY_LEN: usize = 64;
const WRAPPED_IDENTITY_LEN: usize = PRIVATE_IDENTITY_LEN + 16;
const LOCAL_IDENTITY: bool = false;
const RECOVERY_ONLY: bool = true;

/// One portable Ed25519 and X25519 device identity.
pub struct DeviceIdentity {
    signing_key: DeviceSigningKey,
    hpke_secret: StaticSecret,
}

impl DeviceIdentity {
    /// Generates a fresh ordinary device identity from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating-system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        let signing_seed = random::secret::<32>()?;
        let hpke_secret = random::secret::<32>()?;
        Ok(Self::from_seeds(
            *signing_seed.expose(),
            *hpke_secret.expose(),
        ))
    }

    /// Restores deterministic identity material.
    #[must_use]
    pub fn from_seeds(signing_seed: [u8; 32], hpke_secret: [u8; 32]) -> Self {
        Self {
            signing_key: DeviceSigningKey::from_seed(signing_seed),
            hpke_secret: StaticSecret::from(hpke_secret),
        }
    }

    /// The Ed25519 public verification key.
    #[must_use]
    pub fn signing_public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key()
    }

    /// The X25519 public key used by enrollment and grants.
    #[must_use]
    pub fn hpke_public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.hpke_secret).to_bytes()
    }

    /// The key for ordinary operation and membership authoring.
    #[must_use]
    pub const fn signing_key(&self) -> &DeviceSigningKey {
        &self.signing_key
    }

    pub(crate) fn hpke_secret_bytes(&self) -> &[u8; 32] {
        self.hpke_secret.as_bytes()
    }

    fn secret_bytes(&self) -> Zeroizing<[u8; PRIVATE_IDENTITY_LEN]> {
        let signing_seed = self.signing_key.seed_bytes();
        let mut bytes = Zeroizing::new([0; PRIVATE_IDENTITY_LEN]);
        bytes[..32].copy_from_slice(signing_seed.as_ref());
        bytes[32..].copy_from_slice(self.hpke_secret.as_bytes());
        bytes
    }
}

/// A restored identity whose API can only sign replacement enrollment.
pub struct RecoveredDeviceIdentity {
    identity: DeviceIdentity,
    vault_id: Id,
    device_id: Id,
    identity_generation: u64,
}

impl RecoveredDeviceIdentity {
    /// Signs one enrollment with the recovered device key.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::AuthenticationFailed`] when the record is not a
    /// replacement issued by this recovered device for the bound vault.
    pub fn sign_replacement_enrollment(
        &self,
        enrollment: EnrollmentRecord,
    ) -> Result<EnrollmentRecord> {
        ensure!(
            enrollment.vault_id() == &self.vault_id
                && enrollment.issuer_device_id() == &self.device_id
                && enrollment.device_id() != &self.device_id
                && enrollment.membership_generation() > 1,
            AuthenticationFailed,
            "recovered identity can only sign its replacement enrollment"
        );
        ensure!(
            enrollment.signing_public_key() != &self.identity.signing_public_key()
                && enrollment.hpke_public_key() != &self.identity.hpke_public_key(),
            AuthenticationFailed,
            "replacement enrollment reuses recovered identity keys"
        );
        Ok(enrollment.sign(&self.identity.signing_key))
    }

    /// The recovered Ed25519 public verification key.
    #[must_use]
    pub fn signing_public_key(&self) -> [u8; 32] {
        self.identity.signing_public_key()
    }

    /// The recovered X25519 public key.
    #[must_use]
    pub fn hpke_public_key(&self) -> [u8; 32] {
        self.identity.hpke_public_key()
    }

    /// The recovered device identifier.
    #[must_use]
    pub const fn device_id(&self) -> &Id {
        &self.device_id
    }

    /// The recovered identity generation.
    #[must_use]
    pub const fn identity_generation(&self) -> u64 {
        self.identity_generation
    }
}

/// One root-wrapped local or recovery-purpose device identity.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceIdentityEnvelope {
    vault_id: Id,
    device_id: Id,
    identity_generation: u64,
    recovery_only: bool,
    nonce: Nonce,
    wrapped_identity: [u8; WRAPPED_IDENTITY_LEN],
}

impl DeviceIdentityEnvelope {
    /// Exact canonical encoded length.
    pub const LEN: usize = 2 + 2 + 2 + 2 + 16 + 16 + 8 + 1 + NONCE_LEN + WRAPPED_IDENTITY_LEN;

    /// Seals an ordinary local identity for unlocked signing and grant opening.
    pub fn seal_for_local(
        root: &Key,
        vault_id: Id,
        device_id: Id,
        identity_generation: u64,
        nonce: Nonce,
        identity: &DeviceIdentity,
    ) -> Result<Self> {
        Self::seal(
            root,
            vault_id,
            device_id,
            identity_generation,
            LOCAL_IDENTITY,
            nonce,
            identity,
        )
    }

    /// Seals an identity for portable recovery.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::InvalidInput`] for an invalid generation and an
    /// encryption or key-derivation error otherwise.
    pub fn seal_for_recovery(
        root: &Key,
        vault_id: Id,
        device_id: Id,
        identity_generation: u64,
        nonce: Nonce,
        identity: &DeviceIdentity,
    ) -> Result<Self> {
        Self::seal(
            root,
            vault_id,
            device_id,
            identity_generation,
            RECOVERY_ONLY,
            nonce,
            identity,
        )
    }

    fn seal(
        root: &Key,
        vault_id: Id,
        device_id: Id,
        identity_generation: u64,
        recovery_only: bool,
        nonce: Nonce,
        identity: &DeviceIdentity,
    ) -> Result<Self> {
        check_generation(identity_generation)?;
        let wrapping_key = wrapping_key(root, &vault_id)?;
        let aad = identity_aad(&vault_id, &device_id, identity_generation, recovery_only);
        let sealed = aead::seal(
            &wrapping_key,
            &nonce,
            identity.secret_bytes().as_ref(),
            &aad,
        )?;
        let wrapped_identity = sealed.try_into().map_err(|_| {
            Error::new(
                ChurStatus::InternalFailure,
                "wrapped device identity is not 80 bytes",
            )
        })?;
        Ok(Self {
            vault_id,
            device_id,
            identity_generation,
            recovery_only,
            nonce,
            wrapped_identity,
        })
    }

    /// Opens the identity as recovery-only key material.
    ///
    /// # Errors
    ///
    /// Returns [`ChurStatus::ObjectCorrupt`] when authentication fails.
    pub fn open_for_recovery(&self, root: &Key) -> Result<RecoveredDeviceIdentity> {
        ensure!(
            self.recovery_only,
            InvalidInput,
            "ordinary device identity cannot enter recovery mode"
        );
        let identity = self.open_identity(root)?;
        Ok(RecoveredDeviceIdentity {
            identity,
            vault_id: self.vault_id,
            device_id: self.device_id,
            identity_generation: self.identity_generation,
        })
    }

    /// Opens ordinary local identity material inside an unlocked Rust session.
    pub fn open_for_local(&self, root: &Key) -> Result<DeviceIdentity> {
        ensure!(
            !self.recovery_only,
            InvalidInput,
            "recovery-only identity cannot authorize ordinary operations"
        );
        self.open_identity(root)
    }

    fn open_identity(&self, root: &Key) -> Result<DeviceIdentity> {
        let wrapping_key = wrapping_key(root, &self.vault_id)?;
        let plaintext = aead::open(
            &wrapping_key,
            &self.nonce,
            &self.wrapped_identity,
            &identity_aad(
                &self.vault_id,
                &self.device_id,
                self.identity_generation,
                self.recovery_only,
            ),
        )?;
        ensure!(
            plaintext.len() == PRIVATE_IDENTITY_LEN,
            ObjectCorrupt,
            "unwrapped device identity is not 64 bytes"
        );
        let mut signing_seed = Zeroizing::new([0; 32]);
        let mut hpke_secret = Zeroizing::new([0; 32]);
        signing_seed.copy_from_slice(&plaintext[..32]);
        hpke_secret.copy_from_slice(&plaintext[32..]);
        Ok(DeviceIdentity::from_seeds(*signing_seed, *hpke_secret))
    }

    /// Encodes the fixed-width canonical record.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(Self::LEN);
        writer
            .u16(PROTOCOL_VERSION_V1)
            .u16(ENCODING_PROFILE_V1)
            .u16(SIGNING_SUITE_V1)
            .u16(HPKE_SUITE_V1)
            .id(&self.vault_id)
            .id(&self.device_id)
            .u64(self.identity_generation)
            .bool(self.recovery_only)
            .fixed(self.nonce.as_bytes())
            .fixed(&self.wrapped_identity);
        debug_assert_eq!(writer.len(), Self::LEN);
        writer.finish()
    }

    /// Decodes the fixed-width canonical record.
    ///
    /// # Errors
    ///
    /// Returns a stable protocol status for a length, identifier, suite,
    /// generation, or recovery-purpose violation.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == Self::LEN,
            NonCanonicalEncoding,
            "device identity envelope is not 153 bytes"
        );
        let mut reader = Reader::new(bytes, ChurStatus::NonCanonicalEncoding);
        ensure!(
            reader.u16()? == PROTOCOL_VERSION_V1,
            UnsupportedVersion,
            "device identity envelope protocol version is not supported"
        );
        ensure!(
            reader.u16()? == ENCODING_PROFILE_V1,
            UnsupportedVersion,
            "device identity envelope encoding profile is not supported"
        );
        ensure!(
            reader.u16()? == SIGNING_SUITE_V1,
            UnsupportedSuite,
            "device identity signing suite is not supported"
        );
        ensure!(
            reader.u16()? == HPKE_SUITE_V1,
            UnsupportedSuite,
            "device identity HPKE suite is not supported"
        );
        let vault_id = reader.id()?;
        let device_id = reader.id()?;
        let identity_generation = reader.u64()?;
        check_generation(identity_generation)?;
        let recovery_only = reader.bool()?;
        let nonce = Nonce::new(reader.fixed::<NONCE_LEN>()?);
        let wrapped_identity = reader.fixed::<WRAPPED_IDENTITY_LEN>()?;
        reader.finish()?;
        Ok(Self {
            vault_id,
            device_id,
            identity_generation,
            recovery_only,
            nonce,
            wrapped_identity,
        })
    }

    /// The vault bound into the envelope.
    #[must_use]
    pub const fn vault_id(&self) -> &Id {
        &self.vault_id
    }

    /// The device bound into the envelope.
    #[must_use]
    pub const fn device_id(&self) -> &Id {
        &self.device_id
    }

    /// The private identity generation.
    #[must_use]
    pub const fn identity_generation(&self) -> u64 {
        self.identity_generation
    }

    /// Whether this envelope can only enroll a replacement device.
    #[must_use]
    pub const fn is_recovery_only(&self) -> bool {
        self.recovery_only
    }
}

fn check_generation(generation: u64) -> Result<()> {
    ensure!(
        generation != 0 && generation != u64::MAX,
        InvalidInput,
        "identity generation is zero or has no successor"
    );
    Ok(())
}

fn wrapping_key(root: &Key, vault_id: &Id) -> Result<Key> {
    kdf::derive_from(
        root,
        Label::RootDeviceIdentityWrap,
        &Context::vault(vault_id),
    )
}

fn identity_aad(
    vault_id: &Id,
    device_id: &Id,
    identity_generation: u64,
    recovery_only: bool,
) -> Vec<u8> {
    Tuple::new(tag::DEVICE_IDENTITY_ENVELOPE)
        .u16(PROTOCOL_VERSION_V1)
        .u16(ENCODING_PROFILE_V1)
        .u16(SIGNING_SUITE_V1)
        .u16(HPKE_SUITE_V1)
        .id(vault_id)
        .id(device_id)
        .u64(identity_generation)
        .bool(recovery_only)
        .finish()
}

/// Computes the full device verification digest.
#[must_use]
pub fn fingerprint_digest(
    vault_id: &Id,
    device_id: &Id,
    signing_public_key: &[u8; 32],
    hpke_public_key: &[u8; 32],
) -> [u8; 32] {
    commit::commit(
        tag::IDENTITY_FINGERPRINT,
        &[
            vault_id.as_bytes(),
            device_id.as_bytes(),
            signing_public_key,
            hpke_public_key,
        ],
    )
}

/// Formats the portable 160-bit verification string.
#[must_use]
pub fn fingerprint(
    vault_id: &Id,
    device_id: &Id,
    signing_public_key: &[u8; 32],
    hpke_public_key: &[u8; 32],
) -> String {
    let digest = fingerprint_digest(vault_id, device_id, signing_public_key, hpke_public_key);
    let mut display = String::with_capacity(49);
    for (index, pair) in digest[..20].chunks(2).enumerate() {
        if index != 0 {
            display.push(' ');
        }
        for byte in pair {
            display.push(char::from(HEX[usize::from(byte >> 4)]));
            display.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    display
}

/// The binary enrollment QR identity payload, before the checkpoint commitment.
#[must_use]
pub fn qr_identity_payload(
    vault_id: &Id,
    device_id: &Id,
    signing_public_key: &[u8; 32],
    hpke_public_key: &[u8; 32],
) -> [u8; 96] {
    let mut payload = [0; 96];
    payload[..16].copy_from_slice(vault_id.as_bytes());
    payload[16..32].copy_from_slice(device_id.as_bytes());
    payload[32..64].copy_from_slice(signing_public_key);
    payload[64..].copy_from_slice(hpke_public_key);
    payload
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn fingerprint_and_qr_use_the_same_identity_bytes() {
        let vault_id = Id::new([1; 16]).expect("vault");
        let device_id = Id::new([2; 16]).expect("device");
        let signing = [3; 32];
        let hpke = [4; 32];
        let qr = qr_identity_payload(&vault_id, &device_id, &signing, &hpke);

        assert_eq!(&qr[..16], vault_id.as_bytes());
        assert_eq!(&qr[16..32], device_id.as_bytes());
        assert_eq!(&qr[32..64], &signing);
        assert_eq!(&qr[64..], &hpke);
        let display = fingerprint(&vault_id, &device_id, &signing, &hpke);
        assert_eq!(display.len(), 49);
        assert_eq!(display.split(' ').count(), 10);
        assert_eq!(
            fingerprint_digest(&vault_id, &device_id, &signing, &hpke),
            commit::commit(tag::IDENTITY_FINGERPRINT, &[&qr])
        );
    }

    #[test]
    fn recovery_identity_cannot_sign_self_enrollment() {
        let root = Key::new([1; 32]);
        let vault_id = Id::new([2; 16]).expect("vault");
        let device_id = Id::new([3; 16]).expect("device");
        let identity = DeviceIdentity::from_seeds([4; 32], [5; 32]);
        let recovered = DeviceIdentityEnvelope::seal_for_recovery(
            &root,
            vault_id,
            device_id,
            1,
            Nonce::new([6; NONCE_LEN]),
            &identity,
        )
        .expect("seal")
        .open_for_recovery(&root)
        .expect("open");
        let self_enrollment = EnrollmentRecord::initial(
            vault_id,
            device_id,
            recovered.signing_public_key(),
            recovered.hpke_public_key(),
        )
        .expect("self enrollment");

        let error = match recovered.sign_replacement_enrollment(self_enrollment) {
            Ok(_) => panic!("recovered identity signed self-enrollment"),
            Err(error) => error,
        };
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);

        let reused_keys = EnrollmentRecord::new(
            vault_id,
            Id::new([7; 16]).expect("replacement"),
            recovered.signing_public_key(),
            recovered.hpke_public_key(),
            2,
            device_id,
            2,
            [10; 32],
            [11; 32],
        )
        .expect("reused-key enrollment");
        let error = match recovered.sign_replacement_enrollment(reused_keys) {
            Ok(_) => panic!("recovered identity authorized key reuse"),
            Err(error) => error,
        };
        assert_eq!(error.status(), ChurStatus::AuthenticationFailed);

        let replacement_id = Id::new([7; 16]).expect("replacement");
        let replacement = DeviceIdentity::from_seeds([8; 32], [9; 32]);
        let enrollment = EnrollmentRecord::new(
            vault_id,
            replacement_id,
            replacement.signing_public_key(),
            replacement.hpke_public_key(),
            2,
            device_id,
            2,
            [10; 32],
            [11; 32],
        )
        .expect("replacement enrollment");
        let signed = recovered
            .sign_replacement_enrollment(enrollment)
            .expect("sign replacement");
        signed
            .verify_signature(&recovered.signing_public_key())
            .expect("recovered issuer signature");
    }

    #[test]
    fn portable_identity_round_trips_as_recovery_only() {
        let root = Key::new([7; 32]);
        let vault_id = Id::new([8; 16]).expect("vault");
        let device_id = Id::new([9; 16]).expect("device");
        let identity = DeviceIdentity::from_seeds([10; 32], [11; 32]);
        let envelope = DeviceIdentityEnvelope::seal_for_recovery(
            &root,
            vault_id,
            device_id,
            3,
            Nonce::new([12; NONCE_LEN]),
            &identity,
        )
        .expect("seal");

        let decoded = DeviceIdentityEnvelope::decode(&envelope.encode()).expect("decode");
        let restored = decoded.open_for_recovery(&root).expect("open");
        assert_eq!(restored.signing_public_key(), identity.signing_public_key());
        assert_eq!(restored.hpke_public_key(), identity.hpke_public_key());
        assert_eq!(decoded.vault_id(), &vault_id);
        assert_eq!(decoded.device_id(), &device_id);
        assert_eq!(decoded.identity_generation(), 3);
        assert!(decoded.is_recovery_only());

        let wrong_root = Key::new([13; 32]);
        let error = match decoded.open_for_recovery(&wrong_root) {
            Ok(_) => panic!("identity opened under the wrong root"),
            Err(error) => error,
        };
        assert_eq!(error.status(), ChurStatus::ObjectCorrupt);

        let mut ordinary = envelope.encode();
        ordinary[48] = 0;
        let ordinary = DeviceIdentityEnvelope::decode(&ordinary).expect("local envelope shape");
        let error = match ordinary.open_for_local(&root) {
            Ok(_) => panic!("modified purpose opened without authenticating"),
            Err(error) => error,
        };
        assert_eq!(error.status(), ChurStatus::ObjectCorrupt);
    }

    #[test]
    fn local_identity_round_trips_but_cannot_enter_recovery_mode() {
        let root = Key::new([21; 32]);
        let vault_id = Id::new([22; 16]).expect("vault");
        let device_id = Id::new([23; 16]).expect("device");
        let identity = DeviceIdentity::from_seeds([24; 32], [25; 32]);
        let envelope = DeviceIdentityEnvelope::seal_for_local(
            &root,
            vault_id,
            device_id,
            1,
            Nonce::new([26; NONCE_LEN]),
            &identity,
        )
        .expect("seal");
        let decoded = DeviceIdentityEnvelope::decode(&envelope.encode()).expect("decode");
        let restored = decoded.open_for_local(&root).expect("open");

        assert!(!decoded.is_recovery_only());
        assert_eq!(restored.signing_public_key(), identity.signing_public_key());
        assert_eq!(restored.hpke_public_key(), identity.hpke_public_key());
        let error = match decoded.open_for_recovery(&root) {
            Ok(_) => panic!("ordinary identity entered recovery mode"),
            Err(error) => error,
        };
        assert_eq!(error.status(), ChurStatus::InvalidInput);
    }
}

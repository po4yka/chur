//! Internal recipient and signature profile. See ADR-0073.

use crate::Key;
use chur_core::{ChurStatus, Error, Result};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use ml_dsa::{Keypair, MlDsa65, Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

/// Size of an X-Wing recipient public key.
pub const RECIPIENT_LEN: usize = 1216;
/// Size of an X-Wing encapsulation.
pub const ENCAP_LEN: usize = 1120;
/// Exact size of a sealed 32-byte key, including encapsulation and AEAD tag.
pub const ENVELOPE_LEN: usize = ENCAP_LEN + 32 + 16;
/// Size of an ML-DSA-65 verifying key.
pub const VERIFY_LEN: usize = 1952;
/// Size of an ML-DSA-65 signature.
pub const SIGNATURE_LEN: usize = 3309;

fn invalid_key() -> Error {
    Error::new(
        ChurStatus::AuthenticationFailed,
        "invalid recipient key or envelope",
    )
}

/// Rejects a noncontributory X25519 component in a registered peer key or encapsulation.
pub fn validate_contribution(public: &[u8; 32]) -> Result<()> {
    let check = x25519_dalek::StaticSecret::from([0x5a; 32])
        .diffie_hellman(&x25519_dalek::PublicKey::from(*public));
    if check.was_contributory() {
        Ok(())
    } else {
        Err(invalid_key())
    }
}

fn parse_recipient(recipient: &[u8; RECIPIENT_LEN]) -> Result<<XWing as Kem>::PublicKey> {
    validate_contribution(recipient.last_chunk().ok_or_else(invalid_key)?)?;
    <XWing as Kem>::PublicKey::from_bytes(recipient).map_err(|_| invalid_key())
}

/// Validates the ML-KEM encoding and the X25519 contribution before storing a recipient.
pub fn validate_recipient(recipient: &[u8; RECIPIENT_LEN]) -> Result<()> {
    parse_recipient(recipient).map(drop)
}

/// Checks the X25519 component of an exact-size encapsulation. HPKE authenticates the ciphertext on open.
pub fn validate_encapsulation(encapsulation: &[u8; ENCAP_LEN]) -> Result<()> {
    validate_contribution(encapsulation.last_chunk().ok_or_else(invalid_key)?)
}

/// Expands a stored X-Wing private seed into the portable recipient key.
pub fn recipient_public(seed: &Key) -> Result<[u8; RECIPIENT_LEN]> {
    let secret =
        <XWing as Kem>::PrivateKey::from_bytes(seed.expose()).map_err(|_| invalid_key())?;
    Ok(XWing::sk_to_pk(&secret).to_bytes().into())
}

/// Seals one content key. The caller supplies the protocol purpose and the canonical record header.
pub fn seal_key(
    recipient: &[u8; RECIPIENT_LEN],
    info: &[u8],
    header: &[u8],
    key: &Key,
) -> Result<[u8; ENVELOPE_LEN]> {
    let pk = parse_recipient(recipient)?;
    let (enc, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &pk,
        info,
        key.expose(),
        header,
    )
    .map_err(|_| Error::new(ChurStatus::InternalFailure, "recipient key seal failed"))?;
    let mut envelope = [0; ENVELOPE_LEN];
    enc.write_exact(&mut envelope[..ENCAP_LEN]);
    envelope[ENCAP_LEN..].copy_from_slice(&ciphertext);
    Ok(envelope)
}

/// Opens one bounded content-key envelope.
pub fn open_key(
    seed: &Key,
    info: &[u8],
    header: &[u8],
    envelope: &[u8; ENVELOPE_LEN],
) -> Result<Key> {
    let sk = <XWing as Kem>::PrivateKey::from_bytes(seed.expose()).map_err(|_| invalid_key())?;
    let encapsulation = envelope.first_chunk().ok_or_else(invalid_key)?;
    validate_encapsulation(encapsulation)?;
    let enc = <XWing as Kem>::EncappedKey::from_bytes(encapsulation).map_err(|_| invalid_key())?;
    let plaintext = Zeroizing::new(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeR::Base,
            &sk,
            &enc,
            info,
            &envelope[ENCAP_LEN..],
            header,
        )
        .map_err(|_| invalid_key())?,
    );
    let mut key = Key::zeroed();
    key.expose_mut().copy_from_slice(&plaintext);
    Ok(key)
}

/// Portable ML-DSA-65 device signing key.
pub struct IdentitySigner(SigningKey<MlDsa65>);

impl IdentitySigner {
    /// Restores the signing key from a dedicated random seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_seed(seed.into()))
    }

    /// Borrows the secret seed for an authenticated portable identity envelope.
    #[must_use]
    pub fn seed(&self) -> &[u8; 32] {
        self.0.as_seed().as_ref()
    }

    /// Returns the public membership key.
    #[must_use]
    pub fn public(&self) -> [u8; VERIFY_LEN] {
        self.0.verifying_key().encode().into()
    }

    /// Signs a canonical record with its protocol domain tag.
    #[must_use]
    pub fn sign(&self, record: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(record).encode().into()
    }
}

/// Verifies an ML-DSA-65 signature over the complete domain-separated record.
pub fn verify(
    public: &[u8; VERIFY_LEN],
    record: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    let failure = || {
        Error::new(
            ChurStatus::AuthenticationFailed,
            "device signature did not verify",
        )
    };
    let pk = VerifyingKey::<MlDsa65>::decode(public.into());
    let sig = Signature::<MlDsa65>::try_from(signature.as_slice()).map_err(|_| failure())?;
    pk.verify(record, &sig).map_err(|_| failure())
}

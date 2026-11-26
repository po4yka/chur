//! Interoperability with Go's independent HPKE and ML-DSA providers.
#![allow(clippy::expect_used)]
use chur_crypto::Key;
use chur_crypto::post_quantum::{IdentitySigner, open_key, recipient_public, seal_key, verify};

const INFO: &[u8] = b"CHUR\0INBOX\0KEY\0V2";
const HEADER: &[u8] = b"CHURIN02";
const MESSAGE: &[u8] = b"CHUR\0PQ\0VECTOR\0V2";

#[test]
fn authenticated_recipient_envelope_matches_go() {
    let seed = Key::new([0x42; 32]);
    let pk = include_bytes!("../../../../test-vectors/internal-pq/recipient-public.bin");
    let envelope = include_bytes!("../../../../test-vectors/internal-pq/inbox-envelope.bin");
    assert_eq!(&recipient_public(&seed).expect("public key"), pk);
    assert_eq!(
        open_key(&seed, INFO, HEADER, envelope)
            .expect("Go envelope")
            .expose(),
        &[0xa5; 32]
    );
    let local = seal_key(pk, INFO, HEADER, &Key::new([9; 32])).expect("seal");
    assert_eq!(
        open_key(&seed, INFO, HEADER, &local)
            .expect("open")
            .expose(),
        &[9; 32]
    );
    assert!(open_key(&seed, INFO, b"CHURIN01", envelope).is_err());
    assert!(open_key(&seed, b"other purpose", HEADER, envelope).is_err());
    assert!(open_key(&Key::new([0x43; 32]), INFO, HEADER, envelope).is_err());
    let mut weak_key = *pk;
    weak_key[1184..].fill(0);
    assert!(seal_key(&weak_key, INFO, HEADER, &seed).is_err());
    let mut corrupted = *envelope;
    corrupted[0] ^= 1;
    assert!(open_key(&seed, INFO, HEADER, &corrupted).is_err());
}

#[test]
fn device_signature_matches_go() {
    let signer = IdentitySigner::from_seed(&[0x24; 32]);
    let pk = include_bytes!("../../../../test-vectors/internal-pq/device-public.bin");
    let signature = include_bytes!("../../../../test-vectors/internal-pq/device-signature.bin");
    assert_eq!(&signer.public(), pk);
    assert_eq!(&signer.sign(MESSAGE), signature);
    verify(pk, MESSAGE, signature).expect("Go signature");
    assert!(verify(pk, b"other record", signature).is_err());
    let mut corrupted = *signature;
    corrupted[0] ^= 1;
    assert!(verify(pk, MESSAGE, &corrupted).is_err());
}

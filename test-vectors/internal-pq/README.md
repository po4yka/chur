# Internal recipient and signature vectors

Go 1.27.4 generated the binary hybrid HPKE and ML-DSA fixtures with its standard library. The Rust integration test reads the files directly. All repeated-byte seeds below are public test data.

| File | Origin |
|---|---|
| `recipient-public.bin` | `crypto/hpke.MLKEM768X25519().NewPrivateKey` with 32 bytes of `42` hex. Serialize the public key. |
| `inbox-envelope.bin` | Use that public key with `hpke.NewSender`, HKDF-SHA256 and ChaCha20-Poly1305. Set info to ASCII `CHUR\0INBOX\0KEY\0V2`, where each `\0` is one zero byte. Seal 32 bytes of `a5` hex with AAD `CHURIN02`. Store the 1120-byte encapsulation followed by 48 bytes of ciphertext and tag. The sender used fresh randomness. |
| `device-public.bin` | `crypto/mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)` with 32 bytes of `24` hex. Serialize the public key. |
| `device-signature.bin` | Call `SignDeterministic` with that signing key, the message `CHUR\0PQ\0VECTOR\0V2` and an empty signature context. |
| `classical-operation.bin` | Original 237-byte Ed25519 operation from `test-vectors/v1/manifest.json`, case `operation-v1-signed-record` at `db82ed10`. The prototype rejects this input before it reads the payload. |
| `peer-session.bin` | Go 1.27.4 `crypto/hpke`, `crypto/hkdf` and `crypto/sha256`. One complete listener reply followed by its transcript hash, two traffic keys and signature binding. [Wire format and test inputs](../../docs/sync/PEER_PROTOCOL_V3.md#independent-vector) |

The sync protocol test uses `hpke-pq-05-a5.json`. This file contains the complete Base-mode vector for KEM 0x647a, KDF 0x0001 and AEAD 0x0003 from the working group's draft-05 tag. Run `cargo test --locked -p chur-sync-protocol hybrid_hpke_matches_draft_05_appendix_a5` from `rust/`. [Pinned source JSON](https://github.com/hpkewg/hpke-pq/blob/6433c8fce0b8b749dfc86c1095081a88698ccfab/test-vectors.json) · [Published vector](https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.html#appendix-A.5)

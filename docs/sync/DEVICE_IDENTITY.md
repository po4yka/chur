# Device Identity

> **Status:** Accepted normative Phase 3 protocol

Device identity authenticates sync operations, enrollment, and collection grants. It is separate from transport authentication and from local vault-unlock credentials.

## 1. Key separation

Proposed per-device keys:

```text
Ed25519 signing key pair
X25519 HPKE/key-agreement key pair
```

Do not reuse one key pair across signature and KEM roles. Public keys are peer-visible; private keys are wrapped under a root-derived identity key and optionally additionally gated by platform protection.

## 2. Device identifier

`device_id` is random and bound to public keys through a signed enrollment record. User-facing device names are encrypted private metadata and are not cryptographic identifiers.

## 3. Enrollment

Initial device:

1. create vault and identity keys locally;
2. sign self-enrollment/root device record;
3. publish public record;
4. store private keys encrypted under root identity domain.

Additional device:

1. establish a direct authenticated peer connection;
2. generate keys on new device;
3. existing authorized device or recovery flow verifies new keys;
4. authorized device signs enrollment including capabilities and sequence;
5. transfer the signed record directly;
6. new device receives required encrypted root/collection state;
7. all devices update accepted membership.

There is no login. Only explicit fingerprint-verified enrollment authorizes a fresh decryption identity.

## 4. Enrollment record

`EnrollmentRecordV1` is exactly 270 bytes:

```text
protocol_version:u16                         = 0x0001
vault binding:bytes[16]
device_id:bytes[16]
signing_suite:u16                            = 0x0001 (Ed25519)
signing_public_key:bytes[32]
hpke_suite:u16                               = 0x0001 (RFC 9180 X25519/HKDF-SHA-256/ChaCha20-Poly1305)
hpke_public_key:bytes[32]
capabilities:u64                             = 0x0000000000000001 for v1 sync
created_sequence:u64
issuer_device_id:bytes[16]
membership_generation:u64
previous_membership_commitment:bytes[32]
bootstrap_checkpoint_commitment:bytes[32]
issuer_signature:bytes[64]
```

The signature input is `CHUR\x00SYNC\x00ENROLLMENT\x00V1` followed by every field except `issuer_signature`. `created_sequence` equals the containing operation's `device_sequence`; the outer operation issuer and `issuer_device_id` must match. Generation 1 is self-enrollment: issuer equals enrolled device, `created_sequence` is 1, and both commitments are zero. Every later enrollment increments the accepted membership generation by one, names its current membership commitment, and carries a non-zero checkpoint commitment.

`bootstrap_checkpoint_commitment` is BLAKE3-256 over the issuing device's current `CheckpointV1`, defined in [`ROLLBACK_PROTECTION.md`](ROLLBACK_PROTECTION.md) §6. Together with `membership_generation` it is the enrolling device's signed statement of what the vault's history was at enrollment, and it is what gives the new device a freshness floor before it has one of its own. It is 32 bytes, so it also fits the out-of-band payload of §5; the checkpoint record itself is fetched through the peer and accepted only when it hashes to this value.

### 4.1 Membership commitment

After accepting an enrollment or revocation, the new membership commitment is BLAKE3-256 over `CHUR\x00SYNC\x00MEMBERSHIP-CHAIN\x00V1`, one record-kind byte (`0x01` enrollment, `0x02` revocation), and the complete signed canonical membership record. The record already carries the previous commitment and next generation, so this forms one append-only membership chain. Unknown kinds and generation skips are rejected.

## 5. Verification

The device fingerprint is the one value every platform displays for a device:

```text
device_fingerprint = BLAKE3-256(
      "CHUR\x00IDENTITY\x00FINGERPRINT\x00V1"
   || vault binding:bytes[16]
   || device_id:bytes[16]
   || signing_public_key:bytes[32]
   || hpke_public_key:bytes[32]
)
```

The domain tag is a fixed ASCII byte constant with no length prefix, allocated in [`../format/CANONICAL_ENCODING_V1.md`](../format/CANONICAL_ENCODING_V1.md) §15.5; the four elements follow in the order above with no length prefixes, 96 bytes of input in total. Both public keys enter it, so substituting either one changes the string.

Display is the leading 160 bits of the digest as 40 lowercase hexadecimal digits, most significant byte first, in ten groups of four separated by one space: a 49-character string, identical on Android, iOS, and the CLI, never truncated further and never re-grouped by locale.

160 bits is the security parameter. A peer substituting a device's keys must find a key pair whose leading 160 digest bits match those of the real device, a preimage search of about 2^160 operations. A birthday collision between two key pairs of the peer's own choosing costs about 2^80 and does not help, because the user compares against a fixed real device. A shorter spoken string was rejected: one string per device removes the chance of comparing the weaker of two.

The QR payload is the same 96 bytes of digest input, encoded as binary. The scanner recomputes the fingerprint from those bytes and compares it against the enrollment record it holds; it never trusts a rendered string carried inside the code. An enrollment QR additionally carries the 32-byte `bootstrap_checkpoint_commitment` of §4, 128 bytes in total.

Users verify a device through:

- QR scan between the two devices;
- comparison of the 40 digits, read aloud or side by side;
- comparison on an existing authorized device;
- recovery-mediated approval.

Peer-displayed names alone are not proof. Which of these is required and which is optional is fixed by [`PEER_TRUST_MODEL.md`](PEER_TRUST_MODEL.md).

## 6. Private-key protection

- encrypted at rest under dedicated root-derived domain;
- loaded only in authenticated session for signing/decryption operations;
- zeroized/evicted on lock;
- not stored in public Room/DataStore;
- portable recovery behavior explicitly chosen;
- no export through general FFI/application API.

Optional Secure Enclave/Android hardware identity keys require separate suite and interoperability ADR; default portable Rust keys simplify recovery and protocol consistency.

### 6.1 Root-wrapped identity envelope

`DeviceIdentityEnvelopeV1` is exactly 153 bytes:

```text
protocol_version:u16                         = 0x0001
encoding_profile:u16                         = 0x0001
signing_suite:u16                            = 0x0001 (Ed25519)
hpke_suite:u16                               = 0x0001 (X25519)
vault_id:bytes[16]
device_id:bytes[16]
identity_generation:u64                      = 1..0xFFFFFFFFFFFFFFFE
recovery_only:u8                             = 0x00 local or 0x01 recovery-only
nonce:bytes[24]
wrapped_identity:bytes[80]
```

The 64-byte plaintext is the 32-byte Ed25519 seed followed by the 32-byte X25519 private key. `wrapped_identity` is XChaCha20-Poly1305 ciphertext and its 16-byte tag. The wrapping key is `HKDF(VaultRootSecret, "chur/v1/root/device-identity-wrap", vault_id)` from [`../security/KEY_HIERARCHY.md`](../security/KEY_HIERARCHY.md). A local envelope uses purpose byte `0x00` and is opened only inside an unlocked Rust session. A portable backup envelope uses `0x01` and its API can only sign a replacement enrollment.

The AAD is the canonical tuple with tag `CHUR\x00IDENTITY\x00ENVELOPE\x00V1`, followed by `protocol_version`, `encoding_profile`, `signing_suite`, `hpke_suite`, `vault_id`, `device_id`, `identity_generation`, and `recovery_only`, in that order. The nonce is public and is not in the AAD because the AEAD construction authenticates it as an input. A decoder rejects another version, suite, length, generation, or purpose byte before it releases private key material. An opener also rejects a valid envelope whose purpose does not match the requested local or recovery operation.

## 7. Sequence and signing

Every device maintains a strictly increasing operation sequence. Signatures bind:

```text
device_id
sequence
previous operation hash
operation bytes
protocol version
```

Private key use must not sign arbitrary peer-provided bytes without domain/context validation.

## 8. Rotation

Key rotation creates a signed replacement record:

- new key generated locally;
- old signing key authorizes transition when available;
- recovery/quorum procedure used if old key unavailable;
- sequence and previous membership commitment prevent silent replacement;
- old key retained only for historical signature verification;
- compromise event may require collection epoch rotation.

## 9. Revocation

Revocation is a signed membership operation. `RevokeDeviceRecordV1` is the 194-byte payload of the `RevokeDevice` kind:

```text
protocol_version:u16                         = 0x0001
vault identity binding:bytes[16]
revoked_device_id:bytes[16]
final_accepted_device_sequence:u64
final_accepted_operation_digest:bytes[32]
membership_generation:u64
issuer_device_id:bytes[16]
previous_membership_commitment:bytes[32]
issuer_signature:bytes[64]
```

The signature input is `CHUR\x00SYNC\x00REVOCATION\x00V1` followed by every field except `issuer_signature`. The generation is exactly one above the accepted membership state, the previous commitment must equal that state, the issuer is an active device other than the target, and the outer operation issuer must match it. Sequence and digest are both non-zero for an authored branch. An enrolled device with no accepted operation can instead be revoked at exactly `(0, zero32)`; the local author requires no accepted target head or trusted floor. Receivers and the peer require the signed outer operation to omit the target from `observed_heads`; a concurrent relay copy is not the issuer's accepted history. Mixed zero/non-zero points are invalid. This closes a lost approval before the first `DeviceReady` operation.

The pair (`final_accepted_device_sequence`, `final_accepted_operation_digest`) is the accepted revocation point. The sequence is the highest the issuer had accepted from the revoked device; the digest is that operation's `operation_digest` per [`OPERATION_LOG.md`](OPERATION_LOG.md) §4, so the point names one branch and not merely a length, and `membership_generation` fixes which membership state the point belongs to. Canonical encoding and signature domain are versioned with the enrollment record of §4. Acceptance of operations against this point is normative in [`REVOCATION.md`](REVOCATION.md) §7.

After acceptance:

- future root/collection envelopes are not issued to device;
- collection keys rotate per [`REVOCATION.md`](REVOCATION.md) §3;
- subsequent direct sessions reject the revoked device once the revocation is known;
- old signatures remain verifiable;
- previously downloaded keys/plaintext remain outside enforceable deletion.

## 10. Device loss and recovery

A user can remove a lost device from another authorized device. If every physical identity device is lost, a current portable backup may carry the creating device's private identity in a root-wrapped `DeviceIdentityEnvelopeV1` under [ADR-0048](../adr/0048-recover-a-device-from-a-portable-identity-envelope.md).

The restored identity is recovery-only. It first enforces its backed-up checkpoint floor, reconstructs the authenticated log, and then signs an ordinary enrollment for a newly generated device identity. It never authors ordinary catalog changes and is destroyed after the replacement enrollment and a new backup commit. If authenticated current membership revoked the recovered identity, it cannot enroll a replacement.

A backup without the envelope still restores local content but needs another active device to re-enter the old membership. A stale backup with no peer or witness retains the rollback limitation of [`ROLLBACK_PROTECTION.md`](ROLLBACK_PROTECTION.md) §7.

## 11. Multi-vault/decoy

Real and decoy identities do not share device private keys or membership by default. Correlating them through shared invitations or active connections is forbidden.

## 12. Tests

- enrollment happy path and key substitution;
- duplicate/stale device ID;
- wrong issuer/signature/domain;
- sequence rollback/fork;
- key rotation with/without old device;
- revocation and stale operation rejection;
- recovery bootstrap;
- private-key storage/lock lifecycle;
- cross-platform signature/HPKE vectors.

# ADR-0073: Internal post-quantum profile

- **Status:** Experimental
- **Date:** 2026-11-26
- **Related:** [Device recovery](0048-recover-a-device-from-a-portable-identity-envelope.md), [incoming shares](0064-receive-system-shares.md), [peer sessions](0067-signed-peer-transcript-with-x25519.md), [release requirements](../CRYPTOGRAPHY.md#56-post-quantum-readiness)

## Decision

Use one mandatory public-key profile in this internal build. No user vaults need migration. The vault descriptor authenticates the private policy ID `0xff01`. Portable catalog exports carry the same private value in the export-version field. This separates the catalog with the larger keys and records from a classical catalog. Reject an unknown policy before installing or updating a vault.

| Purpose | Key holder and binding |
|---|---|
| Device signatures | Each device owns a separate 32-byte ML-DSA-65 seed. Sign the complete canonical record with its Chur domain. The native handshake reports major ABI 8. Verify the 3309-byte signature against the 1952-byte key in authenticated membership. This covers enrollment, revocation, operations, grants, checkpoints and peer authentication. |
| Recipient grants and pairing approval | Use HPKE Base, MLKEM768-X25519 (X-Wing, KEM 0x647a), HKDF-SHA256 and ChaCha20-Poly1305. Authorize the sender through its device signature. Bind the purpose, version, recipient and record fields. An object request uses an independent disposable key. |
| Peer sessions | Use a fresh hybrid recipient key for each connection. Retain the one-use invitation secret. Bind both flights and roles into the transcript and verify enrolled device signatures before releasing application frames. |
| Incoming share | Give the extension the 1216-byte public key. Keep its matching seed in the main app's device-local Keychain, accessible while unlocked. Wrap each random AES-256 item key with HPKE using the versioned inbox purpose. The queue has no vault-root credential. |
| Recovery | Wrap the two distinct device seeds under the root-derived identity wrapping key. Restore the device in recovery-only mode. Enforce the saved checkpoint and current revocation before enrollment. |
| Local content and portable factors | Retain the existing symmetric content keys and chunk format, Argon2id password slots and random recovery secret. A weak password still permits offline guessing. |

## Pairing and history sizes

A signed pairing request contains 6,559 bytes. The app transfers the request as 8,748 Base64 characters and uses a separate fingerprint for verification. The two users compare the full 256-bit digest over the identity fields through an independent channel. Its text has sixteen groups of four hexadecimal digits. The binary QR payload has 32 bytes. The current app offers text comparison and clipboard transfer.

To measure the cost of a signed history, build the CLI in release mode and run `chur-cli bench signed-history --records 1024 --samples 8`. The command decodes and verifies the signatures and chain links of each operation. It excludes storage and network latency. Use the OS profiler to record peak memory for the same process.

On an Apple M4 Pro, the optimized CLI verified 1,024 operations (3,565,568 bytes) per pass. In 12 passes with other builds active, wall-clock p50 was 1,233.5 ms, p95 was 1,735.7 ms and p99 was 2,042.0 ms. The OS reported 7,258,112 bytes maximum resident set size for the process including history creation. These figures describe a loaded development host. Device latency and memory remain open.

The unsigned ARM64 iPhone Release executable for the share extension grew from 272,640 bytes at `db82ed10` to 798,560 bytes in this profile, an increase of 525,920 bytes. Both measurements use the same Xcode target and SDK. They exclude the main app, bundle resources and distribution signing.

## Prototype verification

The Rust workspace passed 1,001 tests. The CLI verified 123 protocol vectors and 17 binary fixtures. Tests also checked the independent Go keys, signature, inbox envelope and peer-session transcript. The C ABI harness and both Cargo dependency-policy checks passed. Android ARM64 and x86-64 libraries passed the JNI export and 16 KiB ELF alignment checks. The debug APK installed on an Android API 35 ARM64 emulator and reached the public Notes screen. Apple ARM64 libraries passed the ABI checks for iPhone and the simulator.

Two vaults exchanged signed records over TCP through the Kotlin/JNI interface. Tests covered revocation, missing signed prefixes and refusal of classical data before durable staging. A backup test changed the identity suite inside an authenticated archive and checked that restore installed nothing. The simulator accepted an image from Photos through the system share sheet, wrote one encrypted CHURIN02 file and removed it on discard. Swift tests covered opening the encrypted item. The physical Android–iPhone exchange, minimum-OS device measurements and the complete private import through the iOS UI remain open. [Independent vectors](../../test-vectors/internal-pq/README.md) · [Local checks](../../DEVELOPMENT.md#build-commands)

## Dependencies and release decision

The internal implementation uses the existing MIT/Apache-2.0 rust-hpke 0.15.1 with its mlkem feature and RustCrypto ml-dsa 0.1.2 with zeroization. The lockfile pins x-wing 0.1.1 and ml-kem 0.3.4. Both RustCrypto x-wing and ml-dsa document the absence of an independent audit. The Rust implementations avoid OS-specific PQ APIs and retain the iOS 18 deployment target. Test the exact resolved build on each supported architecture when updating it. Review advisory status, binary size, peak memory and device latency before promotion. The checked-in Go fixtures test an independent implementation of the same recipient and signature suites. [hpke](https://docs.rs/crate/hpke/0.15.1) · [x-wing](https://docs.rs/crate/x-wing/0.1.1) · [ml-dsa](https://docs.rs/crate/ml-dsa/0.1.2)

The native handshake sets CHUR_FLAVOR_INTERNAL_PQ. Mobile release applications refuse this build before opening the vault. Internal applications can use an optimized native library for measurements.

The prototype targets the hybrid profile in draft-ietf-hpke-pq-05. The pinned Rust provider describes earlier draft revisions. Interoperability vectors apply to the exact parameters above. Before freezing a public profile, compare the final specification and errata against the implementation, repeat interoperability checks, and obtain independent review of the integrated protocol. Device acceptance must cover Android-to-iPhone enrollment, exchange, revocation, recovery and the iOS share extension on the minimum supported OS. Measure time to verify a long history, peak memory, package growth and QR payload size. Platform code signing and operating-system trust remain external dependencies. [HPKE draft 05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05) · [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) · [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)

[Peer protocol v3](../sync/PEER_PROTOCOL_V3.md) · [Apple inbox interface](../../apps/iosApp/InboxNative/chur_inbox.h)

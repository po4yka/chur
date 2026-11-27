# Internal ABI 8.4 supplement

The isolated internal app checks major ABI 8 and minor version 4 or later before it opens a vault. The library sets build-flavor bit 3, `CHUR_FLAVOR_INTERNAL_PQ`. The ordinary app expects major ABI 7. The [base FFI contract](FFI_CONTRACT.md) defines handle ownership, buffer conventions, status codes and integer encoding. The following records apply to the internal profile.

## Identity and pairing

`chur_sharing_identity` returns `version:u16 = 2`, the 16-byte vault ID, the 16-byte device ID, the 1,952-byte ML-DSA-65 public key and the 1,216-byte X-Wing public key. Three fields follow. Each starts with a big-endian four-byte length, then the fingerprint (79 ASCII bytes), the self-enrollment (6,619 bytes) or the canonical outer operation, respectively. A retry returns identical bytes. An insufficient output buffer gives `RESOURCE_LIMIT_EXCEEDED` and zero output bytes.

`chur_sharing_prepare` and `chur_sharing_inspect_enrollment` accept the 6,619-byte initial enrollment. Inspection verifies its self-signature and returns the version-1 preview with vault ID, device ID and length-prefixed fingerprint. `chur_device_pairing_inspect` accepts an exact 6,559-byte pairing request. Compare the fingerprint from the authenticated record with the full digest received independently. The verification QR carries 32 bytes.

## Object-key grants

| Operation | Internal encoding |
|---|---|
| Request | Input is the collection ID followed by the object ID. Output is one zero byte when the key is already available, or `0x01` followed by a 4,655-byte signed prekey. |
| Issue | Input is the 4,655-byte prekey. Output is the 4,679-byte object-key grant. |
| Accept | Input is `u32(package_length) \|\| acceptance_package \|\| u32(4679) \|\| grant`. |

The native verifier checks the prekey and its recipient, enforces its lifetime and applies the existing deletion policy. After a successful acceptance, local custody follows the object envelope and tombstone rules.

## Synchronization and peer calls

The locked receiver checks each version and canonical encoding before staging any part of a page. `chur_sync_stage` supports up to 256 signed operations in one page, with a 16 MiB limit on the complete staging input. The unlocked processor verifies the signatures and checks dependencies. Classical records cannot enter the internal inbox.

The transport is `CHURP2P3`. Poll returns a ready connection only after the enrolled remote key verifies the signed transcript. The peer input limit is 4 MiB plus 256 bytes. The caller supplies capacity for 4 MiB plus one byte for receive, 2 MiB for history (command 8), 16 KiB for pairing evidence (10), 4,679 bytes for an object key (11) and 1 MiB for a ciphertext range (12). Command 13 takes a four-byte big-endian length and the peer checkpoint. It confirms that the authenticated device signed the checkpoint and that all required operation digests are locally available. Success returns zero bytes. A missing prefix gives `RECOVERY_REQUIRED`. [Peer protocol and history bounds](../sync/PEER_PROTOCOL_V3.md)

Use the internal builder to produce the matching library, adapters, C header and executable in one source tree. A profile change does not migrate historical storage or device identities. [Build instructions](../../DEVELOPMENT.md#internal-post-quantum-build) · [Profile decision](../adr/0073-internal-post-quantum-profile.md)

# Direct peer synchronization

> **Status:** Accepted P2P transport contract; [ADR-0065](../adr/0065-peer-only-sync-without-accounts.md)

## 1. Scope

Two unlocked Chur apps synchronize their own vault over a direct, ephemeral TCP connection. There is no account, backend deployment, HTTP API, bootstrap credential, durable network token, cloud store, relay, or background worker. The current UI takes literal IPv4 addresses. Both devices must have a direct route; automatic discovery and NAT traversal are not implemented.

Signed operation, checkpoint, membership, and object-key formats retain their independently versioned canonical encodings. Rust alone validates them. This transport replaces all previous service-based synchronization behavior.

## 2. Pairing

Restore an encrypted portable backup on the new device. Prepare its fresh pairing request. Transfer the request to an ordinary device, compare the device fingerprint on both screens, and explicitly approve whole-vault access. The approval is HPKE-encrypted for the requesting identity and contains no network address or transport token. Open the approval file on the new device, then connect directly to the approving device. Native finalization requires the pinned checkpoint and every signed ancestor before installing the ordinary identity. Recovery credentials are not remote accounts.

## 3. Invitation and handshake

The ordinary device enters its reachable IPv4 address and creates a one-time invitation `IPv4:port#secret_hex`. Rust chooses a temporary port and a fresh 32-byte OS-random secret. Rust binds the listener only to the entered interface address. The other device enters the invitation and connects directly. A connection does not use the invitation until it proves the secret: its first encrypted frame must open under the derived keys. Until then, the listener sends only its hello. It closes a connection that sends a different hello, a frame that does not open, a first frame larger than the sealed authentication record, or nothing within ten seconds, and it continues to listen. The first frame of an unproven connection can be at most 112 bytes: the 96-byte record of §3.2 and the 16-byte tag, after its 4-byte length. The listener buffers at most 232 bytes of an unproven connection: the 72-byte hello, the 96-byte frame limit, and 64 bytes for the frame length, the tag, and the start of the next read. A first frame that opens but holds a record that does not verify ends the invitation with `AUTHENTICATION_FAILED`. At most four unproven connections are examined at the same time. After 32 failed connections, or two minutes without a proven connection, the invitation closes with a failure. The first proven connection closes the listener. There is no DNS lookup, discovery registry, or external infrastructure.

### 3.1 Version 2 key exchange

The peer protocol is version 2 ([ADR-0067](../adr/0067-signed-peer-transcript-with-x25519.md)). Each endpoint generates a fresh X25519 key pair for each connection and writes the 72-byte hello `CHURP2P2 || random_challenge[32] || x25519_public_key[32]`. A connector that receives the version-1 magic `CHURP2P1` fails with `UNSUPPORTED_VERSION`. A listener counts a version-1 hello as a failed connection, closes it, and continues to listen. Any host can send that hello, so the listener reports `UNSUPPORTED_VERSION` only if the invitation then closes without a proven connection. Any other magic is `AUTHENTICATION_FAILED`.

The transcript hash is SHA-256 over `CHUR\0P2P\0TRANSCRIPT\0V2 || initiator_hello || listener_hello`. Each endpoint computes the X25519 shared secret and refuses a low-order remote key. `PeerHandshakeSecret` is `invitation_secret[32] || x25519_shared_secret[32]`. The registered HKDF derivation of [KEY_HIERARCHY.md](../security/KEY_HIERARCHY.md) §3 derives from it:

- `chur/v1/peer/session` with context `transcript_hash || direction`: direction 1 is initiator to listener; direction 0 is listener to initiator;
- `chur/v1/peer/transcript-binding` with context `transcript_hash`: the 32-byte session binding that each device signature covers.

The ephemeral private keys are erased after the derivation. Disclosure of the invitation secret after the session does not decrypt recorded traffic. No invitation, ephemeral, or connection key is saved.

### 3.2 Device authentication

The first frame in each direction is the authentication record `vault_id[16] || device_id[16] || signature[64]`. The signature is Ed25519 with the enrolled device signing key over `CHUR\0P2P\0AUTH\0V2 || role || vault_id || device_id || transcript_hash || session_binding`. The initiator signs role 1 and the listener signs role 0. The signed transcript thus covers both hellos, both ephemeral public keys, both challenges, and the invitation secret through the binding.

The initiator sends its record directly after the key exchange. The listener sends its record only after the initiator record verifies. Rust verifies a record against the enrolled key of the claimed device. The claimed vault must be the local vault, and the claimed device must be another active member. An ordinary device uses its current membership. A device with a verified pending approval signs with its approved identity and uses the membership in the approval authority records. A record that opens under the session key but does not verify fails the invitation with `AUTHENTICATION_FAILED`. A record from another session does not verify, because the transcript hash and the binding are different.

Native code does not send or receive a caller frame and does not return device history until the remote record verifies. Poll returns true only after that point.

## 4. Frames

A frame is `sealed_length:u32_be || XChaCha20Poly1305(plaintext, nonce, aad)`. Plaintext is bounded at 4 MiB and ciphertext at 4 MiB + 16 bytes. Each direction starts at sequence zero. Its nonce is sixteen zero bytes followed by its 64-bit big-endian sequence, and its AAD is that same sequence. Direction keys differ and are fresh for every handshake. Sequence exhaustion closes the session. Unauthenticated plaintext is never exposed. Native IO pumps are bounded and nonblocking; connection establishment has a three-second timeout, and idle IO has a two-minute timeout.

## 5. Exchange

Encrypted application frames contain bounded JSON `PeerMessage` control records. Binary canonical records remain opaque byte arrays. The vault ID and the remote device ID come only from the signed transcript of §3.2. Before the exchange, each endpoint asks native code for the authenticated device, and native code also confirms that the device is active in the current local membership. Unknown, revoked, and self-asserted devices are rejected before any heads, checkpoint, history, key, or object is served.

The connector pulls from the listener, then the endpoints exchange roles. A source prepares signed ordinary media and album operations from native-verified committed local containers. A receiver requests device heads and bounded per-device signed history pages, stages records, and applies them through native causal validation. Wire pagination positions never advance durable accepted heads. Every advertised head must be reached, and a native-verified source checkpoint must have no pending dependencies.

If initial pairing is pending, native finalization follows that signed-history verification. Missing originals are requested from native receive plans. Disposable prekey requests and addressed signed grants deliver object keys directly. Ciphertext transfers in ranges of at most 256 KiB, resumes from the locally retained prefix, and activates an object only after complete container verification. The existing deterministic conflict and tombstone rules remain in force. Private notes, album parent/order/deletion, and other local-only data remain outside the existing media/album operation contract.

The connector sends `turn` after its pull; the listener pulls while the connector handles requests. The listener then sends `complete`, and the connector acknowledges `complete`. Only this two-way completion reports success. Missing data, unresolved dependencies, failed authentication, interruption, and resource limits report failure or cancellation and preserve already committed local work.

## 6. Lifetime

Connections run only on an explicit foreground action. Stop cancels the run and closes the native connection. Vault lock and session close destroy the socket and keys independently of app coroutine cleanup. No periodic Android work, iOS background task, locked transfer, persisted endpoint, or automatic unlock-time connection exists.

## 7. Limits

No third-device service supplies absent data. A missing original requires reconnecting to a peer that retains it. There is no delivery while a device is offline and no guarantee that a peer erased a copy. See [PEER_TRUST_MODEL.md](PEER_TRUST_MODEL.md).

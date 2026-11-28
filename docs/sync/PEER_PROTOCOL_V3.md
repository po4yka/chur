# Internal peer transport version 3

The isolated post-quantum build offers one foreground invitation. Ordinary release devices use the [version-2 peer protocol](../adr/0067-signed-peer-transcript-with-x25519.md). The invitation text is
`chur-p2p3/IPv4:port#secret_hex`. The secret is 32 random bytes. Only the
literal interface address goes to the listener. An unversioned invitation or
a different protocol version fails before the client connects.

## Exchange

The connector generates a fresh 32-byte X-Wing private seed for each TCP
connection. The recipient public key contains the ML-KEM-768 and X25519
components. The listener creates a fresh random 32-byte session secret. Each
side also generates its own independent random 32-byte challenge.

| Flight | Bytes in order | Size |
| --- | --- | --- |
| Connector offer | ASCII `CHURP2P3`, role byte `01`, challenge, X-Wing public key | 1,257 |
| Listener reply | ASCII `CHURP2P3`, role byte `00`, challenge, X-Wing encapsulation, sealed session secret | 1,209 |

The listener seals the secret to the ephemeral recipient with HPKE base mode,
X-Wing (`0x647a`), HKDF-SHA-256 and ChaCha20-Poly1305. The HPKE info is
`CHUR\0P2P\0HANDSHAKE\0V3` where each `\0` is one zero byte. Associated data
is the complete offer followed by the first 41 bytes of the reply. The
encapsulation is 1,120 bytes and the ciphertext with its tag is 48 bytes.
Reject a noncontributory X25519 component in either flight. The connector
consumes its private seed when it opens the reply.

Compute SHA-256 of `CHUR\0P2P\0TRANSCRIPT\0V3 || offer || reply`. The HKDF
input is `invitation_secret || session_secret` (64 bytes). Use the existing
Chur HKDF salt, info encoding and labels. The context for
`chur/v1/peer/session` is the transcript hash followed by the direction byte
(1 for connector to listener, 0 for listener to connector). The context for
`chur/v1/peer/transcript-binding` is the transcript hash.

## Device proof and limits

The first encrypted frame from each device contains its vault ID, device ID
and ML-DSA-65 signature. The connector sends its proof first. Verify the
signature with the enrolled public key for that device, over the version-3
authentication domain, role, vault ID, device ID, transcript hash and secret
session binding. The listener verifies the connector before it sends its own
proof. Either side must verify the remote proof before it can exchange caller
frames. A connection with another protocol version fails without negotiation.

The listener bounds concurrent candidates at four and failed candidates at 32.
Before authentication, either endpoint buffers at most the expected flight
and one proof frame (3,341 plaintext bytes and 20 bytes for the length and
AEAD tag). After authentication a caller frame carries at most 4 MiB.
A coalesced TCP read leaves subsequent bytes in the socket until the next
frame can be processed. Both roles close an incomplete handshake after ten seconds. The invitation and established connection retain their existing
120-second deadlines.

## Signed history delivery

The `history` response carries the native page as a base64 string in its
`history` field. The native limit is 2 MiB, including each sequence and record
length, with at most 256 records. Its base64 text fits the 4 MiB frame even for
a full page.

A receiver stages a history page only after it checks the count, byte bound,
contiguous sequence numbers, and canonical record versions. While unlocked,
it verifies operation signatures and replays dependencies before accepting
the advertised heads. It processes the signed peer checkpoint for rollback
evidence and checks its issuer against the authenticated device. Each signed
head at or below its revocation cutoff must match a locally accepted operation
digest before the device reports that the transfer is complete.

## Independent vector

`test-vectors/internal-pq/peer-session.bin` contains a Go 1.27 listener reply
followed by four 32-byte fields in order: transcript hash, connector sending
key, listener sending key and signature binding. The vector uses repeated
bytes for the connector seed (`42`), connector challenge (`11`), listener
challenge (`22`), session secret (`33`) and invitation secret (`44`), all
hexadecimal. Go's standard `crypto/hpke` generated the encapsulation and
ciphertext, and `crypto/sha256` and `crypto/hkdf` supplied the expected
transcript and keys. It is public test material. Rust checks the fixture in
the `chur-crypto` suite.

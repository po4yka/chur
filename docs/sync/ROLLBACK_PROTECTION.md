# Rollback, Replay, and Fork Protection

> **Status:** Accepted Phase 3 security model

AEAD and signatures prove authenticity, not freshness or completeness. Chur uses local accepted heads, per-device chains, membership generations, and checkpoints to reject common rollback/replay attacks while documenting malicious-peer limitations.

## 1. Attack classes

- replay identical accepted operation;
- present older prefix as current history;
- omit tombstone or membership change;
- present two different records at same device sequence;
- roll back collection epoch/grant;
- restore old but authentic object/catalog/backup;
- show different histories to different devices;
- erase all local freshness state then present stale peer state.

## 2. Local trusted state

Each device stores, inside protected authenticated catalog state:

```text
membership generation/commitment
latest accepted sequence and hash per device
latest accepted checkpoint commitment
global/materialized state generation when defined
collection epochs and grant generations
```

A peer response below a local accepted head is rejected as rollback.

## 3. Replay

An identical operation already applied is idempotently ignored/acknowledged. A non-identical operation with the same `(device_id, sequence)` is a fork.

Operation IDs alone are not freshness proof.

## 4. Fork handling

On fork:

- stop applying that device's subsequent chain. Every other device's chain keeps applying: a fork is scoped to the forked chain, and freezing the whole vault would let one forged record stop the account;
- retain as evidence the two conflicting signed records at the shared sequence and the last head accepted before them;
- enter the fork state below;
- do not let peer choose branch silently.

The fork state is per (vault, device), persisted in the encrypted catalog, and holds one of three values:

```text
detected        set when the conflicting record is seen; the chain freezes and the user is told
acknowledged    set when the user has seen the report; the chain stays frozen
resolved        set only by reconciliation or by an accepted revocation; the state clears
```

Reconciliation is one procedure. On a device holding a checkpoint issued before the fork, the branch whose head that checkpoint commits to under §6 is the true branch, and the other is discarded with its evidence retained. When no device holds such a checkpoint, reconciliation is impossible and the only exit is revoking the forked device under [`REVOCATION.md`](REVOCATION.md) §2. The user does not pick a branch by hand: that choice is exactly what an equivocating peer wants to influence.

The state is surfaced through the `SYNC_CHAIN_FORK` and `SYNC_HEAD_ROLLBACK` codes of [`../ERROR_MODEL.md`](../ERROR_MODEL.md). Neither is retryable, and both persist until the state clears.

## 5. Membership and key epochs

Device enrollment/revocation and collection epoch changes are signed, monotonically versioned state. Old grants/epochs cannot replace newer accepted state even if cryptographically valid.

## 6. Checkpoints

A checkpoint is one device's signed statement of the history it had accepted. It is a standalone record, not an operation, so it never advances a device chain:

```text
CheckpointHeadV1 =
    device_id:bytes[16]
    device_sequence:u64
    operation_digest:bytes[32]

CheckpointV1 =
    protocol_version:u16
    vault binding:bytes[16]
    issuer_device_id:bytes[16]
    issuer_device_sequence:u64
    membership_generation:u64
    membership_commitment:bytes[32]
    heads:list of CheckpointHeadV1
    collection_epoch_commitment:bytes[32]
    catalog_state_commitment:bytes[32]
    issuer_signature:bytes[64]
```

Encoding follows [`../format/CANONICAL_ENCODING_V1.md`](../format/CANONICAL_ENCODING_V1.md): a `u32` count followed by 56-byte elements sorted by ascending `device_id`, with duplicates and unsorted entries rejected. `operation_digest` is the value defined in [`OPERATION_LOG.md`](OPERATION_LOG.md) §4, so a checkpoint pins a branch and not only a length. Unlike `observed_heads` the list includes the issuer's own head, so it holds at most 32 entries. A revoked device stops counting against the 32-device maximum ([`OPERATION_LOG.md`](OPERATION_LOG.md) §4.2), and its signed revocation cutoff pins its chain up to that point, so the list leaves out a revoked device whose accepted head is at or behind the cutoff. The list names the head of every active device first. A revoked head above the cutoff, accepted concurrently with the revocation, or at the cutoff with another digest, is named as a retained historical claim only while a slot remains: those heads fill the slots the active heads leave free in ascending `device_id` order, and the rest are left out. The Ed25519 signature covers the whole record except the signature field, under the checkpoint domain tag registered in §15.5 of the encoding profile.

The portable `checkpoint_commitment` is BLAKE3-256 over `CHUR\x00SYNC\x00CHECKPOINT-COMMITMENT\x00V1` followed by the complete signed canonical checkpoint bytes. It is this value that enrollment, recovery, and backup records carry; a zero value means no checkpoint only for generation-1 self-enrollment.

One device signs. There is no quorum: a quorum rule needs a membership the receiver already trusts, and membership is exactly what is under attack after state loss, so the rule would be circular. What a checkpoint is trusted for instead:

- a device trusts its own checkpoints as its freshness floor after local state loss, when one is recovered from a portable backup or from the enrollment attestation of §7;
- a checkpoint issued by another device is accepted only as a lower bound, and only to raise the receiver's floor, never to lower it. Raising a floor can reject more peer responses and never fewer, so a checkpoint that overstates heads costs availability rather than integrity, and it is signed evidence of who overstated them;
- a checkpoint naming a head at a sequence the receiver accepted with a different `operation_digest` is fork evidence under §4;
- no checkpoint proves the peer hid nothing that no signer had seen. Completeness still needs direct cross-device comparison.

Current signed revocation bounds these floors. A checkpoint head above that device's signed cutoff is retained as a historical claim, but creates no new floor, so an issuer may leave it out when the list is full, and a checker treats every head of a revoked device as optional. For a revoked device the signed cutoff, not the checkpoint, is the completeness evidence for its chain up to the cutoff: a checkpoint omits that head, so a device that bootstraps from it gets no floor for the chain, and fork detection below the cutoff rests on the branch check of revoked-chain acceptance ([`REVOCATION.md`](REVOCATION.md) §7). A previously retained above-cutoff floor is ignored on reconstruction and retired when a valid checkpoint is accepted. Bootstrap applies the same rule. The signed checkpoint bytes are not rewritten. Below-cutoff digest checks and active-device floors remain in force; no checkpoint restores revoked-device authorization.

A device issues a checkpoint at the end of every sync session in which it accepted an operation, and includes its latest one in every portable backup. It retains its own latest checkpoint and the latest it has accepted from each other device.

### 6.1 Collection and catalog commitments

`collection_epoch_commitment` is BLAKE3-256 over `CHUR\x00SYNC\x00COLLECTION-EPOCHS\x00V1` followed by every `(collection_id:bytes[16], current_epoch:u64)` entry. Entries use ascending `collection_id` order, with no count or separator. Duplicate identifiers and epoch zero are invalid. An empty vault commits to the domain tag alone.

Claims with the same accepted head frontier are unordered; this digest does not create an epoch floor. Readers validate actual epoch and grant state from signed operations, and the relay retains exact checkpoint records for enrollment and retry proofs.

V1 does not compact signed operation history and has no portable materialized-catalog snapshot. Its `catalog_state_commitment` is therefore exactly 32 zero bytes. A V1 reader rejects any other value as an unsupported snapshot format. Object ciphertext and local catalog rows can still complete the tombstone GC flow, but the signed operations and tombstones remain available for bootstrap and stale devices.

## 7. Device loss and reinstall

If all local accepted heads are lost, a malicious peer may present an older authentic history. Mitigations:

- portable backup containing authenticated heads;
- recovery record/checkpoint stored separately;
- comparison with another authorized device;
- future transparency/witness service;
- user-visible backup/checkpoint date after authentication.

A device enrolling for the first time starts from the same empty state but is not the same case: an authorized device is present. Its signed enrollment record carries `membership_generation` and `bootstrap_checkpoint_commitment` per [`DEVICE_IDENTITY.md`](DEVICE_IDENTITY.md) §4, and the new device sets its initial floor from the checkpoint that commitment names before it accepts any operation. Membership, epoch, or head state below that floor is rejected as rollback, so first enrollment does not begin at a null high-water mark and a peer colluding with a revoked device cannot present a pre-revocation membership to it.

Reinstall with no backup and no reachable peer keeps the residual risk. V1 must state that residual risk rather than claim perfect rollback protection.

A portable identity envelope does not remove this limitation. It lets a recovered active identity sign one replacement enrollment, but its backed-up checkpoint remains the only freshness floor. The recovered identity is recovery-only and cannot author ordinary operations; [ADR-0048](../adr/0048-recover-a-device-from-a-portable-identity-envelope.md) defines the lifecycle.

## 8. Offline backups

Backups are authentic but can be stale. Restore compares embedded heads/generations with any surviving trusted local/peer state. User may intentionally restore older state, which creates a new recovery branch under explicit policy rather than silently overwriting newer sync state.

## 9. Peer omission

Per-device chains detect gaps after a known later sequence. The `observed_heads` vector defined in [`OPERATION_LOG.md`](OPERATION_LOG.md) §4 extends detection across devices: any accepted operation that observed a hidden operation names its head, so the receiver buffers instead of applying state that is missing a known cause. To hide a branch the peer must also hide every operation that observed it. It may still hide an entire device whose operations no other device has observed, or all operations after the client's last checkpoint. Cross-device gossip or transparency is required for stronger global completeness.

## 10. Time

Wall-clock timestamps are not rollback proof. They may aid UX after decryption but ordering is based on signed sequence/causal state.

## 11. Tests

- exact duplicate replay;
- modified record same sequence;
- old prefix after newer local head;
- missing middle operation;
- forked device branches;
- stale membership/collection epoch/grant;
- reinstall with and without trusted backup/peer;
- first enrollment where the peer offers membership, collection epochs, or per-device heads below the attested bootstrap checkpoint;
- equivocation between two devices;
- intentional old-backup restore;
- checkpoint signature/commitment corruption;
- revoked device branch.

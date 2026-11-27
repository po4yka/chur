//! Client behavior when an untrusted relay rewrites or withholds protocol state.

#![allow(clippy::expect_used, clippy::panic)]

use chur_core::{ChurStatus, Id};
use chur_crypto::{Key, Nonce};
use chur_sync_protocol::checkpoint::{Checkpoint, CheckpointHead};
use chur_sync_protocol::membership::EnrollmentRecord;
use chur_sync_protocol::operation::{DeviceSigningKey, Operation};
use chur_sync_protocol::operation_log::{ApplyOutcome, CheckpointOutcome, OperationLog};
use chur_sync_protocol::state::MembershipState;

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).expect("id")
}

fn operation(key: &DeviceSigningKey, sequence: u64, previous: [u8; 32], marker: u8) -> Operation {
    Operation::seal(
        id(marker),
        id(1),
        id(2),
        sequence,
        previous,
        Vec::new(),
        id(3),
        &Key::new([4; 32]),
        Nonce::new([marker; 24]),
        &[marker],
    )
    .expect("operation")
    .sign(key)
}

#[test]
fn replay_omission_key_substitution_rollback_and_equivocation_fail_closed() {
    let owner_key = DeviceSigningKey::from_seed([5; 32]);
    let initial = EnrollmentRecord::initial(id(1), id(2), owner_key.verifying_key(), [6; 32])
        .expect("initial enrollment")
        .sign(&owner_key);
    let membership = MembershipState::bootstrap(&initial).expect("membership");
    let first = operation(&owner_key, 1, [0; 32], 7);
    let second = operation(&owner_key, 2, first.digest(), 8);

    let mut replayed = OperationLog::new();
    assert_eq!(
        replayed.accept(&first, &membership).expect("first"),
        ApplyOutcome::Applied
    );
    assert_eq!(
        replayed.accept(&first, &membership).expect("replay"),
        ApplyOutcome::Duplicate
    );
    assert_eq!(
        replayed.accept(&second, &membership).expect("second"),
        ApplyOutcome::Applied
    );

    let mut omitted = OperationLog::new();
    assert_eq!(
        omitted.accept(&second, &membership).expect("omission"),
        ApplyOutcome::PendingGap
    );
    assert!(omitted.head(&id(2)).is_none());

    let attacker_key = DeviceSigningKey::from_seed([9; 32]);
    let forged = operation(&attacker_key, 1, [0; 32], 10);
    assert_eq!(
        OperationLog::new()
            .accept(&forged, &membership)
            .expect_err("substituted key")
            .status(),
        ChurStatus::AuthenticationFailed
    );

    let checkpoint = Checkpoint::new(
        id(1),
        id(2),
        2,
        membership.generation(),
        *membership.commitment(),
        vec![CheckpointHead::new(id(2), 2, second.digest())],
        [11; 32],
        [0; 32],
    )
    .expect("checkpoint")
    .sign(&owner_key);
    let mut rollback = OperationLog::new();
    assert_eq!(
        rollback
            .accept_checkpoint(&checkpoint, &membership)
            .expect("checkpoint"),
        CheckpointOutcome::Raised
    );
    // Building toward the floor is progress, not rollback: the floor still
    // refuses to be lowered, and a contradicting branch at its own sequence is
    // still fork evidence, which the rest of this test asserts.
    assert_eq!(
        rollback
            .accept(&first, &membership)
            .expect("toward the floor"),
        ApplyOutcome::Applied
    );
    assert_eq!(rollback.head(&id(2)), Some((1, first.digest())));
    assert_eq!(
        rollback
            .accept_device_chain(&[first.clone(), second.clone()], &membership)
            .expect("complete chain")
            .len(),
        2
    );

    let alternate = operation(&owner_key, 2, first.digest(), 13);
    let mut left = OperationLog::new();
    left.accept(&first, &membership).expect("left first");
    left.accept(&second, &membership).expect("left second");
    let mut right = OperationLog::new();
    right.accept(&first, &membership).expect("right first");
    right
        .accept(&alternate, &membership)
        .expect("right alternate");
    assert_eq!(
        left.accept(&alternate, &membership)
            .expect_err("left detects equivocation")
            .status(),
        ChurStatus::SyncChainFork
    );
    assert_eq!(
        right
            .accept(&second, &membership)
            .expect_err("right detects equivocation")
            .status(),
        ChurStatus::SyncChainFork
    );
    let evidence = left.fork(&id(2)).expect("fork evidence");
    assert_ne!(evidence.accepted_record(), evidence.conflicting_record());
}

/// A peer checkpoint must not stop the chain it names.
///
/// `ROLLBACK_PROTECTION.md` §6 has a device issue a checkpoint at the end of
/// every sync session, so a floor above the local accepted head is the ordinary
/// case rather than an attack, and §7 has a restored device set its floor before
/// it accepts any operation at all. The receive path offers one operation per
/// call, so a floor that refused everything below it left the author's chain
/// stopped for good, durably, and reported only as `pending`.
///
/// The second half is the property the floor exists for, and it still holds: a
/// different branch at the floor's own sequence is fork evidence even while the
/// history below it is incomplete.
#[test]
fn a_peer_checkpoint_floor_admits_the_chain_one_operation_at_a_time() {
    let owner_key = DeviceSigningKey::from_seed([5; 32]);
    let initial = EnrollmentRecord::initial(id(1), id(2), owner_key.verifying_key(), [6; 32])
        .expect("initial enrollment")
        .sign(&owner_key);
    let membership = MembershipState::bootstrap(&initial).expect("membership");
    let first = operation(&owner_key, 1, [0; 32], 7);
    let second = operation(&owner_key, 2, first.digest(), 8);
    let checkpoint = Checkpoint::new(
        id(1),
        id(2),
        2,
        membership.generation(),
        *membership.commitment(),
        vec![CheckpointHead::new(id(2), 2, second.digest())],
        [11; 32],
        [0; 32],
    )
    .expect("checkpoint")
    .sign(&owner_key);

    let mut log = OperationLog::new();
    assert_eq!(
        log.accept_checkpoint(&checkpoint, &membership)
            .expect("floor"),
        CheckpointOutcome::Raised
    );
    assert_eq!(
        log.accept(&first, &membership).expect("toward the floor"),
        ApplyOutcome::Applied
    );
    assert_eq!(log.head(&id(2)), Some((1, first.digest())));
    assert_eq!(
        log.accept(&second, &membership).expect("at the floor"),
        ApplyOutcome::Applied
    );
    assert_eq!(log.head(&id(2)), Some((2, second.digest())));

    let mut forked = OperationLog::new();
    forked
        .accept_checkpoint(&checkpoint, &membership)
        .expect("floor");
    forked.accept(&first, &membership).expect("first");
    let alternate = operation(&owner_key, 2, first.digest(), 13);
    assert_eq!(
        forked
            .accept(&alternate, &membership)
            .expect_err("branch contradicting the floor")
            .status(),
        ChurStatus::SyncChainFork
    );
    assert!(forked.fork(&id(2)).is_some());
}

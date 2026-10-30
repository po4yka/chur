# Chur Password Profile

> **Status:** Proposed normative password-to-KEK profile; the Argon2id floor of §4 is frozen and is also the v1 default, and calibration may only raise a parameter. The exact password input maximum is outstanding.

## 1. Purpose

Passwords provide a portable factor for unwrapping `VaultRootSecret`. They do not encrypt media and are not stored or recoverable by Chur.

The application can collect a 12–20 digit ASCII PIN as this password factor. It uses the same Argon2id slot and recovery rules. A shorter application PIN would be exposed to offline guessing if an attacker copied the vault files. The device screen-lock PIN is a separate, platform-gated factor under [`KEY_SLOTS.md`](KEY_SLOTS.md) §4 and §5.

## 2. Input acquisition

- use a secure platform text field;
- disable autocorrection, suggestions, capitalization, and logging;
- do not place the password in clipboard, saved state, analytics, crash reports, or general navigation state;
- pass bounded bytes to Rust as soon as practical;
- clear mutable platform buffers best-effort after use.

## 3. Canonical password bytes

Profile v1 proposal:

```text
input: exact Unicode scalar sequence entered by the user
normalization: none
trimming: none
case folding: none
encoding: strict UTF-8
maximum encoded length: 1024 bytes
empty password: rejected for new vaults
minimum length of a new or changed password: 12 Unicode scalar values
```

The minimum applies when a password slot is created: at vault creation and at a password change. It does not apply at unlock, so a slot made before this rule still opens. Rust enforces it in `vault::create` and `Session::replace_password` (`chur_core::limits::password::NEW_MIN_CHARS`), so no host can bypass it, and returns `INVALID_INPUT` for a shorter password. A PIN of 12 to 20 digits meets the rule. The Kotlin forms apply the same rule before they call Rust, and count code points as Rust counts scalar values. With m=64 MiB and t=3, an offline attack on a short password from a copied registry is practical, which is why the floor exists.

The profile identifier is stored in the password slot. Android, iOS, and CLI must produce identical bytes for identical input. Future normalization cannot reinterpret existing slots; it requires a new profile ID.

The UI should warn users about visually confusable or combining characters without changing them silently.

## 4. Argon2id profile

Required algorithm:

```text
Argon2id
version 0x13
output length 32 bytes
random salt at least 16 bytes
```

Frozen v1 floor, which is also the v1 default for a newly created slot:

```text
memory: 65536 KiB (64 MiB)
iterations: 3
parallelism: 1
salt: 16 random bytes
output: 32 bytes
interactive target: approximately 350–750 ms per derivation on the floor device of ADR-0017
```

Calibration under §6 may raise memory or iterations inside the parser bounds of [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §18.3 when the benchmark on that device stays inside the interactive target. It may never lower memory, iterations, or parallelism. The floor is a security constant and the interactive target is a benchmark target: a latency miss is never a reason to reduce a parameter. [ADR-0017](../adr/0017-freeze-the-supported-device-set.md) and [`../assurance/PERFORMANCE_BUDGETS.md`](../assurance/PERFORMANCE_BUDGETS.md) §6 gate on this number.

## 5. Resource limits

Before allocation or KDF execution, reject parameters outside policy. The policy must cap:

- password bytes;
- salt length;
- output length;
- memory KiB;
- iterations;
- lanes/parallelism;
- total derived-work attempts per UI action.

Server- or backup-provided parameters are untrusted.

## 6. Calibration

Calibration for a new vault may:

1. benchmark candidate parameters with synthetic input;
2. keep memory at or above the §4 floor of 65536 KiB, without exception;
3. adjust iterations within approved bounds;
4. target the supported interactive latency range;
5. store exact parameters in the slot;
6. never silently reduce below the compatibility/security floor.

Calibration must not create device-specific parameters that another supported device cannot validate safely. v1 defines no lower-memory compatibility profile, and a device that cannot allocate the §4 memory floor fails closed:

- a vault creation or password change that cannot allocate the floor must not write a slot; it fails with `KDF_MEMORY_UNAVAILABLE` of [`../ERROR_MODEL.md`](../ERROR_MODEL.md);
- an unlock that cannot allocate the floor fails with the same code before the first candidate of [`KEY_SLOTS.md`](KEY_SLOTS.md) §8 runs, so no partial candidate set is attempted;
- the code is a device-resource state, not an authentication result. It is decided before any credential is used and reveals nothing about which slots exist;
- the caller may retry after freeing memory or returning to the foreground, and must never retry with reduced parameters.

The same password must derive the same key on every supported device, so a reduced profile would need its own profile identifier in every slot and would hand an attacker who can induce memory pressure a weaker slot to attack. [ADR-0017](../adr/0017-freeze-the-supported-device-set.md) already makes a device that cannot run the floor unsupported rather than degraded, and [ADR-0026](../adr/0026-argon2id-memory-floor-and-candidate-set.md) records this closure.

## 7. Derivation and wrapping

```text
PasswordKEK = Argon2id(password_bytes, salt, m, t, p, out=32)
wrapped_root = XChaCha20-Poly1305.seal(
    key = PasswordKEK,
    nonce = fresh random 24 bytes,
    plaintext = VaultRootSecret,
    aad = canonical PasswordSlot context
)
```

`PasswordKEK` is zeroized immediately after wrap/unwrap.

## 8. Verification

Chur verifies a password by successfully unwrapping a candidate root and authenticating vault context. It should not store a separate fast password verifier.

The external error for wrong password, corrupted slot, and wrong vault binding is `AUTHENTICATION_FAILED`.

## 9. Parameter upgrade

After a successful unlock, if parameters are below current policy:

1. derive a new KEK with fresh salt and approved parameters;
2. create a new password slot generation;
3. verify it by reopening/authenticating the root;
4. commit descriptor generation atomically;
5. retire the old slot after commit.

Upgrades must be cancellable before commit and must not strand the user.

## 10. Password change

Changing a password requires a currently authenticated root session or valid recovery factor. It does not decrypt/re-encrypt media.

The UI must distinguish:

- changing a known password;
- recovering from a forgotten password;
- replacing an invalidated device slot;
- rotating a recovery secret.

## 11. Rate limiting

Offline resistance comes from Argon2id. Local UI may add delay/rate limiting against casual attempts, but it is not a cryptographic substitute and must not permanently deny recovery after process reinstall or backup restore.

The Rust core enforces one local delay in `chur_vault_unlock`, so a host cannot skip it by calling the C ABI directly:

- only the password factor is delayed. A recovery phrase and a device unlock are never delayed, and no count wipes or locks anything;
- five failed password attempts are free. The next attempt waits 30 seconds after the last failure, then 1 minute, then 5 minutes, then 15 minutes for every later failure. 15 minutes is the cap;
- each password attempt is counted durably before the key derivation starts. If the count cannot be written, the attempt is refused with `IO_FAILURE` and nothing is derived. A process killed during the derivation therefore keeps the failure;
- a success of any identity with any factor resets the count. A password attempt that fails before a credential is tested, for example with `KDF_MEMORY_UNAVAILABLE`, gives its count back;
- a delayed attempt returns `UNLOCK_DELAYED` before any derivation, and the interface shows a neutral wait message that names no identity;
- the count is one record, `unlock-attempts`, in the storage root beside `registry/` and `vaults/`. It is not in a vault, the backup rules do not include it, and a reinstall removes it. A sibling lock file serializes every runtime and process that reads or writes it;
- the record keeps the end of the delay on the boot clock (`CLOCK_BOOTTIME` on Android, `CLOCK_MONOTONIC` on Apple platforms, which count time asleep) and the boot identifier (`/proc/sys/kernel/random/boot_id` on Android, `kern.bootsessionuuid` on Apple platforms). The wall clock has no part in the decision, so changing it does not shorten the delay;
- after a reboot, the full delay of the current count runs again, measured from the boot. A reboot therefore gains nothing, and a user waits at most one delay. Where the boot identifier cannot be read, a boot clock below the time of the last failure shows the reboot;
- a record that cannot be read counts as the first delayed failure.
- creation and backup restore derive the new password against each installed identity to refuse a collision. Those derivations are not counted or delayed, and the oracle is accepted as recorded in [`DECOY_VAULT.md`](DECOY_VAULT.md) §5.

A user who deletes app data removes the count. This is accepted: the delay slows casual guessing on the device, and Argon2id remains the defence against an offline attack.

A future server may rate-limit account operations but cannot be trusted as the only password defense.

## 12. UX and recovery

- require password confirmation during creation/change;
- offer a password manager-compatible input path;
- explain that no server reset can recover data without a valid root envelope;
- require recovery-secret confirmation for users who enable recovery;
- do not reveal whether a credential belongs to real or decoy vault.

## 13. Test vectors

Vectors must cover:

- ASCII, non-ASCII, combining sequences, emoji, and embedded spaces;
- zero-length rejection and maximum length;
- exact UTF-8 bytes;
- Argon2 minimum/default/maximum parameters;
- wrong password and one-bit changes;
- corrupt salt/nonce/tag/slot AAD;
- parameter upgrade and crash recovery;
- Android/iOS/CLI equivalence.

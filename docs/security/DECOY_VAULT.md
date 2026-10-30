# Decoy Vault

> **Status:** Proposed normative isolation and product contract

A Decoy Vault is an independently encrypted vault identity intended to present plausible private content during ordinary or coercive UI inspection. It is not a filtered view of the real vault and is not claimed to be forensically undetectable.

## 1. Cryptographic separation

```text
Real credential → RealRoot → Real catalog/collections/objects
Decoy credential → DecoyRoot → Decoy catalog/collections/objects
```

Real and decoy must not share:

- root, collection, object, catalog, search, settings, or identity keys;
- password/recovery slots;
- Keystore aliases or Keychain item identifiers;
- private catalog files;
- object directories or stable object IDs;
- thumbnail/preview/player caches;
- navigation restoration;
- session generations and handle registries;
- peer sessions or backup manifests.

## 2. Session routing

The session gate resolves a credential to an opaque `VaultSessionHandle`. Ordinary feature code does not receive a durable `isDecoy` flag.

```text
credential/platform action
    → slot candidate resolution
    → root validation
    → opaque vault descriptor
    → session-scoped dependency graph
```

External failure behavior is equivalent for real, decoy, wrong, damaged, or absent credentials.

## 3. Provisioning

Decoy provisioning occurs from an already authenticated real session or a dedicated setup flow. Requirements:

- fresh independent root and slots;
- user confirms the decoy credential is distinct;
- initial plausible content is user-controlled or synthetic and clearly explained;
- the limitation in §10 is stated before the decoy is created: the feature is publicly documented, so a coercer may know to keep demanding credentials;
- no automatic copying of real media or metadata;
- recovery semantics explained separately;
- setup can be disabled without destroying the real vault.

## 4. Storage layout

Perfectly hiding a sibling vault is out of scope. The physical layout should nevertheless avoid obvious semantic labels such as `real/` and `decoy/`.

Use random vault directory identifiers and opaque descriptor references. Do not attempt deceptive filesystem tricks that make recovery or integrity unsafe.

## 5. Timing and side channels

Potential distinguishing signals include:

- Argon2 profiles and unlock latency;
- catalog/object count and storage size;
- presence of platform aliases;
- backup/sync traffic;
- cleanup journals;
- cache warmness;
- error timing.

Mitigations may normalize user-visible flow and avoid explicit labels, but Chur does not promise constant-time whole-vault behavior or hidden storage volume.

Unlock latency is the one signal that is bounded. [`KEY_SLOTS.md`](KEY_SLOTS.md) §8 fixes the password-candidate count at two and pads the list with dummy derivations, so the Argon2id cost of one attempt does not grow with the number of identities present. Two residual leaks remain and are accepted:

- the Argon2id parameters of a password slot are public descriptor bytes, so identities calibrated to different parameters differ in both the published parameters and the cost of one derivation. Provision every identity on one device with the same profile, as [`../CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md) §23 requires;
- a device holding one identity still pays two derivations, and a device that cannot allocate the memory floor fails before the first one under [`PASSWORD_PROFILE.md`](PASSWORD_PROFILE.md) §6. Both are constants of the unlock procedure, readable from these documents, and neither counts identities.

A third residual signal is structural and is accepted here rather than in §10, which otherwise forbids it. [`../format/VAULT_DESCRIPTOR_V1.md`](../format/VAULT_DESCRIPTOR_V1.md) §11 caps the registry at two identities, and §3 above provisions the second one from an authenticated session. So "can another identity be created here" and "are there already two" are the same question, and a session that asks it learns the answer whichever identity it is. The application refuses every creation with one sentence that names no reason, so the *kind* of refusal reveals nothing further; that a refusal happened at all is what remains, and no arrangement of the surface removes it while the cap is two and provisioning is reachable from a session.

Restoring a package that is distinct from every installed identity is a creation and carries the same accepted signal. The application refuses it with the creation sentence, whatever the reason: the registry holds two identities, the package's vault is installed, or its password opens an installed identity. The check runs only after the package credential has opened the package, so a caller with no valid package learns nothing on any device. A caller who does hold a valid package (a backup of another vault, or one built offline from the open format) learns the same bit that a creation attempt gives.

Both creation and restore derive the candidate password against each installed identity to find a collision. That derivation is outside the attempt delay of [`PASSWORD_PROFILE.md`](PASSWORD_PROFILE.md) §11, for creation as for restore, and the oracle is accepted for both: a caller who can create or restore can already supply any password as the new one, so the restore path adds no guess that the creation path does not.

What that costs is bounded. A coercer inside a decoy session who provokes the refusal learns that two identities exist, which is the fact §10 protects. They learn nothing about the second one: not its credential, not its size, not its content, and not whether it is the real one — §11's storage rule and §2's session routing still hold. And they must already know the feature exists to try, which the "Assumed adversary knowledge" section below states they may.

A fourth residual signal comes from the device slot, and it is also accepted here. A device unlock (Android Keystore or Apple Keychain) names no identity: the platform authorizes once, and Chur opens the first registry entry whose slot authenticates. If two identities each held a device slot, the registry order would decide which vault a fingerprint opens, and a coercer who forces the fingerprint could open the real vault. Therefore **one identity at a time holds a device slot**:

- Rust refuses a new Android Keystore or Apple Keychain slot when another registry entry that parses already holds a device slot of either family. The refusal is `PLATFORM_KEY_UNAVAILABLE`, the status of any device unlock that is not available.
- The application shows that refusal with the same sentence as a device that has no enrolled factor or a factor the platform no longer accepts. The sentence names no other identity.
- An identity that holds a device slot can always add a replacement, for example to change the device-slot policy. This also holds on an install where both identities enrolled before this rule. The other identity can enroll only after the first one removes its slot.

The residual signal is this. The locked unlock screen cannot know which identity the user will open, so it offers the device unlock when any identity holds a device slot. A coercer inside a session that holds no device slot can see that the unlock screen offers the device unlock, and that enrollment in this session is refused. The refusal also comes at once and with no biometric prompt, because Rust refuses before the platform asks for the factor, while a device without the factor usually refuses after the platform checks it. Together, these show that another identity exists and holds the device slot. They do not show its credential, size or content. A user who does not want this signal does not enroll a device slot in either identity, or enrolls it only in the decoy.

Re-encryption after a revocation, [`../sync/REVOCATION.md`](../sync/REVOCATION.md) §3.2, is a residual signal and is accepted here. It runs only in an identity that owns a completed collection rotation, that is, one that revoked a sharing member, and only after that identity is unlocked. It never runs inside an unlock, so unlock latency is the same in every identity. While it runs, storage use, network traffic to current members, and battery use differ from an identity with no revoked member; Settings shows a line only when some object cannot be re-encrypted. These show that the open identity revoked a member, not that a sibling identity exists.

The password-attempt delay of [`PASSWORD_PROFILE.md`](PASSWORD_PROFILE.md) §11 is not a signal. One count covers the whole installation and lives outside every vault. A password attempt tries every identity in one call, so a failure counts against no identity in particular, and a success of the real or the decoy identity resets the count in the same way. The wait copy names no identity.

Direct P2P requires an explicit foreground action. Local network prompts, direct connection timing, and traffic volume can reveal that networking is being used; this is a residual signal. No persistent endpoint, account, invitation, or run projection may be shared between vault identities.

## 6. Public and decoy UI

The public shell remains separate from the decoy vault. A decoy session should behave as a complete private vault:

- import/export works according to policy;
- media and metadata are genuinely encrypted;
- lock and recovery rules apply;
- content is not marked as fake inside ordinary UI;
- no settings reveal real-vault counts, backups, or identities.

## 7. Backup and sync

Real and decoy vaults have separate keys, device identities, backups, invitations, and active P2P sessions. There is no account or remote service metadata. Switching or locking a vault closes its peer socket and clears every run projection before a different identity can observe the screen. No background transfer or automatic network connection is allowed. Portable backups remain an explicit local export and carry only their own vault.

## 8. Recovery

Real and decoy recovery secrets are independent. Recovering one must not reveal that another exists. Product UX must prevent accidental overwriting of the other vault's descriptors during restore.

If the user chooses no recovery for decoy, loss is irreversible.

## 9. Deletion

Deleting decoy requires authenticated confirmation in the decoy or an explicit management flow from the real session. It must never delete shared state because shared private state is forbidden.

Deleting the real vault must not silently leave a decoy presented as the only recoverable identity without clear user intent.

## 10. Product claims

Allowed terms:

- Decoy Vault;
- discreet access;
- independent alternate vault;
- coercion-resistant UI with limitations.

Disallowed without a new proven design:

- undetectable;
- deniable filesystem volume;
- impossible to prove another vault exists;
- forensic-proof.

### Assumed adversary knowledge

The existence of this feature is public by design. [`../product/DISCREET_MODE.md`](../product/DISCREET_MODE.md) requires the store listing to describe the discreet interfaces, and [`../IOS.md`](../IOS.md) §37 requires review notes to describe how real and decoy sessions behave. A coercer may therefore know that a second credential can exist before demanding anything, and this specification does not assume otherwise.

What remains is indistinguishability, not concealment: the defence holds only where the coercer cannot tell an opened decoy from a vault that has no sibling. Therefore:

- a decoy session must not prove or disprove the existence of a sibling identity from inside the application. No count, setting, notification, backup state, error, timing class, or management surface reachable from a decoy session may differ according to whether a real vault exists. The three exceptions are the provisioning refusal of §5, which the registry cap of two makes structural; the sync setup refusal of §5, which reads as an ordinary failed setup but still differs in its timing and the other signals that §5 records; and the device-slot rule of §5, where the unlock screen offers a device unlock that a session without the device slot cannot enroll, and the refusal comes at once with no biometric prompt. All three are stated there rather than hidden here;
- the same must hold in a real session with no decoy provisioned, so that "no decoy exists" and "the decoy was not opened" are one observation rather than two;
- §3 provisioning must state this limitation before the user creates a decoy.

This bounds the claim: Decoy Vault raises the cost of a demand to open the vault. It does not defeat a coercer who knows the feature exists and keeps demanding credentials.

## 11. Test matrix

- correct real credential opens only real data;
- correct decoy credential opens only decoy data;
- wrong credential produces equivalent external failure;
- the password-attempt delay counts failures for the whole installation, and a decoy success resets it exactly as a real success does;
- caches and navigation do not cross sessions;
- platform alias invalidation affects only its identity;
- a device-slot enrollment is refused while another identity holds a device slot, with the copy of any unavailable device unlock, and the identity that holds the slot can still replace it;
- backup/restore of one identity does not expose or overwrite the other;
- process death returns to public locked state;
- storage/log/notification inspection finds no semantic real/decoy label;
- lock invalidates readers from both identities;
- migration can process one vault without opening the sibling;
- a decoy session and a real session with no decoy provisioned are indistinguishable from inside the application across counts, settings, notifications, backup state, and error copy;
- a sync setup in an identity that does not own the saved sync state gives a wrong address or secret its own message first, then shows exactly the copy of an ordinary failed setup and sends no request; its timing and the other signals that §5 records still differ, as §5 accepts.

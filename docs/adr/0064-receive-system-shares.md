# ADR-0064: Receive System Shares Through Explicit Vault Import

- **Status:** Proposed
- **Date:** 2026-10-16
- **Decision owners:** @po4yka
- **Related:** [Product contract](../product/INCOMING_SHARES.md), [Plaintext lifecycle](../security/PLAINTEXT_LIFECYCLE.md), [iOS extensions](../IOS.md#26-extensions-and-app-groups)

## Context

System share providers grant temporary access to external content. They can disappear, return malformed metadata, or finish after a vault session changes. An iOS extension has its own lifecycle and cannot use the containing application's vault session.

## Decision

Keep incoming sources with the platform host and expose only a count to the public shell. Require normal vault authentication followed by explicit destination confirmation. Reuse the serial import pipeline, progress, partial results, and cancellation. Bind native import creation, derived writes, and final album placement to the confirmed session generation under the repository mutex. Never request deletion of shared originals.

Android keeps temporary content grants and text in process memory. iOS uses an extension-specific encrypted App Group queue: the extension receives only a public encryption key, while the private key remains in the main application's device-local Keychain. Main-app finalization decrypts only after user confirmation in an unlocked session. The extension does not open the vault or invoke private application-launch APIs. No shared Keychain access group or vault root is added.

## Alternatives considered

Saving incoming content into public Notes discloses it through a different storage and backup boundary. Persisting provider URLs does not preserve temporary grants. A plaintext App Group inbox would retain originals outside the vault across process death. Sharing vault keys with an extension would broaden the root-key and catalog boundary.

## Security impact

This change affects the import, session, redaction, and plaintext lifetime invariants. Untrusted descriptors stay subject to the existing native import limits. The iOS receiving key is independent of vault roots and provides confidentiality for temporary external content, not sender authentication. Compromise of the app or its receiving key can disclose pending batches. Backup exclusion and expiry reduce retention; deletion does not establish physical flash erasure. Managed strings and operating-system provider buffers cannot guarantee memory erasure.

## Compatibility impact

Existing vault, catalog, archive, and signed sharing records do not change. The iOS application gains an embedded Share Extension and App Group entitlement. Signing must provision that group for both targets; local implementation does not modify developer-account or production provisioning state.

Streaming import now refuses EOF before a reported source length. Underreported hints still accept all bytes. A provider that overstates its length must be shared again with correct or unknown length; Chur does not save its incomplete prefix. Cancellation is checked again after reads and through final verification. No ABI or format field is added.

## Validation

Exercise cold and warm Android delivery, multiple sources, literal text and URLs, revoked grants, invalid inputs, partial import, cancellation, and source cleanup. Verify stale generation rejection with the real native layer. Test iOS encrypted round trips, tamper rejection, partial and expired queue cleanup, provider cancellation, and extension packaging. Keep host tests, emulator/simulator checks, signed device acceptance, and CI results distinct.

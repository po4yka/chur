# Share to Chur

> **Status:** Accepted implementation contract; security release gates remain separate

Use the source application's **Share** command and select **Chur**. Chur receives files, photos, video, audio, plain text, and URLs. A URL is stored as text; Chur does not fetch its address. Shared text becomes a private `shared-text.txt` file, separate from public Notes and private notes.

## Import

1. Share the selected content to Chur.
2. Open and unlock the destination vault. A share never creates or opens a vault without the normal user actions.
3. Confirm **Import shared items**, select **All items** or an existing album, then select **Import**. Create an album in the library before sharing if a new destination is needed.
4. Use the normal import progress card to cancel. Saved items remain when another item fails or the operation stops. Share failed or remaining items again.

Chur keeps the source originals. It does not request their deletion. The public notice shows only an item count. Filenames, content, and destination names do not enter public Notes, notifications, system search, logs, or saved UI state. Confirmation belongs to the current unlocked identity; a delayed provider result cannot write to a different identity after lock.

Only one batch can wait or run in the app at a time. A second incoming Android share is refused with a message so that it cannot silently replace the first. Discard releases the pending batch. Confirming an import consumes that batch once, including failed items; a retry requires sharing those items again.

## Android

Both single and multiple share actions accept all MIME types. Files must use readable `content://` grants from the source app. Chur refuses a URI of one of its own providers, and a URI whose authority has a `userId@` prefix, because that prefix moves the authority that the own-provider check reads. Chur streams those descriptors without a persistent plaintext copy. Unsupported media can be stored as files. Plain text and URLs use a bounded memory-backed descriptor.

A batch contains at most 100 items, including an optional text attachment. Text is limited to 1 MiB of UTF-8. An invalid URI or oversized batch is refused before import. A provider can revoke access or become unavailable; that item then fails without removing previously saved items. Pending sources exist only in process memory and are lost after process death. Share again if access expires.

## iOS

The Share Extension saves a temporary encrypted batch and asks the user to open Chur. The app must have been launched once to set up the receiving key. The extension has no vault keys, catalog access, or ability to unlock a vault. It does not use an unsupported API to launch the containing app.

The iOS queue accepts up to eight batches with 64 items per batch, 4 GiB per item, and 8 GiB total including encryption overhead. Text and URLs have a 1 MiB limit. Pending and completed batches expire after 24 hours; maintenance removes them the next time the inbox is used.

Only encrypted payloads and the receiving public key enter the App Group. The app's private receiving key stays in its own device-local Keychain. Payload names and MIME metadata are encrypted. Partial writes are not offered for import. Expired and abandoned entries are removed during inbox maintenance. This queue is local, excluded from backup, and separate from vault backups and synchronization.

Documents and text stream from the authenticated encrypted queue into the importer. The whole envelope is checked before its source is exposed. Media uses the existing codec path; URL-only ImageIO and AVFoundation work can use bounded, protected scratch while the vault is unlocked. Unsupported media or media outside the scratch budget uses the file importer. Import or discard removes the encrypted batch; no automatic retry can duplicate successful items in a later session.

The application and extension must use the same registered App Group in a signed distribution build. Simulator and unsigned build checks do not establish that the distribution profile has this capability.

## Boundaries

Receiving content does not authenticate its origin or make malformed files safe. Chur treats filenames, MIME types, lengths, and provider objects as untrusted input. Existing import limits, decoder custody, encryption, and cancellation rules apply. No new archive, catalog, or signed sharing format is introduced. The iOS inbox is an internal temporary transport, not an export format.

Platform references: [Android receiving data](https://developer.android.com/develop/ui/compose/sharing/receive), [Apple Share extensions](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/Share.html), [Apple shared containers](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html).

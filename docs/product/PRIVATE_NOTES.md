# Private Notes

> **Status:** Accepted local product contract; device and release gates remain separate

## Scope

Private notes belong to the selected unlocked vault identity. Open **Browse → Private notes** from Library. The screen has its own list, search, editor, pinned order, and Trash. It does not use the public Notes model, JSON file, saved-state registry, or disclosure state.

The selected scope is local notes with managed images and files, plaintext portable note packages, and encrypted portable backup. See the shared [Markdown and attachment contract](MARKDOWN_NOTES.md) for editor capabilities, limits, and public/private transfer behavior. Notes do not enter media albums, media search, device-control exports, sync, or collection sharing. Public Notes remain available without unlocking and keep their existing public persistence.

## List and search

- Pinned notes come first, then newest update and descending opaque identifier.
- Each native page has at most 100 rows; the UI requests 50 and offers Previous/Next.
- A summary holds the title and at most 160 Unicode scalar values of body preview. Read the complete body only for the open editor.
- Search covers title and body inside the SQLCipher catalog. It combines at most 32 literal word prefixes with AND and accepts at most 256 UTF-8 bytes.
- Trash is a separate query scope. Editing or changing a note resets pagination; a cursor from an older catalog generation must not be reused.

## Editor and saving

The editor preserves UTF-8 Markdown source and provides an offline CommonMark/GFM preview. Each note stores an explicit format: migrated notes remain literal text until the user changes format; new notes use Markdown. Preview does not execute scripts or document macros. A note has at most 256 UTF-8 bytes of title and 256 KiB of body. A vault holds at most 10000 notes, including Trash.

Saving is explicit. A new empty editor creates no record until Save. On save, Rust commits the row and its search index in one transaction. Each update supplies the last read revision; an outdated editor receives a conflict and cannot overwrite a newer revision. An unchanged save does not advance the revision.

The open editor keeps unsaved changes only in session memory. Leaving with changes offers Save, Discard, or Keep editing. A write failure keeps those changes for a retry.

An ordinary lock saves unsaved changes as a new revision before the session closes. This applies to the lock control, the background lock, and the idle timeout. The lock captures the open text and conceals the screen at once, as before. Then it saves the text through the normal encrypted save with the last read revision, and then it closes the session. The capture is the last action of that editor: no later edit, Save, or second lock saves the same text again, so a new note is never saved twice. The lock lets the save start and finish in at most 2 seconds. A save that has not started its native call in that time never starts. A native call that already started cannot be interrupted, so the close can come later by the rest of that one bounded note transaction, as for any other native call in progress. If the save does not start, fails, or meets a newer revision, the lock continues, the newer revision stays, and the unsaved text is lost. An editor that already runs an action, a trashed note, and a new empty editor save nothing. The lock does not show a notice about a lost edit, because the next session can belong to a different identity.

Panic lock (long press, Lock and hide, and the quick-settings tile) saves nothing and drops unsaved text, because panic closes the session immediately ([Discreet mode](DISCREET_MODE.md)). A panic during the save of an earlier ordinary lock ends that wait at once, and a save that has not started its native call does not start. Identity change, route disposal, and process death also drop unsaved text. The editor states these limits while changes are unsaved. It never saves from disposal and never writes a draft outside the encrypted catalog. Actual input refreshes the normal idle timer; no background keepalive extends the session.

Private text is not written to `SavedState`, `rememberSaveable`, navigation restoration, logs, public Notes, or platform backup. Note input requests no personalized learning on Android and disables autocorrection through the existing private keyboard options. These requests do not establish that a third-party keyboard or compromised platform cannot retain input.

Copy and Cut are disabled through modern and legacy clipboard write guards, context actions, accessibility actions, and hardware shortcuts. Cut must not remove text. Explicit Paste and Select all remain available. Installing this policy does not read or clear the existing system clipboard.

## Trash and deletion

Move to Trash and Restore use the saved revision and commit atomically. Trashed notes are read-only and can be restored or explicitly exported. Delete permanently requires confirmation and removes the live note and search rows. Trash expires after 30 days on the trusted time of [catalog v18](../format/CATALOG_SCHEMA_V18.md), so a device clock that jumps ahead does not expire it at once; native note access clears expired entries before returning results.

The catalog and FTS use secure-delete settings to reduce deleted-cell retention. This is not per-note cryptographic erasure or physical overwrite. Older encrypted backups can still contain earlier notes.

## Export and backup

Export acts on a selected saved revision. A dirty editor first offers Save and Export. The existing destination dialog warns that the copy is unencrypted and can be retained by its recipient. Android offers Files, Downloads, and Share; iOS offers Files and Share.

For a note without files, Markdown export is the exact UTF-8 body as `.md`; it does not prepend the title or add whitespace. Plain text export keeps `title + "\n\n" + body`, including two LF bytes when the title is empty. An unexpired note in Trash can use this plaintext export without being restored; its current saved revision is still required. An expired, purged, or changed note refuses export. This does not enable selective encrypted export of Trash. The exact byte count reserves the platform scratch budget. A session-bound request retains only an identifier, revision, safe filename, format, size, and generation while a picker is open. The host does not fetch body text solely to export it.

A note with files exports a [portable `.churnote` package](../format/NOTE_PACKAGE_V1.md) containing its exact source, explicit format, and all attachment bytes. Private attachment metadata and content remain in the selected encrypted SQLCipher catalog; preview creates no public file or plaintext disk cache. Import validates and commits the complete package atomically. Add/remove requires a saved clean note and its current revision; the automatically inserted Markdown reference is an unsaved text edit until Save.

The normal native Export operation owns a duplicate destination descriptor, reports progress, and accepts cancellation. Rust copies a bounded saved revision into a zeroizing buffer and releases catalog access before provider writes. The host publishes only a complete successful operation under the same session and removes incomplete copies where the provider permits it. A blocked operating-system write has the same cancellation limit as existing media export.

Portable backup includes the encrypted catalog and its note tables for the selected identity. Restore preserves notes, format, revisions, pin state, Trash, search, and attachment bytes. It does not merge the sibling identity or copy notes into the public shell. Historical backups remain separate copies with their original credentials and retention.

### Selective encrypted archives

The list and saved-note editor also offer [selective encrypted archives](SELECTIVE_ENCRYPTED_EXPORT.md). Select page or a long press starts a note selection; selected saved revisions can span pages. The archive has independent keys and a new password. It opens through separate Restore or imports fresh copies into an existing vault. This action remains separate from the deliberate plaintext TXT/Markdown export.

## Storage and compatibility

See [`../format/CATALOG_SCHEMA_V14.md`](../format/CATALOG_SCHEMA_V14.md), [`../interop/FFI_CONTRACT.md`](../interop/FFI_CONTRACT.md) §6.25, and [`../adr/0061-local-private-notes.md`](../adr/0061-local-private-notes.md). The normal authenticated schema migration proceeds sequentially through v13. The v12 format discriminator preserves existing notes as plain text without reinterpreting their content; v13 adds note-scoped encrypted attachment metadata and BLOB content. Native callers require ABI 5.0. Format changes participate in the saved revision. Older clients fail closed on the newer catalog; no media container or sync record changes.

## Validation

Native tests cover atomic create/update, maximum UTF-8 size, conflicts, pin/search/paging, Trash, purge, encrypted persistence, session and identity isolation, export, and backup/restore. UI checks cover saved-state exclusion, clipboard and input policy, lock cleanup, save failure, dirty Back, and narrow screens with large fonts. Host and simulator results are separate from physical-device acceptance.

## Organization and saved versions

Folder/tag filters and **Apply organization** use the same flat, case-sensitive labels as public notes. Private filters are evaluated before the 50-row UI page, with labels bound into the cursor. **Version history** displays retained committed source and original file metadata; restoration requires the clean current saved revision and restores text, format, pin, labels and files atomically. All retained content remains in the encrypted catalog and in encrypted backups/selected archives. Trash retains history; purge and existing Trash expiry remove it through foreign-key cascades. Lock/panic drops the entire history UI and rejects late responses. See [Markdown notes](MARKDOWN_NOTES.md#organization-and-recovery) for limits and the separate current-only portable package contract.

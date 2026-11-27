# Historical vault with a classical device identity

Extract `vault.zip` into an empty application vault root. It contains one disposable password-protected vault, one imported object and one enrolled device. All credentials and data in this fixture are public test material.

| Field | Expected value |
|---|---|
| Source commit | `db82ed10a900605ff0e84f0154b3987910fbcf14` |
| Native ABI | 7.4 |
| Vault ID | `13425f5e0834ba5f815dfd9758e16e88` |
| Password | `Chur public compatibility fixture 2026` |
| Object ID | `df8bdc3d3cb1a831a21b56f321c39808` |
| Original name and content type | `proof.txt`, `text/plain` |
| Original bytes | UTF-8 text `Chur classical vault compatibility fixture` followed by one LF (43 bytes total) |
| Device ID | `286fdccd12d920a874919587d9e54f64` |
| Device Ed25519 public key | `eab1eae044a445f9cb05f8c5b5e7d41f1307c48036429fb4c2fc7299baed82c8` |
| Device fingerprint | `95cb 9e24 4934 b648 c0b6 3abc dfca f185 c01c 0e90` |
| ZIP SHA-256 | `ee4557f20d60e233520f74b54305cdafdcce2d5460fe04199e67224fe47f41fc` |

## Origin and verification

The historical CLI and C ABI library were built with `cargo build --locked --offline` from an isolated `git archive` of the source commit above. The CLI created an empty vault, imported the file, verified it and exported the original. The exported bytes matched the input. The ABI library then opened the same vault, unlocked it with the password and called `chur_sharing_identity` to create its classical device identity and signed enrollment. The session and runtime were closed before archiving.

The ZIP contains the vault root with relative paths, including empty directories. A second extraction passed the ZIP integrity check. On that extraction, the historical ABI returned the same vault ID, device ID and fingerprint. An independent CLI process read the object by ID and returned all 43 expected bytes. Each mobile test must extract a fresh copy because the app may write to a vault when it opens it.

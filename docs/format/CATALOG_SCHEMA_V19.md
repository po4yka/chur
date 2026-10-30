# Catalog schema v19

> **Status:** Accepted

Catalog format `0x0013` stores, for each issuer vault, the highest identity-membership generation of that vault whose evidence this vault has accepted. An issuer vault is the source vault of a collection or a `ManageMembers` delegate vault that signed a record or grant. Earlier catalogs stored no mark.

`sharing_issuer_marks` is a strict table in the existing SQLCipher catalog:

| Column | Contract |
| --- | --- |
| `issuer_vault_id` | 16-byte identity vault identifier of the issuer; primary key |
| `accepted_generation` | Positive; the highest identity-membership generation of that issuer accepted so far |

The mark only rises. A share, a collection membership record, or a collection grant raises the mark of the vault that signed it in the same SQLCipher transaction that stores the accepted state, so the two commit or roll back together. A share raises the mark of the grant sender vault to the last generation of that vault's chain that authenticated the share. A collection membership record raises the mark of its issuer vault to the issuer generation it was signed under, and a collection grant raises the mark of its sender vault to its sender generation. A delegate vault therefore never changes the mark of the source vault. An identical replay changes nothing. Object key grants are checked against the mark but do not raise it.

Evidence for an issuer vault whose chain ends below the stored mark is refused with `AUTHENTICATION_FAILED`. The rule and the cases that stay acceptable are in [`../sync/COLLECTION_GRANTS.md`](../sync/COLLECTION_GRANTS.md) §9. The mark is client state: it never enters a record, an operation, or a sync stream. A catalog export carries the table like every other table, so a restore keeps the mark.

The authenticated v18→v19 transition uses the descriptor `MIGRATING` state. One SQLCipher transaction creates the table, writes one row per issuer vault that has issued a stored `sharing_membership_records` row, with the highest issuer generation among that vault's records, and records version 19. A stored grant names its sender device but not its sender vault, so the migration does not read `sharing_grants`; a mark that the migration cannot derive rises with the next accepted evidence. A vault without a derived row reads as zero. A failed transaction retains v18. A process interruption on either side of the SQL commit resumes that step before unlock returns. Restore runs each earlier migration in order and then this step. New catalogs install v19 directly. Readers that support only v18 reject the authenticated descriptor as `UNSUPPORTED_VERSION`; there is no downgrade exception. Retain an encrypted backup until the upgrade is accepted.

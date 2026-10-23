# Backing up and recovering the setup

This continues Alice's setup from [openpgp-keys.md](openpgp-keys.md): an
offline primary key recovered from 22 words, with subkeys for daily work.

Alice's paper words restore the primary secret and its creation time.
Keeping her whole setup recoverable takes a few separate backups:

| What Alice keeps | What it preserves |
| --- | --- |
| Paper words | The primary secret and creation time. Anyone with the words can recover it. |
| Public certificate | Identities, certifications, subkey bindings, expiry updates, and revocations. |
| Private subkeys | Access to the existing subkeys, especially decryption of old messages. |
| Revocation certificate | A way to revoke the primary if she can no longer use it. |
| Local GnuPG state | Ownertrust and any configuration she wants to retain. |

If the subkeys live on a hardware key, the card holds the only copy of what
was moved onto it; [nitrokey.md](nitrokey.md) explains how to keep the
offline keyring as the backup.

After changing identities, subkeys, expiry, or revocations, she saves a fresh
public certificate from the offline keyring. For the first copy:

```sh
gpg --homedir offline-gnupg --output alice-public.asc --armor \
  --export PRIMARY_FINGERPRINT
```

On later exports, she uses a new filename or deliberately replaces the old
backup. The public certificate is shareable; the paper and private-key
backups must remain confidential.

## Recovering after losing the offline keyring

Alice practices recovery before she depends on the backup:

1. She types the words from paper into a file and restores the secret into
   her saved public certificate:

   ```sh
   paper-pgp export --input recovered-words.txt --certificate alice-public.asc \
     --passphrase-file passphrase.txt --output recovered-primary.asc
   ```

   This adds the primary secret to the certificate and signs nothing, so the
   result carries exactly the identities, subkey bindings, expiry, and
   revocations she saved.
2. She compares the printed fingerprint with the paper and her saved public
   certificate. They must identify the same primary key.
3. She imports the result into a fresh offline GnuPG home:

   ```sh
   mkdir -m 700 recovered-gnupg
   gpg --homedir recovered-gnupg --import recovered-primary.asc
   ```

4. She restores any separately backed-up private subkeys and ownertrust,
   then checks the resulting identities, capabilities, expiry, revocations,
   and subkeys before use.

### If the public certificate is lost too

Alice follows the [README's fresh-export example](../../README.md#recover-from-paper)
instead, using a User ID she intends to certify now. Recovery then keeps the
original creation time in the primary-key packet and creates a fresh
self-signature dated at export time. This certifies the supplied User ID anew.
If a copy of the public certificate turns up later and she merges it, its
packets are retained, including revocations and subkey bindings, but the
fresh certification can reactivate a retired User ID or replace earlier
capability and expiry settings. It does not undo a compromised-primary-key
revocation.

**If Alice wants the fresh certificate to expire, she passes `--expires`.**
If the new self-signature becomes active after merging, its settings apply,
including no expiry when that option is omitted. It is not guaranteed to take
precedence: signatures made in the same second, a clock that has moved
backwards, or existing future-dated signatures can affect selection. Alice
checks the merged certificate and uses GnuPG's key-management commands to
make deliberate changes to its settings.

With her primary restored, Alice can authorize new subkeys. To decrypt old
messages, she still needs the original private encryption subkey. Its public
binding and her recovered primary secret cannot reconstruct it.

For the backup format and independent recovery instructions, see
[FORMAT.md](../FORMAT.md). For a document to keep with the handwritten words,
see the [printable booklet](../../paper-backup/README.md).

Next: [Using a Nitrokey 3 for the subkeys](nitrokey.md), or the
[technical appendix](packets.md) for packet and signature details.

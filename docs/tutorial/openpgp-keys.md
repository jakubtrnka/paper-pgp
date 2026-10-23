# Understand your PGP key and its paper backup

Alice wants to sign files and receive encrypted messages without keeping her
most important secret key on her everyday computer. This guide follows her
setup, explains what each part does, and shows what she can recover from paper.

The [README](../../README.md) has the commands for creating a key and its
paper backup. Here we build on that example, using `Alice <alice@example.org>`
and the exported `primary.asc`. You can read along without running the
commands. The backup and recovery steps continue in
[backup-recovery.md](backup-recovery.md), moving the subkeys onto a hardware
key is covered in [nitrokey.md](nitrokey.md), and packet layouts and signature
types are collected in the [technical appendix](packets.md).

## 1. The setup we are building

Alice keeps her **primary key** offline and uses separate **subkeys** for
everyday work. The primary key authorizes those subkeys and connects them to
her identity. She brings it out when she needs to change that arrangement.

```mermaid
flowchart LR
    paper["Paper backup (private)"] -->|restores| primary["Primary secret key (offline)"]
    primary -->|certifies| signing["Signing subkey"]
    primary -->|certifies| encryption["Encryption subkey"]
    primary -->|certifies| authentication["Authentication subkey (optional)"]
```

The subkeys have their own secrets. Alice can keep them on her daily computer
or a suitable [hardware token](nitrokey.md). Losing a subkey does not require changing her
primary key, and a stolen subkey does not give someone the primary secret.

The public parts travel together in an **OpenPGP certificate**: the primary
public key, Alice's identities, public subkeys, and signatures connecting
them. Other people use this certificate to check her signatures and encrypt
messages to her. It contains no private keys.

GnuPG often calls the whole bundle a "key" or "public key". In this guide,
*certificate* means the public bundle, and *key* means an individual key pair.
Each pair has a public part to share and a secret part to protect.

## 2. Alice's primary key, identity, and fingerprint

Following the README, Alice generates 22 words and exports `primary.asc`.
The words let `paper-pgp` reconstruct her primary secret key. The export adds
her chosen identity and packages the result for OpenPGP tools.

She imports it into a dedicated GnuPG home on her offline machine:

```sh
mkdir -m 700 offline-gnupg
gpg --homedir offline-gnupg --import primary.asc
gpg --homedir offline-gnupg --list-secret-keys --with-subkey-fingerprint
```

The listing shows a primary key marked `[C]`, for **certification**. Its job
is to sign statements about identities and subkeys. The keys exported by
`paper-pgp` have only this capability; Alice will add subkeys for other jobs.

### Her name is a claim attached to the key

`Alice <alice@example.org>` is a **User ID**. The primary key signs a statement
connecting that text to itself. This is a **self-signature**: the key holder
is making a claim about their own identity.

It proves that the holder of the secret key chose that identity. Someone
checking it still needs a reason to believe the key belongs to the Alice
they know. We return to that question in section 5.

### Her fingerprint identifies the primary key

The **fingerprint** is calculated from the primary public key and its packet
metadata, including its creation time. Alice records it beside her words so
she can check that recovery produced the right key.

The creation time matters: the same secret with a different creation time
would produce a different fingerprint. That is why the words store both the
secret material and the original timestamp.

Her name, email address, expiry, and subkeys are attached through signatures.
Changing those does not change the primary fingerprint. The export passphrase
does not change it either; that passphrase protects the exported secret file.

Alice now has a recoverable primary key and a public identity claim. Next
she gives separate keys permission to do her everyday work.

## 3. Subkeys for everyday work

Alice creates a signing subkey and an encryption subkey in the offline
keyring. In every command below, replace `PRIMARY_FINGERPRINT` with her full
primary fingerprint:

```sh
gpg --homedir offline-gnupg --quick-add-key PRIMARY_FINGERPRINT ed25519 sign 1y
gpg --homedir offline-gnupg --quick-add-key PRIMARY_FINGERPRINT cv25519 encr 1y
```

GnuPG prompts for the passphrase as needed. It generates independent keys and
has the primary sign a **binding signature** for each one. The binding says
that this subkey belongs to Alice's certificate and specifies its role and
expiry. These commands give the subkeys one year of validity.

| Role | Alice uses it for | If the secret is lost |
| --- | --- | --- |
| Signing (`S`) | Files, mail, and Git commits | She can create a replacement for future signatures. |
| Encryption (`E`) | Decrypting messages sent to her | She needs a backup to read messages encrypted to that key. |
| Authentication (`A`, optional) | Logging in through tools such as SSH | She can replace it and update the systems that accept it. |

Separating the roles lets Alice replace or revoke one subkey without
replacing the others. For example, giving a recovery system access to an
encryption key need not give it the ability to sign as her.

**The paper backup does not contain these subkeys.** Alice must back up the
private encryption subkey before relying on it, including before moving it
to a smart card. A new primary-key export cannot recreate its secret.

For daily use, she transfers the needed secret subkeys and the public
certificate to her working environment, while keeping the primary secret
offline. GnuPG provides `--export-secret-subkeys` for this purpose; hardware
tokens have their own provisioning steps, shown for a Nitrokey 3 in
[nitrokey.md](nitrokey.md). See the
[GnuPG command reference](https://www.gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html)
for the export options. These exports contain secrets and need protection.

Some GnuPG setups use a primary marked `[SC]`, which can also sign data.
Alice's arrangement keeps everyday signing on a subkey so that it does not
require access to the primary secret.

## 4. What Alice's signature proves

Alice signs a file with her signing subkey. Bob receives the file, its
signature, and her public certificate. His software checks three things:

1. The data signature verifies with the signing subkey's public key.
2. The subkey has a valid binding to the primary, including the required
   confirmation from the signing subkey itself.
3. The keys and signatures meet the verifier's validity and security policy.

The software can then connect the signing subkey to Alice's certificate and
display her User ID. This is why a GnuPG message such as
`Good signature from "Alice <alice@example.org>"` can appear even though her
primary key never touched the file.

That result establishes a connection between the file and a key. Bob still
has to decide whether that key belongs to Alice. A valid signature also does
not tell him whether Alice personally reviewed the file or whether software
signed it automatically.

### Several email addresses still share one certificate

Alice can add a work email address as another User ID. Both identities then
share the same primary key, and anyone with the full certificate can see
their association.

A signature identifies the signing key. OpenPGP also allows a *Signer's
User ID* field to indicate a role, but it does not create independent keys
or control for each identity. See the
[specification's description of this field](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.30).

If Alice runs a bot that signs automatically, a separate certificate gives
it a distinct identity and primary secret. She can then distinguish a bot's
output from work signed with her personal key. She may certify the bot's
identity with her primary to state that she operates it.

## 5. Trust, expiry, and revocation

Alice and Bob now need ways to establish whose keys they have and to learn
when those keys should stop being used.

### Connecting a key to a person

Bob can compare Alice's full fingerprint with her over a channel he already
trusts. Another person can also sign a statement connecting Alice's User ID
to her primary key. This is a **third-party certification**. Its usefulness
to Bob depends on how much he trusts that person's identity checks.

GnuPG distinguishes two ideas:

| Term | Question it answers |
| --- | --- |
| Validity | Do I accept that this User ID belongs to this key? |
| Ownertrust | How much do I trust this key holder to certify other people's identities? |

In GnuPG's web-of-trust model, certifications and Bob's trust in their
issuers let him establish validity through other people. The **web of trust**
is this network of certifications. A cryptographically good signature may
still come with an identity warning when GnuPG cannot establish that link.

Alice also tells GnuPG that her own key is hers. In her offline keyring:

```sh
echo "PRIMARY_FINGERPRINT:6:" | gpg --homedir offline-gnupg --import-ownertrust
```

The `6` assigns ultimate ownertrust in GnuPG's import format. She repeats this
in each new keyring she uses for her own key. Ownertrust is local state: it
does not travel inside the public certificate. It can be saved separately
with `--export-ownertrust`. The
[GnuPG manual](https://www.gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html)
documents both commands.

### Expiry sets a date for renewal

Alice's subkeys expire after the year she chose. Before then, she can use
her offline primary to extend their validity or authorize replacements, then
distribute the updated public certificate.

Expiry is recorded in signatures. Extending it changes the certificate's
metadata, while the key fingerprints stay the same. The same principle
applies to the primary: `paper-pgp export --expires 2y` sets a validity of two
years from the export time. Without `--expires`, its exports do not expire.

An expiry date helps limit continued use of a forgotten key. Someone holding
the primary secret can extend it, so it does not protect against theft of
that secret.

### Revocation announces that a key should no longer be used

If Alice loses control of a subkey, she uses her offline primary to revoke
it and distributes the updated certificate. If the primary itself is
compromised, she needs to revoke the whole certificate and establish a new
primary key.

She prepares a **revocation certificate** while she still has her primary:

```sh
gpg --homedir offline-gnupg --output revoke.asc --armor \
  --gen-revoke PRIMARY_FINGERPRINT
```

This creates a signed revocation for later use; it does not publish it or
immediately revoke her working keyring. She keeps it separately so that she
can still revoke the key if the primary and its backup are lost. Anyone
who obtains it can distribute the revocation, so it needs protection too.
The [GnuPG key-management manual](https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html)
describes how to apply and distribute it.

Retiring or expiring a signing subkey does not by itself erase the value of
older signatures. A compromise revocation is different: past signatures are
suspect because someone with the stolen secret could forge a signing date.
The verifier's policy and the revocation reason matter. See
[OpenPGP's revocation reasons](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.31).

Revoking a User ID similarly announces that the identity is no longer in
use. It does not remove that identity from copies already distributed.

Next: [Backing up and recovering the setup](backup-recovery.md).

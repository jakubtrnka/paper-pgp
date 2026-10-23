# Using a Nitrokey 3 for the subkeys

Alice's primary key lives on paper and in an offline keyring. Her subkeys do
the daily work, and so far they sit in a keyring on her everyday computer.
This guide moves them onto a Nitrokey 3, so that the secrets leave the
computer entirely, and shows how to keep the paper and the offline keyring as
the backup behind the card.

The GnuPG commands work with any OpenPGP card, such as a YubiKey or an older
Nitrokey. Lines that use `nitropy` are specific to the Nitrokey 3. The
walkthrough assumes the setup from [openpgp-keys.md](openpgp-keys.md): a
certification-only primary in `offline-gnupg`, an Ed25519 signing subkey, and
a Curve25519 encryption subkey. Replace `PRIMARY_FINGERPRINT` with Alice's
full primary fingerprint throughout.

## 1. What the card changes

An OpenPGP card holds up to three private keys, one per role, and performs
the signing, decryption, and authentication operations itself. The keys
cannot be read back out. Each use needs the card's User PIN, and the card can
be set to require a touch of its button for every operation.

| Event | Subkeys in a file on the daily computer | Subkeys on the card |
| --- | --- | --- |
| Someone copies the disk | They have the subkeys. | They have nothing usable. |
| Malware on the computer | It can use and steal the subkeys. | It can ask the card to sign or decrypt while the card is plugged in and unlocked. A touch requirement limits that to one operation per tap. It cannot take the keys. |
| The hardware is lost | The subkeys go with it unless backed up. | The same. The card is not a backup. |

The last row is the one that matters for this project. `keytocard` moves a
key: afterwards the card holds the only copy, and nothing can extract it. The
paper words recover only the primary. So the offline keyring, which keeps the
private subkeys, becomes the backup for the card, and Alice treats it with
the same care as the paper.

The Nitrokey 3 also offers FIDO2 passkeys, one-time codes, and a PIV
application. They are separate applications with their own PINs and are not
used here; the [Nitrokey 3 documentation](https://docs.nitrokey.com/nitrokey3/)
covers them.

## 2. Preparing the card

### Host software

GnuPG reaches the card through its smartcard daemon, `scdaemon`, which needs
the PC/SC service and a CCID driver. `nitropy` is Nitrokey's command-line tool
for the device itself. On Arch Linux:

```sh
sudo pacman -S python-pynitrokey nitrokey-udev-rules ccid pcsc-tools
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo systemctl enable --now pcscd.socket
```

Other distributions package the same pieces under similar names (`pcscd`,
`libccid`, `scdaemon`), and `pipx install pynitrokey` provides `nitropy`
anywhere. Plug in the card and check that both paths to it work:

```sh
nitropy nk3 status      # firmware version and device UUID
gpg --card-status       # the OpenPGP application, still at factory defaults
```

### Firmware and key storage

Update the firmware before anything is on the card, with `nitropy nk3
update`. Updates preserve the card's contents, but a blank card is the
cheapest moment for them.

The Nitrokey 3 keeps OpenPGP keys either in its secure element or in the
microcontroller's own storage. Devices shipped with firmware 1.7.0 or later
use the secure element. Changing the setting wipes the OpenPGP application,
so Alice checks it once and leaves it alone afterwards:

```sh
nitropy nk3 get-config opcard.use_se050_backend
```

### PINs and touch

The OpenPGP application has two PINs. The **User PIN** (factory `123456`,
at least 6 characters) unlocks signing and decryption. The **Admin PIN**
(factory `12345678`, at least 8 characters) is needed to write keys and change
settings. Each allows three wrong attempts. A locked User PIN is reset with
the Admin PIN. A locked Admin PIN cannot be reset; the only way out is a
factory reset of the OpenPGP application, which erases the keys. Alice records
both PINs in her password manager before going on.

`gpg-card` is GnuPG's card manager. Alice changes both PINs and turns on touch
confirmation for all three slots:

```text
$ gpg-card
gpg/card> passwd       # 1 changes the User PIN, 3 the Admin PIN
gpg/card> uif 1 on     # the signature slot requires a touch
gpg/card> uif 2 on     # the encryption slot
gpg/card> uif 3 on     # the authentication slot
gpg/card> name         # optional: cardholder name
gpg/card> url          # optional: where her public certificate can be fetched
gpg/card> quit
```

The `url` is worth filling in. On a new computer, `fetch` in `gpg-card`
downloads the public certificate from it, which is the one thing the card
does not carry.

## 3. Moving the subkeys onto the card

This step happens on the offline machine, with the card plugged into it.
Alice works on a copy of the offline keyring, so that `offline-gnupg` keeps
the private subkeys as the backup for the card:

```sh
cp -a offline-gnupg card-gnupg
gpg --homedir card-gnupg --edit-key PRIMARY_FINGERPRINT
```

Inside the editor she selects each subkey, moves it to its slot, and
deselects it before the next one:

```text
gpg> key 1          # selects the first subkey; it gains a * in the listing
gpg> keytocard      # choose 1, the signature slot; enter the Admin PIN
gpg> key 1          # deselects it
gpg> key 2          # the encryption subkey
gpg> keytocard      # choose 2, the encryption slot
gpg> key 2
gpg> save
```

The numbers follow the order of the `ssb` lines in the listing, so she reads
the listing rather than assuming it. With an authentication subkey, she
repeats the steps with `key 3` and slot 3.

`save` replaces the secret subkeys in `card-gnupg` with stubs that name the
card's serial number. The GnuPG manual states that the local secret is
replaced only on `save`, but the copy makes that detail irrelevant:
`offline-gnupg` is untouched either way. `card-gnupg` now holds only stubs
and a second copy of the primary secret, so Alice deletes it.

On the daily computer, the card and the saved public certificate are all
GnuPG needs:

```sh
gpg --import alice-public.asc     # the public certificate from the offline keyring
gpg --card-status                 # creates the stubs that point at the card
gpg --list-secret-keys            # ssb> marks a subkey that lives on the card
```

The `>` after `ssb` is GnuPG's way of saying the secret is on a card. The
primary shows as `sec#`: GnuPG knows it exists and has no secret for it,
which is exactly the arrangement from [openpgp-keys.md](openpgp-keys.md).

## 4. Daily use

Signing and decrypting work as before; GnuPG asks for the User PIN on first
use, then the card asks for a touch if that was enabled:

```sh
gpg --sign --armor report.txt
gpg --decrypt message.asc
```

The agent caches the PIN until the card is removed. `gpg --card-status`
shows the signature counter, which only goes up, so an unexpected jump is a
sign that something used the card without her.

With an authentication subkey on the card, the same key serves SSH. Alice adds
`enable-ssh-support` to `~/.gnupg/gpg-agent.conf`, points SSH at the agent,
and reads the public key to install on servers:

```sh
export SSH_AUTH_SOCK="$(gpgconf --list-dirs agent-ssh-socket)"
ssh-add -L
```

Renewing the subkeys' expiry, as described in
[openpgp-keys.md](openpgp-keys.md#expiry-sets-a-date-for-renewal), does not
touch the card at all. Expiry lives in the binding signatures, which the
offline primary refreshes; Alice exports the updated public certificate and
imports it on the daily computer.

## 5. Two cards with the same subkeys

Because the subkeys were generated in the offline keyring, a second card can
carry identical copies. Alice repeats section 3 with a fresh copy:

```sh
cp -a offline-gnupg card2-gnupg
gpg --homedir card2-gnupg --edit-key PRIMARY_FINGERPRINT
```

The public certificate does not change, and signatures from either card are
indistinguishable. Both cards get their own PINs and touch settings.

Each stub in the daily keyring remembers the serial number of the card it
was created from. Current GnuPG finds the key on whichever card is inserted.
If it insists on the other card's serial number, Alice runs
`gpg --card-status` with the new card plugged in, which rewrites the stubs.

This is what makes the hardware key fit the paper backup: the primary comes
back from the words, the subkeys come back from the offline keyring, and a
card is a replaceable holder for copies of them.

## 6. Losing a card

A finder gets three guesses at the User PIN and three at the Admin PIN; after
that the OpenPGP application can only be factory-reset, which erases the keys.
The keys cannot be extracted at any point. Alice still treats a lost card as
a compromise of the subkeys, because she cannot know whether someone watched
her type the PIN.

1. In the offline keyring she revokes the subkeys that were on the card and
   creates replacements:

    ```text
    $ gpg --homedir offline-gnupg --edit-key PRIMARY_FINGERPRINT
    gpg> key 1
    gpg> revkey        # reason 1: key has been compromised
    gpg> key 1
    gpg> key 2
    gpg> revkey
    gpg> save
    ```

    The `--quick-add-key` commands from
    [openpgp-keys.md](openpgp-keys.md#3-subkeys-for-everyday-work) then
    add new subkeys.
2. She exports the public certificate again and distributes it, so that
   others stop using the revoked subkeys. The revocation and the new bindings
   travel inside it.
3. She loads the new subkeys onto a replacement card, following section 3,
   and imports the new public certificate on the daily computer.

Messages encrypted to the revoked encryption subkey stay readable in the
offline keyring, which still holds its secret. GnuPG warns about the
revocation and decrypts anyway.

If the card merely broke, nothing was exposed: Alice skips the revocation and
loads the same subkeys onto a replacement card, as in section 5.

If the offline keyring is lost as well, the paper words bring back the
primary; [backup-recovery.md](backup-recovery.md) walks through that. The
subkeys cannot be recovered that way. She revokes them with the restored
primary, creates new ones, and accepts that messages encrypted to the old
encryption subkey are unreadable, as the recovery chapter warns.

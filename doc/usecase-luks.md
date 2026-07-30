# LUKS2 Volume Encryption with Ledger Security Key

`systemd-cryptenroll` supports enrolling a FIDO2 key as an unlock factor for a LUKS2 volume via the `hmac-secret` extension. This lets you mount an encrypted image file or partition by tapping your Ledger — no passphrase typed.

A passphrase fallback is set during formatting and can always be used if the device is unavailable.

**Requirements:** cryptsetup 2.4+, systemd 251+, Ubuntu 22.04+

---

## Phase 1: Create and Format the Encrypted Volume

Create an image file (adjust size as needed):

```sh
fallocate -l 8G vault.img
```

Format it as a LUKS2 volume with strong cryptographic parameters. You will be asked to type `YES` and set a fallback passphrase:

```sh
sudo cryptsetup luksFormat \
  --type luks2 \
  --cipher aes-xts-plain64 \
  --key-size 512 \
  --hash sha512 \
  --pbkdf argon2id \
  vault.img
```

---

## Phase 2: Enroll Your Ledger

Plug in your Ledger, unlock it with your PIN, and open the **Security Key** app so it displays "Ready".

```sh
sudo systemd-cryptenroll --fido2-device=auto vault.img
```

You will be asked for the fallback passphrase, then prompted to tap the Ledger.

---

## Phase 3: Format the Inner Filesystem (first time only)

Unlock the volume:

```sh
sudo /lib/systemd/systemd-cryptsetup attach my_vault vault.img none fido2-device=auto
```

Format the decrypted space:

```sh
sudo mkfs.ext4 /dev/mapper/my_vault
```

Then lock it again:

```sh
sudo cryptsetup close my_vault
```

---

## Phase 4: Mount and Unmount

**Mount (hardware key):**

```sh
sudo /lib/systemd/systemd-cryptsetup attach my_vault vault.img none fido2-device=auto
sudo mkdir -p /media/$USER/vault
sudo mount /dev/mapper/my_vault /media/$USER/vault
sudo chown $USER:$USER /media/$USER/vault
```

**Mount (passphrase fallback):**

```sh
sudo cryptsetup luksOpen vault.img my_vault
sudo mkdir -p /media/$USER/vault
sudo mount /dev/mapper/my_vault /media/$USER/vault
sudo chown $USER:$USER /media/$USER/vault
```

**Unmount:**

```sh
sudo umount /media/$USER/vault
sudo cryptsetup close my_vault
```

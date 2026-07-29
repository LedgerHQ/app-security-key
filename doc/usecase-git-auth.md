# Git SSH Authentication with Ledger Security Key

OpenSSH 8.2+ natively supports FIDO2 security keys as SSH key backends. This lets you use your Ledger as a hardware-bound SSH key for authenticating to GitHub, GitLab, and remote servers — the private key never leaves the device.

**Requirements:** OpenSSH 8.2+

---

## Step 1: Generate the SSH Key

Plug in your Ledger, unlock it with your PIN, and open the **Security Key** app so it displays "Ready".

```sh
ssh-keygen -t ed25519-sk -f ~/.ssh/id_ledger_sk
```

Your Ledger will prompt for confirmation — tap the screen. Optionally set a passphrase when asked.

Two files are created:
- `~/.ssh/id_ledger_sk` — the key handle (references the hardware key, not a secret itself)
- `~/.ssh/id_ledger_sk.pub` — the public key to register with services

---

## Step 2: Register the Public Key

**GitHub:** Settings → SSH and GPG Keys → New SSH Key → **Authentication Key** → paste the contents of `~/.ssh/id_ledger_sk.pub`.

For remote servers, append the public key to `~/.ssh/authorized_keys` on the target host.

---

## Step 3: Use It

```sh
git clone git@github.com:your-org/your-repo.git
```

Each operation that requires authentication will prompt you to tap the Ledger.

---

## Notes

- Use `-t ecdsa-sk` instead of `-t ed25519-sk` if the server does not support Ed25519.
- Add `-O no-touch-required` to skip the tap prompt, though some services (including GitHub) refuse keys generated with this flag.
- See the [Ledger blog post](https://www.ledger.com/blog/strengthen-the-security-of-your-accounts-with-webauthn) for a full walkthrough with example output.

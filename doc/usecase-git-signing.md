# Git Commit Signing with Ledger Security Key

Git 2.34+ supports SSH-based commit and tag signing. Combined with a FIDO2 SSH key, every commit you sign is hardware-bound: the signature requires a physical tap on your Ledger.

**Requirements:** Git 2.34+, OpenSSH 8.2+

---

## Step 1: Generate a Dedicated Signing Key

Plug in your Ledger, unlock it with your PIN, and open the **Security Key** app so it displays "Ready".

```sh
ssh-keygen -t ed25519-sk -f ~/.ssh/id_ledger_sk_signing
```

Tap the Ledger when prompted.

---

## Step 2: Configure Git

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ledger_sk_signing.pub
git config --global commit.gpgsign true
```

Register yourself as an allowed signer for local verification:

```sh
echo "$(git config user.email) $(cat ~/.ssh/id_ledger_sk_signing.pub)" >> ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

---

## Step 3: Register on GitHub

Settings → SSH and GPG Keys → New SSH Key → **Signing Key** (not Authentication Key) → paste the contents of `~/.ssh/id_ledger_sk_signing.pub`.

---

## Step 4: Use It

With `commit.gpgsign true`, all commits are signed automatically. Each commit will prompt a tap on the Ledger.

To sign a single commit explicitly:

```sh
git commit -S -m "your message"
```

To verify a commit signature locally:

```sh
git log --show-signature
```

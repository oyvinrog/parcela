# Parcela

Parcela is a highly secure encryption vault.

Parcela provides stronger encryption than other encryption tools by splitting the encrypted file into 2-of-3 shares. Any two shares can recover the original file. The files are encrypted with AES-256-GCM. This means that: 

1) If someone steals 2-3 shares, they cannot decrypt the original file. Because they don't have the password.
2) If someone steals the password, they cannot decrypt the original file. Because they don't have the shares.

Parcela also provides a virtual drive feature. You can create a virtual drive that is a RAM-backed filesystem. You can store files in the virtual drive and it will be encrypted with AES-256-GCM. Any two shares can recover the virtual drive.

![Parcela Architecture](docs/assets/architecture.png)

## Features

- Split a file into 2-of-3 shares. Any two shares can recover the original file.
- Combine any two shares to recover the original file.
- Create a virtual drive that is a RAM-backed filesystem.
- Store files in the virtual drive and it will be encrypted with AES-256-GCM.
- Any two shares can recover the virtual drive.


## Technical details

Parcela is a minimal Rust + Tauri GUI that encrypts a file with AES-256-GCM and splits the encrypted blob into 2-of-3 shares. Any two shares can recover the original file.

## Build & test

```bash
cargo test
```

## GUI (Tauri)

Install the Tauri CLI (v2):

```bash
cargo install tauri-cli --version "^2"
```

Run the desktop app:

```bash
cargo tauri dev
```

## Release builds (Windows, macOS, Linux)

Tauri bundles are OS-specific, so you must build on each platform. This repo includes a GitHub Actions workflow that does it for you and attaches installers to a GitHub Release.

Release steps:

1) Commit and push your changes.
2) Create a version tag (example):

```bash
git tag v0.1.0
git push origin v0.1.0
```

3) The GitHub Actions workflow builds the GUI for Windows/macOS/Linux and creates a draft release with installers attached.
4) Open the draft release on GitHub and publish it.

Manual local build:

```bash
cargo tauri build
```

Output artifacts are under `src-tauri/target/release/bundle/`.

## Release checklist (first time)

- Run `cargo test`
- Run `cargo tauri dev`
- Update version in `src-tauri/tauri.conf.json`
- Commit and push
- Tag and push: `git tag v0.1.0 && git push origin v0.1.0`
- Confirm GitHub Actions workflow completes
- Download and test the Windows installer
- Publish the GitHub Release

## Code signing notes

- Windows: unsigned installers may trigger SmartScreen. For production, sign with an Authenticode certificate (EV recommended).
- macOS: notarization is required for smooth installs; you will need an Apple Developer ID certificate and `notarytool`.
- Linux: signing is uncommon; provide checksums (SHA-256) on the release page instead.

## Usage

Split a file into shares:

```bash
cargo run -- split --input /path/to/file.txt --out-dir /path/to/shares --password "your-passphrase"
```

This produces:

- `file.txt.share1`
- `file.txt.share2`
- `file.txt.share3`

Combine any two shares back into the original file:

```bash
cargo run -- combine \
  --shares /path/to/shares/file.txt.share1 /path/to/shares/file.txt.share3 \
  --output /path/to/file.txt \
  --password "your-passphrase"
```

## File format (v1)

Encrypted blob layout:

- `MAGIC_BLOB` (8 bytes): `PARCELA1`
- Nonce (12 bytes)
- Ciphertext (AES-256-GCM)

Share layout:

- `MAGIC_SHARE` (8 bytes): `PSHARE01`
- `index` (1 byte): 1, 2, or 3
- `total` (1 byte): 3
- `threshold` (1 byte): 2
- `len` (4 bytes, big-endian)
- `payload` (len bytes)

## Notes

- This is a v1 MVP focused on correctness and test coverage.
- Key derivation is SHA-256(passphrase) for now. If you want a stronger KDF (Argon2/PBKDF2), we can upgrade.

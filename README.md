# Parcela

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

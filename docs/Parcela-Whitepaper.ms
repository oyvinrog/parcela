.TL
Parcela: Split-Key Encryption with 2-of-3 Secret Sharing and Steganographic Shares
.AU
S. Nakamoto
.AI
Independent Researcher
.AB
We present Parcela, a split-key encryption vault that eliminates the single point of failure in traditional password-based encryption. Parcela combines password-derived authenticated encryption with a 2-of-3 threshold secret sharing scheme. Recovery requires both the password and any two of three shares, distributed across independent locations. We describe the file format, share encoding, and steganographic embedding into valid PNG images, and we analyze the security properties under realistic threat models. The system is implemented as a cross-platform desktop application with a CLI and a RAM-backed virtual drive.
.AE

.SH
Introduction
.PP
Traditional encryption systems protect data with a single secret: the password. If the password is compromised, the data is lost. If the encrypted file is stolen, attackers can attempt offline guessing. Parcela removes this single point of failure by requiring two independent factors: a password-derived encryption key and physical possession of multiple shares. The design targets high-value personal and organizational data where loss or coercion risks are non-trivial.

.SH
Threat Model
.PP
We consider adversaries who can steal the encrypted file, steal a password, or gain access to one share. We assume the attacker does not compromise two independent storage locations at once. The system does not protect against coercion to reveal both password and two shares, nor against re-encoding of steganographic images by third-party services.

.SH
System Overview
.PP
Parcela operates in four stages:
.IP
1. Encrypt the file using AES-256-GCM with a key derived via Argon2id.
.IP
2. Split the encrypted blob into 3 shares using a 2-of-3 threshold scheme.
.IP
3. Distribute shares across independent locations or devices.
.IP
4. Reconstruct the encrypted blob from any 2 shares and decrypt with the password.

.SH
Cryptographic Construction
.PP
Key derivation uses Argon2id with a random 32-byte salt, 64 MiB memory, 3 iterations, and 4 lanes, targeting approximately 2 seconds on modern hardware. The resulting 32-byte key is used with AES-256-GCM to encrypt the plaintext. The output is an authenticated ciphertext and nonce.
.PP
The encrypted blob format (v2) is:
.nf
PARCELA2   (8 bytes magic)
<salt>     (32 bytes)
<nonce>    (12 bytes)
<ciphertext>
.fi

.SH
Secret Sharing
.PP
The encrypted blob is split with a 2-of-3 threshold scheme. Any two shares can reconstruct the original blob; one share alone reveals no information. Shares are stored as either binary files or embedded within PNG images.
.PP
The share file format is:
.nf
PSHARE01   (8 bytes magic)
<index>    (1 byte: 1, 2, or 3)
<total>    (1 byte: 3)
<threshold>(1 byte: 2)
<length>   (4 bytes, big-endian)
<payload>
.fi

.SH
Steganographic Image Shares
.PP
To improve concealment during storage and transport, Parcela embeds share data in custom PNG chunks. The images remain valid PNG files and can be opened by standard image viewers. The data survives normal file copying but is lost if the image is re-encoded by social platforms or editors.

.SH
Virtual Drive
.PP
Parcela includes a RAM-backed virtual drive that exposes decrypted files to the operating system without writing plaintext to disk. On Windows, it uses Projected File System (ProjFS); on macOS and Linux, a tmpfs-backed directory in /tmp is used. Files exist only in memory and are cleared on shutdown.

.SH
Security Analysis
.PP
Password compromise alone is insufficient because reconstruction requires two shares. Share compromise alone yields no information about the encrypted blob or plaintext. File theft alone is ineffective due to Argon2id hardening and AES-GCM authentication. The design thus resists common offline attacks and improves resilience against partial breaches.
.PP
Residual risks include loss of shares, improper handling of steganographic images, and coercion attacks. Users must distribute shares across independent locations to preserve the threat model.

.SH
Implementation Notes
.PP
Parcela is implemented in Rust with a cross-platform GUI and a CLI. The CLI supports splitting and combining shares, and can output either PNG-embedded or legacy binary shares for compatibility.

.SH
Use Cases
.PP
Parcela targets scenarios where a single key is too risky: estate planning, password backups, sensitive personal records, and high-value corporate secrets. Distribution of shares across physical and organizational boundaries is the primary security benefit.

.SH
Limitations
.PP
Parcela does not protect against an adversary who obtains the password and two shares. It also does not protect against malware on the local machine at the time of decryption. Steganographic shares must not be altered by services that re-encode images.

.SH
Conclusion
.PP
Parcela combines password-based encryption with threshold secret sharing to remove single points of failure. By requiring both a password and a quorum of shares, it offers a practical and user-friendly approach to long-term secure storage of sensitive data.

.SH
References
.IP
[1] Parcela project documentation and source code.

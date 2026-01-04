use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Argon2, Algorithm, Version, Params};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod virtual_drive;

#[cfg(target_os = "windows")]
pub mod projfs_fs;

pub use virtual_drive::{
    VirtualDrive, VirtualDriveError, VirtualDriveMetadata, MemoryFileSystem,
    get_mount_path, get_mounted_path, is_mounted, is_memory_mode, lock_drive, unlock_drive,
    uses_memory_mode, vdrive_create_dir, vdrive_delete_file, vdrive_list_files,
    vdrive_read_file, vdrive_write_file,
    MAGIC_VDRIVE, DEFAULT_DRIVE_SIZE_MB,
};

#[cfg(target_os = "windows")]
pub use projfs_fs::is_projfs_available;

/// Legacy format magic (SHA-256 key derivation) - for reading old files only
pub const MAGIC_BLOB_V1: &[u8; 8] = b"PARCELA1";
/// Current format magic (Argon2id key derivation)
pub const MAGIC_BLOB: &[u8; 8] = b"PARCELA2";
/// Legacy share format (no checksum)
pub const MAGIC_SHARE: &[u8; 8] = b"PSHARE01";
/// Current share format with SHA-256 checksum for integrity verification
pub const MAGIC_SHARE_V2: &[u8; 8] = b"PSHARE02";

/// Salt size for Argon2id
pub const SALT_SIZE: usize = 32;

/// Argon2id parameters for high security (targets ~2s on modern hardware)
/// - Memory: 64 MiB (good resistance against GPU/ASIC attacks)
/// - Time: 3 iterations
/// - Parallelism: 4 lanes
const ARGON2_M_COST: u32 = 64 * 1024; // 64 MiB in KiB
const ARGON2_T_COST: u32 = 3;         // 3 iterations
const ARGON2_P_COST: u32 = 4;         // 4 parallel lanes
pub const SHARE_TOTAL: u8 = 3;
pub const SHARE_THRESHOLD: u8 = 2;

/// Secure key wrapper that zeros memory on drop.
/// This ensures encryption keys don't persist in memory after use.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecureKey([u8; 32]);

#[derive(Debug)]
pub enum ParcelaError {
    InvalidFormat(&'static str),
    InvalidShare(&'static str),
    CryptoFailure,
}

impl std::fmt::Display for ParcelaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParcelaError::InvalidFormat(msg) => write!(f, "invalid format: {msg}"),
            ParcelaError::InvalidShare(msg) => write!(f, "invalid share: {msg}"),
            ParcelaError::CryptoFailure => write!(f, "cryptographic failure"),
        }
    }
}

impl std::error::Error for ParcelaError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub index: u8,
    pub payload: Vec<u8>,
}

/// Legacy key derivation using SHA-256 (for reading PARCELA1 files only).
/// Returns a SecureKey that will be zeroed on drop.
fn derive_key_legacy(password: &str) -> SecureKey {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    SecureKey(key)
}

/// Derive encryption key using Argon2id with high-security parameters.
/// This function is intentionally slow (10-20 seconds) to protect against brute-force attacks.
/// Returns a SecureKey that will be zeroed on drop.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<SecureKey, ParcelaError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|_| ParcelaError::CryptoFailure)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| ParcelaError::CryptoFailure)?;
    Ok(SecureKey(key))
}

pub fn encrypt_with_rng(
    plaintext: &[u8],
    password: &str,
    rng: &mut impl RngCore,
) -> Result<Vec<u8>, ParcelaError> {
    // Generate random salt for Argon2id
    let mut salt = [0u8; SALT_SIZE];
    rng.fill_bytes(&mut salt);

    // Key is automatically zeroed when dropped
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|_| ParcelaError::CryptoFailure)?;
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| ParcelaError::CryptoFailure)?;

    // Format: MAGIC (8) + SALT (32) + NONCE (12) + CIPHERTEXT
    let mut out = Vec::with_capacity(MAGIC_BLOB.len() + SALT_SIZE + nonce_bytes.len() + ciphertext.len());
    out.extend_from_slice(MAGIC_BLOB);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
    // key is zeroed here when it goes out of scope
}

pub fn encrypt(plaintext: &[u8], password: &str) -> Result<Vec<u8>, ParcelaError> {
    let mut rng = rand::rngs::OsRng;
    encrypt_with_rng(plaintext, password, &mut rng)
}

pub fn decrypt(blob: &[u8], password: &str) -> Result<Vec<u8>, ParcelaError> {
    if blob.len() < 8 {
        return Err(ParcelaError::InvalidFormat("blob too small"));
    }

    let magic = &blob[..8];

    // Handle legacy PARCELA1 format (SHA-256 key derivation)
    // WARNING: This format uses weak key derivation (SHA-256) which is vulnerable
    // to GPU-accelerated brute force attacks. Consider re-encrypting with the
    // current PARCELA2 format using Argon2id.
    if magic == MAGIC_BLOB_V1 {
        // Emit deprecation warning to stderr
        eprintln!(
            "WARNING: Decrypting legacy PARCELA1 format file. \
             This format uses weak SHA-256 key derivation. \
             Consider re-encrypting with the current format for better security."
        );

        if blob.len() < 8 + 12 {
            return Err(ParcelaError::InvalidFormat("blob too small"));
        }
        let nonce_start = 8;
        let nonce_end = nonce_start + 12;
        let nonce = Nonce::from_slice(&blob[nonce_start..nonce_end]);
        let ciphertext = &blob[nonce_end..];

        // Key is automatically zeroed when dropped
        let key = derive_key_legacy(password);
        let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|_| ParcelaError::CryptoFailure)?;
        return cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| ParcelaError::CryptoFailure);
        // key is zeroed here
    }

    // Handle current PARCELA2 format (Argon2id key derivation)
    if magic == MAGIC_BLOB {
        // Format: MAGIC (8) + SALT (32) + NONCE (12) + CIPHERTEXT
        if blob.len() < 8 + SALT_SIZE + 12 {
            return Err(ParcelaError::InvalidFormat("blob too small"));
        }
        let salt_start = 8;
        let salt_end = salt_start + SALT_SIZE;
        let salt = &blob[salt_start..salt_end];

        let nonce_start = salt_end;
        let nonce_end = nonce_start + 12;
        let nonce = Nonce::from_slice(&blob[nonce_start..nonce_end]);
        let ciphertext = &blob[nonce_end..];

        // Key is automatically zeroed when dropped
        let key = derive_key(password, salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|_| ParcelaError::CryptoFailure)?;
        return cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| ParcelaError::CryptoFailure);
        // key is zeroed here
    }

    Err(ParcelaError::InvalidFormat("bad magic"))
}

pub fn split_shares_with_rng(
    secret: &[u8],
    rng: &mut impl RngCore,
) -> Result<[Share; 3], ParcelaError> {
    let mut s1 = Vec::with_capacity(secret.len());
    let mut s2 = Vec::with_capacity(secret.len());
    let mut s3 = Vec::with_capacity(secret.len());

    for &byte in secret {
        let mut a = [0u8; 1];
        rng.fill_bytes(&mut a);
        let a = a[0];
        let y1 = gf_add(byte, gf_mul(a, 1));
        let y2 = gf_add(byte, gf_mul(a, 2));
        let y3 = gf_add(byte, gf_mul(a, 3));
        s1.push(y1);
        s2.push(y2);
        s3.push(y3);
    }

    Ok([
        Share {
            index: 1,
            payload: s1,
        },
        Share {
            index: 2,
            payload: s2,
        },
        Share {
            index: 3,
            payload: s3,
        },
    ])
}

pub fn split_shares(secret: &[u8]) -> Result<[Share; 3], ParcelaError> {
    let mut rng = rand::rngs::OsRng;
    split_shares_with_rng(secret, &mut rng)
}

pub fn combine_shares(shares: &[Share]) -> Result<Vec<u8>, ParcelaError> {
    if shares.len() < 2 {
        return Err(ParcelaError::InvalidShare("need at least two shares"));
    }
    let s1 = &shares[0];
    let s2 = &shares[1];
    if s1.index == s2.index {
        return Err(ParcelaError::InvalidShare("duplicate share index"));
    }
    if s1.payload.len() != s2.payload.len() {
        return Err(ParcelaError::InvalidShare("share length mismatch"));
    }

    let x1 = s1.index;
    let x2 = s2.index;
    let denom = gf_add(x1, x2);
    if denom == 0 {
        return Err(ParcelaError::InvalidShare("invalid share indices"));
    }
    let inv_denom = gf_inv(denom)?;

    let mut secret = Vec::with_capacity(s1.payload.len());
    for (&y1, &y2) in s1.payload.iter().zip(s2.payload.iter()) {
        let a = gf_mul(gf_add(y1, y2), inv_denom);
        let s = gf_add(y1, gf_mul(a, x1));
        secret.push(s);
    }

    Ok(secret)
}

/// Encode a share with integrity checksum (PSHARE02 format).
/// Format: MAGIC (8) + INDEX (1) + TOTAL (1) + THRESHOLD (1) + LEN (4) + PAYLOAD (N) + SHA256 (32)
pub fn encode_share(share: &Share) -> Vec<u8> {
    // Calculate checksum over index + payload
    let mut hasher = Sha256::new();
    hasher.update([share.index]);
    hasher.update(&share.payload);
    let checksum = hasher.finalize();

    let mut out = Vec::with_capacity(8 + 1 + 1 + 1 + 4 + share.payload.len() + 32);
    out.extend_from_slice(MAGIC_SHARE_V2);
    out.push(share.index);
    out.push(SHARE_TOTAL);
    out.push(SHARE_THRESHOLD);
    let len = share.payload.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&share.payload);
    out.extend_from_slice(&checksum);
    out
}

/// Decode a share, supporting both legacy (PSHARE01) and current (PSHARE02) formats.
pub fn decode_share(data: &[u8]) -> Result<Share, ParcelaError> {
    if data.len() < 8 + 1 + 1 + 1 + 4 {
        return Err(ParcelaError::InvalidFormat("share too small"));
    }

    let magic = &data[..8];

    // Handle legacy PSHARE01 format (no checksum)
    // WARNING: This format lacks integrity verification. Consider re-splitting
    // with the current PSHARE02 format to detect corruption.
    if magic == MAGIC_SHARE {
        // Emit deprecation warning to stderr
        eprintln!(
            "WARNING: Reading legacy PSHARE01 format share. \
             This format lacks integrity verification. \
             Consider re-creating shares with the current format."
        );

        let index = data[8];
        let total = data[9];
        let threshold = data[10];
        if total != SHARE_TOTAL || threshold != SHARE_THRESHOLD {
            return Err(ParcelaError::InvalidShare("unsupported scheme"));
        }
        let len = u32::from_be_bytes([data[11], data[12], data[13], data[14]]) as usize;
        let payload = data
            .get(15..15 + len)
            .ok_or(ParcelaError::InvalidFormat("truncated share"))?
            .to_vec();
        return Ok(Share { index, payload });
    }

    // Handle current PSHARE02 format (with SHA-256 checksum)
    if magic == MAGIC_SHARE_V2 {
        let index = data[8];
        let total = data[9];
        let threshold = data[10];
        if total != SHARE_TOTAL || threshold != SHARE_THRESHOLD {
            return Err(ParcelaError::InvalidShare("unsupported scheme"));
        }
        let len = u32::from_be_bytes([data[11], data[12], data[13], data[14]]) as usize;

        // Verify we have enough data for payload + checksum
        if data.len() < 15 + len + 32 {
            return Err(ParcelaError::InvalidFormat("truncated share or checksum"));
        }

        let payload = data[15..15 + len].to_vec();
        let stored_checksum = &data[15 + len..15 + len + 32];

        // Verify checksum
        let mut hasher = Sha256::new();
        hasher.update([index]);
        hasher.update(&payload);
        let computed_checksum = hasher.finalize();

        if computed_checksum.as_slice() != stored_checksum {
            return Err(ParcelaError::InvalidShare("checksum mismatch - share corrupted"));
        }

        return Ok(Share { index, payload });
    }

    Err(ParcelaError::InvalidFormat("bad share magic"))
}

fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

fn gf_pow(mut a: u8, mut exp: u8) -> u8 {
    let mut result = 1u8;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, a);
        }
        a = gf_mul(a, a);
        exp >>= 1;
    }
    result
}

fn gf_inv(a: u8) -> Result<u8, ParcelaError> {
    if a == 0 {
        return Err(ParcelaError::InvalidShare("zero has no inverse"));
    }
    Ok(gf_pow(a, 254))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let data = b"hello parcela";
        let enc = encrypt_with_rng(data, "pass", &mut rng).unwrap();
        let dec = decrypt(&enc, "pass").unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn decrypt_wrong_password_fails() {
        let mut rng = StdRng::seed_from_u64(7);
        let data = b"secret";
        let enc = encrypt_with_rng(data, "correct", &mut rng).unwrap();
        let err = decrypt(&enc, "wrong").unwrap_err();
        assert!(matches!(err, ParcelaError::CryptoFailure));
    }

    #[test]
    fn split_combine_any_two() {
        let mut rng = StdRng::seed_from_u64(1);
        let data = b"split me";
        let shares = split_shares_with_rng(data, &mut rng).unwrap();
        let recovered = combine_shares(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn combine_rejects_duplicate_index() {
        let mut rng = StdRng::seed_from_u64(2);
        let data = b"dup";
        let shares = split_shares_with_rng(data, &mut rng).unwrap();
        let err = combine_shares(&[shares[0].clone(), shares[0].clone()]).unwrap_err();
        assert!(matches!(
            err,
            ParcelaError::InvalidShare("duplicate share index")
        ));
    }

    #[test]
    fn share_encode_decode_roundtrip() {
        let share = Share {
            index: 2,
            payload: vec![1, 2, 3, 4],
        };
        let encoded = encode_share(&share);
        let decoded = decode_share(&encoded).unwrap();
        assert_eq!(decoded, share);
    }

    #[test]
    fn decrypt_rejects_bad_magic() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"BADMAGIC");
        blob.extend_from_slice(&[0u8; 12]);
        blob.extend_from_slice(&[1u8, 2, 3]);
        let err = decrypt(&blob, "pass").unwrap_err();
        assert!(matches!(err, ParcelaError::InvalidFormat("bad magic")));
    }

    #[test]
    fn decrypt_rejects_too_small() {
        // Test v1 format (PARCELA1) with insufficient size
        let mut blob_v1 = Vec::new();
        blob_v1.extend_from_slice(MAGIC_BLOB_V1);
        blob_v1.extend_from_slice(&[0u8; 11]); // Need 12 bytes for nonce
        let err = decrypt(&blob_v1, "pass").unwrap_err();
        assert!(matches!(err, ParcelaError::InvalidFormat("blob too small")));
        
        // Test v2 format (PARCELA2) with insufficient size
        let mut blob_v2 = Vec::new();
        blob_v2.extend_from_slice(MAGIC_BLOB);
        blob_v2.extend_from_slice(&[0u8; 43]); // Need 32 (salt) + 12 (nonce) = 44 bytes
        let err = decrypt(&blob_v2, "pass").unwrap_err();
        assert!(matches!(err, ParcelaError::InvalidFormat("blob too small")));
    }

    #[test]
    fn combine_rejects_too_few_shares() {
        let share = Share {
            index: 1,
            payload: vec![0u8; 3],
        };
        let err = combine_shares(&[share]).unwrap_err();
        assert!(matches!(
            err,
            ParcelaError::InvalidShare("need at least two shares")
        ));
    }

    #[test]
    fn combine_rejects_length_mismatch() {
        let s1 = Share {
            index: 1,
            payload: vec![1, 2, 3],
        };
        let s2 = Share {
            index: 2,
            payload: vec![4, 5],
        };
        let err = combine_shares(&[s1, s2]).unwrap_err();
        assert!(matches!(
            err,
            ParcelaError::InvalidShare("share length mismatch")
        ));
    }

    #[test]
    fn decode_share_rejects_bad_magic() {
        let mut data = encode_share(&Share {
            index: 1,
            payload: vec![1, 2, 3],
        });
        data[..8].copy_from_slice(b"BADMAGIC");
        let err = decode_share(&data).unwrap_err();
        assert!(matches!(err, ParcelaError::InvalidFormat("bad share magic")));
    }

    #[test]
    fn decode_share_rejects_truncated_payload() {
        let mut data = encode_share(&Share {
            index: 1,
            payload: vec![1, 2, 3, 4],
        });
        // Truncate the checksum (last 32 bytes)
        data.truncate(data.len() - 2);
        let err = decode_share(&data).unwrap_err();
        // With new format, truncation affects checksum verification
        assert!(matches!(
            err,
            ParcelaError::InvalidFormat("truncated share or checksum")
        ));
    }

    #[test]
    fn decode_share_detects_corruption() {
        let mut data = encode_share(&Share {
            index: 1,
            payload: vec![1, 2, 3, 4],
        });
        // Corrupt the payload (flip a bit)
        data[15] ^= 0xFF;
        let err = decode_share(&data).unwrap_err();
        assert!(matches!(
            err,
            ParcelaError::InvalidShare("checksum mismatch - share corrupted")
        ));
    }

    #[test]
    fn decode_share_rejects_unsupported_scheme() {
        // Use legacy format to test scheme validation (since new format
        // would fail checksum first)
        let share = Share {
            index: 1,
            payload: vec![1, 2, 3],
        };
        let mut data = Vec::with_capacity(8 + 1 + 1 + 1 + 4 + share.payload.len());
        data.extend_from_slice(MAGIC_SHARE); // Legacy format
        data.push(share.index);
        data.push(4); // Invalid total (not 3)
        data.push(SHARE_THRESHOLD);
        let len = share.payload.len() as u32;
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(&share.payload);

        let err = decode_share(&data).unwrap_err();
        assert!(matches!(
            err,
            ParcelaError::InvalidShare("unsupported scheme")
        ));
    }
}

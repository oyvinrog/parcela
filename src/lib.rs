use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const MAGIC_BLOB: &[u8; 8] = b"PARCELA1";
pub const MAGIC_SHARE: &[u8; 8] = b"PSHARE01";
pub const SHARE_TOTAL: u8 = 3;
pub const SHARE_THRESHOLD: u8 = 2;

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

pub fn derive_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

pub fn encrypt_with_rng(
    plaintext: &[u8],
    password: &str,
    rng: &mut impl RngCore,
) -> Result<Vec<u8>, ParcelaError> {
    let key = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| ParcelaError::CryptoFailure)?;
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| ParcelaError::CryptoFailure)?;

    let mut out = Vec::with_capacity(MAGIC_BLOB.len() + nonce_bytes.len() + ciphertext.len());
    out.extend_from_slice(MAGIC_BLOB);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn encrypt(plaintext: &[u8], password: &str) -> Result<Vec<u8>, ParcelaError> {
    let mut rng = rand::rngs::OsRng;
    encrypt_with_rng(plaintext, password, &mut rng)
}

pub fn decrypt(blob: &[u8], password: &str) -> Result<Vec<u8>, ParcelaError> {
    if blob.len() < MAGIC_BLOB.len() + 12 {
        return Err(ParcelaError::InvalidFormat("blob too small"));
    }
    if &blob[..MAGIC_BLOB.len()] != MAGIC_BLOB {
        return Err(ParcelaError::InvalidFormat("bad magic"));
    }
    let nonce_start = MAGIC_BLOB.len();
    let nonce_end = nonce_start + 12;
    let nonce = Nonce::from_slice(&blob[nonce_start..nonce_end]);
    let ciphertext = &blob[nonce_end..];

    let key = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| ParcelaError::CryptoFailure)?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| ParcelaError::CryptoFailure)
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

pub fn encode_share(share: &Share) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 1 + 1 + 1 + 4 + share.payload.len());
    out.extend_from_slice(MAGIC_SHARE);
    out.push(share.index);
    out.push(SHARE_TOTAL);
    out.push(SHARE_THRESHOLD);
    let len = share.payload.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&share.payload);
    out
}

pub fn decode_share(data: &[u8]) -> Result<Share, ParcelaError> {
    if data.len() < 8 + 1 + 1 + 1 + 4 {
        return Err(ParcelaError::InvalidFormat("share too small"));
    }
    if &data[..8] != MAGIC_SHARE {
        return Err(ParcelaError::InvalidFormat("bad share magic"));
    }
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
    Ok(Share { index, payload })
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
}

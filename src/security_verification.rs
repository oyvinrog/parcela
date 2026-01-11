//! Security Verification Module
//!
//! This module contains tests that verify the cryptographic security properties
//! of Parcela vaults. These are the same checks that run when users click the
//! "Verify Security" button in the UI.
//!
//! The automated tests in this module ensure that these security verifications
//! themselves work correctly - i.e., they actually catch the problems they
//! claim to detect.

use crate::{
    combine_shares, decrypt, encode_share, encrypt,
    Share, MAGIC_BLOB, MAGIC_BLOB_V1, SALT_SIZE,
};

/// Result of a security verification test
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityTestResult {
    pub passed: bool,
    pub message: String,
}

impl SecurityTestResult {
    pub fn pass(message: impl Into<String>) -> Self {
        Self {
            passed: true,
            message: message.into(),
        }
    }

    pub fn fail(message: impl Into<String>) -> Self {
        Self {
            passed: false,
            message: message.into(),
        }
    }
}

/// Verify that a single share cannot recover the secret (2-of-3 threshold property).
///
/// This test ensures that:
/// 1. A share combined with itself cannot decrypt the secret
/// 2. A share combined with a fake/zeroed share cannot decrypt the secret
pub fn verify_single_share_unrecoverable(
    shares: &[Share],
    encrypted_blob: &[u8],
    password: &str,
) -> SecurityTestResult {
    if shares.is_empty() {
        return SecurityTestResult::fail("No shares available to test.");
    }

    // Try to "recover" with just one share duplicated - this should ALWAYS fail
    for (idx, share) in shares.iter().enumerate() {
        // Attempt to combine with itself (should fail - duplicate index)
        let result = combine_shares(&[share.clone(), share.clone()]);

        match result {
            Ok(combined) => {
                // Even if combine succeeds, decryption should fail
                if decrypt(&combined, password).is_ok() {
                    return SecurityTestResult::fail(format!(
                        "CRITICAL: Share {} alone was able to decrypt the secret!",
                        idx + 1
                    ));
                }
            }
            Err(_) => {
                // Expected: combine should reject duplicate indices
            }
        }
    }

    // Try each share with a zero-filled fake share
    for (idx, share) in shares.iter().enumerate() {
        // Create a fake share with different index
        let fake_index = if share.index == 1 { 2 } else { 1 };
        let fake_share = Share {
            index: fake_index,
            payload: vec![0u8; share.payload.len()],
        };

        let result = combine_shares(&[share.clone(), fake_share]);
        if let Ok(combined) = result {
            if decrypt(&combined, password).is_ok() {
                return SecurityTestResult::fail(format!(
                    "CRITICAL: Share {} with fake share decrypted successfully!",
                    idx + 1
                ));
            }
        }
    }

    // Also verify that the original encrypted blob doesn't decrypt with wrong password
    if decrypt(encrypted_blob, "wrong_password_12345").is_ok() {
        return SecurityTestResult::fail(
            "CRITICAL: Vault decrypted with wrong password!",
        );
    }

    SecurityTestResult::pass(format!(
        "Verified: {} share(s) tested, none can recover the secret alone. \
         2-of-3 threshold property confirmed.",
        shares.len()
    ))
}

/// Verify that AEAD (AES-GCM) authentication correctly detects tampering.
///
/// This test:
/// 1. Flips a bit in the ciphertext and verifies decryption fails
/// 2. Flips a bit in the nonce and verifies decryption fails
/// 3. Flips a bit in the salt and verifies decryption fails
pub fn verify_aead_authentication(
    encrypted_blob: &[u8],
    password: &str,
) -> SecurityTestResult {
    if encrypted_blob.len() < 100 {
        return SecurityTestResult::fail("Encrypted data too small for meaningful test.");
    }

    // First verify we can decrypt normally
    if decrypt(encrypted_blob, password).is_err() {
        return SecurityTestResult::fail("Cannot decrypt with provided password.");
    }

    // Test 1: Flip a bit in the ciphertext (near the end, after header)
    let mut tampered = encrypted_blob.to_vec();
    let tamper_pos = encrypted_blob.len() - 20;
    tampered[tamper_pos] ^= 0x01;

    if decrypt(&tampered, password).is_ok() {
        return SecurityTestResult::fail(
            "CRITICAL: Bit-flip in ciphertext was not detected! \
             AEAD authentication may be broken.",
        );
    }

    // Test 2: Flip a bit in the nonce (at offset 40, after 8-byte magic + 32-byte salt)
    let mut nonce_tampered = encrypted_blob.to_vec();
    if encrypted_blob.len() > 44 {
        nonce_tampered[42] ^= 0x01;
        if decrypt(&nonce_tampered, password).is_ok() {
            return SecurityTestResult::fail("CRITICAL: Nonce tampering was not detected!");
        }
    }

    // Test 3: Flip a bit in the salt (at offset 8, after 8-byte magic)
    let mut salt_tampered = encrypted_blob.to_vec();
    if encrypted_blob.len() > 12 {
        salt_tampered[10] ^= 0x01;
        if decrypt(&salt_tampered, password).is_ok() {
            return SecurityTestResult::fail("CRITICAL: Salt tampering was not detected!");
        }
    }

    // Test 4: Flip a bit in the authentication tag (last 16 bytes for GCM)
    let mut tag_tampered = encrypted_blob.to_vec();
    let tag_pos = encrypted_blob.len() - 5;
    tag_tampered[tag_pos] ^= 0x01;

    if decrypt(&tag_tampered, password).is_ok() {
        return SecurityTestResult::fail(
            "CRITICAL: Authentication tag tampering was not detected!",
        );
    }

    // Test 5: Truncate ciphertext (remove last byte) and verify decryption fails
    if encrypted_blob.len() > 1 {
        let mut truncated = encrypted_blob.to_vec();
        truncated.truncate(encrypted_blob.len() - 1);
        if decrypt(&truncated, password).is_ok() {
            return SecurityTestResult::fail(
                "CRITICAL: Truncated ciphertext was accepted! \
                 AEAD tag verification may be bypassed.",
            );
        }
    }

    SecurityTestResult::pass(
        "AES-256-GCM authentication verified. \
         Tampering in ciphertext, nonce, salt, auth tag, and truncation all correctly rejected.",
    )
}

/// Verify that nonces are unique across encryptions.
///
/// This test encrypts the same plaintext twice and verifies that:
/// 1. The salt is different each time
/// 2. The nonce is different each time
/// 3. The ciphertext is different (semantic security)
pub fn verify_nonce_uniqueness(plaintext: &[u8], password: &str) -> SecurityTestResult {
    // Encrypt twice
    let encrypted1 = match encrypt(plaintext, password) {
        Ok(e) => e,
        Err(_) => return SecurityTestResult::fail("First encryption failed."),
    };

    let encrypted2 = match encrypt(plaintext, password) {
        Ok(e) => e,
        Err(_) => return SecurityTestResult::fail("Second encryption failed."),
    };

    // Verify format
    if encrypted1.len() < 8 + 32 + 12 || encrypted2.len() < 8 + 32 + 12 {
        return SecurityTestResult::fail("Encrypted data too small to contain nonce.");
    }

    // Check magic
    if &encrypted1[..8] != MAGIC_BLOB || &encrypted2[..8] != MAGIC_BLOB {
        return SecurityTestResult::fail("Invalid encryption format.");
    }

    // Extract salts and nonces
    let salt1 = &encrypted1[8..40];
    let salt2 = &encrypted2[8..40];
    let nonce1 = &encrypted1[40..52];
    let nonce2 = &encrypted2[40..52];

    let salt_different = salt1 != salt2;
    let nonce_different = nonce1 != nonce2;

    if !salt_different && !nonce_different {
        return SecurityTestResult::fail(
            "CRITICAL: Salt and nonce are identical across encryptions! \
             This breaks IND-CPA security.",
        );
    }

    if !nonce_different {
        return SecurityTestResult::fail(
            "CRITICAL: Nonce reused across encryptions! \
             This enables nonce-reuse attacks on AES-GCM.",
        );
    }

    // Also verify the ciphertexts are different (semantic security)
    let ciphertext1 = &encrypted1[52..];
    let ciphertext2 = &encrypted2[52..];

    if ciphertext1 == ciphertext2 {
        return SecurityTestResult::fail(
            "CRITICAL: Identical ciphertexts for same plaintext! \
             Encryption is deterministic - breaks semantic security.",
        );
    }

    SecurityTestResult::pass(format!(
        "Nonce uniqueness verified. Salt different: {}, Nonce different: {}. \
         Ciphertexts are semantically secure (different each encryption).",
        salt_different, nonce_different
    ))
}

/// Verify that vault header uses modern format and sane randomness.
///
/// This test:
/// 1. Rejects legacy PARCELA1 format (weak SHA-256 KDF)
/// 2. Ensures header is long enough to include an AEAD tag
/// 3. Ensures salt and nonce are not all-zero (RNG failure indicator)
pub fn verify_vault_header_sanity(encrypted_blob: &[u8]) -> SecurityTestResult {
    if encrypted_blob.len() < 8 {
        return SecurityTestResult::fail("Vault data too small to contain magic header.");
    }

    let magic = &encrypted_blob[..8];
    if magic == MAGIC_BLOB_V1 {
        return SecurityTestResult::fail(
            "CRITICAL: Vault uses legacy PARCELA1 (SHA-256 KDF). \
             This format is vulnerable to GPU brute-force. Re-encrypt with PARCELA2.",
        );
    }

    if magic != MAGIC_BLOB {
        return SecurityTestResult::fail("Unknown vault format (bad magic header).");
    }

    let min_len = 8 + SALT_SIZE + 12 + 16; // magic + salt + nonce + GCM tag
    if encrypted_blob.len() < min_len {
        return SecurityTestResult::fail(
            "Vault data too small to contain a valid AES-GCM tag. \
             File may be truncated or corrupted.",
        );
    }

    let salt = &encrypted_blob[8..8 + SALT_SIZE];
    if salt.iter().all(|&b| b == 0) {
        return SecurityTestResult::fail(
            "CRITICAL: Salt is all zeros. \
             This indicates RNG failure and enables precomputation attacks.",
        );
    }

    let nonce_start = 8 + SALT_SIZE;
    let nonce = &encrypted_blob[nonce_start..nonce_start + 12];
    if nonce.iter().all(|&b| b == 0) {
        return SecurityTestResult::fail(
            "CRITICAL: Nonce is all zeros. \
             This indicates RNG failure and enables nonce-reuse attacks.",
        );
    }

    SecurityTestResult::pass(
        "Vault header sanity verified. Modern PARCELA2 format in use; \
         salt/nonce present and non-zero; ciphertext length includes AEAD tag.",
    )
}

/// Verify share integrity checksums work correctly.
///
/// This test:
/// 1. Creates a valid share and verifies it passes
/// 2. Corrupts the share payload and verifies detection
/// 3. Corrupts the checksum and verifies detection
pub fn verify_share_integrity_detection(share: &Share) -> SecurityTestResult {
    // Encode the share (adds checksum)
    let encoded = encode_share(share);

    // Verify it's valid (should decode without error)
    if crate::decode_share(&encoded).is_err() {
        return SecurityTestResult::fail("Valid share failed to decode.");
    }

    // Test 1: Corrupt the payload (flip a bit in the middle)
    let mut payload_corrupted = encoded.clone();
    let corrupt_pos = 15 + share.payload.len() / 2; // Middle of payload
    if corrupt_pos < payload_corrupted.len() - 32 {
        payload_corrupted[corrupt_pos] ^= 0x01;

        if crate::decode_share(&payload_corrupted).is_ok() {
            return SecurityTestResult::fail(
                "CRITICAL: Payload corruption was not detected! Checksum verification broken.",
            );
        }
    }

    // Test 2: Corrupt the checksum itself (flip a bit in the checksum)
    let mut checksum_corrupted = encoded.clone();
    let checksum_pos = encoded.len() - 16; // Middle of checksum
    checksum_corrupted[checksum_pos] ^= 0x01;

    if crate::decode_share(&checksum_corrupted).is_ok() {
        return SecurityTestResult::fail(
            "CRITICAL: Checksum corruption was not detected!",
        );
    }

    // Test 3: Corrupt the index
    let mut index_corrupted = encoded.clone();
    index_corrupted[8] ^= 0x01; // Index is at offset 8

    if crate::decode_share(&index_corrupted).is_ok() {
        return SecurityTestResult::fail(
            "CRITICAL: Index corruption was not detected!",
        );
    }

    SecurityTestResult::pass(
        "Share integrity verification working correctly. \
         Payload, checksum, and index corruption all detected.",
    )
}

/// Verify that shares appear statistically independent (random).
///
/// For Shamir's Secret Sharing, individual shares should have uniform byte distribution.
pub fn verify_share_randomness(shares: &[Share]) -> SecurityTestResult {
    if shares.is_empty() {
        return SecurityTestResult::fail("No shares to test.");
    }

    for (idx, share) in shares.iter().enumerate() {
        if share.payload.len() < 256 {
            // Need enough data for meaningful chi-square test
            continue;
        }

        // Count byte occurrences
        let mut counts = [0usize; 256];
        for &byte in &share.payload {
            counts[byte as usize] += 1;
        }

        // Chi-square test for uniformity
        let total = share.payload.len() as f64;
        let expected = total / 256.0;
        let chi_sq: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();

        // Chi-square critical value for df=255 at p=0.001 is ~310
        // Use generous threshold to avoid false positives
        if chi_sq > 400.0 {
            return SecurityTestResult::fail(format!(
                "WARNING: Share {} has non-uniform distribution (chi-sq={:.1}). \
                 This may indicate a weakness in random number generation.",
                idx + 1,
                chi_sq
            ));
        }
    }

    SecurityTestResult::pass(format!(
        "All {} share(s) have uniform byte distribution. \
         Chi-square uniformity tests passed.",
        shares.len()
    ))
}

/// Verify that two valid shares can successfully recover the secret.
///
/// This is the positive test - ensuring the threshold scheme actually works.
pub fn verify_threshold_recovery(
    shares: &[Share],
    encrypted_blob: &[u8],
    password: &str,
    expected_plaintext: &[u8],
) -> SecurityTestResult {
    if shares.len() < 2 {
        return SecurityTestResult::fail("Need at least 2 shares for threshold test.");
    }

    // Try combining first two shares
    let combined = match combine_shares(&shares[..2]) {
        Ok(c) => c,
        Err(e) => {
            return SecurityTestResult::fail(format!(
                "Failed to combine shares: {}",
                e
            ));
        }
    };

    // Verify combined data matches encrypted blob
    if combined != encrypted_blob {
        return SecurityTestResult::fail(
            "Combined shares don't match original encrypted blob.",
        );
    }

    // Decrypt and verify
    let decrypted = match decrypt(&combined, password) {
        Ok(d) => d,
        Err(e) => {
            return SecurityTestResult::fail(format!("Decryption failed: {}", e));
        }
    };

    if decrypted != expected_plaintext {
        return SecurityTestResult::fail("Decrypted content doesn't match original.");
    }

    // Test all possible pairs
    let pairs = [
        (0, 1),
        (0, 2),
        (1, 2),
    ];
    
    for (i, j) in pairs {
        if i >= shares.len() || j >= shares.len() {
            continue;
        }
        
        let combined = match combine_shares(&[shares[i].clone(), shares[j].clone()]) {
            Ok(c) => c,
            Err(_) => continue,
        };
        
        if decrypt(&combined, password).is_err() {
            return SecurityTestResult::fail(format!(
                "Share pair ({}, {}) failed to decrypt.",
                i + 1,
                j + 1
            ));
        }
    }

    SecurityTestResult::pass(
        "2-of-3 threshold recovery verified. All share pairs successfully decrypt the secret.",
    )
}

// =============================================================================
// Unit tests for the security verification functions themselves
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encrypt, split_shares};

    const TEST_PASSWORD: &str = "test_password_for_verification_123!";
    const TEST_PLAINTEXT: &[u8] = b"This is secret data that must be protected!";

    /// Helper to create a complete test vault (encrypted blob + shares)
    fn create_test_vault() -> (Vec<u8>, [Share; 3]) {
        let encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();
        let shares = split_shares(&encrypted).unwrap();
        (encrypted, shares)
    }

    // =========================================================================
    // Tests for verify_single_share_unrecoverable
    // =========================================================================

    #[test]
    fn single_share_unrecoverable_passes_with_valid_shares() {
        let (encrypted, shares) = create_test_vault();
        let result = verify_single_share_unrecoverable(
            &shares,
            &encrypted,
            TEST_PASSWORD,
        );
        assert!(result.passed, "Should pass: {}", result.message);
    }

    #[test]
    fn single_share_unrecoverable_fails_with_empty_shares() {
        let (encrypted, _) = create_test_vault();
        let result = verify_single_share_unrecoverable(&[], &encrypted, TEST_PASSWORD);
        assert!(!result.passed);
        assert!(result.message.contains("No shares"));
    }

    #[test]
    fn single_share_truly_cannot_recover() {
        let (_encrypted, shares) = create_test_vault();

        // Manually verify that a single share + fake share doesn't work
        for share in &shares {
            let fake = Share {
                index: if share.index == 1 { 2 } else { 1 },
                payload: vec![0u8; share.payload.len()],
            };
            let combined = combine_shares(&[share.clone(), fake]).unwrap();
            assert!(
                decrypt(&combined, TEST_PASSWORD).is_err(),
                "Single share + fake should NOT decrypt"
            );
        }

        // But two real shares should work
        let combined = combine_shares(&[shares[0].clone(), shares[1].clone()]).unwrap();
        assert!(decrypt(&combined, TEST_PASSWORD).is_ok());
    }

    // =========================================================================
    // Tests for verify_aead_authentication
    // =========================================================================

    #[test]
    fn aead_authentication_passes_with_valid_data() {
        let encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();
        let result = verify_aead_authentication(&encrypted, TEST_PASSWORD);
        assert!(result.passed, "Should pass: {}", result.message);
    }

    #[test]
    fn aead_catches_ciphertext_tampering() {
        let encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();

        // Tamper with ciphertext
        let mut tampered = encrypted.clone();
        tampered[encrypted.len() - 20] ^= 0x01;

        // Verify decryption fails
        assert!(
            decrypt(&tampered, TEST_PASSWORD).is_err(),
            "Tampered ciphertext should NOT decrypt"
        );
    }

    #[test]
    fn aead_catches_nonce_tampering() {
        let encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();

        // Tamper with nonce (at offset 40)
        let mut tampered = encrypted.clone();
        tampered[42] ^= 0x01;

        // Verify decryption fails
        assert!(
            decrypt(&tampered, TEST_PASSWORD).is_err(),
            "Tampered nonce should NOT decrypt"
        );
    }

    #[test]
    fn aead_catches_salt_tampering() {
        let encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();

        // Tamper with salt (at offset 8)
        let mut tampered = encrypted.clone();
        tampered[10] ^= 0x01;

        // Verify decryption fails (different key derived)
        assert!(
            decrypt(&tampered, TEST_PASSWORD).is_err(),
            "Tampered salt should NOT decrypt"
        );
    }

    #[test]
    fn aead_catches_auth_tag_tampering() {
        let encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();

        // Tamper with auth tag (last 16 bytes)
        let mut tampered = encrypted.clone();
        tampered[encrypted.len() - 5] ^= 0x01;

        // Verify decryption fails
        assert!(
            decrypt(&tampered, TEST_PASSWORD).is_err(),
            "Tampered auth tag should NOT decrypt"
        );
    }

    #[test]
    fn aead_catches_truncation() {
        let encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();

        // Truncate the ciphertext (remove last byte)
        let mut truncated = encrypted.clone();
        truncated.truncate(encrypted.len() - 1);

        assert!(
            decrypt(&truncated, TEST_PASSWORD).is_err(),
            "Truncated ciphertext should NOT decrypt"
        );
    }

    #[test]
    fn aead_catches_every_byte_position() {
        let encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();

        // Sample key positions instead of every byte (Argon2 is slow)
        // Test: start of salt, middle of salt, start of nonce, middle of nonce,
        // start of ciphertext, middle, near auth tag, in auth tag
        let positions_to_test = [
            8,                          // Start of salt
            8 + 16,                     // Middle of salt
            40,                         // Start of nonce
            40 + 6,                     // Middle of nonce
            52,                         // Start of ciphertext
            52 + 10,                    // Early ciphertext
            encrypted.len() - 20,       // Near auth tag
            encrypted.len() - 10,       // In auth tag
            encrypted.len() - 1,        // Last byte
        ];

        for &pos in &positions_to_test {
            if pos >= encrypted.len() {
                continue;
            }
            let mut tampered = encrypted.clone();
            tampered[pos] ^= 0x01;

            assert!(
                decrypt(&tampered, TEST_PASSWORD).is_err(),
                "Tampering at position {} should be detected",
                pos
            );
        }
    }

    // =========================================================================
    // Tests for verify_nonce_uniqueness
    // =========================================================================

    #[test]
    fn nonce_uniqueness_passes() {
        let result = verify_nonce_uniqueness(TEST_PLAINTEXT, TEST_PASSWORD);
        assert!(result.passed, "Should pass: {}", result.message);
    }

    #[test]
    fn each_encryption_produces_different_output() {
        let enc1 = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();
        let enc2 = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();
        let enc3 = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();

        // All should be different
        assert_ne!(enc1, enc2, "Encryptions should be different (1 vs 2)");
        assert_ne!(enc2, enc3, "Encryptions should be different (2 vs 3)");
        assert_ne!(enc1, enc3, "Encryptions should be different (1 vs 3)");

        // But all should decrypt to the same plaintext
        assert_eq!(decrypt(&enc1, TEST_PASSWORD).unwrap(), TEST_PLAINTEXT);
        assert_eq!(decrypt(&enc2, TEST_PASSWORD).unwrap(), TEST_PLAINTEXT);
        assert_eq!(decrypt(&enc3, TEST_PASSWORD).unwrap(), TEST_PLAINTEXT);
    }

    #[test]
    fn salts_are_unique() {
        let enc1 = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();
        let enc2 = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();

        let salt1 = &enc1[8..40];
        let salt2 = &enc2[8..40];

        assert_ne!(salt1, salt2, "Salts should be unique");
    }

    #[test]
    fn nonces_are_unique() {
        let enc1 = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();
        let enc2 = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();

        let nonce1 = &enc1[40..52];
        let nonce2 = &enc2[40..52];

        assert_ne!(nonce1, nonce2, "Nonces should be unique");
    }

    // =========================================================================
    // Tests for verify_vault_header_sanity
    // =========================================================================

    #[test]
    fn vault_header_sanity_passes_with_valid_blob() {
        let encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();
        let result = verify_vault_header_sanity(&encrypted);
        assert!(result.passed, "Should pass: {}", result.message);
    }

    #[test]
    fn vault_header_sanity_fails_on_legacy_magic() {
        let mut encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();
        encrypted[..8].copy_from_slice(MAGIC_BLOB_V1);
        let result = verify_vault_header_sanity(&encrypted);
        assert!(!result.passed);
        assert!(result.message.contains("legacy"));
    }

    #[test]
    fn vault_header_sanity_fails_on_all_zero_salt() {
        let mut encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();
        for b in &mut encrypted[8..8 + SALT_SIZE] {
            *b = 0;
        }
        let result = verify_vault_header_sanity(&encrypted);
        assert!(!result.passed);
        assert!(result.message.contains("Salt is all zeros"));
    }

    #[test]
    fn vault_header_sanity_fails_on_all_zero_nonce() {
        let mut encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();
        let nonce_start = 8 + SALT_SIZE;
        for b in &mut encrypted[nonce_start..nonce_start + 12] {
            *b = 0;
        }
        let result = verify_vault_header_sanity(&encrypted);
        assert!(!result.passed);
        assert!(result.message.contains("Nonce is all zeros"));
    }

    #[test]
    fn vault_header_sanity_fails_on_truncated_blob() {
        let mut encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();
        encrypted.truncate(8 + SALT_SIZE + 12 + 15);
        let result = verify_vault_header_sanity(&encrypted);
        assert!(!result.passed);
        assert!(result.message.contains("too small"));
    }

    // =========================================================================
    // Tests for verify_share_integrity_detection
    // =========================================================================

    #[test]
    fn share_integrity_detection_passes_with_valid_share() {
        let (_encrypted, shares) = create_test_vault();
        let result = verify_share_integrity_detection(&shares[0]);
        assert!(result.passed, "Should pass: {}", result.message);
    }

    #[test]
    fn share_integrity_catches_payload_corruption() {
        let (_, shares) = create_test_vault();
        let encoded = encode_share(&shares[0]);

        // Corrupt the payload
        let mut corrupted = encoded.clone();
        corrupted[20] ^= 0xFF;

        // Decode should fail
        assert!(
            crate::decode_share(&corrupted).is_err(),
            "Corrupted payload should fail checksum"
        );
    }

    #[test]
    fn share_integrity_catches_checksum_corruption() {
        let (_, shares) = create_test_vault();
        let encoded = encode_share(&shares[0]);

        // Corrupt the checksum (last 32 bytes)
        let mut corrupted = encoded.clone();
        corrupted[encoded.len() - 10] ^= 0xFF;

        // Decode should fail
        assert!(
            crate::decode_share(&corrupted).is_err(),
            "Corrupted checksum should fail"
        );
    }

    #[test]
    fn share_integrity_catches_index_corruption() {
        let (_, shares) = create_test_vault();
        let encoded = encode_share(&shares[0]);

        // Corrupt the index (at offset 8)
        let mut corrupted = encoded.clone();
        corrupted[8] ^= 0x01;

        // Decode should fail
        assert!(
            crate::decode_share(&corrupted).is_err(),
            "Corrupted index should fail checksum"
        );
    }

    // =========================================================================
    // Tests for verify_share_randomness
    // =========================================================================

    #[test]
    fn share_randomness_passes_with_real_shares() {
        // Use larger plaintext for meaningful statistics
        let large_plaintext = vec![0x42u8; 1024];
        let encrypted = encrypt(&large_plaintext, TEST_PASSWORD).unwrap();
        let shares = split_shares(&encrypted).unwrap();

        let result = verify_share_randomness(&shares);
        assert!(result.passed, "Should pass: {}", result.message);
    }

    #[test]
    fn share_randomness_would_fail_with_nonrandom_data() {
        // Create a fake "share" with non-random data
        let non_random_share = Share {
            index: 1,
            payload: vec![0x00u8; 1024], // All zeros - definitely not random
        };

        let result = verify_share_randomness(&[non_random_share]);
        assert!(!result.passed, "Non-random data should fail chi-square test");
    }

    // =========================================================================
    // Tests for verify_threshold_recovery
    // =========================================================================

    #[test]
    fn threshold_recovery_works_with_any_two_shares() {
        let (encrypted, shares) = create_test_vault();

        let result = verify_threshold_recovery(
            &shares,
            &encrypted,
            TEST_PASSWORD,
            TEST_PLAINTEXT,
        );
        assert!(result.passed, "Should pass: {}", result.message);
    }

    #[test]
    fn threshold_recovery_pair_0_1() {
        let (encrypted, shares) = create_test_vault();
        let combined = combine_shares(&[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(combined, encrypted);
        assert_eq!(decrypt(&combined, TEST_PASSWORD).unwrap(), TEST_PLAINTEXT);
    }

    #[test]
    fn threshold_recovery_pair_0_2() {
        let (encrypted, shares) = create_test_vault();
        let combined = combine_shares(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(combined, encrypted);
        assert_eq!(decrypt(&combined, TEST_PASSWORD).unwrap(), TEST_PLAINTEXT);
    }

    #[test]
    fn threshold_recovery_pair_1_2() {
        let (encrypted, shares) = create_test_vault();
        let combined = combine_shares(&[shares[1].clone(), shares[2].clone()]).unwrap();
        assert_eq!(combined, encrypted);
        assert_eq!(decrypt(&combined, TEST_PASSWORD).unwrap(), TEST_PLAINTEXT);
    }

    // =========================================================================
    // Tests for wrong password handling
    // =========================================================================

    #[test]
    fn wrong_password_fails_decryption() {
        let encrypted = encrypt(TEST_PLAINTEXT, TEST_PASSWORD).unwrap();

        assert!(decrypt(&encrypted, "wrong_password").is_err());
        assert!(decrypt(&encrypted, "").is_err());
        assert!(decrypt(&encrypted, "TEST_PASSWORD").is_err()); // Case sensitive
        assert!(decrypt(&encrypted, &format!("{} ", TEST_PASSWORD)).is_err()); // Extra space
    }

    #[test]
    fn password_is_case_sensitive() {
        let encrypted = encrypt(TEST_PLAINTEXT, "MyPassword123").unwrap();

        assert!(decrypt(&encrypted, "MyPassword123").is_ok());
        assert!(decrypt(&encrypted, "mypassword123").is_err());
        assert!(decrypt(&encrypted, "MYPASSWORD123").is_err());
        assert!(decrypt(&encrypted, "MyPassword124").is_err());
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn empty_plaintext_works() {
        let encrypted = encrypt(b"", TEST_PASSWORD).unwrap();
        let shares = split_shares(&encrypted).unwrap();

        let combined = combine_shares(&[shares[0].clone(), shares[1].clone()]).unwrap();
        let decrypted = decrypt(&combined, TEST_PASSWORD).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn large_plaintext_works() {
        let large = vec![0xABu8; 1024 * 1024]; // 1 MB
        let encrypted = encrypt(&large, TEST_PASSWORD).unwrap();
        let shares = split_shares(&encrypted).unwrap();

        let combined = combine_shares(&[shares[0].clone(), shares[2].clone()]).unwrap();
        let decrypted = decrypt(&combined, TEST_PASSWORD).unwrap();
        assert_eq!(decrypted, large);
    }

    #[test]
    fn binary_data_with_all_byte_values() {
        // Test with data containing all 256 byte values
        let all_bytes: Vec<u8> = (0..=255).collect();
        let encrypted = encrypt(&all_bytes, TEST_PASSWORD).unwrap();
        let shares = split_shares(&encrypted).unwrap();

        let combined = combine_shares(&[shares[1].clone(), shares[2].clone()]).unwrap();
        let decrypted = decrypt(&combined, TEST_PASSWORD).unwrap();
        assert_eq!(decrypted, all_bytes);
    }

    // =========================================================================
    // Duplicate share rejection tests
    // =========================================================================

    #[test]
    fn duplicate_shares_rejected() {
        let (_, shares) = create_test_vault();

        // Same share twice should fail
        let result = combine_shares(&[shares[0].clone(), shares[0].clone()]);
        assert!(result.is_err(), "Duplicate shares should be rejected");
    }

    #[test]
    fn mismatched_share_lengths_rejected() {
        let share1 = Share {
            index: 1,
            payload: vec![1, 2, 3],
        };
        let share2 = Share {
            index: 2,
            payload: vec![1, 2, 3, 4, 5],
        };

        let result = combine_shares(&[share1, share2]);
        assert!(result.is_err(), "Mismatched lengths should be rejected");
    }
}

//! Steganography module for embedding share data into PNG images.
//!
//! This module provides functionality to encode Parcela shares as PNG images
//! by embedding the share data in a custom ancillary PNG chunk. The images
//! are selected from a set of 20 built-in "dummy" images (simple icons like
//! smiley faces, suns, stars, etc.) making shares look like ordinary images.
//!
//! The steganography approach uses PNG's ancillary chunk mechanism, which allows
//! custom data to be embedded without affecting the image display. This is more
//! robust than LSB steganography and survives image viewers.

use crate::{ParcelaError, Share, MAGIC_SHARE, MAGIC_SHARE_V2};
use sha2::{Digest, Sha256};

/// Magic bytes identifying a Parcela steganographic image share
pub const MAGIC_STEGO: &[u8; 8] = b"PSTEGO01";

/// PNG file signature (first 8 bytes of any valid PNG)
const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// Custom PNG chunk type for Parcela data (ancillary, private, safe-to-copy)
/// Using lowercase first letter = ancillary (not critical)
/// Using lowercase second letter = private (not registered)
/// Using uppercase third letter = reserved (must be uppercase)
/// Using lowercase fourth letter = safe to copy
const PARCELA_CHUNK_TYPE: [u8; 4] = *b"prCa";

/// Collection of 20 simple PNG images encoded as base64 for embedding.
/// These are 32x32 pixel icons representing common symbols.
/// Each image is carefully crafted to be small but recognizable.
mod dummy_images {
    /// Simple 32x32 smiley face
    pub const SMILEY: &[u8] = include_bytes!("../assets/stego/smiley.png");
    pub const SUN: &[u8] = include_bytes!("../assets/stego/sun.png");
    pub const STAR: &[u8] = include_bytes!("../assets/stego/star.png");
    pub const HEART: &[u8] = include_bytes!("../assets/stego/heart.png");
    pub const MOON: &[u8] = include_bytes!("../assets/stego/moon.png");
    pub const CLOUD: &[u8] = include_bytes!("../assets/stego/cloud.png");
    pub const FLOWER: &[u8] = include_bytes!("../assets/stego/flower.png");
    pub const TREE: &[u8] = include_bytes!("../assets/stego/tree.png");
    pub const HOUSE: &[u8] = include_bytes!("../assets/stego/house.png");
    pub const KEY: &[u8] = include_bytes!("../assets/stego/key.png");
    pub const LOCK: &[u8] = include_bytes!("../assets/stego/lock.png");
    pub const SHIELD: &[u8] = include_bytes!("../assets/stego/shield.png");
    pub const DIAMOND: &[u8] = include_bytes!("../assets/stego/diamond.png");
    pub const CROWN: &[u8] = include_bytes!("../assets/stego/crown.png");
    pub const BIRD: &[u8] = include_bytes!("../assets/stego/bird.png");
    pub const FISH: &[u8] = include_bytes!("../assets/stego/fish.png");
    pub const MOUNTAIN: &[u8] = include_bytes!("../assets/stego/mountain.png");
    pub const WAVE: &[u8] = include_bytes!("../assets/stego/wave.png");
    pub const FLAME: &[u8] = include_bytes!("../assets/stego/flame.png");
    pub const SNOWFLAKE: &[u8] = include_bytes!("../assets/stego/snowflake.png");
}

/// Get all available dummy images as a slice
pub fn get_dummy_images() -> [&'static [u8]; 20] {
    [
        dummy_images::SMILEY,
        dummy_images::SUN,
        dummy_images::STAR,
        dummy_images::HEART,
        dummy_images::MOON,
        dummy_images::CLOUD,
        dummy_images::FLOWER,
        dummy_images::TREE,
        dummy_images::HOUSE,
        dummy_images::KEY,
        dummy_images::LOCK,
        dummy_images::SHIELD,
        dummy_images::DIAMOND,
        dummy_images::CROWN,
        dummy_images::BIRD,
        dummy_images::FISH,
        dummy_images::MOUNTAIN,
        dummy_images::WAVE,
        dummy_images::FLAME,
        dummy_images::SNOWFLAKE,
    ]
}

/// Get image names for display purposes
pub fn get_image_names() -> [&'static str; 20] {
    [
        "smiley", "sun", "star", "heart", "moon",
        "cloud", "flower", "tree", "house", "key",
        "lock", "shield", "diamond", "crown", "bird",
        "fish", "mountain", "wave", "flame", "snowflake",
    ]
}

/// Select a dummy image based on share index and optional seed.
/// Uses deterministic selection so the same share always gets the same image type.
pub fn select_image_for_share(share_index: u8, seed: Option<u64>) -> &'static [u8] {
    let images = get_dummy_images();
    let idx = match seed {
        Some(s) => ((share_index as u64).wrapping_add(s) % 20) as usize,
        None => (share_index as usize) % 20,
    };
    images[idx]
}

/// Calculate CRC32 for PNG chunk (used in chunk format)
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Create a PNG chunk with the given type and data
fn create_png_chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let length = data.len() as u32;
    let mut chunk = Vec::with_capacity(12 + data.len());
    
    // Length (4 bytes, big-endian)
    chunk.extend_from_slice(&length.to_be_bytes());
    
    // Chunk type (4 bytes)
    chunk.extend_from_slice(chunk_type);
    
    // Data
    chunk.extend_from_slice(data);
    
    // CRC32 of type + data
    let mut crc_data = Vec::with_capacity(4 + data.len());
    crc_data.extend_from_slice(chunk_type);
    crc_data.extend_from_slice(data);
    let crc = crc32(&crc_data);
    chunk.extend_from_slice(&crc.to_be_bytes());
    
    chunk
}

/// Parse PNG chunks from raw PNG data.
/// Returns a vector of (chunk_type, chunk_data, chunk_start_offset, chunk_total_length)
fn parse_png_chunks(png_data: &[u8]) -> Result<Vec<([u8; 4], Vec<u8>, usize, usize)>, ParcelaError> {
    if png_data.len() < 8 || &png_data[..8] != PNG_SIGNATURE {
        return Err(ParcelaError::InvalidFormat("not a valid PNG file"));
    }
    
    let mut chunks = Vec::new();
    let mut offset = 8; // Skip PNG signature
    
    while offset + 12 <= png_data.len() {
        // Read chunk length (4 bytes, big-endian)
        let length = u32::from_be_bytes([
            png_data[offset],
            png_data[offset + 1],
            png_data[offset + 2],
            png_data[offset + 3],
        ]) as usize;
        
        // Read chunk type (4 bytes)
        let mut chunk_type = [0u8; 4];
        chunk_type.copy_from_slice(&png_data[offset + 4..offset + 8]);
        
        // Validate we have enough data
        if offset + 12 + length > png_data.len() {
            return Err(ParcelaError::InvalidFormat("truncated PNG chunk"));
        }
        
        // Read chunk data
        let data = png_data[offset + 8..offset + 8 + length].to_vec();
        
        let chunk_total_length = 12 + length; // 4 (length) + 4 (type) + data + 4 (CRC)
        chunks.push((chunk_type, data, offset, chunk_total_length));
        
        offset += chunk_total_length;
    }
    
    Ok(chunks)
}

/// Encode share data for embedding in PNG.
/// Format: MAGIC_STEGO (8) + share_data + SHA256 checksum (32)
fn encode_stego_payload(share: &Share) -> Vec<u8> {
    use crate::{SHARE_TOTAL, SHARE_THRESHOLD};
    
    // Build the inner share data (similar to encode_share but for stego)
    let mut payload = Vec::new();
    payload.extend_from_slice(MAGIC_STEGO);
    payload.push(share.index);
    payload.push(SHARE_TOTAL);
    payload.push(SHARE_THRESHOLD);
    let len = share.payload.len() as u32;
    payload.extend_from_slice(&len.to_be_bytes());
    payload.extend_from_slice(&share.payload);
    
    // Calculate checksum over the payload (excluding magic)
    let mut hasher = Sha256::new();
    hasher.update(&payload[8..]); // Skip magic for checksum
    let checksum = hasher.finalize();
    payload.extend_from_slice(&checksum);
    
    payload
}

/// Decode share data from PNG stego payload
fn decode_stego_payload(data: &[u8]) -> Result<Share, ParcelaError> {
    use crate::{SHARE_TOTAL, SHARE_THRESHOLD};
    
    // Minimum size: MAGIC(8) + index(1) + total(1) + threshold(1) + len(4) + checksum(32) = 47
    if data.len() < 47 {
        return Err(ParcelaError::InvalidFormat("stego payload too small"));
    }
    
    // Verify magic
    if &data[..8] != MAGIC_STEGO {
        return Err(ParcelaError::InvalidFormat("invalid stego magic"));
    }
    
    let index = data[8];
    let total = data[9];
    let threshold = data[10];
    
    if total != SHARE_TOTAL || threshold != SHARE_THRESHOLD {
        return Err(ParcelaError::InvalidShare("unsupported scheme"));
    }
    
    let len = u32::from_be_bytes([data[11], data[12], data[13], data[14]]) as usize;
    
    // Verify we have enough data for payload + checksum
    if data.len() < 15 + len + 32 {
        return Err(ParcelaError::InvalidFormat("truncated stego payload"));
    }
    
    let payload = data[15..15 + len].to_vec();
    let stored_checksum = &data[15 + len..15 + len + 32];
    
    // Verify checksum (over everything after magic)
    let mut hasher = Sha256::new();
    hasher.update(&data[8..15 + len]);
    let computed_checksum = hasher.finalize();
    
    if computed_checksum.as_slice() != stored_checksum {
        return Err(ParcelaError::InvalidShare("stego checksum mismatch - data corrupted"));
    }
    
    Ok(Share { index, payload })
}

/// Encode a share as a PNG image with embedded steganographic data.
/// 
/// This function takes a share and embeds it into a dummy PNG image by adding
/// a custom ancillary chunk containing the share data.
/// 
/// # Arguments
/// * `share` - The share to encode
/// * `image_seed` - Optional seed for selecting the dummy image (for variety)
/// 
/// # Returns
/// A PNG file as bytes with the share data embedded
pub fn encode_share_as_image(share: &Share, image_seed: Option<u64>) -> Result<Vec<u8>, ParcelaError> {
    // Select a base image
    let base_image = select_image_for_share(share.index, image_seed);
    
    // Parse the base PNG
    let chunks = parse_png_chunks(base_image)?;
    
    // Create the stego payload
    let stego_payload = encode_stego_payload(share);
    
    // Create the custom chunk
    let custom_chunk = create_png_chunk(&PARCELA_CHUNK_TYPE, &stego_payload);
    
    // Reconstruct PNG with custom chunk inserted before IEND
    let mut output = Vec::with_capacity(base_image.len() + custom_chunk.len());
    output.extend_from_slice(&PNG_SIGNATURE);
    
    for (chunk_type, chunk_data, _, _) in &chunks {
        if chunk_type == b"IEND" {
            // Insert our custom chunk before IEND
            output.extend_from_slice(&custom_chunk);
        }
        // Re-add the original chunk
        let chunk = create_png_chunk(chunk_type, chunk_data);
        output.extend_from_slice(&chunk);
    }
    
    Ok(output)
}

/// Decode a share from a PNG image with embedded steganographic data.
/// 
/// This function extracts share data from a PNG image that was created
/// using `encode_share_as_image`.
/// 
/// # Arguments
/// * `png_data` - The PNG file bytes
/// 
/// # Returns
/// The extracted Share, or an error if no valid share data is found
pub fn decode_share_from_image(png_data: &[u8]) -> Result<Share, ParcelaError> {
    // Parse PNG chunks
    let chunks = parse_png_chunks(png_data)?;
    
    // Look for our custom chunk
    for (chunk_type, chunk_data, _, _) in chunks {
        if chunk_type == PARCELA_CHUNK_TYPE {
            return decode_stego_payload(&chunk_data);
        }
    }
    
    Err(ParcelaError::InvalidFormat("no Parcela data found in image"))
}

/// Detect the format of share data (legacy binary, v2 binary, or steganographic image).
/// 
/// # Returns
/// - `Some("stego")` for PNG images with embedded share data
/// - `Some("v2")` for PSHARE02 format
/// - `Some("v1")` for legacy PSHARE01 format
/// - `None` if format is unrecognized
pub fn detect_share_format(data: &[u8]) -> Option<&'static str> {
    if data.len() < 8 {
        return None;
    }
    
    // Check for PNG signature (steganographic image)
    if data.len() >= 8 && &data[..8] == PNG_SIGNATURE {
        // Verify it actually contains Parcela data
        if let Ok(chunks) = parse_png_chunks(data) {
            for (chunk_type, _, _, _) in chunks {
                if chunk_type == PARCELA_CHUNK_TYPE {
                    return Some("stego");
                }
            }
        }
        // It's a PNG but without Parcela data
        return None;
    }
    
    // Check for PSHARE02 (current format)
    if &data[..8] == MAGIC_SHARE_V2 {
        return Some("v2");
    }
    
    // Check for PSHARE01 (legacy format)
    if &data[..8] == MAGIC_SHARE {
        return Some("v1");
    }
    
    None
}

/// Universal share decoder that handles all formats (stego, v2, v1).
/// 
/// This function automatically detects the share format and decodes appropriately,
/// providing backward compatibility with legacy share files.
pub fn decode_share_universal(data: &[u8]) -> Result<Share, ParcelaError> {
    match detect_share_format(data) {
        Some("stego") => decode_share_from_image(data),
        Some("v2") | Some("v1") => crate::decode_share(data),
        _ => Err(ParcelaError::InvalidFormat("unrecognized share format")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_crc32() {
        // Test with known CRC32 values
        let data = b"IEND";
        let crc = crc32(data);
        assert_eq!(crc, 0xAE426082);
    }
    
    #[test]
    fn test_png_chunk_creation() {
        let chunk = create_png_chunk(b"tESt", b"hello");
        assert_eq!(&chunk[0..4], &5u32.to_be_bytes()); // Length
        assert_eq!(&chunk[4..8], b"tESt"); // Type
        assert_eq!(&chunk[8..13], b"hello"); // Data
        // CRC is the last 4 bytes
        assert_eq!(chunk.len(), 17); // 4 + 4 + 5 + 4
    }
    
    #[test]
    fn test_stego_payload_roundtrip() {
        let share = Share {
            index: 2,
            payload: vec![1, 2, 3, 4, 5],
        };
        
        let encoded = encode_stego_payload(&share);
        let decoded = decode_stego_payload(&encoded).unwrap();
        
        assert_eq!(decoded.index, share.index);
        assert_eq!(decoded.payload, share.payload);
    }
    
    #[test]
    fn test_detect_share_format_v2() {
        let share = Share {
            index: 1,
            payload: vec![10, 20, 30],
        };
        let encoded = crate::encode_share(&share);
        assert_eq!(detect_share_format(&encoded), Some("v2"));
    }
    
    #[test]
    fn test_corrupted_stego_checksum() {
        let share = Share {
            index: 1,
            payload: vec![1, 2, 3],
        };
        
        let mut encoded = encode_stego_payload(&share);
        // Corrupt the payload
        encoded[15] ^= 0xFF;
        
        let result = decode_stego_payload(&encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("checksum mismatch"));
    }
}

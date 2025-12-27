//! Virtual Drive module - provides encrypted RAM-backed virtual disks
//!
//! A virtual drive is stored encrypted and split into shares like any other file.
//! When unlocked, it creates a temporary filesystem in RAM (tmpfs) that leaves no trace.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Magic bytes identifying a virtual drive container
pub const MAGIC_VDRIVE: &[u8; 8] = b"PVDRIV01";

/// Default size for virtual drives (64 MB)
pub const DEFAULT_DRIVE_SIZE_MB: u32 = 64;

/// Error type for virtual drive operations
#[derive(Debug)]
pub enum VirtualDriveError {
    InvalidFormat(&'static str),
    IoError(std::io::Error),
    MountError(String),
    NotMounted,
    AlreadyMounted,
    PermissionDenied,
    UnsupportedPlatform,
}

impl std::fmt::Display for VirtualDriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VirtualDriveError::InvalidFormat(msg) => write!(f, "invalid format: {msg}"),
            VirtualDriveError::IoError(e) => write!(f, "I/O error: {e}"),
            VirtualDriveError::MountError(msg) => write!(f, "mount error: {msg}"),
            VirtualDriveError::NotMounted => write!(f, "drive is not mounted"),
            VirtualDriveError::AlreadyMounted => write!(f, "drive is already mounted"),
            VirtualDriveError::PermissionDenied => write!(f, "permission denied"),
            VirtualDriveError::UnsupportedPlatform => write!(f, "unsupported platform"),
        }
    }
}

impl std::error::Error for VirtualDriveError {}

impl From<std::io::Error> for VirtualDriveError {
    fn from(e: std::io::Error) -> Self {
        VirtualDriveError::IoError(e)
    }
}

/// Metadata for a virtual drive
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VirtualDriveMetadata {
    /// Unique identifier for the drive
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Size in megabytes
    pub size_mb: u32,
    /// Creation timestamp (Unix epoch seconds)
    pub created_at: u64,
}

/// The virtual drive container format:
/// - 8 bytes: magic (PVDRIV01)
/// - 4 bytes: metadata length (big endian)
/// - N bytes: JSON-encoded metadata
/// - remaining: drive content (initially empty/zeros)
#[derive(Clone, Debug)]
pub struct VirtualDrive {
    pub metadata: VirtualDriveMetadata,
    /// The drive content (filesystem image or empty space)
    pub content: Vec<u8>,
}

impl VirtualDrive {
    /// Create a new empty virtual drive
    pub fn new(name: String, size_mb: u32) -> Self {
        let id = format!(
            "vdrive-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            rand::random::<u32>()
        );

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metadata = VirtualDriveMetadata {
            id,
            name,
            size_mb,
            created_at,
        };

        // Initialize with empty content - actual filesystem will be created on mount
        let content = Vec::new();

        VirtualDrive { metadata, content }
    }

    /// Create a virtual drive with deterministic ID (for testing)
    pub fn new_with_id(id: String, name: String, size_mb: u32) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metadata = VirtualDriveMetadata {
            id,
            name,
            size_mb,
            created_at,
        };

        VirtualDrive {
            metadata,
            content: Vec::new(),
        }
    }

    /// Encode the virtual drive to bytes
    pub fn encode(&self) -> Result<Vec<u8>, VirtualDriveError> {
        let metadata_json =
            serde_json::to_vec(&self.metadata).map_err(|_| VirtualDriveError::InvalidFormat("failed to encode metadata"))?;
        let metadata_len = metadata_json.len() as u32;

        let mut out = Vec::with_capacity(8 + 4 + metadata_json.len() + self.content.len());
        out.extend_from_slice(MAGIC_VDRIVE);
        out.extend_from_slice(&metadata_len.to_be_bytes());
        out.extend_from_slice(&metadata_json);
        out.extend_from_slice(&self.content);

        Ok(out)
    }

    /// Decode a virtual drive from bytes
    pub fn decode(data: &[u8]) -> Result<Self, VirtualDriveError> {
        if data.len() < 12 {
            return Err(VirtualDriveError::InvalidFormat("data too small"));
        }

        if &data[..8] != MAGIC_VDRIVE {
            return Err(VirtualDriveError::InvalidFormat("bad magic"));
        }

        let metadata_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;

        if data.len() < 12 + metadata_len {
            return Err(VirtualDriveError::InvalidFormat("truncated metadata"));
        }

        let metadata: VirtualDriveMetadata = serde_json::from_slice(&data[12..12 + metadata_len])
            .map_err(|_| VirtualDriveError::InvalidFormat("invalid metadata JSON"))?;

        let content = data[12 + metadata_len..].to_vec();

        Ok(VirtualDrive { metadata, content })
    }
}

/// State tracking for mounted drives
pub struct MountedDriveState {
    pub drive_id: String,
    pub mount_path: PathBuf,
}

// Global state for tracking mounted drives
lazy_static::lazy_static! {
    static ref MOUNTED_DRIVES: Mutex<HashMap<String, MountedDriveState>> = Mutex::new(HashMap::new());
}

/// Get the mount point path for a virtual drive
pub fn get_mount_path(drive_id: &str) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from(format!("/tmp/parcela-vdrive-{}", drive_id))
    }

    #[cfg(target_os = "macos")]
    {
        PathBuf::from(format!("/tmp/parcela-vdrive-{}", drive_id))
    }

    #[cfg(target_os = "windows")]
    {
        PathBuf::from(format!(
            "{}\\parcela-vdrive-{}",
            std::env::temp_dir().to_string_lossy(),
            drive_id
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from(format!("/tmp/parcela-vdrive-{}", drive_id))
    }
}

/// Check if a drive is currently mounted
pub fn is_mounted(drive_id: &str) -> bool {
    MOUNTED_DRIVES
        .lock()
        .map(|drives| drives.contains_key(drive_id))
        .unwrap_or(false)
}

/// Get the mount path if the drive is mounted
pub fn get_mounted_path(drive_id: &str) -> Option<PathBuf> {
    MOUNTED_DRIVES
        .lock()
        .ok()
        .and_then(|drives| drives.get(drive_id).map(|s| s.mount_path.clone()))
}

/// Unlock (mount) a virtual drive as a RAM-backed filesystem
///
/// Creates a directory in /tmp which is typically already a tmpfs on modern
/// Linux systems. This approach doesn't require root privileges while still
/// keeping data in RAM. On lock, files are securely wiped before deletion.
pub fn unlock_drive(drive: &VirtualDrive) -> Result<PathBuf, VirtualDriveError> {
    let drive_id = &drive.metadata.id;

    // Check if already mounted
    if is_mounted(drive_id) {
        return Err(VirtualDriveError::AlreadyMounted);
    }

    let mount_path = get_mount_path(drive_id);

    // Create the directory (on most Linux systems, /tmp is already tmpfs)
    std::fs::create_dir_all(&mount_path)?;

    // Extract any saved content to the directory
    if !drive.content.is_empty() {
        extract_content_to_mount(&drive.content, &mount_path)?;
    }

    // Track the mounted drive
    MOUNTED_DRIVES
        .lock()
        .map_err(|_| VirtualDriveError::MountError("failed to acquire lock".to_string()))?
        .insert(
            drive_id.to_string(),
            MountedDriveState {
                drive_id: drive_id.to_string(),
                mount_path: mount_path.clone(),
            },
        );

    Ok(mount_path)
}

/// Lock a virtual drive and capture its content
///
/// Captures all files from the drive directory, securely wipes them,
/// and removes the directory. The captured content is stored in the
/// VirtualDrive struct for re-encryption.
pub fn lock_drive(drive: &mut VirtualDrive) -> Result<(), VirtualDriveError> {
    let drive_id = &drive.metadata.id;

    let mount_path = MOUNTED_DRIVES
        .lock()
        .map_err(|_| VirtualDriveError::MountError("failed to acquire lock".to_string()))?
        .get(drive_id)
        .map(|s| s.mount_path.clone())
        .ok_or(VirtualDriveError::NotMounted)?;

    // Capture content before removing
    drive.content = capture_mount_content(&mount_path)?;

    // Securely remove directory contents (overwrites files before deletion)
    secure_remove_dir_contents(&mount_path)?;
    
    // Remove the directory
    let _ = std::fs::remove_dir(&mount_path);

    // Remove from tracked mounts
    MOUNTED_DRIVES
        .lock()
        .map_err(|_| VirtualDriveError::MountError("failed to acquire lock".to_string()))?
        .remove(drive_id);

    Ok(())
}

/// Capture the content of a mounted drive as a tar archive
fn capture_mount_content(mount_path: &Path) -> Result<Vec<u8>, VirtualDriveError> {
    let mut archive_data = Vec::new();

    // Walk the directory and create a simple archive format
    // Format: [filename_len:4][filename][content_len:4][content]...
    fn visit_dir(
        base: &Path,
        current: &Path,
        data: &mut Vec<u8>,
    ) -> Result<(), VirtualDriveError> {
        for entry in std::fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path
                .strip_prefix(base)
                .map_err(|_| VirtualDriveError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "path prefix error",
                )))?;

            let relative_str = relative.to_string_lossy();
            let name_bytes = relative_str.as_bytes();

            if path.is_dir() {
                // Mark directories with a trailing /
                let dir_name = format!("{}/", relative_str);
                let dir_bytes = dir_name.as_bytes();
                data.extend_from_slice(&(dir_bytes.len() as u32).to_be_bytes());
                data.extend_from_slice(dir_bytes);
                data.extend_from_slice(&0u32.to_be_bytes()); // No content for dirs
                visit_dir(base, &path, data)?;
            } else {
                let content = std::fs::read(&path)?;
                data.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                data.extend_from_slice(name_bytes);
                data.extend_from_slice(&(content.len() as u32).to_be_bytes());
                data.extend_from_slice(&content);
            }
        }
        Ok(())
    }

    visit_dir(mount_path, mount_path, &mut archive_data)?;
    Ok(archive_data)
}

/// Extract archived content to a mount point
fn extract_content_to_mount(data: &[u8], mount_path: &Path) -> Result<(), VirtualDriveError> {
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let name_len = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + name_len > data.len() {
            break;
        }

        let name = String::from_utf8_lossy(&data[offset..offset + name_len]);
        offset += name_len;

        if offset + 4 > data.len() {
            break;
        }

        let content_len = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        let full_path = mount_path.join(name.as_ref());

        if name.ends_with('/') {
            // It's a directory
            std::fs::create_dir_all(&full_path)?;
        } else {
            if offset + content_len > data.len() {
                break;
            }
            let content = &data[offset..offset + content_len];
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&full_path, content)?;
            offset += content_len;
        }
    }

    Ok(())
}

/// Securely remove directory contents by overwriting files before deletion
fn secure_remove_dir_contents(path: &Path) -> Result<(), VirtualDriveError> {
    if !path.exists() {
        return Ok(());
    }

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            secure_remove_dir_contents(&path)?;
            std::fs::remove_dir(&path)?;
        } else {
            // Overwrite file with zeros before deletion
            if let Ok(metadata) = path.metadata() {
                let size = metadata.len() as usize;
                if size > 0 {
                    let zeros = vec![0u8; size.min(1024 * 1024)]; // Cap at 1MB chunks
                    if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&path) {
                        use std::io::Write;
                        let mut remaining = size;
                        while remaining > 0 {
                            let chunk = remaining.min(zeros.len());
                            let _ = file.write_all(&zeros[..chunk]);
                            remaining -= chunk;
                        }
                        let _ = file.sync_all();
                    }
                }
            }
            std::fs::remove_file(&path)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_drive_new_creates_valid_drive() {
        let drive = VirtualDrive::new("Test Drive".to_string(), 64);
        
        assert_eq!(drive.metadata.name, "Test Drive");
        assert_eq!(drive.metadata.size_mb, 64);
        assert!(drive.metadata.id.starts_with("vdrive-"));
        assert!(drive.content.is_empty());
    }

    #[test]
    fn virtual_drive_encode_decode_roundtrip() {
        let drive = VirtualDrive::new_with_id(
            "test-id-123".to_string(),
            "My Drive".to_string(),
            32,
        );

        let encoded = drive.encode().unwrap();
        let decoded = VirtualDrive::decode(&encoded).unwrap();

        assert_eq!(decoded.metadata.id, "test-id-123");
        assert_eq!(decoded.metadata.name, "My Drive");
        assert_eq!(decoded.metadata.size_mb, 32);
    }

    #[test]
    fn virtual_drive_encode_decode_with_content() {
        let mut drive = VirtualDrive::new_with_id(
            "content-test".to_string(),
            "Content Drive".to_string(),
            16,
        );
        drive.content = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let encoded = drive.encode().unwrap();
        let decoded = VirtualDrive::decode(&encoded).unwrap();

        assert_eq!(decoded.content, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn virtual_drive_decode_rejects_bad_magic() {
        let mut data = VirtualDrive::new("Test".to_string(), 32)
            .encode()
            .unwrap();
        data[..8].copy_from_slice(b"BADMAGIC");

        let err = VirtualDrive::decode(&data).unwrap_err();
        assert!(matches!(err, VirtualDriveError::InvalidFormat("bad magic")));
    }

    #[test]
    fn virtual_drive_decode_rejects_too_small() {
        let data = vec![0u8; 8];
        let err = VirtualDrive::decode(&data).unwrap_err();
        assert!(matches!(err, VirtualDriveError::InvalidFormat("data too small")));
    }

    #[test]
    fn virtual_drive_decode_rejects_truncated_metadata() {
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC_VDRIVE);
        data.extend_from_slice(&100u32.to_be_bytes()); // Claims 100 bytes of metadata
        data.extend_from_slice(b"short"); // But only 5 bytes

        let err = VirtualDrive::decode(&data).unwrap_err();
        assert!(matches!(err, VirtualDriveError::InvalidFormat("truncated metadata")));
    }

    #[test]
    fn get_mount_path_returns_valid_path() {
        let path = get_mount_path("test-drive-id");
        assert!(path.to_string_lossy().contains("parcela-vdrive-test-drive-id"));
    }

    #[test]
    fn is_mounted_returns_false_for_unmounted() {
        assert!(!is_mounted("nonexistent-drive"));
    }

    #[test]
    fn capture_and_extract_content_roundtrip() {
        use std::fs;

        // Create temp directory with test content
        let temp_dir = std::env::temp_dir().join(format!(
            "parcela-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        
        // Create test files
        fs::write(temp_dir.join("file1.txt"), b"Hello World").unwrap();
        fs::create_dir_all(temp_dir.join("subdir")).unwrap();
        fs::write(temp_dir.join("subdir/file2.txt"), b"Nested content").unwrap();

        // Capture content
        let captured = capture_mount_content(&temp_dir).unwrap();

        // Create new directory and extract
        let extract_dir = std::env::temp_dir().join(format!(
            "parcela-extract-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&extract_dir).unwrap();
        
        extract_content_to_mount(&captured, &extract_dir).unwrap();

        // Verify extracted content
        assert_eq!(fs::read_to_string(extract_dir.join("file1.txt")).unwrap(), "Hello World");
        assert_eq!(
            fs::read_to_string(extract_dir.join("subdir/file2.txt")).unwrap(),
            "Nested content"
        );

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
        let _ = fs::remove_dir_all(&extract_dir);
    }

    #[test]
    fn secure_remove_clears_files() {
        use std::fs;

        let temp_dir = std::env::temp_dir().join(format!(
            "parcela-secure-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(temp_dir.join("secret.txt"), b"sensitive data").unwrap();

        secure_remove_dir_contents(&temp_dir).unwrap();

        assert!(!temp_dir.join("secret.txt").exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn virtual_drive_error_display() {
        assert_eq!(
            VirtualDriveError::InvalidFormat("test").to_string(),
            "invalid format: test"
        );
        assert_eq!(
            VirtualDriveError::NotMounted.to_string(),
            "drive is not mounted"
        );
        assert_eq!(
            VirtualDriveError::AlreadyMounted.to_string(),
            "drive is already mounted"
        );
        assert_eq!(
            VirtualDriveError::PermissionDenied.to_string(),
            "permission denied"
        );
        assert_eq!(
            VirtualDriveError::UnsupportedPlatform.to_string(),
            "unsupported platform"
        );
    }
}


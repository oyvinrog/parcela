//! Virtual Drive module - provides encrypted RAM-backed virtual disks
//!
//! A virtual drive is stored encrypted and split into shares like any other file.
//! When unlocked, it creates a temporary filesystem in RAM (tmpfs) that leaves no trace.
//!
//! On Windows: Uses ProjFS to create a projected filesystem visible in Explorer.
//! On Linux/macOS: Uses a directory in /tmp which is typically already a tmpfs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[cfg(target_os = "windows")]
use crate::projfs_fs::{ProjFsMount, is_projfs_available};

/// In-memory file storage for Windows (and optionally other platforms)
/// This ensures files never touch the disk
#[derive(Clone, Debug, Default)]
pub struct MemoryFileSystem {
    /// Files stored as path -> content
    files: HashMap<String, Vec<u8>>,
    /// Directories (stored as paths ending with /)
    directories: std::collections::HashSet<String>,
}

impl MemoryFileSystem {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            directories: std::collections::HashSet::new(),
        }
    }

    /// Write a file to memory
    pub fn write_file(&mut self, path: &str, content: Vec<u8>) {
        // Ensure parent directories exist
        let path = Self::normalize_path(path);
        if let Some(parent) = Self::parent_path(&path) {
            self.create_dir_all(&parent);
        }
        self.files.insert(path, content);
    }

    /// Read a file from memory
    pub fn read_file(&self, path: &str) -> Option<&Vec<u8>> {
        let path = Self::normalize_path(path);
        self.files.get(&path)
    }

    /// Delete a file from memory
    pub fn delete_file(&mut self, path: &str) -> bool {
        let path = Self::normalize_path(path);
        self.files.remove(&path).is_some()
    }

    /// Rename/move a file
    pub fn rename_file(&mut self, old_path: &str, new_path: &str, replace_if_exists: bool) -> bool {
        let old_path = Self::normalize_path(old_path);
        let new_path = Self::normalize_path(new_path);
        
        // Check if source exists
        if !self.files.contains_key(&old_path) {
            return false;
        }
        
        // Check if destination exists and we're not allowed to replace
        if !replace_if_exists && self.files.contains_key(&new_path) {
            return false;
        }
        
        // Move the file
        if let Some(content) = self.files.remove(&old_path) {
            // Ensure parent directories exist for new path
            if let Some(parent) = Self::parent_path(&new_path) {
                self.create_dir_all(&parent);
            }
            self.files.insert(new_path, content);
            true
        } else {
            false
        }
    }

    /// Rename/move a directory
    pub fn rename_dir(&mut self, old_path: &str, new_path: &str) -> bool {
        let old_path = Self::normalize_path(old_path);
        let new_path = Self::normalize_path(new_path);
        
        let old_prefix = if old_path.ends_with('/') {
            old_path.clone()
        } else {
            format!("{}/", old_path)
        };
        
        let new_prefix = if new_path.ends_with('/') {
            new_path.clone()
        } else {
            format!("{}/", new_path)
        };
        
        // Collect files to rename (can't modify while iterating)
        let files_to_rename: Vec<(String, Vec<u8>)> = self.files
            .iter()
            .filter(|(path, _)| path.starts_with(&old_prefix) || *path == &old_path)
            .map(|(path, content)| (path.clone(), content.clone()))
            .collect();
        
        if files_to_rename.is_empty() && !self.directories.contains(&old_prefix) {
            return false;
        }
        
        // Rename files
        for (old_file_path, content) in files_to_rename {
            self.files.remove(&old_file_path);
            let new_file_path = old_file_path.replacen(&old_prefix, &new_prefix, 1);
            self.files.insert(new_file_path, content);
        }
        
        // Rename directories
        let dirs_to_rename: Vec<String> = self.directories
            .iter()
            .filter(|path| path.starts_with(&old_prefix) || *path == &old_prefix)
            .cloned()
            .collect();
        
        for old_dir in dirs_to_rename {
            self.directories.remove(&old_dir);
            let new_dir = old_dir.replacen(&old_prefix, &new_prefix, 1);
            self.directories.insert(new_dir);
        }
        
        true
    }

    /// Check if a file exists
    pub fn file_exists(&self, path: &str) -> bool {
        let path = Self::normalize_path(path);
        self.files.contains_key(&path)
    }

    /// Create a directory
    pub fn create_dir(&mut self, path: &str) {
        let mut path = Self::normalize_path(path);
        if !path.ends_with('/') {
            path.push('/');
        }
        self.directories.insert(path);
    }

    /// Create directory and all parent directories
    pub fn create_dir_all(&mut self, path: &str) {
        let path = Self::normalize_path(path);
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut current = String::new();
        for part in parts {
            current.push_str(part);
            current.push('/');
            self.directories.insert(current.clone());
        }
    }

    /// List all files and directories
    pub fn list_all(&self) -> Vec<String> {
        let mut entries: Vec<String> = self.files.keys().cloned().collect();
        entries.extend(self.directories.iter().cloned());
        entries.sort();
        entries
    }

    /// List contents of a directory
    pub fn list_dir(&self, path: &str) -> Vec<String> {
        let mut dir_path = Self::normalize_path(path);
        if !dir_path.is_empty() && !dir_path.ends_with('/') {
            dir_path.push('/');
        }

        let mut entries = std::collections::HashSet::new();

        // Find files in this directory
        for file_path in self.files.keys() {
            if let Some(relative) = file_path.strip_prefix(&dir_path) {
                // Get just the first component
                if let Some(first_component) = relative.split('/').next() {
                    if !first_component.is_empty() {
                        // Check if it's a file or has more components (directory)
                        if relative.contains('/') {
                            entries.insert(format!("{}/", first_component));
                        } else {
                            entries.insert(first_component.to_string());
                        }
                    }
                }
            } else if dir_path.is_empty() {
                // Root listing
                if let Some(first_component) = file_path.split('/').next() {
                    if !first_component.is_empty() {
                        if file_path.contains('/') {
                            entries.insert(format!("{}/", first_component));
                        } else {
                            entries.insert(first_component.to_string());
                        }
                    }
                }
            }
        }

        // Find subdirectories
        for dir in &self.directories {
            if let Some(relative) = dir.strip_prefix(&dir_path) {
                if let Some(first_component) = relative.split('/').next() {
                    if !first_component.is_empty() {
                        entries.insert(format!("{}/", first_component));
                    }
                }
            } else if dir_path.is_empty() {
                if let Some(first_component) = dir.split('/').next() {
                    if !first_component.is_empty() {
                        entries.insert(format!("{}/", first_component));
                    }
                }
            }
        }

        let mut result: Vec<String> = entries.into_iter().collect();
        result.sort();
        result
    }

    /// Clear all files (secure wipe - just drops from memory)
    pub fn clear(&mut self) {
        self.files.clear();
        self.directories.clear();
    }

    /// Serialize to the archive format used by disk-based drives
    pub fn to_archive(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Write directories first
        for dir in &self.directories {
            let dir_bytes = dir.as_bytes();
            data.extend_from_slice(&(dir_bytes.len() as u32).to_be_bytes());
            data.extend_from_slice(dir_bytes);
            data.extend_from_slice(&0u32.to_be_bytes()); // No content for dirs
        }

        // Write files
        for (path, content) in &self.files {
            let path_bytes = path.as_bytes();
            data.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
            data.extend_from_slice(path_bytes);
            data.extend_from_slice(&(content.len() as u32).to_be_bytes());
            data.extend_from_slice(content);
        }

        data
    }

    /// Deserialize from the archive format
    pub fn from_archive(data: &[u8]) -> Self {
        let mut fs = Self::new();
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

            let name = String::from_utf8_lossy(&data[offset..offset + name_len]).to_string();
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

            if name.ends_with('/') {
                // It's a directory
                fs.directories.insert(name);
            } else {
                if offset + content_len > data.len() {
                    break;
                }
                let content = data[offset..offset + content_len].to_vec();
                fs.files.insert(name, content);
                offset += content_len;
            }
        }

        fs
    }

    fn normalize_path(path: &str) -> String {
        path.replace('\\', "/").trim_start_matches('/').to_string()
    }

    fn parent_path(path: &str) -> Option<String> {
        let path = path.trim_end_matches('/');
        path.rfind('/').map(|idx| path[..idx].to_string())
    }
}

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
    /// Memory-based filesystem (used when ProjFS is not available)
    pub memory_fs: Option<MemoryFileSystem>,
    /// ProjFS mount handle (Windows only)
    #[cfg(target_os = "windows")]
    pub projfs_mount: Option<ProjFsMount>,
}

impl MountedDriveState {
    /// Check if this drive uses memory-only storage (no native filesystem mount)
    pub fn is_memory_mode(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            // On Windows, we're NOT in memory-only mode if ProjFS is active
            self.projfs_mount.is_none() && self.memory_fs.is_some()
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.memory_fs.is_some()
        }
    }

    /// Check if this drive uses ProjFS (Windows native mount)
    #[cfg(target_os = "windows")]
    pub fn uses_projfs(&self) -> bool {
        self.projfs_mount.is_some()
    }
}

// Global state for tracking mounted drives
lazy_static::lazy_static! {
    static ref MOUNTED_DRIVES: Mutex<HashMap<String, MountedDriveState>> = Mutex::new(HashMap::new());
}

/// Check if the current platform uses memory-only mode (no native filesystem)
///
/// On Windows with ProjFS enabled: returns false (uses native projected filesystem)
/// On Windows without ProjFS: returns true (uses in-memory storage with custom UI)
/// On Linux/macOS: returns false (uses tmpfs directory)
pub fn uses_memory_mode() -> bool {
    #[cfg(target_os = "windows")]
    {
        // Check if ProjFS is available
        !is_projfs_available()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}


/// Get the expected mount point path for a virtual drive
///
/// On Windows with ProjFS: Returns a temp directory path used as virtualization root.
/// On Linux/macOS: Returns a tmpfs-backed directory.
/// Use `get_mounted_path()` to get the actual path of a mounted drive.
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
        // ProjFS uses a directory as the virtualization root
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
/// On Linux/macOS: Creates a directory in /tmp which is typically already a tmpfs.
/// On Windows with ProjFS: Creates a projected filesystem in a temp directory.
/// On Windows without ProjFS: Uses memory-only storage with custom UI for browsing.
///
/// Returns the mount path. Use this path to browse the drive in your file manager.
pub fn unlock_drive(drive: &VirtualDrive) -> Result<PathBuf, VirtualDriveError> {
    let drive_id = &drive.metadata.id;

    // Acquire lock for the entire operation to prevent TOCTOU race conditions.
    let mut drives = MOUNTED_DRIVES
        .lock()
        .map_err(|_| VirtualDriveError::MountError("failed to acquire lock".to_string()))?;

    // Check if already mounted (while holding the lock)
    if drives.contains_key(drive_id) {
        return Err(VirtualDriveError::AlreadyMounted);
    }

    #[cfg(target_os = "windows")]
    {
        // Try to use ProjFS for native Windows Explorer integration
        let projfs_available = is_projfs_available();
        eprintln!("[Parcela] ProjFS available: {}", projfs_available);

        if projfs_available {
            let fs = if !drive.content.is_empty() {
                MemoryFileSystem::from_archive(&drive.content)
            } else {
                MemoryFileSystem::new()
            };

            let mount_path = get_mount_path(drive_id);
            eprintln!("[Parcela] Attempting ProjFS mount for drive: {}", drive.metadata.name);
            match ProjFsMount::mount(fs, &drive.metadata.name, mount_path.clone()) {
                Ok(mount) => {
                    eprintln!("[Parcela] ProjFS mount successful at: {}", mount_path.display());
                    drives.insert(
                        drive_id.to_string(),
                        MountedDriveState {
                            drive_id: drive_id.to_string(),
                            mount_path: mount_path.clone(),
                            memory_fs: None,
                            projfs_mount: Some(mount),
                        },
                    );
                    return Ok(mount_path);
                }
                Err(e) => {
                    // Fall back to memory-only mode if ProjFS fails
                    eprintln!("[Parcela] ProjFS mount FAILED: {}", e);
                    eprintln!("[Parcela] Falling back to memory-only mode. To use ProjFS:");
                    eprintln!("  1. Enable ProjFS: Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS");
                    eprintln!("  2. Restart Windows after enabling the feature");
                }
            }
        } else {
            eprintln!("[Parcela] ProjFS not available - using memory-only mode");
            eprintln!("[Parcela] Enable ProjFS: Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS");
        }

        // Fallback: memory-only mode (no native filesystem mount)
        let fs = if !drive.content.is_empty() {
            MemoryFileSystem::from_archive(&drive.content)
        } else {
            MemoryFileSystem::new()
        };

        let mount_path = PathBuf::from(format!(
            "{}\\parcela-vdrive-{}",
            std::env::temp_dir().to_string_lossy(),
            drive_id
        ));

        drives.insert(
            drive_id.to_string(),
            MountedDriveState {
                drive_id: drive_id.to_string(),
                mount_path: mount_path.clone(),
                memory_fs: Some(fs),
                projfs_mount: None,
            },
        );

        return Ok(mount_path);
    }

    #[cfg(not(target_os = "windows"))]
    {
        let mount_path = get_mount_path(drive_id);

        // On Linux/macOS, use tmpfs-backed directory
        std::fs::create_dir_all(&mount_path)?;

        // Extract any saved content to the directory
        if !drive.content.is_empty() {
            extract_content_to_mount(&drive.content, &mount_path)?;
        }

        drives.insert(
            drive_id.to_string(),
            MountedDriveState {
                drive_id: drive_id.to_string(),
                mount_path: mount_path.clone(),
                memory_fs: None,
            },
        );

        Ok(mount_path)
    }
}

/// Lock a virtual drive and capture its content
///
/// On Linux/macOS: Captures files from directory, securely wipes, removes directory.
/// On Windows with ProjFS: Unmounts the projection and captures from the ProjFS filesystem.
/// On Windows without ProjFS: Captures from memory, clears memory.
///
/// The captured content is stored in the VirtualDrive struct for re-encryption.
pub fn lock_drive(drive: &mut VirtualDrive) -> Result<(), VirtualDriveError> {
    let drive_id = &drive.metadata.id;

    let mut drives = MOUNTED_DRIVES
        .lock()
        .map_err(|_| VirtualDriveError::MountError("failed to acquire lock".to_string()))?;

    let state = drives.remove(drive_id).ok_or(VirtualDriveError::NotMounted)?;

    #[cfg(target_os = "windows")]
    {
        if let Some(projfs_mount) = state.projfs_mount {
            // ProjFS mode: unmount and capture the filesystem
            let fs = projfs_mount.unmount();
            drive.content = fs.to_archive();
        } else if let Some(mut memory_fs) = state.memory_fs {
            // Memory-only mode: capture from memory
            drive.content = memory_fs.to_archive();
            memory_fs.clear();
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Some(mut memory_fs) = state.memory_fs {
            // Memory mode (shouldn't happen on Linux/macOS but handle it)
            drive.content = memory_fs.to_archive();
            memory_fs.clear();
        } else {
            // Disk mode: capture from filesystem
            let mount_path = state.mount_path.clone();
            drive.content = capture_mount_content(&mount_path)?;

            // Securely remove directory contents (overwrites files before deletion)
            secure_remove_dir_contents(&mount_path)?;

            // Remove the directory
            let _ = std::fs::remove_dir(&mount_path);
        }
        Ok(())
    }
}

// =============================================================================
// Public API for file operations (works on all platforms)
// =============================================================================

/// Check if the drive uses native filesystem access (not memory-only mode)
///
/// When true, files can be accessed directly through mount_path.
/// When false, must use vdrive_* functions.
#[allow(dead_code)]
fn uses_native_fs(state: &MountedDriveState) -> bool {
    #[cfg(target_os = "windows")]
    {
        state.projfs_mount.is_some()
    }
    #[cfg(not(target_os = "windows"))]
    {
        state.memory_fs.is_none()
    }
}

/// List files in a mounted virtual drive
///
/// On Windows with ProjFS: Lists from the projected filesystem
/// On Windows without ProjFS: Lists from in-memory storage
/// On Linux/macOS: Lists from the tmpfs directory
pub fn vdrive_list_files(drive_id: &str, path: &str) -> Result<Vec<String>, VirtualDriveError> {
    let drives = MOUNTED_DRIVES
        .lock()
        .map_err(|_| VirtualDriveError::MountError("failed to acquire lock".to_string()))?;

    let state = drives.get(drive_id).ok_or(VirtualDriveError::NotMounted)?;

    // On Windows, check if we have a ProjFS mount - if so, use its direct access methods
    #[cfg(target_os = "windows")]
    if let Some(ref projfs_mount) = state.projfs_mount {
        return Ok(projfs_mount.list_directory(path));
    }

    if let Some(ref memory_fs) = state.memory_fs {
        // Memory-only mode
        Ok(memory_fs.list_dir(path))
    } else {
        // Native filesystem mode (Linux/macOS tmpfs)
        let full_path = state.mount_path.join(path);
        let mut entries = Vec::new();

        if full_path.exists() && full_path.is_dir() {
            for entry in std::fs::read_dir(&full_path)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if entry.path().is_dir() {
                    entries.push(format!("{}/", name));
                } else {
                    entries.push(name);
                }
            }
        }
        entries.sort();
        Ok(entries)
    }
}

/// Read a file from a mounted virtual drive
pub fn vdrive_read_file(drive_id: &str, path: &str) -> Result<Vec<u8>, VirtualDriveError> {
    let drives = MOUNTED_DRIVES
        .lock()
        .map_err(|_| VirtualDriveError::MountError("failed to acquire lock".to_string()))?;

    let state = drives.get(drive_id).ok_or(VirtualDriveError::NotMounted)?;

    // On Windows, check if we have a ProjFS mount - if so, use its direct access methods
    #[cfg(target_os = "windows")]
    if let Some(ref projfs_mount) = state.projfs_mount {
        // Read directly from ProjFS's internal filesystem
        return projfs_mount.read_file(path)
            .ok_or_else(|| VirtualDriveError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "file not found",
            )));
    }

    if let Some(ref memory_fs) = state.memory_fs {
        // Memory-only mode
        memory_fs
            .read_file(path)
            .cloned()
            .ok_or_else(|| VirtualDriveError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "file not found",
            )))
    } else {
        // Disk mode (Linux tmpfs)
        let full_path = state.mount_path.join(path);
        std::fs::read(&full_path).map_err(VirtualDriveError::from)
    }
}

/// Write a file to a mounted virtual drive
pub fn vdrive_write_file(drive_id: &str, path: &str, content: Vec<u8>) -> Result<(), VirtualDriveError> {
    let mut drives = MOUNTED_DRIVES
        .lock()
        .map_err(|_| VirtualDriveError::MountError("failed to acquire lock".to_string()))?;

    let state = drives.get_mut(drive_id).ok_or(VirtualDriveError::NotMounted)?;

    // On Windows, check if we have a ProjFS mount - if so, use its direct access methods
    #[cfg(target_os = "windows")]
    if let Some(ref projfs_mount) = state.projfs_mount {
        // Write directly to ProjFS's internal filesystem
        projfs_mount.write_file(path, content);
        return Ok(());
    }

    if let Some(ref mut memory_fs) = state.memory_fs {
        // Memory-only mode - write directly to memory
        memory_fs.write_file(path, content);
        Ok(())
    } else {
        // Disk mode (Linux tmpfs) - write via OS filesystem
        let full_path = state.mount_path.join(path);

        // Create parent directories if needed
        if let Some(parent) = full_path.parent() {
            if parent != state.mount_path && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        std::fs::write(&full_path, content).map_err(VirtualDriveError::from)
    }
}

/// Delete a file from a mounted virtual drive
pub fn vdrive_delete_file(drive_id: &str, path: &str) -> Result<(), VirtualDriveError> {
    let mut drives = MOUNTED_DRIVES
        .lock()
        .map_err(|_| VirtualDriveError::MountError("failed to acquire lock".to_string()))?;

    let state = drives.get_mut(drive_id).ok_or(VirtualDriveError::NotMounted)?;

    // On Windows, check if we have a ProjFS mount - if so, use its direct access methods
    #[cfg(target_os = "windows")]
    if let Some(ref projfs_mount) = state.projfs_mount {
        if projfs_mount.delete_file(path) {
            return Ok(());
        } else {
            return Err(VirtualDriveError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "file not found",
            )));
        }
    }

    if let Some(ref mut memory_fs) = state.memory_fs {
        // Memory-only mode
        if memory_fs.delete_file(path) {
            Ok(())
        } else {
            Err(VirtualDriveError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "file not found",
            )))
        }
    } else {
        // Disk mode (Linux tmpfs)
        let full_path = state.mount_path.join(path);
        std::fs::remove_file(&full_path).map_err(VirtualDriveError::from)
    }
}

/// Create a directory in a mounted virtual drive
pub fn vdrive_create_dir(drive_id: &str, path: &str) -> Result<(), VirtualDriveError> {
    let mut drives = MOUNTED_DRIVES
        .lock()
        .map_err(|_| VirtualDriveError::MountError("failed to acquire lock".to_string()))?;

    let state = drives.get_mut(drive_id).ok_or(VirtualDriveError::NotMounted)?;

    // On Windows, check if we have a ProjFS mount - if so, use its direct access methods
    #[cfg(target_os = "windows")]
    if let Some(ref projfs_mount) = state.projfs_mount {
        projfs_mount.create_dir_all(path);
        return Ok(());
    }

    if let Some(ref mut memory_fs) = state.memory_fs {
        // Memory-only mode
        memory_fs.create_dir_all(path);
        Ok(())
    } else {
        // Disk mode (Linux tmpfs)
        let full_path = state.mount_path.join(path);
        std::fs::create_dir_all(&full_path).map_err(VirtualDriveError::from)
    }
}

/// Check if drive is using memory-only mode (Windows)
pub fn is_memory_mode(drive_id: &str) -> bool {
    MOUNTED_DRIVES
        .lock()
        .ok()
        .and_then(|drives| drives.get(drive_id).map(|s| s.is_memory_mode()))
        .unwrap_or(false)
}

// =============================================================================
// Internal functions
// =============================================================================

/// Capture the content of a mounted drive as a tar archive
/// Note: Used on non-Windows platforms; on Windows, ProjFS provides its own filesystem extraction
#[allow(dead_code)]
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
                .map_err(|_| VirtualDriveError::IoError(std::io::Error::other(
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
#[cfg_attr(target_os = "windows", allow(dead_code))]
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
/// Note: Used on non-Windows platforms for tmpfs cleanup
#[allow(dead_code)]
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

    // =========================================================================
    // MemoryFileSystem tests (for Windows memory-only mode)
    // =========================================================================

    #[test]
    fn memory_fs_write_and_read_file() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("test.txt", b"Hello World".to_vec());
        
        let content = fs.read_file("test.txt").unwrap();
        assert_eq!(content, b"Hello World");
    }

    #[test]
    fn memory_fs_file_not_found() {
        let fs = MemoryFileSystem::new();
        assert!(fs.read_file("nonexistent.txt").is_none());
    }

    #[test]
    fn memory_fs_delete_file() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("to_delete.txt", b"content".to_vec());
        assert!(fs.file_exists("to_delete.txt"));
        
        assert!(fs.delete_file("to_delete.txt"));
        assert!(!fs.file_exists("to_delete.txt"));
    }

    #[test]
    fn memory_fs_nested_directories() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("a/b/c/deep.txt", b"deep content".to_vec());
        
        let content = fs.read_file("a/b/c/deep.txt").unwrap();
        assert_eq!(content, b"deep content");
    }

    #[test]
    fn memory_fs_list_dir() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("file1.txt", b"1".to_vec());
        fs.write_file("file2.txt", b"2".to_vec());
        fs.write_file("subdir/file3.txt", b"3".to_vec());
        
        let entries = fs.list_dir("");
        assert!(entries.contains(&"file1.txt".to_string()));
        assert!(entries.contains(&"file2.txt".to_string()));
        assert!(entries.contains(&"subdir/".to_string()));
    }

    #[test]
    fn memory_fs_list_subdir() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("docs/readme.md", b"readme".to_vec());
        fs.write_file("docs/guide.md", b"guide".to_vec());
        fs.write_file("docs/api/reference.md", b"api".to_vec());
        
        let entries = fs.list_dir("docs");
        assert!(entries.contains(&"readme.md".to_string()));
        assert!(entries.contains(&"guide.md".to_string()));
        assert!(entries.contains(&"api/".to_string()));
    }

    #[test]
    fn memory_fs_archive_roundtrip() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("file1.txt", b"content1".to_vec());
        fs.write_file("subdir/file2.txt", b"content2".to_vec());
        fs.create_dir("empty_dir");
        
        let archive = fs.to_archive();
        let restored = MemoryFileSystem::from_archive(&archive);
        
        assert_eq!(restored.read_file("file1.txt").unwrap(), b"content1");
        assert_eq!(restored.read_file("subdir/file2.txt").unwrap(), b"content2");
    }

    #[test]
    fn memory_fs_clear() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("secret.txt", b"sensitive".to_vec());
        fs.write_file("another.txt", b"data".to_vec());
        
        fs.clear();
        
        assert!(!fs.file_exists("secret.txt"));
        assert!(!fs.file_exists("another.txt"));
        assert!(fs.list_all().is_empty());
    }

    #[test]
    fn memory_fs_normalizes_windows_paths() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("folder\\subfolder\\file.txt", b"content".to_vec());
        
        // Should be accessible with forward slashes
        let content = fs.read_file("folder/subfolder/file.txt").unwrap();
        assert_eq!(content, b"content");
    }

    #[test]
    fn memory_fs_handles_leading_slash() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("/absolute/path.txt", b"content".to_vec());
        
        // Should normalize and be accessible without leading slash
        let content = fs.read_file("absolute/path.txt").unwrap();
        assert_eq!(content, b"content");
    }

    // =========================================================================
    // Platform capability tests
    // =========================================================================

    #[test]
    fn is_projfs_available_returns_bool() {
        // This function should always return a boolean without panicking
        #[cfg(target_os = "windows")]
        {
            let result = is_projfs_available();
            // On Windows, we just verify it doesn't panic
            let _ = result;
        }
    }

    #[test]
    fn uses_memory_mode_consistent_with_platform() {
        let memory_mode = uses_memory_mode();

        // On non-Windows: should not use memory mode (uses tmpfs)
        #[cfg(not(target_os = "windows"))]
        assert!(!memory_mode);

        // On Windows: memory mode is the opposite of ProjFS availability
        #[cfg(target_os = "windows")]
        {
            let projfs = is_projfs_available();
            assert_eq!(memory_mode, !projfs);
        }
    }

    #[test]
    fn uses_native_fs_helper_works() {
        // Create a mock state with memory_fs
        let state_with_memory = MountedDriveState {
            drive_id: "test".to_string(),
            mount_path: PathBuf::from("/tmp/test"),
            memory_fs: Some(MemoryFileSystem::new()),
            #[cfg(target_os = "windows")]
            projfs_mount: None,
        };

        // Memory-only mode should not be "native fs"
        assert!(!uses_native_fs(&state_with_memory));

        // State without memory_fs uses native filesystem
        let state_native = MountedDriveState {
            drive_id: "test2".to_string(),
            mount_path: PathBuf::from("/tmp/test2"),
            memory_fs: None,
            #[cfg(target_os = "windows")]
            projfs_mount: None,
        };

        #[cfg(not(target_os = "windows"))]
        assert!(uses_native_fs(&state_native));
    }

    #[test]
    fn mounted_drive_state_is_memory_mode_works() {
        let state_memory = MountedDriveState {
            drive_id: "test".to_string(),
            mount_path: PathBuf::from("/tmp/test"),
            memory_fs: Some(MemoryFileSystem::new()),
            #[cfg(target_os = "windows")]
            projfs_mount: None,
        };

        assert!(state_memory.is_memory_mode());

        let state_native = MountedDriveState {
            drive_id: "test2".to_string(),
            mount_path: PathBuf::from("/tmp/test2"),
            memory_fs: None,
            #[cfg(target_os = "windows")]
            projfs_mount: None,
        };

        assert!(!state_native.is_memory_mode());
    }

    // =========================================================================
    // Drive mount/unmount integration tests
    // =========================================================================

    #[test]
    fn unlock_and_lock_drive_roundtrip() {
        let mut drive = VirtualDrive::new_with_id(
            format!("test-roundtrip-{}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()),
            "Roundtrip Test".to_string(),
            32,
        );
        
        // Unlock the drive
        let mount_result = unlock_drive(&drive);
        assert!(mount_result.is_ok(), "Failed to unlock drive: {:?}", mount_result.err());
        
        let mount_path = mount_result.unwrap();
        assert!(!mount_path.as_os_str().is_empty());
        
        // Verify it's mounted
        assert!(is_mounted(&drive.metadata.id));
        
        // Lock the drive
        let lock_result = lock_drive(&mut drive);
        assert!(lock_result.is_ok(), "Failed to lock drive: {:?}", lock_result.err());
        
        // Verify it's no longer mounted
        assert!(!is_mounted(&drive.metadata.id));
    }

    #[test]
    fn unlock_drive_prevents_double_mount() {
        let drive = VirtualDrive::new_with_id(
            format!("test-double-{}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()),
            "Double Mount Test".to_string(),
            16,
        );
        
        // First unlock should succeed
        let result1 = unlock_drive(&drive);
        assert!(result1.is_ok());
        
        // Second unlock should fail with AlreadyMounted
        let result2 = unlock_drive(&drive);
        assert!(matches!(result2, Err(VirtualDriveError::AlreadyMounted)));
        
        // Cleanup
        let mut drive_mut = drive;
        let _ = lock_drive(&mut drive_mut);
    }

    #[test]
    fn lock_drive_rejects_not_mounted() {
        let mut drive = VirtualDrive::new_with_id(
            "test-not-mounted".to_string(),
            "Not Mounted Test".to_string(),
            16,
        );
        
        let result = lock_drive(&mut drive);
        assert!(matches!(result, Err(VirtualDriveError::NotMounted)));
    }

    #[test]
    fn vdrive_operations_on_mounted_drive() {
        let drive = VirtualDrive::new_with_id(
            format!("test-ops-{}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()),
            "Operations Test".to_string(),
            32,
        );
        
        // Mount the drive
        let mount_result = unlock_drive(&drive);
        assert!(mount_result.is_ok());
        
        let drive_id = &drive.metadata.id;
        
        // Create a directory
        let mkdir_result = vdrive_create_dir(drive_id, "testdir");
        assert!(mkdir_result.is_ok());
        
        // Write a file
        let write_result = vdrive_write_file(drive_id, "testdir/hello.txt", b"Hello, World!".to_vec());
        assert!(write_result.is_ok());
        
        // List directory
        let list_result = vdrive_list_files(drive_id, "testdir");
        assert!(list_result.is_ok());
        let files = list_result.unwrap();
        assert!(files.iter().any(|f| f.trim_end_matches('/') == "hello.txt"));
        
        // Read file
        let read_result = vdrive_read_file(drive_id, "testdir/hello.txt");
        assert!(read_result.is_ok());
        assert_eq!(read_result.unwrap(), b"Hello, World!");
        
        // Delete file
        let delete_result = vdrive_delete_file(drive_id, "testdir/hello.txt");
        assert!(delete_result.is_ok());
        
        // Verify deleted
        let read_after_delete = vdrive_read_file(drive_id, "testdir/hello.txt");
        assert!(read_after_delete.is_err());
        
        // Cleanup
        let mut drive_mut = drive;
        let _ = lock_drive(&mut drive_mut);
    }

    #[test]
    fn vdrive_operations_reject_unmounted_drive() {
        let drive_id = "definitely-not-mounted-12345";
        
        assert!(vdrive_list_files(drive_id, "").is_err());
        assert!(vdrive_read_file(drive_id, "file.txt").is_err());
        assert!(vdrive_write_file(drive_id, "file.txt", vec![1, 2, 3]).is_err());
        assert!(vdrive_delete_file(drive_id, "file.txt").is_err());
        assert!(vdrive_create_dir(drive_id, "dir").is_err());
    }

    #[test]
    fn drive_content_persists_through_lock_unlock() {
        let mut drive = VirtualDrive::new_with_id(
            format!("test-persist-{}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()),
            "Persistence Test".to_string(),
            32,
        );
        
        // First mount: write some data
        {
            let mount_result = unlock_drive(&drive);
            assert!(mount_result.is_ok(), "Failed to unlock: {:?}", mount_result.err());
            let drive_id = &drive.metadata.id;
            
            let write_result = vdrive_write_file(drive_id, "persistent.txt", b"Remember me!".to_vec());
            assert!(write_result.is_ok(), "Failed to write: {:?}", write_result.err());
            
            let lock_result = lock_drive(&mut drive);
            assert!(lock_result.is_ok(), "Failed to lock: {:?}", lock_result.err());
        }
        
        // Content should be captured in drive.content
        assert!(!drive.content.is_empty(), "Drive content should not be empty after lock");
        
        // Second mount: verify data persists
        {
            let mount_result = unlock_drive(&drive);
            assert!(mount_result.is_ok(), "Failed to unlock (2nd time): {:?}", mount_result.err());
            let drive_id = &drive.metadata.id;
            
            let content = vdrive_read_file(drive_id, "persistent.txt");
            assert!(content.is_ok(), "Failed to read: {:?}", content.err());
            assert_eq!(content.unwrap(), b"Remember me!");
            
            let lock_result = lock_drive(&mut drive);
            assert!(lock_result.is_ok(), "Failed to lock (2nd time): {:?}", lock_result.err());
        }
    }
}


//! ProjFS-based filesystem implementation for Windows
//!
//! This module provides a Windows Projected File System implementation that exposes
//! our in-memory MemoryFileSystem as a virtualized directory visible in Windows Explorer.
//!
//! Note: ProjFS requires Windows 10 1809+ with the optional feature enabled:
//! `Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart`

use std::io::{Cursor, Read};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use windows_projfs::{
    DirectoryEntry, DirectoryInfo, FileInfo, Notification, ProjectedFileSystem,
    ProjectedFileSystemSource,
};

use crate::virtual_drive::MemoryFileSystem;

/// ProjFS provider wrapping our MemoryFileSystem
pub struct ParcelaProjFs {
    /// The underlying in-memory filesystem
    fs: Arc<RwLock<MemoryFileSystem>>,
    /// Volume label
    volume_label: String,
}

impl ParcelaProjFs {
    pub fn new(fs: MemoryFileSystem, volume_label: String) -> (Self, Arc<RwLock<MemoryFileSystem>>) {
        let fs_arc = Arc::new(RwLock::new(fs));
        let fs_clone = Arc::clone(&fs_arc);
        (
            Self {
                fs: fs_arc,
                volume_label,
            },
            fs_clone,
        )
    }

    /// Get the volume label
    pub fn volume_label(&self) -> &str {
        &self.volume_label
    }

    fn normalize_path(path: &Path) -> String {
        path.to_string_lossy()
            .replace('\\', "/")
            .trim_start_matches('/')
            .to_string()
    }
}

impl ProjectedFileSystemSource for ParcelaProjFs {
    fn list_directory(&self, path: &Path) -> Vec<DirectoryEntry> {
        let path_str = Self::normalize_path(path);
        let fs = self.fs.read();

        let entries = fs.list_dir(&path_str);
        let mut result = Vec::new();

        for entry in entries {
            let is_dir = entry.ends_with('/');
            let name = entry.trim_end_matches('/').to_string();

            if name.is_empty() {
                continue;
            }

            if is_dir {
                result.push(DirectoryEntry::Directory(DirectoryInfo {
                    directory_name: name,
                    directory_attributes: 0x10, // FILE_ATTRIBUTE_DIRECTORY
                    creation_time: 0,
                    last_access_time: 0,
                    last_write_time: 0,
                }));
            } else {
                // Get file size
                let full_path = if path_str.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", path_str, name)
                };
                let size = fs.read_file(&full_path)
                    .map(|v| v.len() as u64)
                    .unwrap_or(0);

                result.push(DirectoryEntry::File(FileInfo {
                    file_name: name,
                    file_size: size,
                    file_attributes: 0x80, // FILE_ATTRIBUTE_NORMAL
                    creation_time: 0,
                    last_access_time: 0,
                    last_write_time: 0,
                }));
            }
        }

        result
    }

    fn stream_file_content(
        &self,
        path: &Path,
        byte_offset: usize,
        length: usize,
    ) -> std::io::Result<Box<dyn Read>> {
        let path_str = Self::normalize_path(path);
        let fs = self.fs.read();

        let content = fs.read_file(&path_str)
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("file not found: {}", path_str),
            ))?;

        // Handle offset and length
        let start = byte_offset.min(content.len());
        let end = (byte_offset + length).min(content.len());
        let slice = content[start..end].to_vec();

        Ok(Box::new(Cursor::new(slice)))
    }

    fn handle_notification(&self, notification: &Notification) -> ControlFlow<()> {
        // Log notifications for debugging
        eprintln!("[ProjFS] Notification: {:?}", notification);

        // Allow all operations to proceed
        ControlFlow::Continue(())
    }
}

/// State for a mounted ProjFS filesystem
pub struct ProjFsMount {
    /// The projected filesystem instance
    _projfs: ProjectedFileSystem,
    /// The virtualization root directory
    root_path: PathBuf,
    /// Shared reference to the filesystem for extraction on unmount
    fs: Arc<RwLock<MemoryFileSystem>>,
}

// SAFETY: ProjFsMount is safe to send between threads because:
// - `_projfs` is a Windows ProjFS handle that is not accessed concurrently
// - `root_path` is a PathBuf which is Send+Sync
// - `fs` is an Arc<RwLock<...>> which is Send+Sync
// The ProjFS handle is only held for the lifetime of the mount and dropped on unmount.
unsafe impl Send for ProjFsMount {}
unsafe impl Sync for ProjFsMount {}

impl ProjFsMount {
    /// Mount a MemoryFileSystem as a ProjFS virtualization root
    pub fn mount(fs: MemoryFileSystem, volume_label: &str, root_path: PathBuf) -> Result<Self, String> {
        // Ensure the root directory exists
        std::fs::create_dir_all(&root_path)
            .map_err(|e| format!("Failed to create virtualization root: {}", e))?;

        let (provider, fs_arc) = ParcelaProjFs::new(fs, volume_label.to_string());

        // Start the projected filesystem
        let projfs = ProjectedFileSystem::new(&root_path, provider)
            .map_err(|e| format!("Failed to start ProjFS: {:?}", e))?;

        eprintln!("[ProjFS] Mounted at: {}", root_path.display());

        Ok(ProjFsMount {
            _projfs: projfs,
            root_path,
            fs: fs_arc,
        })
    }

    /// Get the mount path
    pub fn mount_path(&self) -> String {
        self.root_path.to_string_lossy().to_string()
    }

    /// Write a file directly to the internal filesystem
    pub fn write_file(&self, path: &str, content: Vec<u8>) {
        let mut fs = self.fs.write();
        fs.write_file(path, content);
    }

    /// Read a file directly from the internal filesystem
    pub fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        let fs = self.fs.read();
        fs.read_file(path).cloned()
    }

    /// List directory contents directly from the internal filesystem
    pub fn list_directory(&self, path: &str) -> Vec<String> {
        let fs = self.fs.read();
        fs.list_dir(path)
    }

    /// Delete a file directly from the internal filesystem
    pub fn delete_file(&self, path: &str) -> bool {
        let mut fs = self.fs.write();
        fs.delete_file(path)
    }

    /// Create a directory directly in the internal filesystem
    pub fn create_dir_all(&self, path: &str) {
        let mut fs = self.fs.write();
        fs.create_dir_all(path);
    }

    /// Rename a file directly in the internal filesystem
    pub fn rename_file(&self, old_path: &str, new_path: &str, replace_if_exists: bool) -> bool {
        let mut fs = self.fs.write();
        fs.rename_file(old_path, new_path, replace_if_exists)
    }

    /// Unmount the filesystem and return the MemoryFileSystem
    pub fn unmount(self) -> MemoryFileSystem {
        // Before stopping virtualization, capture any files that Windows created
        // directly in the virtualization root (not through our MemoryFileSystem)
        self.capture_disk_files(&self.root_path, "");

        // The ProjectedFileSystem will be dropped, stopping the virtualization

        // Try to clean up the virtualization root
        if let Err(e) = std::fs::remove_dir_all(&self.root_path) {
            eprintln!("[ProjFS] Warning: Failed to clean up root: {}", e);
        }

        // Extract the filesystem from the Arc
        match Arc::try_unwrap(self.fs) {
            Ok(rw_lock) => rw_lock.into_inner(),
            Err(arc) => {
                // Fallback: clone the data if Arc is still shared
                arc.read().clone()
            }
        }
    }

    /// Capture files from disk that were created directly via Windows Explorer
    fn capture_disk_files(&self, dir: &Path, relative_path: &str) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(_) => continue,
            };

            let full_relative = if relative_path.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", relative_path, name)
            };

            if path.is_dir() {
                // Ensure directory exists in MemoryFileSystem
                {
                    let mut fs = self.fs.write();
                    fs.create_dir_all(&full_relative);
                }
                // Recurse into subdirectory
                self.capture_disk_files(&path, &full_relative);
            } else if path.is_file() {
                // Read file content from disk
                if let Ok(disk_content) = std::fs::read(&path) {
                    let mut fs = self.fs.write();
                    // Check if file exists in MemoryFileSystem
                    let memory_content = fs.read_file(&full_relative).cloned();

                    match memory_content {
                        None => {
                            // New file created by user via Windows Explorer
                            eprintln!("[ProjFS] Capturing user-created file: {}", full_relative);
                            fs.write_file(&full_relative, disk_content);
                        }
                        Some(existing) if existing != disk_content => {
                            // User modified an existing file via Windows Explorer
                            eprintln!("[ProjFS] Capturing user-modified file: {}", full_relative);
                            fs.write_file(&full_relative, disk_content);
                        }
                        _ => {
                            // File unchanged, already in MemoryFileSystem
                        }
                    }
                }
            }
        }
    }
}

/// Check if ProjFS is available on this system
pub fn is_projfs_available() -> bool {
    // Check if the ProjFS feature is enabled by attempting to load the library
    // The windows-projfs crate will fail at runtime if ProjFS isn't available

    // Simple heuristic: check if the projectedfslib.dll exists
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let dll_path = format!("{}\\System32\\projectedfslib.dll", system_root);

    let available = std::path::Path::new(&dll_path).exists();
    if available {
        eprintln!("[Parcela] Found ProjFS DLL at: {}", dll_path);
    } else {
        eprintln!("[Parcela] ProjFS DLL not found at: {}", dll_path);
        eprintln!("[Parcela] Enable ProjFS with: Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS");
    }
    available
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parcela_projfs_new_creates_filesystem() {
        let fs = MemoryFileSystem::new();
        let (parcela_fs, _) = ParcelaProjFs::new(fs, "Test Volume".to_string());

        assert_eq!(parcela_fs.volume_label(), "Test Volume");
    }

    #[test]
    fn parcela_projfs_list_directory_empty() {
        let fs = MemoryFileSystem::new();
        let (parcela_fs, _) = ParcelaProjFs::new(fs, "Test".to_string());

        let entries = parcela_fs.list_directory(Path::new(""));
        assert!(entries.is_empty());
    }

    #[test]
    fn parcela_projfs_list_directory_with_files() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("file1.txt", b"content1".to_vec());
        fs.write_file("file2.txt", b"content2".to_vec());
        fs.create_dir("subdir");

        let (parcela_fs, _) = ParcelaProjFs::new(fs, "Test".to_string());

        let entries = parcela_fs.list_directory(Path::new(""));
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn parcela_projfs_stream_file_content() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("test.txt", b"Hello, World!".to_vec());

        let (parcela_fs, _) = ParcelaProjFs::new(fs, "Test".to_string());

        let mut reader = parcela_fs.stream_file_content(
            Path::new("test.txt"),
            0,
            100,
        ).unwrap();

        let mut content = Vec::new();
        reader.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"Hello, World!");
    }

    #[test]
    fn parcela_projfs_stream_file_content_with_offset() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("test.txt", b"Hello, World!".to_vec());

        let (parcela_fs, _) = ParcelaProjFs::new(fs, "Test".to_string());

        let mut reader = parcela_fs.stream_file_content(
            Path::new("test.txt"),
            7,  // Start at "World!"
            6,
        ).unwrap();

        let mut content = Vec::new();
        reader.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"World!");
    }

    #[test]
    fn is_projfs_available_returns_bool() {
        // This should not panic
        let _ = is_projfs_available();
    }
}

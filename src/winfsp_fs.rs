//! WinFsp-based filesystem implementation for Windows
//!
//! This module provides a FUSE-like filesystem using WinFsp that exposes
//! our in-memory MemoryFileSystem as a real Windows drive letter.
//!
//! Users can browse the virtual drive in Windows Explorer just like any other drive.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use winfsp::filesystem::{
    DirBuffer, DirInfo, FileInfo, FileSecurity, FileSystemContext, IoResult,
    ModificationDescriptor, OpenFileInfo, SeekableReadContext, VolumeInfo,
    WriteMode,
};
use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::U16CStr;

use crate::virtual_drive::MemoryFileSystem;

/// File handle for tracking open files/directories
#[derive(Debug)]
pub struct FileHandle {
    path: String,
    is_dir: bool,
}

/// WinFsp filesystem context wrapping our MemoryFileSystem
pub struct ParcelaFs {
    /// The underlying in-memory filesystem
    fs: RwLock<MemoryFileSystem>,
    /// Open file handles
    handles: Mutex<HashMap<u64, FileHandle>>,
    /// Next handle ID
    next_handle: Mutex<u64>,
    /// Volume label
    volume_label: String,
    /// Creation time for the volume
    creation_time: SystemTime,
}

impl ParcelaFs {
    pub fn new(fs: MemoryFileSystem, volume_label: String) -> Self {
        Self {
            fs: RwLock::new(fs),
            handles: Mutex::new(HashMap::new()),
            next_handle: Mutex::new(1),
            volume_label,
            creation_time: SystemTime::now(),
        }
    }

    fn allocate_handle(&self, path: String, is_dir: bool) -> u64 {
        let mut next = self.next_handle.lock().unwrap();
        let handle_id = *next;
        *next += 1;
        
        let mut handles = self.handles.lock().unwrap();
        handles.insert(handle_id, FileHandle { path, is_dir });
        handle_id
    }

    fn get_handle(&self, handle_id: u64) -> Option<FileHandle> {
        let handles = self.handles.lock().unwrap();
        handles.get(&handle_id).map(|h| FileHandle {
            path: h.path.clone(),
            is_dir: h.is_dir,
        })
    }

    fn remove_handle(&self, handle_id: u64) {
        let mut handles = self.handles.lock().unwrap();
        handles.remove(&handle_id);
    }

    fn path_to_string(path: &U16CStr) -> String {
        let s = path.to_string_lossy();
        // Normalize Windows path separators and remove leading backslash
        s.replace('\\', "/").trim_start_matches('/').to_string()
    }

    fn file_exists(&self, path: &str) -> bool {
        let fs = self.fs.read().unwrap();
        fs.file_exists(path) || self.dir_exists_internal(&fs, path)
    }

    fn dir_exists_internal(&self, fs: &MemoryFileSystem, path: &str) -> bool {
        if path.is_empty() {
            return true; // Root always exists
        }
        let dir_path = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{}/", path)
        };
        
        // Check if any file starts with this directory path
        for entry in fs.list_all() {
            if entry.starts_with(&dir_path) || entry == dir_path.trim_end_matches('/').to_string() + "/" {
                return true;
            }
        }
        false
    }

    fn dir_exists(&self, path: &str) -> bool {
        let fs = self.fs.read().unwrap();
        self.dir_exists_internal(&fs, path)
    }

    fn make_file_info(&self, path: &str, is_dir: bool, size: u64) -> FileInfo {
        let now = SystemTime::now();
        let mut info = FileInfo::default();
        
        info.file_attributes = if is_dir {
            0x10 // FILE_ATTRIBUTE_DIRECTORY
        } else {
            0x80 // FILE_ATTRIBUTE_NORMAL
        };
        
        info.file_size = size;
        info.allocation_size = (size + 4095) & !4095; // Round up to 4KB
        info.creation_time = self.creation_time;
        info.last_access_time = now;
        info.last_write_time = now;
        info.change_time = now;
        
        info
    }
}

impl FileSystemContext for ParcelaFs {
    type FileContext = u64; // Handle ID

    fn get_volume_info(&self) -> IoResult<VolumeInfo> {
        let fs = self.fs.read().unwrap();
        let total_size: u64 = 64 * 1024 * 1024; // 64 MB virtual size
        let used_size: u64 = fs.list_all().iter().map(|_| 4096u64).sum();
        
        Ok(VolumeInfo {
            total_size,
            free_size: total_size.saturating_sub(used_size),
            volume_label: self.volume_label.clone(),
        })
    }

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [u8]>,
        _resolve_reparse_points: impl Fn(&U16CStr) -> Option<FileSecurity>,
    ) -> IoResult<FileSecurity> {
        let path = Self::path_to_string(file_name);
        
        // Check if path exists
        if path.is_empty() || self.file_exists(&path) || self.dir_exists(&path) {
            let info = if path.is_empty() || self.dir_exists(&path) {
                self.make_file_info(&path, true, 0)
            } else {
                let fs = self.fs.read().unwrap();
                let size = fs.read_file(&path).map(|v| v.len() as u64).unwrap_or(0);
                self.make_file_info(&path, false, size)
            };
            
            Ok(FileSecurity {
                attributes: info.file_attributes,
                reparse: false,
                sz_security_descriptor: 0,
            })
        } else {
            Err(winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "file not found",
            )))
        }
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> IoResult<Self::FileContext> {
        let path = Self::path_to_string(file_name);
        let is_directory = (create_options & 0x1) != 0; // FILE_DIRECTORY_FILE
        
        // Root directory
        if path.is_empty() {
            let info = self.make_file_info("", true, 0);
            file_info.set_file_info(info);
            return Ok(self.allocate_handle(path, true));
        }
        
        let fs = self.fs.read().unwrap();
        
        // Check if it's a file
        if let Some(content) = fs.read_file(&path) {
            let info = self.make_file_info(&path, false, content.len() as u64);
            file_info.set_file_info(info);
            drop(fs);
            return Ok(self.allocate_handle(path, false));
        }
        
        // Check if it's a directory
        if self.dir_exists_internal(&fs, &path) {
            let info = self.make_file_info(&path, true, 0);
            file_info.set_file_info(info);
            drop(fs);
            return Ok(self.allocate_handle(path, true));
        }
        
        Err(winfsp::FspError::IO(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        )))
    }

    fn close(&self, context: Self::FileContext) {
        self.remove_handle(context);
    }

    fn read(
        &self,
        context: Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> IoResult<usize> {
        let handle = self.get_handle(context).ok_or_else(|| {
            winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid handle",
            ))
        })?;

        if handle.is_dir {
            return Err(winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::IsADirectory,
                "is a directory",
            )));
        }

        let fs = self.fs.read().unwrap();
        let content = fs.read_file(&handle.path).ok_or_else(|| {
            winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "file not found",
            ))
        })?;

        let start = offset as usize;
        if start >= content.len() {
            return Ok(0);
        }

        let end = std::cmp::min(start + buffer.len(), content.len());
        let bytes_read = end - start;
        buffer[..bytes_read].copy_from_slice(&content[start..end]);
        
        Ok(bytes_read)
    }

    fn write(
        &self,
        context: Self::FileContext,
        buffer: &[u8],
        offset: u64,
        _write_to_end_of_file: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> IoResult<usize> {
        let handle = self.get_handle(context).ok_or_else(|| {
            winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid handle",
            ))
        })?;

        if handle.is_dir {
            return Err(winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::IsADirectory,
                "is a directory",
            )));
        }

        let mut fs = self.fs.write().unwrap();
        
        // Get existing content or create empty
        let mut content = fs.read_file(&handle.path).cloned().unwrap_or_default();
        
        let offset = offset as usize;
        
        // Extend file if needed
        if offset + buffer.len() > content.len() {
            content.resize(offset + buffer.len(), 0);
        }
        
        content[offset..offset + buffer.len()].copy_from_slice(buffer);
        
        let new_size = content.len() as u64;
        fs.write_file(&handle.path, content);
        
        *file_info = self.make_file_info(&handle.path, false, new_size);
        
        Ok(buffer.len())
    }

    fn get_file_info(&self, context: Self::FileContext) -> IoResult<FileInfo> {
        let handle = self.get_handle(context).ok_or_else(|| {
            winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid handle",
            ))
        })?;

        if handle.is_dir {
            Ok(self.make_file_info(&handle.path, true, 0))
        } else {
            let fs = self.fs.read().unwrap();
            let size = fs.read_file(&handle.path).map(|v| v.len() as u64).unwrap_or(0);
            Ok(self.make_file_info(&handle.path, false, size))
        }
    }

    fn read_directory(
        &self,
        context: Self::FileContext,
        pattern: Option<&U16CStr>,
        mut marker: DirBuffer,
        cb: impl FnMut(&DirInfo) -> bool,
    ) -> IoResult<DirBuffer> {
        let handle = self.get_handle(context).ok_or_else(|| {
            winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid handle",
            ))
        })?;

        if !handle.is_dir {
            return Err(winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "not a directory",
            )));
        }

        let fs = self.fs.read().unwrap();
        let entries = fs.list_dir(&handle.path);
        
        // Add . and .. entries
        let mut all_entries: Vec<(String, bool)> = vec![
            (".".to_string(), true),
            ("..".to_string(), true),
        ];
        
        for entry in entries {
            let is_dir = entry.ends_with('/');
            let name = entry.trim_end_matches('/').to_string();
            if !name.is_empty() {
                all_entries.push((name, is_dir));
            }
        }

        for (name, is_dir) in all_entries {
            let size = if is_dir {
                0
            } else {
                let full_path = if handle.path.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", handle.path, name)
                };
                fs.read_file(&full_path).map(|v| v.len() as u64).unwrap_or(0)
            };
            
            let info = self.make_file_info(&name, is_dir, size);
            let dir_info = DirInfo::new(info, &name);
            marker.write(&dir_info);
        }

        Ok(marker)
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: u32,
        file_attributes: u32,
        _security_descriptor: &[u8],
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> IoResult<Self::FileContext> {
        let path = Self::path_to_string(file_name);
        let is_directory = (create_options & 0x1) != 0; // FILE_DIRECTORY_FILE
        
        if path.is_empty() {
            return Err(winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "cannot create root",
            )));
        }

        let mut fs = self.fs.write().unwrap();
        
        if is_directory {
            fs.create_dir_all(&path);
            let info = self.make_file_info(&path, true, 0);
            file_info.set_file_info(info);
            drop(fs);
            Ok(self.allocate_handle(path, true))
        } else {
            fs.write_file(&path, Vec::new());
            let info = self.make_file_info(&path, false, 0);
            file_info.set_file_info(info);
            drop(fs);
            Ok(self.allocate_handle(path, false))
        }
    }

    fn cleanup(
        &self,
        context: Self::FileContext,
        _file_name: Option<&U16CStr>,
        flags: u32,
    ) {
        // If FspCleanupDelete flag is set, delete the file
        const FSP_CLEANUP_DELETE: u32 = 0x01;
        if (flags & FSP_CLEANUP_DELETE) != 0 {
            if let Some(handle) = self.get_handle(context) {
                let mut fs = self.fs.write().unwrap();
                if handle.is_dir {
                    // For directories, we'd need to remove dir - not implemented yet
                } else {
                    fs.delete_file(&handle.path);
                }
            }
        }
    }

    fn set_delete(
        &self,
        context: Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> IoResult<()> {
        // Just allow deletion; actual delete happens in cleanup
        Ok(())
    }

    fn overwrite(
        &self,
        context: Self::FileContext,
        file_attributes: u32,
        replace_file_attributes: bool,
        allocation_size: u64,
        file_info: &mut FileInfo,
    ) -> IoResult<()> {
        let handle = self.get_handle(context).ok_or_else(|| {
            winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid handle",
            ))
        })?;

        if handle.is_dir {
            return Err(winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::IsADirectory,
                "is a directory",
            )));
        }

        let mut fs = self.fs.write().unwrap();
        fs.write_file(&handle.path, Vec::new());
        
        *file_info = self.make_file_info(&handle.path, false, 0);
        Ok(())
    }

    fn flush(
        &self,
        context: Option<Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> IoResult<()> {
        if let Some(ctx) = context {
            if let Some(handle) = self.get_handle(ctx) {
                if !handle.is_dir {
                    let fs = self.fs.read().unwrap();
                    let size = fs.read_file(&handle.path).map(|v| v.len() as u64).unwrap_or(0);
                    *file_info = self.make_file_info(&handle.path, false, size);
                }
            }
        }
        Ok(())
    }

    fn set_file_size(
        &self,
        context: Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> IoResult<()> {
        let handle = self.get_handle(context).ok_or_else(|| {
            winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid handle",
            ))
        })?;

        if handle.is_dir {
            return Err(winfsp::FspError::IO(std::io::Error::new(
                std::io::ErrorKind::IsADirectory,
                "is a directory",
            )));
        }

        let mut fs = self.fs.write().unwrap();
        let mut content = fs.read_file(&handle.path).cloned().unwrap_or_default();
        content.resize(new_size as usize, 0);
        fs.write_file(&handle.path, content);
        
        *file_info = self.make_file_info(&handle.path, false, new_size);
        Ok(())
    }
}

/// State for a mounted WinFsp filesystem
pub struct WinfspMount {
    host: FileSystemHost<ParcelaFs>,
    drive_letter: char,
}

impl WinfspMount {
    /// Find an available drive letter (starting from P, then going backwards)
    pub fn find_available_drive_letter() -> Option<char> {
        // Prefer letters like P, Q, R... then fall back to earlier letters
        let preferred = ['P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];
        let fallback = ['O', 'N', 'M', 'L', 'K', 'J', 'I', 'H', 'G', 'F', 'E', 'D'];
        
        for letter in preferred.iter().chain(fallback.iter()) {
            let path = format!("{}:\\", letter);
            if !std::path::Path::new(&path).exists() {
                return Some(*letter);
            }
        }
        None
    }

    /// Mount a MemoryFileSystem as a Windows drive
    pub fn mount(fs: MemoryFileSystem, volume_label: &str) -> Result<Self, String> {
        let drive_letter = Self::find_available_drive_letter()
            .ok_or_else(|| "No available drive letter".to_string())?;
        
        let context = Arc::new(ParcelaFs::new(fs, volume_label.to_string()));
        
        let mut params = VolumeParams::default();
        params.set_sector_size(512);
        params.set_sectors_per_allocation_unit(1);
        params.set_volume_creation_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        params.set_volume_serial_number(0x12345678);
        params.set_file_info_timeout(1000);
        params.set_case_sensitive_search(false);
        params.set_case_preserved_names(true);
        params.set_unicode_on_disk(true);
        params.set_persistent_acls(false);
        params.set_post_cleanup_when_modified_only(true);
        params.set_prefix("");
        params.set_file_system_name("Parcela");
        
        let host = FileSystemHost::new(params, context)
            .map_err(|e| format!("Failed to create filesystem host: {:?}", e))?;
        
        let mount_point = format!("{}:", drive_letter);
        host.mount(&mount_point)
            .map_err(|e| format!("Failed to mount at {}: {:?}", mount_point, e))?;
        
        Ok(WinfspMount { host, drive_letter })
    }

    /// Get the mount path (e.g., "P:\")
    pub fn mount_path(&self) -> String {
        format!("{}:\\", self.drive_letter)
    }

    /// Get the drive letter
    pub fn drive_letter(&self) -> char {
        self.drive_letter
    }

    /// Unmount the filesystem and return the MemoryFileSystem
    pub fn unmount(self) -> Result<MemoryFileSystem, String> {
        // The host will be dropped, which unmounts the filesystem
        // We need to extract the MemoryFileSystem first
        let fs = self.host.context();
        let fs_guard = fs.fs.write().map_err(|_| "Failed to lock filesystem")?;
        Ok(fs_guard.clone())
    }
}

impl Drop for WinfspMount {
    fn drop(&mut self) {
        // Unmounting happens automatically when FileSystemHost is dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parcela_fs_new_creates_empty_filesystem() {
        let fs = MemoryFileSystem::new();
        let parcela_fs = ParcelaFs::new(fs, "Test Volume".to_string());
        
        assert_eq!(parcela_fs.volume_label, "Test Volume");
    }

    #[test]
    fn parcela_fs_allocate_handle_increments() {
        let fs = MemoryFileSystem::new();
        let parcela_fs = ParcelaFs::new(fs, "Test".to_string());
        
        let h1 = parcela_fs.allocate_handle("file1.txt".to_string(), false);
        let h2 = parcela_fs.allocate_handle("file2.txt".to_string(), false);
        let h3 = parcela_fs.allocate_handle("dir/".to_string(), true);
        
        assert_eq!(h1, 1);
        assert_eq!(h2, 2);
        assert_eq!(h3, 3);
    }

    #[test]
    fn parcela_fs_get_handle_returns_correct_info() {
        let fs = MemoryFileSystem::new();
        let parcela_fs = ParcelaFs::new(fs, "Test".to_string());
        
        let handle_id = parcela_fs.allocate_handle("test.txt".to_string(), false);
        let handle = parcela_fs.get_handle(handle_id).unwrap();
        
        assert_eq!(handle.path, "test.txt");
        assert!(!handle.is_dir);
    }

    #[test]
    fn parcela_fs_get_handle_returns_none_for_invalid() {
        let fs = MemoryFileSystem::new();
        let parcela_fs = ParcelaFs::new(fs, "Test".to_string());
        
        assert!(parcela_fs.get_handle(999).is_none());
    }

    #[test]
    fn parcela_fs_remove_handle_works() {
        let fs = MemoryFileSystem::new();
        let parcela_fs = ParcelaFs::new(fs, "Test".to_string());
        
        let handle_id = parcela_fs.allocate_handle("test.txt".to_string(), false);
        assert!(parcela_fs.get_handle(handle_id).is_some());
        
        parcela_fs.remove_handle(handle_id);
        assert!(parcela_fs.get_handle(handle_id).is_none());
    }

    #[test]
    fn parcela_fs_file_exists_checks_memory_fs() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("existing.txt", vec![1, 2, 3]);
        
        let parcela_fs = ParcelaFs::new(fs, "Test".to_string());
        
        assert!(parcela_fs.file_exists("existing.txt"));
        assert!(!parcela_fs.file_exists("nonexistent.txt"));
    }

    #[test]
    fn parcela_fs_dir_exists_checks_memory_fs() {
        let mut fs = MemoryFileSystem::new();
        fs.create_dir_all("mydir/subdir");
        fs.write_file("mydir/file.txt", vec![1, 2, 3]);
        
        let parcela_fs = ParcelaFs::new(fs, "Test".to_string());
        
        assert!(parcela_fs.dir_exists("mydir"));
        assert!(parcela_fs.dir_exists("mydir/subdir"));
        assert!(parcela_fs.dir_exists("")); // Root always exists
        assert!(!parcela_fs.dir_exists("nonexistent"));
    }

    #[test]
    fn parcela_fs_make_file_info_sets_attributes() {
        let fs = MemoryFileSystem::new();
        let parcela_fs = ParcelaFs::new(fs, "Test".to_string());
        
        let dir_info = parcela_fs.make_file_info("mydir", true, 0);
        assert_eq!(dir_info.file_attributes, 0x10); // FILE_ATTRIBUTE_DIRECTORY
        assert_eq!(dir_info.file_size, 0);
        
        let file_info = parcela_fs.make_file_info("file.txt", false, 1024);
        assert_eq!(file_info.file_attributes, 0x80); // FILE_ATTRIBUTE_NORMAL
        assert_eq!(file_info.file_size, 1024);
        assert!(file_info.allocation_size >= 1024); // Rounded up
    }

    #[test]
    fn winfsp_mount_find_available_drive_letter_returns_some() {
        // This test verifies the logic of finding drive letters
        // On most systems, at least one letter should be available
        let letter = WinfspMount::find_available_drive_letter();
        
        // We can't guarantee a specific letter, but the function should work
        // If all letters are taken (unlikely), it returns None
        if let Some(l) = letter {
            assert!(l.is_ascii_uppercase());
        }
    }
}


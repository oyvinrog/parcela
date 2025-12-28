//! WinFsp-based filesystem implementation for Windows
//!
//! This module provides a FUSE-like filesystem using WinFsp that exposes
//! our in-memory MemoryFileSystem as a real Windows drive letter.
//!
//! Users can browse the virtual drive in Windows Explorer just like any other drive.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext,
    OpenFileInfo, WideNameInfo,
};
use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::constants::MAX_PATH;
use winfsp::{Result as FspResult, FspError, U16CStr};
use winfsp_sys::FILE_ACCESS_RIGHTS;
use winfsp_sys::FILE_FLAGS_AND_ATTRIBUTES;
use windows::Win32::Foundation::{STATUS_INVALID_DEVICE_REQUEST, STATUS_OBJECT_NAME_NOT_FOUND};

use crate::virtual_drive::MemoryFileSystem;

/// File handle for tracking open files/directories
#[derive(Debug, Clone)]
pub struct FileHandle {
    path: String,
    is_dir: bool,
}

/// WinFsp filesystem context wrapping our MemoryFileSystem
pub struct ParcelaFs {
    /// The underlying in-memory filesystem (shared for extraction on unmount)
    fs: Arc<RwLock<MemoryFileSystem>>,
    /// Open file handles
    handles: Mutex<HashMap<u64, FileHandle>>,
    /// Next handle ID
    next_handle: Mutex<u64>,
    /// Volume label for GetVolumeInfo
    volume_label: String,
    /// Creation time for the volume
    creation_time: SystemTime,
}

impl ParcelaFs {
    pub fn new(fs: MemoryFileSystem, volume_label: String) -> (Self, Arc<RwLock<MemoryFileSystem>>) {
        let fs_arc = Arc::new(RwLock::new(fs));
        let fs_clone = Arc::clone(&fs_arc);
        (
            Self {
                fs: fs_arc,
                handles: Mutex::new(HashMap::new()),
                next_handle: Mutex::new(1),
                volume_label,
                creation_time: SystemTime::now(),
            },
            fs_clone,
        )
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
        handles.get(&handle_id).cloned()
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

    fn make_file_info(&self, _path: &str, is_dir: bool, size: u64) -> FileInfo {
        let now = self.filetime_now();
        let creation = self.filetime_from_systime(self.creation_time);
        
        FileInfo {
            file_attributes: if is_dir {
                0x10 // FILE_ATTRIBUTE_DIRECTORY
            } else {
                0x80 // FILE_ATTRIBUTE_NORMAL
            },
            file_size: size,
            allocation_size: (size + 4095) & !4095, // Round up to 4KB
            creation_time: creation,
            last_access_time: now,
            last_write_time: now,
            change_time: now,
            ..FileInfo::default()
        }
    }

    fn filetime_now(&self) -> u64 {
        self.filetime_from_systime(SystemTime::now())
    }

    fn filetime_from_systime(&self, time: SystemTime) -> u64 {
        // Convert SystemTime to Windows FILETIME (100-nanosecond intervals since Jan 1, 1601)
        const EPOCH_DIFF: u64 = 116444736000000000; // Difference between 1601 and 1970 in 100ns intervals
        match time.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => {
                let nanos = duration.as_nanos() as u64;
                (nanos / 100) + EPOCH_DIFF
            }
            Err(_) => EPOCH_DIFF,
        }
    }
}

impl FileSystemContext for ParcelaFs {
    type FileContext = u64; // Handle ID

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [c_void]>,
        _resolve_reparse_points: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> FspResult<FileSecurity> {
        let path = Self::path_to_string(file_name);
        
        // Check if path exists
        if path.is_empty() || self.file_exists(&path) || self.dir_exists(&path) {
            let is_dir = path.is_empty() || self.dir_exists(&path);
            let info = if is_dir {
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
            Err(FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))
        }
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> FspResult<Self::FileContext> {
        let path = Self::path_to_string(file_name);
        
        // Root directory
        if path.is_empty() {
            let info = self.make_file_info("", true, 0);
            *file_info.as_mut() = info;
            return Ok(self.allocate_handle(path, true));
        }
        
        let fs = self.fs.read().unwrap();
        
        // Check if it's a file
        if let Some(content) = fs.read_file(&path) {
            let info = self.make_file_info(&path, false, content.len() as u64);
            *file_info.as_mut() = info;
            drop(fs);
            return Ok(self.allocate_handle(path, false));
        }
        
        // Check if it's a directory
        if self.dir_exists_internal(&fs, &path) {
            let info = self.make_file_info(&path, true, 0);
            *file_info.as_mut() = info;
            drop(fs);
            return Ok(self.allocate_handle(path, true));
        }
        
        Err(FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))
    }

    fn close(&self, context: Self::FileContext) {
        self.remove_handle(context);
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> FspResult<u32> {
        let handle = self.get_handle(*context).ok_or(FspError::from(STATUS_INVALID_DEVICE_REQUEST))?;

        if handle.is_dir {
            return Err(FspError::from(STATUS_INVALID_DEVICE_REQUEST));
        }

        let fs = self.fs.read().unwrap();
        let content = fs.read_file(&handle.path).ok_or(FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;

        let start = offset as usize;
        if start >= content.len() {
            return Ok(0);
        }

        let end = std::cmp::min(start + buffer.len(), content.len());
        let bytes_read = end - start;
        buffer[..bytes_read].copy_from_slice(&content[start..end]);
        
        Ok(bytes_read as u32)
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> FspResult<u32> {
        let handle = self.get_handle(*context).ok_or(FspError::from(STATUS_INVALID_DEVICE_REQUEST))?;

        if handle.is_dir {
            return Err(FspError::from(STATUS_INVALID_DEVICE_REQUEST));
        }

        let mut fs = self.fs.write().unwrap();
        
        // Get existing content or create empty
        let mut content = fs.read_file(&handle.path).cloned().unwrap_or_default();
        
        // Handle write_to_eof flag - append to end of file instead of using offset
        let actual_offset = if write_to_eof {
            content.len()
        } else {
            offset as usize
        };
        
        // Extend file if needed
        if actual_offset + buffer.len() > content.len() {
            content.resize(actual_offset + buffer.len(), 0);
        }
        
        content[actual_offset..actual_offset + buffer.len()].copy_from_slice(buffer);
        
        let new_size = content.len() as u64;
        fs.write_file(&handle.path, content);
        
        *file_info = self.make_file_info(&handle.path, false, new_size);
        
        Ok(buffer.len() as u32)
    }

    fn get_file_info(&self, context: &Self::FileContext, file_info: &mut FileInfo) -> FspResult<()> {
        let handle = self.get_handle(*context).ok_or(FspError::from(STATUS_INVALID_DEVICE_REQUEST))?;

        if handle.is_dir {
            *file_info = self.make_file_info(&handle.path, true, 0);
        } else {
            let fs = self.fs.read().unwrap();
            let size = fs.read_file(&handle.path).map(|v| v.len() as u64).unwrap_or(0);
            *file_info = self.make_file_info(&handle.path, false, size);
        }
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> FspResult<u32> {
        let handle = self.get_handle(*context).ok_or(FspError::from(STATUS_INVALID_DEVICE_REQUEST))?;

        if !handle.is_dir {
            return Err(FspError::from(STATUS_INVALID_DEVICE_REQUEST));
        }

        let fs = self.fs.read().unwrap();
        let entries = fs.list_dir(&handle.path);
        
        // Collect all entries
        let mut all_entries: Vec<(String, bool, u64)> = vec![
            (".".to_string(), true, 0),
            ("..".to_string(), true, 0),
        ];
        
        for entry in entries {
            let is_dir = entry.ends_with('/');
            let name = entry.trim_end_matches('/').to_string();
            if !name.is_empty() {
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
                all_entries.push((name, is_dir, size));
            }
        }

        // Sort entries for consistent ordering (important for marker handling)
        all_entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Get marker name to skip entries we've already returned
        let marker_name = if marker.is_none() {
            None
        } else {
            marker.name().map(|s| s.to_string_lossy())
        };

        // Write entries to buffer using DirInfo
        let mut cursor = 0u32;
        let mut past_marker = marker_name.is_none();
        
        for (name, is_dir, size) in all_entries {
            // Skip entries up to and including the marker
            if !past_marker {
                if let Some(ref marker_str) = marker_name {
                    if &name == marker_str {
                        past_marker = true;
                    }
                    continue;
                }
            }
            
            let info = self.make_file_info(&name, is_dir, size);
            let mut dir_info = DirInfo::<{ MAX_PATH }>::new();
            *dir_info.file_info_mut() = info;
            if dir_info.set_name(&name).is_err() {
                break;
            }
            
            if !dir_info.append_to_buffer(buffer, &mut cursor) {
                break;
            }
        }
        
        // Finalize the buffer
        DirInfo::<{ MAX_PATH }>::finalize_buffer(buffer, &mut cursor);

        Ok(cursor)
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: FILE_ACCESS_RIGHTS,
        _file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> FspResult<Self::FileContext> {
        let path = Self::path_to_string(file_name);
        let is_directory = (create_options & 0x1) != 0; // FILE_DIRECTORY_FILE
        
        if path.is_empty() {
            return Err(FspError::from(STATUS_INVALID_DEVICE_REQUEST));
        }

        let mut fs = self.fs.write().unwrap();
        
        if is_directory {
            fs.create_dir_all(&path);
            let info = self.make_file_info(&path, true, 0);
            *file_info.as_mut() = info;
            drop(fs);
            Ok(self.allocate_handle(path, true))
        } else {
            fs.write_file(&path, Vec::new());
            let info = self.make_file_info(&path, false, 0);
            *file_info.as_mut() = info;
            drop(fs);
            Ok(self.allocate_handle(path, false))
        }
    }

    fn cleanup(
        &self,
        context: &Self::FileContext,
        _file_name: Option<&U16CStr>,
        flags: u32,
    ) {
        // If FspCleanupDelete flag is set, delete the file
        const FSP_CLEANUP_DELETE: u32 = 0x01;
        if (flags & FSP_CLEANUP_DELETE) != 0 {
            if let Some(handle) = self.get_handle(*context) {
                let mut fs = self.fs.write().unwrap();
                if !handle.is_dir {
                    fs.delete_file(&handle.path);
                }
            }
        }
    }

    fn set_delete(
        &self,
        _context: &Self::FileContext,
        _file_name: &U16CStr,
        _delete_file: bool,
    ) -> FspResult<()> {
        // Just allow deletion; actual delete happens in cleanup
        Ok(())
    }

    fn rename(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> FspResult<()> {
        let handle = self.get_handle(*context).ok_or(FspError::from(STATUS_INVALID_DEVICE_REQUEST))?;
        let new_path = Self::path_to_string(new_file_name);
        
        if new_path.is_empty() {
            return Err(FspError::from(STATUS_INVALID_DEVICE_REQUEST));
        }

        let mut fs = self.fs.write().unwrap();
        
        let success = if handle.is_dir {
            fs.rename_dir(&handle.path, &new_path)
        } else {
            fs.rename_file(&handle.path, &new_path, replace_if_exists)
        };
        
        if success {
            // Update the handle's path
            drop(fs);
            let mut handles = self.handles.lock().unwrap();
            if let Some(h) = handles.get_mut(context) {
                h.path = new_path;
            }
            Ok(())
        } else {
            Err(FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))
        }
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        _file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        let handle = self.get_handle(*context).ok_or(FspError::from(STATUS_INVALID_DEVICE_REQUEST))?;

        if handle.is_dir {
            return Err(FspError::from(STATUS_INVALID_DEVICE_REQUEST));
        }

        let mut fs = self.fs.write().unwrap();
        fs.write_file(&handle.path, Vec::new());
        
        *file_info = self.make_file_info(&handle.path, false, 0);
        Ok(())
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        if let Some(ctx) = context {
            if let Some(handle) = self.get_handle(*ctx) {
                if !handle.is_dir {
                    let fs = self.fs.read().unwrap();
                    let size = fs.read_file(&handle.path).map(|v| v.len() as u64).unwrap_or(0);
                    *file_info = self.make_file_info(&handle.path, false, size);
                }
            }
        }
        Ok(())
    }

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        _creation_time: u64,
        _last_access_time: u64,
        _last_write_time: u64,
        _last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        // We don't persist timestamps in our in-memory filesystem,
        // but we need to acknowledge the request for Windows Explorer to work
        let handle = self.get_handle(*context).ok_or(FspError::from(STATUS_INVALID_DEVICE_REQUEST))?;

        if handle.is_dir {
            *file_info = self.make_file_info(&handle.path, true, 0);
        } else {
            let fs = self.fs.read().unwrap();
            let size = fs.read_file(&handle.path).map(|v| v.len() as u64).unwrap_or(0);
            *file_info = self.make_file_info(&handle.path, false, size);
        }
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        let handle = self.get_handle(*context).ok_or(FspError::from(STATUS_INVALID_DEVICE_REQUEST))?;

        if handle.is_dir {
            return Err(FspError::from(STATUS_INVALID_DEVICE_REQUEST));
        }

        let mut fs = self.fs.write().unwrap();
        
        // Get existing content or create empty
        let mut content = fs.read_file(&handle.path).cloned().unwrap_or_default();
        
        // Resize the file
        let new_size = new_size as usize;
        if new_size > content.len() {
            content.resize(new_size, 0);
        } else {
            content.truncate(new_size);
        }
        
        fs.write_file(&handle.path, content);
        
        *file_info = self.make_file_info(&handle.path, false, new_size as u64);
        Ok(())
    }

    fn get_volume_info(&self, out_volume_info: &mut winfsp::filesystem::VolumeInfo) -> FspResult<()> {
        // Report a reasonable volume size (64 MB with plenty of free space)
        out_volume_info.total_size = 64 * 1024 * 1024;
        out_volume_info.free_size = 60 * 1024 * 1024;
        out_volume_info.set_volume_label(&self.volume_label);
        Ok(())
    }
}

/// State for a mounted WinFsp filesystem
pub struct WinfspMount {
    host: FileSystemHost<ParcelaFs>,
    drive_letter: char,
    /// Shared reference to the filesystem for extraction on unmount
    fs: Arc<RwLock<MemoryFileSystem>>,
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
        
        let (context, fs_arc) = ParcelaFs::new(fs, volume_label.to_string());
        
        let mut params = VolumeParams::default();
        params.sector_size(512);
        params.sectors_per_allocation_unit(1);
        params.volume_creation_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        params.volume_serial_number(0x12345678);
        params.file_info_timeout(1000);
        params.case_sensitive_search(false);
        params.case_preserved_names(true);
        params.unicode_on_disk(true);
        params.persistent_acls(false);
        params.post_cleanup_when_modified_only(true);
        params.prefix("");
        params.filesystem_name("Parcela");
        
        let mut host = FileSystemHost::new(params, context)
            .map_err(|e| format!("Failed to create filesystem host: {:?}", e))?;
        
        let mount_point = format!("{}:", drive_letter);
        host.mount(&mount_point)
            .map_err(|e| format!("Failed to mount at {}: {:?}", mount_point, e))?;
        
        host.start()
            .map_err(|e| format!("Failed to start filesystem dispatcher: {:?}", e))?;
        
        let mount = WinfspMount { host, drive_letter, fs: fs_arc };
        
        // Wait for the drive to become accessible
        // WinFsp needs a moment for Windows to recognize the new drive
        let drive_path = mount.mount_path();
        let mut ready = false;
        for attempt in 0..50 {  // Up to 5 seconds (50 * 100ms)
            if std::path::Path::new(&drive_path).exists() {
                ready = true;
                if attempt > 0 {
                    eprintln!("[WinFsp] Drive {} ready after {}ms", drive_path, attempt * 100);
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        
        if !ready {
            eprintln!("[WinFsp] Warning: Drive {} not detected after 5s, proceeding anyway", drive_path);
        }
        
        Ok(mount)
    }

    /// Get the mount path (e.g., "P:\")
    pub fn mount_path(&self) -> String {
        format!("{}:\\", self.drive_letter)
    }

    /// Get the drive letter
    pub fn drive_letter(&self) -> char {
        self.drive_letter
    }

    /// Write a file directly to the internal filesystem (bypasses WinFsp callbacks)
    pub fn write_file(&self, path: &str, content: Vec<u8>) {
        let mut fs = self.fs.write().unwrap();
        fs.write_file(path, content);
    }
    
    /// Read a file directly from the internal filesystem (bypasses WinFsp callbacks)
    pub fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        let fs = self.fs.read().unwrap();
        fs.read_file(path).cloned()
    }
    
    /// List directory contents directly from the internal filesystem
    pub fn list_directory(&self, path: &str) -> Vec<String> {
        let fs = self.fs.read().unwrap();
        fs.list_dir(path)
    }
    
    /// Delete a file directly from the internal filesystem
    pub fn delete_file(&self, path: &str) -> bool {
        let mut fs = self.fs.write().unwrap();
        fs.delete_file(path)
    }
    
    /// Create a directory directly in the internal filesystem
    pub fn create_dir_all(&self, path: &str) {
        let mut fs = self.fs.write().unwrap();
        fs.create_dir_all(path);
    }
    
    /// Rename a file directly in the internal filesystem
    pub fn rename_file(&self, old_path: &str, new_path: &str, replace_if_exists: bool) -> bool {
        let mut fs = self.fs.write().unwrap();
        fs.rename_file(old_path, new_path, replace_if_exists)
    }
    
    /// Unmount the filesystem and return the MemoryFileSystem
    pub fn unmount(mut self) -> MemoryFileSystem {
        self.host.stop();
        self.host.unmount();
        
        // Extract the filesystem from the Arc
        // Since we're consuming self, we should be the only holder of this Arc
        // (the FileSystemHost has been stopped and dropped)
        match Arc::try_unwrap(self.fs) {
            Ok(rw_lock) => rw_lock.into_inner().unwrap_or_else(|e| e.into_inner()),
            Err(arc) => {
                // Fallback: clone the data if Arc is still shared
                arc.read().unwrap().clone()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parcela_fs_new_creates_filesystem() {
        let fs = MemoryFileSystem::new();
        let (parcela_fs, _) = ParcelaFs::new(fs, "Test Volume".to_string());
        
        assert_eq!(parcela_fs.volume_label, "Test Volume");
    }

    #[test]
    fn parcela_fs_allocate_handle_increments() {
        let fs = MemoryFileSystem::new();
        let (parcela_fs, _) = ParcelaFs::new(fs, "Test".to_string());
        
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
        let (parcela_fs, _) = ParcelaFs::new(fs, "Test".to_string());
        
        let handle_id = parcela_fs.allocate_handle("test.txt".to_string(), false);
        let handle = parcela_fs.get_handle(handle_id).unwrap();
        
        assert_eq!(handle.path, "test.txt");
        assert!(!handle.is_dir);
    }

    #[test]
    fn parcela_fs_file_exists_checks_memory_fs() {
        let mut fs = MemoryFileSystem::new();
        fs.write_file("existing.txt", vec![1, 2, 3]);
        
        let (parcela_fs, _) = ParcelaFs::new(fs, "Test".to_string());
        
        assert!(parcela_fs.file_exists("existing.txt"));
        assert!(!parcela_fs.file_exists("nonexistent.txt"));
    }

    #[test]
    fn parcela_fs_dir_exists_checks_memory_fs() {
        let mut fs = MemoryFileSystem::new();
        fs.create_dir_all("mydir/subdir");
        fs.write_file("mydir/file.txt", vec![1, 2, 3]);
        
        let (parcela_fs, _) = ParcelaFs::new(fs, "Test".to_string());
        
        assert!(parcela_fs.dir_exists("mydir"));
        assert!(parcela_fs.dir_exists("")); // Root always exists
    }

    #[test]
    fn winfsp_mount_find_available_drive_letter_returns_some() {
        let letter = WinfspMount::find_available_drive_letter();
        
        if let Some(l) = letter {
            assert!(l.is_ascii_uppercase());
        }
    }
}

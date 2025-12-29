#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use rfd::FileDialog;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Represents a regular file entry in the vault
#[derive(Clone, Debug, Serialize, Deserialize)]
struct VaultFile {
    id: String,
    name: String,
    shares: [Option<String>; 3],
    #[serde(default)]
    file_type: FileType,
}

/// Type of entry in the vault
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FileType {
    #[default]
    Regular,
    VirtualDrive,
}

/// Virtual drive entry with its encrypted data and metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
struct VaultVirtualDrive {
    id: String,
    name: String,
    size_mb: u32,
    shares: [Option<String>; 3],
    /// Drive metadata stored for reconstruction
    #[serde(default)]
    created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct VaultData {
    version: u32,
    files: Vec<VaultFile>,
    #[serde(default)]
    virtual_drives: Vec<VaultVirtualDrive>,
}

/// Runtime state for unlocked virtual drives
struct UnlockedDriveState {
    drive: parcela::VirtualDrive,
    mount_path: String,
}

lazy_static::lazy_static! {
    static ref UNLOCKED_DRIVES: Mutex<HashMap<String, UnlockedDriveState>> = Mutex::new(HashMap::new());
}

#[tauri::command]
fn pick_input_file() -> Option<String> {
    FileDialog::new()
        .pick_file()
        .map(|path| path.to_string_lossy().to_string())
}

#[tauri::command]
fn pick_destination_folder(title: String) -> Option<String> {
    FileDialog::new()
        .set_title(&title)
        .pick_folder()
        .map(|path| path.to_string_lossy().to_string())
}

#[tauri::command]
fn move_file(source: String, dest_folder: String) -> Result<String, String> {
    let source_path = std::path::Path::new(&source);
    if !source_path.exists() {
        return Err(format!("Source file not found: {}", source));
    }
    
    let filename = source_path.file_name()
        .ok_or("Invalid source path")?;
    
    let dest_path = std::path::Path::new(&dest_folder).join(filename);
    
    // Try rename first (fast path for same filesystem)
    match std::fs::rename(source_path, &dest_path) {
        Ok(()) => Ok(dest_path.to_string_lossy().to_string()),
        Err(e) => {
            // Check for cross-device link error and fall back to copy-then-delete
            // - Unix/Linux: EXDEV = 18
            // - Windows: ERROR_NOT_SAME_DEVICE = 17
            let is_cross_device = e.kind() == std::io::ErrorKind::CrossesDevices
                || (cfg!(unix) && e.raw_os_error() == Some(18))
                || (cfg!(windows) && e.raw_os_error() == Some(17));
            
            if is_cross_device {
                std::fs::copy(source_path, &dest_path)
                    .map_err(|e| format!("Failed to copy file: {}", e))?;
                std::fs::remove_file(source_path)
                    .map_err(|e| format!("Failed to remove original file after copy: {}", e))?;
                Ok(dest_path.to_string_lossy().to_string())
            } else {
                Err(format!("Failed to move file: {}", e))
            }
        }
    }
}

#[tauri::command]
fn pick_output_dir() -> Option<String> {
    FileDialog::new()
        .pick_folder()
        .map(|path| path.to_string_lossy().to_string())
}

#[tauri::command]
fn pick_share_files() -> Option<Vec<String>> {
    FileDialog::new().pick_files().map(|paths| {
        paths
            .into_iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect()
    })
}

#[tauri::command]
fn pick_vault_file() -> Option<String> {
    FileDialog::new()
        .add_filter("Parcela Vault", &["pva"])
        .pick_file()
        .map(|path| path.to_string_lossy().to_string())
}

#[tauri::command]
fn pick_vault_save() -> Option<String> {
    FileDialog::new()
        .add_filter("Parcela Vault", &["pva"])
        .set_file_name("vault.pva")
        .save_file()
        .map(|path| path.to_string_lossy().to_string())
}

#[tauri::command]
fn pick_output_file() -> Option<String> {
    FileDialog::new()
        .save_file()
        .map(|path| path.to_string_lossy().to_string())
}

#[tauri::command]
async fn combine_shares(
    share_paths: Vec<String>,
    output_path: String,
    password: String,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if share_paths.len() < 2 {
            return Err("need at least two shares".to_string());
        }

        let mut shares = Vec::with_capacity(share_paths.len());
        for path in share_paths {
            let data = std::fs::read(&path).map_err(|e| e.to_string())?;
            let share = parcela::decode_share(&data).map_err(|e| e.to_string())?;
            shares.push(share);
        }

        let encrypted = parcela::combine_shares(&shares).map_err(|e| e.to_string())?;
        let plaintext = parcela::decrypt(&encrypted, &password).map_err(|e| e.to_string())?;
        std::fs::write(&output_path, plaintext).map_err(|e| e.to_string())?;

        Ok(output_path)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn create_vault(path: String, password: String) -> Result<VaultData, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let vault = VaultData {
            version: 1,
            files: Vec::new(),
            virtual_drives: Vec::new(),
        };
        save_vault_sync(&path, &password, &vault)?;
        Ok(vault)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn open_vault(path: String, password: String) -> Result<VaultData, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        let decrypted = parcela::decrypt(&data, &password).map_err(|e| e.to_string())?;
        let vault: VaultData = serde_json::from_slice(&decrypted).map_err(|e| e.to_string())?;
        Ok(vault)
    })
    .await
    .map_err(|e| e.to_string())?
}

// Sync helper for internal use
fn save_vault_sync(path: &str, password: &str, vault: &VaultData) -> Result<(), String> {
    let json = serde_json::to_vec(vault).map_err(|e| e.to_string())?;
    let encrypted = parcela::encrypt(&json, password).map_err(|e| e.to_string())?;
    std::fs::write(path, encrypted).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn save_vault(path: String, password: String, vault: VaultData) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        save_vault_sync(&path, &password, &vault)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn check_paths(paths: Vec<String>) -> Vec<bool> {
    paths
        .into_iter()
        .map(|path| {
            if path.trim().is_empty() {
                false
            } else {
                std::path::Path::new(&path).exists()
            }
        })
        .collect()
}

#[tauri::command]
fn open_path(path: String) -> Result<(), String> {
    open::that(path).map_err(|e| e.to_string())
}

/// Create a new virtual drive in the vault
#[tauri::command]
async fn create_virtual_drive(
    name: String,
    size_mb: u32,
    out_dir: String,
    password: String,
) -> Result<VaultVirtualDrive, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let drive = parcela::VirtualDrive::new(name.clone(), size_mb);
        let drive_id = drive.metadata.id.clone();
        let created_at = drive.metadata.created_at;

        // Encode and encrypt the drive
        let encoded = drive.encode().map_err(|e| e.to_string())?;
        let encrypted = parcela::encrypt(&encoded, &password).map_err(|e| e.to_string())?;

        // Split into shares
        let shares = parcela::split_shares(&encrypted).map_err(|e| e.to_string())?;

        // Save shares to the output directory
        std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
        let base_name = format!("{}.vdrive", name.replace(['/', '\\', ':'], "_"));

        let mut share_paths: [Option<String>; 3] = [None, None, None];
        for share in shares.iter() {
            let filename = format!("{}.share{}", base_name, share.index);
            let path = std::path::PathBuf::from(&out_dir).join(filename);
            let data = parcela::encode_share(share);
            std::fs::write(&path, data).map_err(|e| e.to_string())?;
            share_paths[(share.index - 1) as usize] = Some(path.to_string_lossy().to_string());
        }

        Ok(VaultVirtualDrive {
            id: drive_id,
            name,
            size_mb,
            shares: share_paths,
            created_at,
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Unlock a virtual drive (mount it as a RAM filesystem)
#[tauri::command]
async fn unlock_virtual_drive(
    share_paths: Vec<String>,
    password: String,
) -> Result<UnlockedDriveInfo, String> {
    if share_paths.len() < 2 {
        return Err("need at least two shares".to_string());
    }

    // Do the heavy crypto work in a blocking thread
    let (drive, drive_id, drive_name) = tauri::async_runtime::spawn_blocking(move || {
        // Read and decode shares
        let mut shares = Vec::with_capacity(share_paths.len());
        for path in &share_paths {
            let data = std::fs::read(path).map_err(|e| e.to_string())?;
            let share = parcela::decode_share(&data).map_err(|e| e.to_string())?;
            shares.push(share);
        }

        // Combine shares and decrypt
        let encrypted = parcela::combine_shares(&shares).map_err(|e| e.to_string())?;
        let decrypted = parcela::decrypt(&encrypted, &password).map_err(|e| e.to_string())?;

        // Decode the virtual drive
        let drive = parcela::VirtualDrive::decode(&decrypted).map_err(|e| e.to_string())?;
        let drive_id = drive.metadata.id.clone();
        let drive_name = drive.metadata.name.clone();

        Ok::<_, String>((drive, drive_id, drive_name))
    })
    .await
    .map_err(|e| e.to_string())??;

    // Unlock (mount) the drive - this should be fast
    let mount_path = parcela::unlock_drive(&drive).map_err(|e| e.to_string())?;
    let mount_path_str = mount_path.to_string_lossy().to_string();

    // Store the unlocked state
    UNLOCKED_DRIVES
        .lock()
        .map_err(|_| "failed to acquire lock")?
        .insert(
            drive_id.clone(),
            UnlockedDriveState {
                drive,
                mount_path: mount_path_str.clone(),
            },
        );

    // Check if this drive is using native filesystem or memory mode
    let uses_native_fs = !parcela::is_memory_mode(&drive_id);
    
    Ok(UnlockedDriveInfo {
        drive_id,
        name: drive_name,
        mount_path: mount_path_str,
        uses_native_fs,
    })
}

/// Info about an unlocked drive
#[derive(Clone, Debug, Serialize, Deserialize)]
struct UnlockedDriveInfo {
    drive_id: String,
    name: String,
    mount_path: String,
    /// True if using native filesystem (ProjFS on Windows, tmpfs on Linux)
    /// False if using in-memory mode (no native filesystem browsing)
    uses_native_fs: bool,
}

/// Lock a virtual drive (unmount and re-encrypt)
#[tauri::command]
async fn lock_virtual_drive(
    drive_id: String,
    share_paths: [Option<String>; 3],
    password: String,
) -> Result<(), String> {
    // Get the unlocked drive state
    let mut state = UNLOCKED_DRIVES
        .lock()
        .map_err(|_| "failed to acquire lock")?
        .remove(&drive_id)
        .ok_or("drive is not unlocked")?;

    // Lock the drive (captures content) - this is fast
    if let Err(e) = parcela::lock_drive(&mut state.drive) {
        // Re-insert the state so user can retry
        if let Ok(mut drives) = UNLOCKED_DRIVES.lock() {
            drives.insert(drive_id, state);
        }
        return Err(e.to_string());
    }

    // Do the heavy crypto work in a blocking thread.
    // On failure, the state is returned so we can re-insert it and preserve user data.
    let result: Result<(), (UnlockedDriveState, String)> =
        tauri::async_runtime::spawn_blocking(move || {
            let encoded = match state.drive.encode() {
                Ok(e) => e,
                Err(e) => return Err((state, e.to_string())),
            };
            let encrypted = match parcela::encrypt(&encoded, &password) {
                Ok(e) => e,
                Err(e) => return Err((state, e.to_string())),
            };

            // Re-split into shares
            let shares = match parcela::split_shares(&encrypted) {
                Ok(s) => s,
                Err(e) => return Err((state, e.to_string())),
            };

            // Save to the existing share locations
            for share in shares.iter() {
                let idx = (share.index - 1) as usize;
                if let Some(path) = &share_paths[idx] {
                    let data = parcela::encode_share(share);
                    if let Err(e) = std::fs::write(path, data) {
                        return Err((state, e.to_string()));
                    }
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())?;

    match result {
        Ok(()) => Ok(()),
        Err((mut state, e)) => {
            // Re-insert the state so user can retry saving.
            // Clear mount_path since lock_drive already unmounted the drive.
            state.mount_path = String::new();
            if let Ok(mut drives) = UNLOCKED_DRIVES.lock() {
                drives.insert(drive_id, state);
            }
            Err(format!("failed to save shares (drive state preserved): {}", e))
        }
    }
}

/// Check if a virtual drive is currently unlocked
#[tauri::command]
fn is_drive_unlocked(drive_id: String) -> bool {
    UNLOCKED_DRIVES
        .lock()
        .map(|drives| drives.contains_key(&drive_id))
        .unwrap_or(false)
}

/// Get mount path for an unlocked drive
#[tauri::command]
fn get_drive_mount_path(drive_id: String) -> Option<String> {
    UNLOCKED_DRIVES
        .lock()
        .ok()
        .and_then(|drives| drives.get(&drive_id).map(|s| s.mount_path.clone()))
}

/// Get list of all unlocked drives
#[tauri::command]
fn get_unlocked_drives() -> Vec<UnlockedDriveInfo> {
    UNLOCKED_DRIVES
        .lock()
        .map(|drives| {
            drives
                .iter()
                .map(|(id, state)| {
                    let uses_native_fs = !parcela::is_memory_mode(id);
                    UnlockedDriveInfo {
                        drive_id: id.clone(),
                        name: state.drive.metadata.name.clone(),
                        mount_path: state.mount_path.clone(),
                        uses_native_fs,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Check if the platform uses memory-only mode for virtual drives.
///
/// Returns true if the platform cannot mount a native filesystem:
/// - Windows without ProjFS enabled
///
/// Returns false when native browsing is available:
/// - Linux/macOS (tmpfs directory)
/// - Windows with ProjFS (projected filesystem)
#[tauri::command]
fn uses_memory_mode() -> bool {
    parcela::uses_memory_mode()
}

/// Check if ProjFS is available on Windows.
/// Always returns false on non-Windows platforms.
#[tauri::command]
fn is_projfs_available() -> bool {
    #[cfg(target_os = "windows")]
    {
        parcela::is_projfs_available()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// Get detailed ProjFS status for debugging
#[tauri::command]
fn get_projfs_status() -> ProjfsStatus {
    #[cfg(target_os = "windows")]
    {
        let is_available = parcela::is_projfs_available();
        let uses_memory = parcela::uses_memory_mode();

        // Check if ProjFS DLL exists
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let dll_path = format!("{}\\System32\\projectedfslib.dll", system_root);
        let found_path = if std::path::Path::new(&dll_path).exists() {
            Some(dll_path)
        } else {
            None
        };

        ProjfsStatus {
            platform: "windows".to_string(),
            is_available,
            uses_memory_mode: uses_memory,
            projfs_path: found_path,
            message: if is_available {
                "ProjFS is enabled and available".to_string()
            } else {
                "ProjFS not enabled. Run: Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS".to_string()
            },
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        ProjfsStatus {
            platform: if cfg!(target_os = "macos") { "macos" } else { "linux" }.to_string(),
            is_available: false,
            uses_memory_mode: false,
            projfs_path: None,
            message: "Native filesystem support (tmpfs) - no ProjFS needed".to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProjfsStatus {
    platform: String,
    is_available: bool,
    uses_memory_mode: bool,
    projfs_path: Option<String>,
    message: String,
}

// =============================================================================
// Virtual Drive File Browser Commands (for Windows memory-only mode)
// =============================================================================

/// File entry info for the file browser
#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileEntry {
    name: String,
    is_dir: bool,
    size: Option<usize>,
}

/// List files in a virtual drive directory
#[tauri::command]
fn vdrive_list_files(drive_id: String, path: String) -> Result<Vec<FileEntry>, String> {
    let entries = parcela::vdrive_list_files(&drive_id, &path).map_err(|e| e.to_string())?;
    
    Ok(entries
        .into_iter()
        .map(|name| {
            let is_dir = name.ends_with('/');
            let clean_name = if is_dir {
                name.trim_end_matches('/').to_string()
            } else {
                name
            };
            FileEntry {
                name: clean_name,
                is_dir,
                size: None,
            }
        })
        .collect())
}

/// Read a file from a virtual drive
#[tauri::command]
fn vdrive_read_file(drive_id: String, path: String) -> Result<Vec<u8>, String> {
    parcela::vdrive_read_file(&drive_id, &path).map_err(|e| e.to_string())
}

/// Write a file to a virtual drive
#[tauri::command]
fn vdrive_write_file(drive_id: String, path: String, content: Vec<u8>) -> Result<(), String> {
    parcela::vdrive_write_file(&drive_id, &path, content).map_err(|e| e.to_string())
}

/// Delete a file from a virtual drive
#[tauri::command]
fn vdrive_delete_file(drive_id: String, path: String) -> Result<(), String> {
    parcela::vdrive_delete_file(&drive_id, &path).map_err(|e| e.to_string())
}

/// Create a directory in a virtual drive
#[tauri::command]
fn vdrive_create_dir(drive_id: String, path: String) -> Result<(), String> {
    parcela::vdrive_create_dir(&drive_id, &path).map_err(|e| e.to_string())
}

/// Import a file from disk into the virtual drive
#[tauri::command]
fn vdrive_import_file(drive_id: String, dest_path: String) -> Result<String, String> {
    // Pick a file from disk
    let source = rfd::FileDialog::new()
        .pick_file()
        .ok_or("No file selected")?;
    
    // Read the file content
    let content = std::fs::read(&source).map_err(|e| e.to_string())?;
    
    // Get the filename
    let filename = source
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    
    // Build destination path
    let full_dest = if dest_path.is_empty() {
        filename.to_string()
    } else {
        format!("{}/{}", dest_path.trim_end_matches('/'), filename)
    };
    
    // Write to virtual drive
    parcela::vdrive_write_file(&drive_id, &full_dest, content).map_err(|e| e.to_string())?;
    
    Ok(full_dest)
}

/// Delete multiple files from the filesystem
#[tauri::command]
fn delete_files(paths: Vec<String>) -> Result<(), String> {
    for path in paths {
        if path.is_empty() {
            continue;
        }
        let path = std::path::Path::new(&path);
        // Skip non-existent paths silently
        if !path.exists() {
            continue;
        }
        // Verify the path is a regular file before attempting deletion
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("Failed to read metadata for {}: {}", path.display(), e))?;
        if !metadata.is_file() {
            return Err(format!(
                "Refusing to delete non-file path: {}",
                path.display()
            ));
        }
        std::fs::remove_file(path)
            .map_err(|e| format!("Failed to delete {}: {}", path.display(), e))?;
    }
    Ok(())
}

/// Export a file from the virtual drive to disk
#[tauri::command]
fn vdrive_export_file(drive_id: String, path: String) -> Result<String, String> {
    // Read from virtual drive
    let content = parcela::vdrive_read_file(&drive_id, &path).map_err(|e| e.to_string())?;
    
    // Get suggested filename from path
    let filename = path.split('/').next_back().unwrap_or("file");
    
    // Pick save location
    let dest = rfd::FileDialog::new()
        .set_file_name(filename)
        .save_file()
        .ok_or("No save location selected")?;
    
    // Write to disk
    std::fs::write(&dest, content).map_err(|e| e.to_string())?;
    
    Ok(dest.to_string_lossy().to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            pick_input_file,
            pick_destination_folder,
            move_file,
            pick_output_dir,
            pick_share_files,
            pick_vault_file,
            pick_vault_save,
            pick_output_file,
            combine_shares,
            create_vault,
            open_vault,
            save_vault,
            check_paths,
            open_path,
            // Virtual drive commands
            create_virtual_drive,
            unlock_virtual_drive,
            lock_virtual_drive,
            is_drive_unlocked,
            get_drive_mount_path,
            get_unlocked_drives,
            uses_memory_mode,
            is_projfs_available,
            get_projfs_status,
            // Virtual drive file browser commands
            vdrive_list_files,
            vdrive_read_file,
            vdrive_write_file,
            vdrive_delete_file,
            vdrive_create_dir,
            vdrive_import_file,
            vdrive_export_file,
            delete_files
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

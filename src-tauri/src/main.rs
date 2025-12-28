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
fn split_file(input_path: String, out_dir: String, password: String) -> Result<Vec<String>, String> {
    let input = std::path::PathBuf::from(&input_path);
    let out_dir = std::path::PathBuf::from(&out_dir);

    let plaintext = std::fs::read(&input).map_err(|e| e.to_string())?;
    let encrypted = parcela::encrypt(&plaintext, &password).map_err(|e| e.to_string())?;
    let shares = parcela::split_shares(&encrypted).map_err(|e| e.to_string())?;

    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let base_name = input
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");

    let mut output_paths = Vec::with_capacity(shares.len());
    for share in shares.iter() {
        let filename = format!("{base_name}.share{}", share.index);
        let path = out_dir.join(filename);
        let data = parcela::encode_share(share);
        std::fs::write(&path, data).map_err(|e| e.to_string())?;
        output_paths.push(path.to_string_lossy().to_string());
    }

    Ok(output_paths)
}

#[tauri::command]
fn combine_shares(
    share_paths: Vec<String>,
    output_path: String,
    password: String,
) -> Result<String, String> {
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
}

#[tauri::command]
fn create_vault(path: String, password: String) -> Result<VaultData, String> {
    let vault = VaultData {
        version: 1,
        files: Vec::new(),
        virtual_drives: Vec::new(),
    };
    save_vault(path, password, vault.clone())?;
    Ok(vault)
}

#[tauri::command]
fn open_vault(path: String, password: String) -> Result<VaultData, String> {
    let data = std::fs::read(&path).map_err(|e| e.to_string())?;
    let decrypted = parcela::decrypt(&data, &password).map_err(|e| e.to_string())?;
    let vault: VaultData = serde_json::from_slice(&decrypted).map_err(|e| e.to_string())?;
    Ok(vault)
}

#[tauri::command]
fn save_vault(path: String, password: String, vault: VaultData) -> Result<(), String> {
    let json = serde_json::to_vec(&vault).map_err(|e| e.to_string())?;
    let encrypted = parcela::encrypt(&json, &password).map_err(|e| e.to_string())?;
    std::fs::write(&path, encrypted).map_err(|e| e.to_string())?;
    Ok(())
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
fn create_virtual_drive(
    name: String,
    size_mb: u32,
    out_dir: String,
    password: String,
) -> Result<VaultVirtualDrive, String> {
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
}

/// Unlock a virtual drive (mount it as a RAM filesystem)
#[tauri::command]
fn unlock_virtual_drive(
    share_paths: Vec<String>,
    password: String,
) -> Result<UnlockedDriveInfo, String> {
    if share_paths.len() < 2 {
        return Err("need at least two shares".to_string());
    }

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

    // Unlock (mount) the drive
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

    Ok(UnlockedDriveInfo {
        drive_id,
        name: drive_name,
        mount_path: mount_path_str,
    })
}

/// Info about an unlocked drive
#[derive(Clone, Debug, Serialize, Deserialize)]
struct UnlockedDriveInfo {
    drive_id: String,
    name: String,
    mount_path: String,
}

/// Lock a virtual drive (unmount and re-encrypt)
#[tauri::command]
fn lock_virtual_drive(
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

    // Lock the drive (captures content)
    // If this fails, re-insert the state to avoid orphaning the drive
    if let Err(e) = parcela::lock_drive(&mut state.drive) {
        // Re-insert the state so user can retry
        if let Ok(mut drives) = UNLOCKED_DRIVES.lock() {
            drives.insert(drive_id, state);
        }
        return Err(e.to_string());
    }

    // Re-encode, encrypt, and save shares
    // If any of these fail, preserve the state so user can retry saving
    let save_result = (|| -> Result<(), String> {
        let encoded = state.drive.encode().map_err(|e| e.to_string())?;
        let encrypted = parcela::encrypt(&encoded, &password).map_err(|e| e.to_string())?;

        // Re-split into shares
        let shares = parcela::split_shares(&encrypted).map_err(|e| e.to_string())?;

        // Save to the existing share locations
        for share in shares.iter() {
            let idx = (share.index - 1) as usize;
            if let Some(path) = &share_paths[idx] {
                let data = parcela::encode_share(share);
                std::fs::write(path, data).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    })();

    if let Err(e) = save_result {
        // Drive is locked (removed from MOUNTED_DRIVES) but content is captured.
        // Keep it in UNLOCKED_DRIVES so user can retry saving.
        // Clear mount path since it's no longer mounted.
        state.mount_path = String::new();
        if let Ok(mut drives) = UNLOCKED_DRIVES.lock() {
            drives.insert(drive_id, state);
        }
        return Err(format!(
            "drive locked but failed to save shares: {}. Content preserved for retry.",
            e
        ));
    }

    Ok(())
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
                .map(|(id, state)| UnlockedDriveInfo {
                    drive_id: id.clone(),
                    name: state.drive.metadata.name.clone(),
                    mount_path: state.mount_path.clone(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Check if the platform uses memory-only mode for virtual drives.
/// On Windows, virtual drives are kept in memory only (no actual directory on disk).
#[tauri::command]
fn uses_memory_mode() -> bool {
    parcela::uses_memory_mode()
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

/// Export a file from the virtual drive to disk
#[tauri::command]
fn vdrive_export_file(drive_id: String, path: String) -> Result<String, String> {
    // Read from virtual drive
    let content = parcela::vdrive_read_file(&drive_id, &path).map_err(|e| e.to_string())?;
    
    // Get suggested filename from path
    let filename = path.split('/').last().unwrap_or("file");
    
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
            pick_output_dir,
            pick_share_files,
            pick_vault_file,
            pick_vault_save,
            pick_output_file,
            split_file,
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
            // Virtual drive file browser commands
            vdrive_list_files,
            vdrive_read_file,
            vdrive_write_file,
            vdrive_delete_file,
            vdrive_create_dir,
            vdrive_import_file,
            vdrive_export_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

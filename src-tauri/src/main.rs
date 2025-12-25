#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use rfd::FileDialog;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct VaultFile {
    id: String,
    name: String,
    shares: [Option<String>; 3],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct VaultData {
    version: u32,
    files: Vec<VaultFile>,
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
            check_paths
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

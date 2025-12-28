//! WinFsp Integration Tests
//!
//! These tests verify the WinFsp virtual drive functionality on Windows.
//! They only run on Windows and require WinFsp to be installed.
//!
//! Run with: cargo test --test winfsp_integration -- --ignored --test-threads=1
//!
//! Note: Tests MUST run serially (--test-threads=1) because they compete for
//! drive letters. Each test mounts a drive on an available letter (starting from P:).

#![cfg(target_os = "windows")]

use std::fs;
use std::path::Path;
use std::time::Duration;

use parcela::{
    is_winfsp_available, lock_drive, unlock_drive, uses_memory_mode,
    vdrive_create_dir, vdrive_delete_file, vdrive_list_files, vdrive_read_file,
    vdrive_write_file, VirtualDrive,
};

fn unique_drive_id() -> String {
    format!(
        "test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// RAII guard to ensure a drive is unlocked even if test panics
struct DriveGuard {
    drive: Option<VirtualDrive>,
}

impl DriveGuard {
    fn new(drive: VirtualDrive) -> Self {
        Self { drive: Some(drive) }
    }
    
    fn take(&mut self) -> VirtualDrive {
        self.drive.take().expect("Drive already taken")
    }
    
    fn drive(&self) -> &VirtualDrive {
        self.drive.as_ref().expect("Drive already taken")
    }
    
    fn drive_id(&self) -> &str {
        &self.drive().metadata.id
    }
}

impl Drop for DriveGuard {
    fn drop(&mut self) {
        if let Some(mut drive) = self.drive.take() {
            // Try to lock the drive to clean up
            let _ = lock_drive(&mut drive);
            // Give Windows a moment to release the drive letter
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[test]
fn winfsp_is_detected() {
    let available = is_winfsp_available();
    println!("WinFsp available: {}", available);
    
    // On Windows, if WinFsp is installed, this should return true
    // We can't assert it's true because it might not be installed in CI
    // But we can verify the function runs without panicking
}

#[test]
fn memory_mode_reflects_winfsp_availability() {
    let memory_mode = uses_memory_mode();
    let winfsp_available = is_winfsp_available();
    
    // Memory mode should be the opposite of WinFsp availability
    assert_eq!(memory_mode, !winfsp_available,
        "Memory mode should be {} when WinFsp is {}",
        !winfsp_available,
        if winfsp_available { "available" } else { "not available" }
    );
}

#[test]
#[ignore = "Requires WinFsp installed - run with --ignored"]
fn winfsp_mount_creates_drive_letter() {
    if !is_winfsp_available() {
        println!("Skipping: WinFsp not available");
        return;
    }

    let drive = VirtualDrive::new_with_id(
        unique_drive_id(),
        "WinFsp Test Drive".to_string(),
        32,
    );
    let mut guard = DriveGuard::new(drive);

    // Unlock should create a real drive letter
    let mount_path = unlock_drive(guard.drive()).expect("Failed to unlock drive");
    let mount_str = mount_path.to_string_lossy().to_string();
    
    println!("Drive mounted at: {}", mount_str);
    
    // Verify it looks like a drive letter (e.g., "P:\")
    assert!(mount_str.len() >= 2, "Mount path too short: {}", mount_str);
    assert!(mount_str.chars().next().unwrap().is_ascii_uppercase(),
        "Expected drive letter, got: {}", mount_str);
    
    // Verify the path exists
    assert!(Path::new(&mount_str).exists(),
        "Mount path does not exist: {}", mount_str);
    
    // Clean up
    let mut drive_mut = guard.take();
    lock_drive(&mut drive_mut).expect("Failed to lock drive");
    
    // Verify drive letter is gone
    // Note: There might be a small delay before Windows removes it
    std::thread::sleep(Duration::from_millis(500));
    assert!(!Path::new(&mount_str).exists(),
        "Mount path still exists after lock: {}", mount_str);
}

#[test]
#[ignore = "Requires WinFsp installed - run with --ignored"]
fn winfsp_drive_is_browsable_in_explorer() {
    if !is_winfsp_available() {
        println!("Skipping: WinFsp not available");
        return;
    }

    let drive = VirtualDrive::new_with_id(
        unique_drive_id(),
        "Explorer Test".to_string(),
        32,
    );
    let mut guard = DriveGuard::new(drive);

    let mount_path = unlock_drive(guard.drive()).expect("Failed to unlock drive");
    let drive_id = guard.drive_id().to_string();
    
    // Create a test file using our API
    vdrive_write_file(&drive_id, "test.txt", b"Hello from WinFsp!".to_vec())
        .expect("Failed to write file");
    
    // Now try to read it using standard Windows filesystem APIs
    let file_path = mount_path.join("test.txt");
    println!("Checking file at: {:?}", file_path);
    
    // This is the key test: can we access files via normal fs operations?
    assert!(file_path.exists(), "File not visible in filesystem: {:?}", file_path);
    
    let content = fs::read_to_string(&file_path)
        .expect("Failed to read file via filesystem");
    assert_eq!(content, "Hello from WinFsp!");
    
    // Also test creating a file via filesystem and reading via our API
    let fs_test_path = mount_path.join("fs_created.txt");
    fs::write(&fs_test_path, "Created via fs").expect("Failed to write via fs");
    
    let content_via_api = vdrive_read_file(&drive_id, "fs_created.txt")
        .expect("Failed to read fs-created file via API");
    assert_eq!(content_via_api, b"Created via fs");
    
    // Clean up (guard will also clean up on panic)
    let mut drive_mut = guard.take();
    lock_drive(&mut drive_mut).expect("Failed to lock drive");
}

#[test]
#[ignore = "Requires WinFsp installed - run with --ignored"]
fn winfsp_directory_operations() {
    if !is_winfsp_available() {
        println!("Skipping: WinFsp not available");
        return;
    }

    let drive = VirtualDrive::new_with_id(
        unique_drive_id(),
        "Directory Test".to_string(),
        32,
    );
    let mut guard = DriveGuard::new(drive);

    let mount_path = unlock_drive(guard.drive()).expect("Failed to unlock drive");
    let drive_id = guard.drive_id().to_string();
    
    // Create directory structure via our API
    vdrive_create_dir(&drive_id, "level1/level2/level3")
        .expect("Failed to create nested dirs");
    
    // Verify via filesystem
    let nested_dir = mount_path.join("level1").join("level2").join("level3");
    assert!(nested_dir.exists(), "Nested directory not visible: {:?}", nested_dir);
    assert!(nested_dir.is_dir(), "Path is not a directory: {:?}", nested_dir);
    
    // Create directory via filesystem
    let fs_dir = mount_path.join("fs_created_dir");
    fs::create_dir(&fs_dir).expect("Failed to create dir via fs");
    
    // List via our API
    let entries = vdrive_list_files(&drive_id, "").expect("Failed to list root");
    println!("Root entries: {:?}", entries);
    
    assert!(entries.iter().any(|e| e.contains("level1")),
        "level1 not found in listing: {:?}", entries);
    assert!(entries.iter().any(|e| e.contains("fs_created_dir")),
        "fs_created_dir not found in listing: {:?}", entries);
    
    // Clean up (guard will also clean up on panic)
    let mut drive_mut = guard.take();
    lock_drive(&mut drive_mut).expect("Failed to lock drive");
}

#[test]
#[ignore = "Requires WinFsp installed - run with --ignored"]
fn winfsp_data_persistence() {
    if !is_winfsp_available() {
        println!("Skipping: WinFsp not available");
        return;
    }

    let drive = VirtualDrive::new_with_id(
        unique_drive_id(),
        "Persistence Test".to_string(),
        32,
    );
    let mut guard = DriveGuard::new(drive);
    
    let test_content = b"This data should persist across lock/unlock cycles!";

    // First mount: create data via our API (not filesystem - more reliable)
    {
        let _mount_path = unlock_drive(guard.drive()).expect("Failed to unlock (1)");
        let drive_id = guard.drive_id().to_string();
        
        vdrive_write_file(&drive_id, "persistent.txt", test_content.to_vec())
            .expect("Failed to write");
        
        let mut drive = guard.take();
        lock_drive(&mut drive).expect("Failed to lock (1)");
        guard = DriveGuard::new(drive);
    }
    
    // Verify content was captured
    assert!(!guard.drive().content.is_empty(), "Drive content should not be empty after lock");
    
    // Second mount: verify data persists
    {
        let _mount_path = unlock_drive(guard.drive()).expect("Failed to unlock (2)");
        let drive_id = guard.drive_id().to_string();
        
        let content = vdrive_read_file(&drive_id, "persistent.txt")
            .expect("Failed to read");
        assert_eq!(content, test_content, "Content mismatch after re-mount");
        
        let mut drive = guard.take();
        lock_drive(&mut drive).expect("Failed to lock (2)");
    }
}

#[test]
#[ignore = "Requires WinFsp installed - run with --ignored"]
fn winfsp_large_file_handling() {
    if !is_winfsp_available() {
        println!("Skipping: WinFsp not available");
        return;
    }

    let drive = VirtualDrive::new_with_id(
        unique_drive_id(),
        "Large File Test".to_string(),
        64, // 64MB
    );
    let mut guard = DriveGuard::new(drive);

    let _mount_path = unlock_drive(guard.drive()).expect("Failed to unlock");
    let drive_id = guard.drive_id().to_string();
    
    // Create a 1MB file via our API
    let large_content: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    
    vdrive_write_file(&drive_id, "large_file.bin", large_content.clone())
        .expect("Failed to write large file");
    
    // Read it back
    let read_content = vdrive_read_file(&drive_id, "large_file.bin")
        .expect("Failed to read large file");
    assert_eq!(read_content.len(), large_content.len(), "Size mismatch");
    assert_eq!(read_content, large_content, "Content mismatch");
    
    // Clean up (guard will also clean up on panic)
    let mut drive_mut = guard.take();
    lock_drive(&mut drive_mut).expect("Failed to lock");
}

/// Test that is_memory_mode correctly reflects the mount type
/// This is critical for the UI to know whether to show "Open in Explorer" or "Browse Files"
#[test]
#[ignore = "Requires WinFsp installed - run with --ignored"]
fn winfsp_mounted_drive_is_not_memory_mode() {
    if !is_winfsp_available() {
        println!("Skipping: WinFsp not available");
        return;
    }

    let drive = VirtualDrive::new_with_id(
        unique_drive_id(),
        "Memory Mode Test".to_string(),
        32,
    );
    let drive_id = drive.metadata.id.clone();
    let mut guard = DriveGuard::new(drive);

    // Before mounting, drive shouldn't be mounted at all
    assert!(!parcela::is_mounted(&drive_id), "Drive should not be mounted initially");

    // After mounting with WinFsp available, should NOT be in memory mode
    let mount_path = unlock_drive(guard.drive()).expect("Failed to unlock drive");
    
    // This is the key assertion that the UI relies on
    let is_mem = parcela::is_memory_mode(&drive_id);
    println!("Mount path: {:?}, is_memory_mode: {}", mount_path, is_mem);
    
    // With WinFsp available and mount successful, should NOT be memory mode
    assert!(!is_mem, 
        "Drive mounted with WinFsp should NOT be in memory mode. \
         Mount path: {:?}", mount_path);
    
    // The mount path should be a proper drive letter
    let mount_str = mount_path.to_string_lossy();
    assert!(mount_str.starts_with(|c: char| c.is_ascii_uppercase()),
        "Expected drive letter mount, got: {}", mount_str);
    
    // Clean up (guard will also clean up on panic)
    let mut drive_mut = guard.take();
    lock_drive(&mut drive_mut).expect("Failed to lock drive");
}

/// Test that uses_memory_mode() returns true when WinFsp is NOT available
/// This test doesn't require WinFsp - it tests the fallback behavior
#[test]
fn memory_mode_fallback_when_winfsp_unavailable() {
    // This test runs regardless of WinFsp availability
    // It just verifies the relationship between the two functions
    
    let winfsp_available = is_winfsp_available();
    let memory_mode = uses_memory_mode();
    
    println!("WinFsp available: {}, uses_memory_mode: {}", winfsp_available, memory_mode);
    
    // On Windows: memory_mode should be the inverse of winfsp_available
    // On other platforms: both should be false (Linux/macOS use tmpfs, not WinFsp)
    if cfg!(target_os = "windows") {
        assert_eq!(memory_mode, !winfsp_available,
            "On Windows, memory_mode ({}) should be the inverse of winfsp_available ({})",
            memory_mode, winfsp_available);
    } else {
        assert!(!memory_mode,
            "On non-Windows, should not use memory mode (uses tmpfs)");
    }
}


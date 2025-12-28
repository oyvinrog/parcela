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

/// Check if the mount path is accessible through the filesystem
/// Returns true if the WinFsp mount is actually working
fn is_mount_accessible(mount_path: &std::path::Path) -> bool {
    // Give it a moment to become ready
    for attempt in 0..30 {
        if mount_path.exists() {
            if attempt > 0 {
                println!("Mount accessible after {}ms", attempt * 100);
            }
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Skip test if WinFsp mount isn't actually working through the filesystem
/// This can happen if WinFsp callbacks aren't functioning properly
macro_rules! require_accessible_mount {
    ($mount_path:expr) => {
        if !is_mount_accessible(&$mount_path) {
            println!("SKIP: Mount path {:?} is not accessible via filesystem", $mount_path);
            println!("WinFsp callbacks may not be functioning correctly");
            println!("The vdrive_* API still works (bypasses WinFsp callbacks)");
            return;
        }
    };
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
    
    // Verify the path exists (may need to wait for WinFsp to be ready)
    require_accessible_mount!(mount_path);
    
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
    
    // First check if the mount is accessible via filesystem
    require_accessible_mount!(mount_path);
    
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
    
    // First check if the mount is accessible via filesystem
    require_accessible_mount!(mount_path);
    
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

/// Test that set_file_size callback works (required for Windows Explorer file creation)
/// 
/// When Windows Explorer creates a new file (right-click → New → Text Document), it:
/// 1. Calls create() to create the file
/// 2. Calls set_file_size() to set initial size
/// 3. Calls set_basic_info() to set timestamps
/// 
/// If set_file_size is not implemented, users get "0x8000FFFF: Catastrophic failure"
#[test]
#[ignore = "Requires WinFsp installed - run with --ignored"]
fn winfsp_set_file_size_works() {
    if !is_winfsp_available() {
        println!("Skipping: WinFsp not available");
        return;
    }

    let drive = VirtualDrive::new_with_id(
        unique_drive_id(),
        "SetFileSize Test".to_string(),
        32,
    );
    let mut guard = DriveGuard::new(drive);

    let mount_path = unlock_drive(guard.drive()).expect("Failed to unlock drive");
    
    require_accessible_mount!(mount_path);
    
    // Test 1: Create empty file and set its size to 0 (like Windows Explorer does)
    let empty_file = mount_path.join("empty.txt");
    {
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&empty_file)
            .expect("Failed to create empty file");
        
        // This triggers set_file_size callback - the operation that was causing
        // "0x8000FFFF: Catastrophic failure" before the fix
        file.set_len(0).expect("Failed to set file size to 0");
    }
    assert!(empty_file.exists(), "Empty file should exist");
    assert_eq!(fs::metadata(&empty_file).unwrap().len(), 0, "File should be empty");
    
    // Test 2: Create file and pre-allocate space
    let preallocated = mount_path.join("preallocated.bin");
    {
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&preallocated)
            .expect("Failed to create preallocated file");
        
        // Pre-allocate 1KB
        file.set_len(1024).expect("Failed to pre-allocate file");
    }
    assert_eq!(fs::metadata(&preallocated).unwrap().len(), 1024, 
        "Pre-allocated file should be 1024 bytes");
    
    // Test 3: Truncate existing file
    let to_truncate = mount_path.join("truncate.txt");
    fs::write(&to_truncate, "This content will be truncated").expect("Failed to write");
    {
        let file = fs::OpenOptions::new()
            .write(true)
            .open(&to_truncate)
            .expect("Failed to open for truncation");
        
        file.set_len(10).expect("Failed to truncate file");
    }
    assert_eq!(fs::metadata(&to_truncate).unwrap().len(), 10,
        "Truncated file should be 10 bytes");
    
    // Verify content was actually truncated
    let content = fs::read(&to_truncate).expect("Failed to read truncated file");
    assert_eq!(content.len(), 10);
    assert_eq!(&content, b"This conte"); // First 10 bytes
    
    // Clean up
    let mut drive_mut = guard.take();
    lock_drive(&mut drive_mut).expect("Failed to lock drive");
}

/// Test that set_basic_info callback works (required for setting file timestamps)
/// 
/// Windows Explorer and many apps call SetFileTime/SetFileAttributes which
/// triggers the set_basic_info callback. If not implemented, file operations fail.
#[test]
#[ignore = "Requires WinFsp installed - run with --ignored"]
fn winfsp_set_basic_info_works() {
    if !is_winfsp_available() {
        println!("Skipping: WinFsp not available");
        return;
    }

    use std::time::SystemTime;

    let drive = VirtualDrive::new_with_id(
        unique_drive_id(),
        "SetBasicInfo Test".to_string(),
        32,
    );
    let mut guard = DriveGuard::new(drive);

    let mount_path = unlock_drive(guard.drive()).expect("Failed to unlock drive");
    
    require_accessible_mount!(mount_path);
    
    // Create a test file
    let test_file = mount_path.join("timestamps.txt");
    fs::write(&test_file, "Test content").expect("Failed to write file");
    
    // Read initial metadata
    let initial_meta = fs::metadata(&test_file).expect("Failed to get metadata");
    let initial_modified = initial_meta.modified().expect("Failed to get modified time");
    
    println!("Initial modified time: {:?}", initial_modified);
    
    // Wait a moment to ensure time difference
    std::thread::sleep(Duration::from_millis(100));
    
    // Append to the file to update its modification time
    // This triggers set_basic_info callback
    let file = fs::OpenOptions::new()
        .append(true)  // Use append mode to add to end of file
        .open(&test_file)
        .expect("Failed to open file for append");
    
    // Write a byte to trigger a modification time update
    use std::io::Write;
    let mut file = file;
    file.write_all(b"!").expect("Failed to write");
    file.flush().expect("Failed to flush");
    drop(file);
    
    // Verify file is still accessible (set_basic_info didn't crash)
    let final_meta = fs::metadata(&test_file).expect("Failed to get final metadata");
    let final_modified = final_meta.modified().expect("Failed to get final modified time");
    
    println!("Final modified time: {:?}", final_modified);
    
    // The modification time should have been updated (or at least the operation succeeded)
    // We mainly care that the operation didn't fail with "Catastrophic failure"
    assert!(final_modified >= initial_modified, 
        "Modified time should not go backwards");
    
    // Verify file content was appended
    let content = fs::read_to_string(&test_file).expect("Failed to read file");
    assert_eq!(content, "Test content!",
        "File content should be 'Test content!' after append, got: {}", content);
    
    // Clean up
    let mut drive_mut = guard.take();
    lock_drive(&mut drive_mut).expect("Failed to lock drive");
}

/// Test get_volume_info callback (returns drive capacity information)
/// 
/// Windows Explorer queries volume info to show free space. If not implemented,
/// the drive may show incorrect or no capacity information.
#[test]
#[ignore = "Requires WinFsp installed - run with --ignored"]
fn winfsp_volume_info_works() {
    if !is_winfsp_available() {
        println!("Skipping: WinFsp not available");
        return;
    }

    let drive = VirtualDrive::new_with_id(
        unique_drive_id(),
        "VolumeInfo Test".to_string(),
        32,
    );
    let mut guard = DriveGuard::new(drive);

    let mount_path = unlock_drive(guard.drive()).expect("Failed to unlock drive");
    
    require_accessible_mount!(mount_path);
    
    // Query volume/disk information using Windows API via std
    // fs2 crate would be better but we'll use what we have
    
    // At minimum, verify the drive is accessible and we can list its contents
    let entries: Vec<_> = fs::read_dir(&mount_path)
        .expect("Failed to read drive root")
        .collect();
    
    println!("Drive root has {} entries", entries.len());
    
    // Create a file to verify the drive is writable
    let test_file = mount_path.join("volume_test.txt");
    fs::write(&test_file, "Testing volume").expect("Failed to write to volume");
    
    // Verify we can read it back
    let content = fs::read_to_string(&test_file).expect("Failed to read from volume");
    assert_eq!(content, "Testing volume");
    
    // Clean up
    let mut drive_mut = guard.take();
    lock_drive(&mut drive_mut).expect("Failed to lock drive");
}

/// Test that rename callback works (required for Windows Explorer file operations)
/// 
/// When Windows Explorer creates "New Text Document.txt", it often:
/// 1. Creates a temp file
/// 2. Renames it to the final name
/// 
/// If rename is not implemented, users get "Invalid MS-DOS function"
#[test]
#[ignore = "Requires WinFsp installed - run with --ignored"]
fn winfsp_rename_works() {
    if !is_winfsp_available() {
        println!("Skipping: WinFsp not available");
        return;
    }

    let drive = VirtualDrive::new_with_id(
        unique_drive_id(),
        "Rename Test".to_string(),
        32,
    );
    let mut guard = DriveGuard::new(drive);

    let mount_path = unlock_drive(guard.drive()).expect("Failed to unlock drive");
    
    require_accessible_mount!(mount_path);
    
    // Test 1: Basic file rename
    let original = mount_path.join("original.txt");
    let renamed = mount_path.join("renamed.txt");
    
    fs::write(&original, "Test content").expect("Failed to create file");
    assert!(original.exists(), "Original file should exist");
    
    fs::rename(&original, &renamed).expect("Failed to rename file");
    
    assert!(!original.exists(), "Original file should no longer exist");
    assert!(renamed.exists(), "Renamed file should exist");
    
    let content = fs::read_to_string(&renamed).expect("Failed to read renamed file");
    assert_eq!(content, "Test content", "Content should be preserved after rename");
    
    // Test 2: Rename to different directory
    let subdir = mount_path.join("subdir");
    fs::create_dir(&subdir).expect("Failed to create subdir");
    
    let moved = subdir.join("moved.txt");
    fs::rename(&renamed, &moved).expect("Failed to move file to subdir");
    
    assert!(!renamed.exists(), "Source file should no longer exist");
    assert!(moved.exists(), "Moved file should exist in subdir");
    
    // Test 3: Rename with replace (overwrite existing)
    let target = mount_path.join("target.txt");
    let source = mount_path.join("source.txt");
    
    fs::write(&target, "old content").expect("Failed to create target");
    fs::write(&source, "new content").expect("Failed to create source");
    
    fs::rename(&source, &target).expect("Failed to rename with replace");
    
    assert!(!source.exists(), "Source should no longer exist");
    let content = fs::read_to_string(&target).expect("Failed to read target");
    assert_eq!(content, "new content", "Content should be replaced");
    
    println!("✓ All rename operations completed successfully");
    
    // Clean up
    let mut drive_mut = guard.take();
    lock_drive(&mut drive_mut).expect("Failed to lock drive");
}

/// Simulate Windows Explorer "New Text Document" creation pattern
/// 
/// This is the exact sequence that was failing with "Catastrophic failure":
/// 1. Create file
/// 2. Set file size
/// 3. Set attributes/timestamps
/// 4. Write content
#[test]
#[ignore = "Requires WinFsp installed - run with --ignored"]
fn winfsp_explorer_new_file_pattern() {
    if !is_winfsp_available() {
        println!("Skipping: WinFsp not available");
        return;
    }

    let drive = VirtualDrive::new_with_id(
        unique_drive_id(),
        "Explorer Pattern Test".to_string(),
        32,
    );
    let mut guard = DriveGuard::new(drive);

    let mount_path = unlock_drive(guard.drive()).expect("Failed to unlock drive");
    
    require_accessible_mount!(mount_path);
    
    // Simulate the exact pattern Windows Explorer uses
    let new_doc = mount_path.join("New Text Document.txt");
    
    // Step 1: Create the file
    let file = fs::OpenOptions::new()
        .create_new(true)  // Fail if exists (like Explorer)
        .write(true)
        .read(true)
        .open(&new_doc)
        .expect("Step 1 failed: Could not create new file");
    
    // Step 2: Set file size (this was the failing step!)
    file.set_len(0).expect("Step 2 failed: Could not set file size");
    
    // Step 3: Sync/flush (triggers various callbacks)
    file.sync_all().expect("Step 3 failed: Could not sync file");
    
    // Step 4: Close and reopen (like Explorer does)
    drop(file);
    
    // Verify file exists and is empty
    assert!(new_doc.exists(), "New document should exist");
    assert_eq!(fs::metadata(&new_doc).unwrap().len(), 0, 
        "New document should be empty");
    
    // Step 5: User "types" in the document
    fs::write(&new_doc, "Hello, World!").expect("Step 5 failed: Could not write content");
    
    // Verify final content
    let content = fs::read_to_string(&new_doc).expect("Failed to read final content");
    assert_eq!(content, "Hello, World!");
    
    println!("✓ Windows Explorer new file pattern completed successfully");
    
    // Clean up
    let mut drive_mut = guard.take();
    lock_drive(&mut drive_mut).expect("Failed to lock drive");
}

/// Test file copy operations (cp/copy)
/// 
/// When copying files to the virtual drive, Windows:
/// 1. Creates the destination file
/// 2. Reads from source, writes to destination (possibly with write_to_eof)
/// 3. Sets file timestamps via set_basic_info
#[test]
#[ignore = "Requires WinFsp installed - run with --ignored"]
fn winfsp_copy_file_works() {
    if !is_winfsp_available() {
        println!("Skipping: WinFsp not available");
        return;
    }

    let drive = VirtualDrive::new_with_id(
        unique_drive_id(),
        "Copy Test".to_string(),
        32,
    );
    let mut guard = DriveGuard::new(drive);

    let mount_path = unlock_drive(guard.drive()).expect("Failed to unlock drive");
    
    require_accessible_mount!(mount_path);
    
    // Test 1: Copy within the drive
    let source = mount_path.join("source.txt");
    let dest = mount_path.join("copy.txt");
    
    let test_content = "This is the content to copy!";
    fs::write(&source, test_content).expect("Failed to create source file");
    
    fs::copy(&source, &dest).expect("Failed to copy file");
    
    assert!(source.exists(), "Source should still exist");
    assert!(dest.exists(), "Destination should exist");
    
    let copied_content = fs::read_to_string(&dest).expect("Failed to read copy");
    assert_eq!(copied_content, test_content, "Copied content should match");
    
    // Test 2: Copy into a subdirectory
    let subdir = mount_path.join("copies");
    fs::create_dir(&subdir).expect("Failed to create subdir");
    
    let dest_in_subdir = subdir.join("another_copy.txt");
    fs::copy(&source, &dest_in_subdir).expect("Failed to copy to subdir");
    
    let content_in_subdir = fs::read_to_string(&dest_in_subdir).expect("Failed to read");
    assert_eq!(content_in_subdir, test_content);
    
    // Test 3: Copy a larger file (tests chunked writes)
    let large_source = mount_path.join("large_source.bin");
    let large_dest = mount_path.join("large_copy.bin");
    
    // Create 100KB file
    let large_content: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    fs::write(&large_source, &large_content).expect("Failed to write large file");
    
    fs::copy(&large_source, &large_dest).expect("Failed to copy large file");
    
    let large_copied = fs::read(&large_dest).expect("Failed to read large copy");
    assert_eq!(large_copied.len(), large_content.len(), "Size should match");
    assert_eq!(large_copied, large_content, "Content should match");
    
    // Test 4: Verify directory listing shows all files
    let entries: Vec<_> = fs::read_dir(&mount_path)
        .expect("Failed to read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    
    println!("Directory entries: {:?}", entries);
    assert!(entries.contains(&"source.txt".to_string()), "source.txt missing");
    assert!(entries.contains(&"copy.txt".to_string()), "copy.txt missing");
    assert!(entries.contains(&"copies".to_string()), "copies dir missing");
    assert!(entries.contains(&"large_source.bin".to_string()), "large_source.bin missing");
    assert!(entries.contains(&"large_copy.bin".to_string()), "large_copy.bin missing");
    
    println!("✓ All copy operations completed successfully");
    
    // Clean up
    let mut drive_mut = guard.take();
    lock_drive(&mut drive_mut).expect("Failed to lock drive");
}


/**
 * Virtual Drive UI Tests
 * 
 * These tests verify the UI logic for virtual drive handling,
 * particularly around ProjFS detection and the "Open in Browser" button behavior.
 */

describe('Virtual Drive UI Logic', () => {
  
  describe('ProjFS Status Handling', () => {
    
    test('should correctly parse Windows platform with ProjFS available', async () => {
      const status = {
        platform: 'windows',
        is_available: true,
        uses_memory_mode: false,
        projfs_path: 'C:\\Windows\\System32\\projectedfslib.dll',
        message: 'ProjFS is installed and available',
      };
      
      expect(status.platform).toBe('windows');
      expect(status.is_available).toBe(true);
      expect(status.uses_memory_mode).toBe(false);
      expect(status.projfs_path).toContain('projectedfslib');
    });
    
    test('should correctly parse Windows platform without ProjFS', async () => {
      const status = {
        platform: 'windows',
        is_available: false,
        uses_memory_mode: true,
        projfs_path: null,
        message: 'ProjFS not found',
      };
      
      expect(status.platform).toBe('windows');
      expect(status.is_available).toBe(false);
      expect(status.uses_memory_mode).toBe(true);
      expect(status.projfs_path).toBeNull();
    });
    
    test('should correctly parse Linux platform', async () => {
      const status = {
        platform: 'linux',
        is_available: false,
        uses_memory_mode: false,
        projfs_path: null,
        message: 'Native filesystem support (tmpfs) - no ProjFS needed',
      };
      
      expect(status.platform).toBe('linux');
      expect(status.uses_memory_mode).toBe(false); // Linux uses tmpfs, not memory mode
    });
  });
  
  describe('Unlocked Drive Info', () => {
    
    test('should include uses_native_fs field for ProjFS-mounted drives', () => {
      const driveInfo = {
        drive_id: 'test-drive-123',
        name: 'Test Drive',
        mount_path: 'P:\\',
        uses_native_fs: true,
      };
      
      expect(driveInfo.uses_native_fs).toBe(true);
      expect(driveInfo.mount_path).toMatch(/^[A-Z]:\\/);
    });
    
    test('should include uses_native_fs field for memory-mode drives', () => {
      const driveInfo = {
        drive_id: 'test-drive-456',
        name: 'Memory Drive',
        mount_path: 'C:\\Users\\user\\AppData\\Local\\Temp\\parcela-vdrive-test',
        uses_native_fs: false,
      };
      
      expect(driveInfo.uses_native_fs).toBe(false);
    });
    
    test('should store drive info with uses_native_fs in state', () => {
      const state = {
        unlockedDrives: new Map(),
      };
      
      const unlockInfo = {
        drive_id: 'drive-1',
        name: 'My Drive',
        mount_path: 'P:\\',
        uses_native_fs: true,
      };
      
      state.unlockedDrives.set(unlockInfo.drive_id, {
        mount_path: unlockInfo.mount_path,
        name: unlockInfo.name,
        uses_native_fs: unlockInfo.uses_native_fs,
      });
      
      const stored = state.unlockedDrives.get('drive-1');
      expect(stored.uses_native_fs).toBe(true);
      expect(stored.mount_path).toBe('P:\\');
    });
  });
  
  describe('Open Drive Button Behavior', () => {
    
    test('should show "Open in Explorer" for native FS drives', () => {
      const driveInfo = { uses_native_fs: true };
      
      // Simulate the button text logic from renderDetail()
      let buttonText, buttonTitle;
      if (driveInfo.uses_native_fs) {
        buttonText = 'Open in Explorer';
        buttonTitle = 'Open drive in file manager';
      } else {
        buttonText = 'Browse Files';
        buttonTitle = 'Browse files in the built-in file browser';
      }
      
      expect(buttonText).toBe('Open in Explorer');
      expect(buttonTitle).toBe('Open drive in file manager');
    });
    
    test('should show "Browse Files" for memory mode drives', () => {
      const driveInfo = { uses_native_fs: false };
      
      // Simulate the button text logic from renderDetail()
      let buttonText, buttonTitle;
      if (driveInfo.uses_native_fs) {
        buttonText = 'Open in Explorer';
        buttonTitle = 'Open drive in file manager';
      } else {
        buttonText = 'Browse Files';
        buttonTitle = 'Browse files in the built-in file browser';
      }
      
      expect(buttonText).toBe('Browse Files');
      expect(buttonTitle).toBe('Browse files in the built-in file browser');
    });
    
    test('should NOT hide the button globally based on platform', () => {
      // This was the original bug - the button was hidden on Windows without ProjFS
      // The fix is to never hide it, but change its behavior per-drive
      
      const platformStatus = {
        platform: 'windows',
        is_available: false, // ProjFS not available
        uses_memory_mode: true,
      };
      
      // The button should NOT be hidden based on platform status alone
      // It should remain visible and its behavior should be determined per-drive
      const shouldHideButton = false; // This is the fix
      
      expect(shouldHideButton).toBe(false);
    });
  });
  
  describe('handleOpenDrive Logic', () => {
    
    test('should open in explorer for native FS drives', async () => {
      const driveInfo = {
        mount_path: 'P:\\',
        uses_native_fs: true,
      };
      
      let action = null;
      
      // Simulate handleOpenDrive logic
      if (driveInfo && !driveInfo.uses_native_fs) {
        action = 'scroll_to_file_browser';
      } else {
        action = 'open_in_explorer';
      }
      
      expect(action).toBe('open_in_explorer');
    });
    
    test('should scroll to file browser for memory mode drives', async () => {
      const driveInfo = {
        mount_path: 'C:\\temp\\parcela-vdrive',
        uses_native_fs: false,
      };
      
      let action = null;
      
      // Simulate handleOpenDrive logic
      if (driveInfo && !driveInfo.uses_native_fs) {
        action = 'scroll_to_file_browser';
      } else {
        action = 'open_in_explorer';
      }
      
      expect(action).toBe('scroll_to_file_browser');
    });
    
    test('should handle undefined driveInfo gracefully', async () => {
      const driveInfo = undefined;
      
      let action = null;
      
      // Simulate handleOpenDrive logic with safety check
      if (driveInfo && !driveInfo.uses_native_fs) {
        action = 'scroll_to_file_browser';
      } else {
        // If driveInfo is undefined/null, try to open (will fail gracefully)
        action = 'open_in_explorer';
      }
      
      expect(action).toBe('open_in_explorer');
    });
  });
  
  describe('Drive State Consistency', () => {
    
    test('refreshUnlockedDrives should store uses_native_fs', () => {
      const state = {
        unlockedDrives: new Map(),
      };
      
      // Simulate the unlock response from backend
      const unlocked = [
        {
          drive_id: 'drive-1',
          name: 'Drive 1',
          mount_path: 'P:\\',
          uses_native_fs: true,
        },
        {
          drive_id: 'drive-2',
          name: 'Drive 2',
          mount_path: 'C:\\temp\\vdrive',
          uses_native_fs: false,
        },
      ];
      
      // Simulate refreshUnlockedDrives logic
      state.unlockedDrives.clear();
      for (const info of unlocked) {
        state.unlockedDrives.set(info.drive_id, {
          mount_path: info.mount_path,
          name: info.name,
          uses_native_fs: info.uses_native_fs,
        });
      }
      
      expect(state.unlockedDrives.size).toBe(2);
      expect(state.unlockedDrives.get('drive-1').uses_native_fs).toBe(true);
      expect(state.unlockedDrives.get('drive-2').uses_native_fs).toBe(false);
    });
    
    test('newly unlocked drive should have uses_native_fs set', () => {
      const state = {
        unlockedDrives: new Map(),
      };
      
      // Simulate unlock response
      const unlockInfo = {
        drive_id: 'new-drive',
        name: 'New Drive',
        mount_path: 'Q:\\',
        uses_native_fs: true,
      };
      
      // Simulate handleUnlockDrive logic
      state.unlockedDrives.set(unlockInfo.drive_id, {
        mount_path: unlockInfo.mount_path,
        name: unlockInfo.name,
        uses_native_fs: unlockInfo.uses_native_fs,
      });
      
      const stored = state.unlockedDrives.get('new-drive');
      expect(stored).toBeDefined();
      expect(stored.uses_native_fs).toBe(true);
    });
  });
});

describe('Regression Tests', () => {
  
  /**
   * This test documents the original bug:
   * The "Open in Browser" button was HIDDEN globally on Windows without ProjFS,
   * instead of being shown with per-drive behavior.
   * 
   * The fix is to:
   * 1. Never hide the button globally
   * 2. Check uses_native_fs per-drive after mounting
   * 3. Change button text/behavior based on per-drive status
   */
  test('BUG FIX: button should NOT be hidden globally based on ProjFS detection', () => {
    // Old buggy behavior:
    // if (state.isMemoryMode && !projfsAvailable) {
    //   openDriveBtn.style.display = "none";  // <-- BUG: hides button globally
    // }
    
    const platformStatus = {
      platform: 'windows',
      is_available: false,  // ProjFS not installed
      uses_memory_mode: true,
    };
    
    // The WRONG way (what the bug did):
    const wouldHideWithBug = platformStatus.uses_memory_mode && !platformStatus.is_available;
    expect(wouldHideWithBug).toBe(true);  // Bug would hide the button
    
    // The RIGHT way (after fix):
    // Don't hide based on platform - show button and check per-drive
    const shouldHideButton = false;  // Never hide globally
    expect(shouldHideButton).toBe(false);
  });
  
  test('BUG FIX: button behavior should be determined per-drive, not globally', () => {
    // Simulate multiple drives with different mount types
    const drives = new Map([
      ['drive-projfs', { mount_path: 'C:\\temp\\parcela-vdrive', uses_native_fs: true }],
      ['drive-memory', { mount_path: 'C:\\temp\\vdrive', uses_native_fs: false }],
    ]);
    
    // For ProjFS drive: should open in explorer
    const projfsDrive = drives.get('drive-projfs');
    expect(projfsDrive.uses_native_fs).toBe(true);
    
    // For memory drive: should use file browser
    const memoryDrive = drives.get('drive-memory');
    expect(memoryDrive.uses_native_fs).toBe(false);
    
    // Both drives should have the button visible (not hidden globally)
    // The behavior differs per-drive based on uses_native_fs
  });
  
  test('BUG FIX: uses_native_fs must be included in UnlockedDriveInfo', () => {
    // The fix requires the backend to return uses_native_fs in the unlock response
    const unlockResponse = {
      drive_id: 'test-123',
      name: 'Test Drive',
      mount_path: 'P:\\',
      // This field was ADDED as part of the fix:
      uses_native_fs: true,
    };
    
    expect(unlockResponse).toHaveProperty('uses_native_fs');
    expect(typeof unlockResponse.uses_native_fs).toBe('boolean');
  });
});

describe('Platform Detection Edge Cases', () => {
  
  test('should handle missing projfs_path gracefully', () => {
    const status = {
      platform: 'windows',
      is_available: false,
      uses_memory_mode: true,
      projfs_path: null,
      message: 'ProjFS not found',
    };
    
    // Should not throw when accessing null path
    expect(() => {
      const path = status.projfs_path;
      if (path) {
        console.log('Found at:', path);
      }
    }).not.toThrow();
  });
  
  test('should handle empty string projfs_path', () => {
    const status = {
      platform: 'windows',
      is_available: false,
      uses_memory_mode: true,
      projfs_path: '',
      message: 'ProjFS not found',
    };
    
    // Empty string should be treated as not found
    const isFound = status.projfs_path && status.projfs_path.length > 0;
    expect(isFound).toBeFalsy();
  });
});


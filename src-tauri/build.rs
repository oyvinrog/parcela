fn main() {
    // Enable delay-loading of WinFsp DLL on Windows
    // This allows the application to start even if WinFsp is not installed,
    // gracefully falling back to memory-only mode for virtual drives
    #[cfg(windows)]
    {
        winfsp::build::winfsp_link_delayload();
    }
    
    tauri_build::build()
}

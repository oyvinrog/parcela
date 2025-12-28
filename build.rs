fn main() {
    // Enable delay-loading of WinFsp DLL on Windows
    // This allows the application to start even if WinFsp is not installed,
    // and show a helpful error message instead of crashing
    #[cfg(windows)]
    {
        winfsp::build::winfsp_link_delayload();
    }
}


; Parcela NSIS Installer Hooks
; This script installs WinFsp if it's not already present

!include "LogicLib.nsh"

; Check if WinFsp is installed by looking for the DLL
!macro CheckWinFspInstalled Result
    StrCpy ${Result} "0"
    
    ; Check in Program Files
    IfFileExists "$PROGRAMFILES64\WinFsp\bin\winfsp-x64.dll" 0 +3
        StrCpy ${Result} "1"
        Goto done_check
    
    ; Also check 32-bit Program Files
    IfFileExists "$PROGRAMFILES\WinFsp\bin\winfsp-x64.dll" 0 +3
        StrCpy ${Result} "1"
        Goto done_check
    
    done_check:
!macroend

; Called before installation starts
!macro NSIS_HOOK_PREINSTALL
    ; Check if WinFsp is installed
    Var /GLOBAL WinFspInstalled
    !insertmacro CheckWinFspInstalled $WinFspInstalled
    
    ${If} $WinFspInstalled == "0"
        ; Inform user that WinFsp will be installed
        MessageBox MB_YESNO|MB_ICONQUESTION \
            "Parcela requires WinFsp for virtual drive support.$\n$\n\
            WinFsp is not currently installed. Would you like to install it now?$\n$\n\
            If you choose No, Parcela will work but with limited virtual drive features." \
            IDYES install_winfsp IDNO skip_winfsp
        
        install_winfsp:
            ; Note: The actual WinFsp MSI would need to be bundled with the installer
            ; This requires downloading it during build and including it as a resource
            ; For now, we'll open the download page
            ExecShell "open" "https://winfsp.dev/rel/"
            MessageBox MB_OK "Please download and install WinFsp, then run this installer again."
            Abort "WinFsp installation required"
        
        skip_winfsp:
            ; Continue without WinFsp
    ${EndIf}
!macroend

; Called after installation completes
!macro NSIS_HOOK_POSTINSTALL
    ; Nothing to do here for now
!macroend


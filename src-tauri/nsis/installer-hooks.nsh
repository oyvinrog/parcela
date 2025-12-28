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
        ; Inform user that WinFsp is recommended but not required
        MessageBox MB_YESNO|MB_ICONQUESTION \
            "Parcela works best with WinFsp for virtual drive support.$\n$\n\
            WinFsp is not currently installed. Would you like to open the download page?$\n$\n\
            You can install WinFsp now or later. Parcela will continue to install either way." \
            IDYES open_winfsp_page IDNO skip_winfsp
        
        open_winfsp_page:
            ; Open the WinFsp download page for the user
            ExecShell "open" "https://winfsp.dev/rel/"
            MessageBox MB_OK "The WinFsp download page has been opened in your browser.$\n$\n\
            You can install WinFsp now or later to enable virtual drive features.$\n$\n\
            The Parcela installation will now continue."
            ; Fall through to continue installation
        
        skip_winfsp:
            ; Continue installation without WinFsp
    ${EndIf}
!macroend

; Called after installation completes
!macro NSIS_HOOK_POSTINSTALL
    ; Nothing to do here for now
!macroend


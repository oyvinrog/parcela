; Parcela NSIS Installer Hooks
; This script checks for ProjFS and informs users how to enable it

!include "LogicLib.nsh"

; Check if ProjFS is available by looking for the DLL
!macro CheckProjFsInstalled Result
    StrCpy ${Result} "0"

    ; Check for projectedfslib.dll in System32
    IfFileExists "$WINDIR\System32\projectedfslib.dll" 0 +3
        StrCpy ${Result} "1"
        Goto done_check

    done_check:
!macroend

; Called before installation starts
!macro NSIS_HOOK_PREINSTALL
    ; Check if ProjFS is available
    Var /GLOBAL ProjFsInstalled
    !insertmacro CheckProjFsInstalled $ProjFsInstalled

    ${If} $ProjFsInstalled == "0"
        ; Inform user that ProjFS is recommended but not required
        MessageBox MB_YESNO|MB_ICONQUESTION \
            "Parcela works best with Windows Projected File System (ProjFS) for virtual drive support.$\n$\n\
            ProjFS is not currently enabled. Would you like to see how to enable it?$\n$\n\
            You can enable ProjFS now or later. Parcela will continue to install either way." \
            IDYES show_projfs_info IDNO skip_projfs

        show_projfs_info:
            ; Show instructions for enabling ProjFS
            MessageBox MB_OK "To enable ProjFS, run this command in PowerShell (as Administrator):$\n$\n\
            Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS$\n$\n\
            You may need to restart Windows after enabling the feature.$\n$\n\
            The Parcela installation will now continue."
            ; Fall through to continue installation

        skip_projfs:
            ; Continue installation without ProjFS
    ${EndIf}
!macroend

; Called after installation completes
!macro NSIS_HOOK_POSTINSTALL
    ; Nothing to do here for now
!macroend


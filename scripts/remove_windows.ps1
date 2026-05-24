<#
.SYNOPSIS
    Removes the "ChatGPT Plus Free Trial" Info-Stealer (Deno-based) from Windows.

.DESCRIPTION
    This script:
    1. Detects and kills malware processes (Deno loader, port 2744 lock)
    2. Removes Run-Key persistence and Alpha29 registry markers
    3. Deletes malware payloads (.js stage 2, MSI installation folders)
    4. Uninstalls MSI products planted by the attacker
    5. Optionally removes Deno (if installed by malware)
    6. Generates a removal report on your Desktop

.NOTES
    READ THIS SCRIPT BEFORE RUNNING IT.
    Run as Administrator for full effectiveness.
    Source: https://github.com/YOUR-REPO/chatgpt-trial-stealer-analysis

.EXAMPLE
    # Dry run first (shows findings, deletes nothing):
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\remove_windows.ps1 -DryRun

    # Live removal:
    .\remove_windows.ps1

    # Also remove Deno (only if you did NOT install it yourself):
    .\remove_windows.ps1 -RemoveDeno
#>

[CmdletBinding()]
param(
    [switch]$RemoveDeno,
    [switch]$DryRun
)

$ErrorActionPreference = "Continue"
$findings = @()
$removed  = @()

function Write-Status($icon, $msg) {
    $color = switch ($icon) {
        "!!" { "Red" }
        "OK" { "Green" }
        "??" { "Yellow" }
        "--" { "Cyan" }
        default { "White" }
    }
    Write-Host "[$icon] " -ForegroundColor $color -NoNewline
    Write-Host $msg
}

function Add-Finding($category, $detail) {
    $script:findings += [PSCustomObject]@{ Category=$category; Detail=$detail }
    Write-Status "!!" "$category : $detail"
}

function Add-Removed($what) {
    $script:removed += $what
    Write-Status "OK" "Removed: $what"
}

# ════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "  ChatGPT Trial Stealer - Windows Removal Tool" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""
if ($DryRun) {
    Write-Status "--" "DRY-RUN mode: nothing will be deleted, findings only."
    Write-Host ""
}

# --- Known malware signatures ---
$malwareUrls       = @("ms-telemetry-gateway-us.com", "ms-telemetry-gateway", "acca66ea", "45.137.99.121")
$malwareJsPatterns = @("proxyUrls", "buildId", "ms-telemetry", "acca66ea", "Bearer eyJ", "2744")
$affiliateKeys     = @("Alpha29")
$msiProductNames   = @("kontakt8","autotune","autotuneplugin","zenology","finalcut","logicpro","echo_app")
$malwareBinaries   = @("claude","tbot","autotune","finalcut","logicpro","kontakt8","zenology")

# ──────────────────────────────────────────────────
# STEP 1: Detect and kill malware processes
# ──────────────────────────────────────────────────
Write-Status "--" "Step 1/6: Scanning for malware processes..."

# 1a. Deno processes with suspicious command lines
$denoProcs = Get-Process deno -ErrorAction SilentlyContinue
foreach ($p in $denoProcs) {
    try {
        $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)").CommandLine
    } catch { $cmd = "" }

    $suspicious = $false
    foreach ($sig in $malwareUrls) {
        if ($cmd -like "*$sig*") { $suspicious = $true; break }
    }
    if ($cmd -match 'deno.*-A.*https?://') { $suspicious = $true }
    if ($cmd -match 'deno.*-A.*\\[0-9a-f]{8,}\.js') { $suspicious = $true }

    if ($suspicious) {
        Add-Finding "Process" "deno.exe PID=$($p.Id) CMD=$cmd"
        if (-not $DryRun) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            Add-Removed "Process deno.exe PID=$($p.Id)"
        }
    }
}

# 1b. Port 2744 listener (malware single-instance lock)
$portCheck = netstat -ano 2>$null | Select-String ":2744\s.*LISTENING"
if ($portCheck) {
    $pid2744 = ($portCheck.ToString().Trim() -split '\s+')[-1]
    $procName = (Get-Process -Id $pid2744 -ErrorAction SilentlyContinue).ProcessName
    Add-Finding "Port lock" "TCP 2744 held by PID=$pid2744 ($procName)"
    if (-not $DryRun) {
        Stop-Process -Id $pid2744 -Force -ErrorAction SilentlyContinue
        Add-Removed "Port-2744 process PID=$pid2744"
    }
}

# 1c. Other known malware binary names
foreach ($name in $malwareBinaries) {
    $procs = Get-Process $name -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        Add-Finding "Process" "$name.exe PID=$($p.Id)"
        if (-not $DryRun) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            Add-Removed "Process $name.exe PID=$($p.Id)"
        }
    }
}

# ──────────────────────────────────────────────────
# STEP 2: Remove persistence mechanisms
# ──────────────────────────────────────────────────
Write-Status "--" "Step 2/6: Checking persistence (Run keys, registry)..."

# 2a. Run key entries
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
if (Test-Path $runKey) {
    $props = Get-ItemProperty $runKey
    $props.PSObject.Properties | Where-Object {
        $val = $_.Value
        ($val -like "*deno*" -and $val -like "*-A*") -or
        ($val -like "*ms-telemetry*") -or
        ($val -like "*acca66ea*") -or
        ($val -match '\\[0-9a-f]{8,}\.js')
    } | ForEach-Object {
        Add-Finding "Persistence" "Run key: $($_.Name) = $($_.Value)"
        if (-not $DryRun) {
            Remove-ItemProperty -Path $runKey -Name $_.Name -Force
            Add-Removed "Run key '$($_.Name)'"
        }
    }
}

# 2b. Affiliate registry markers
foreach ($key in $affiliateKeys) {
    $path = "HKCU:\Software\$key"
    if (Test-Path $path) {
        $subkeys = Get-ChildItem $path -ErrorAction SilentlyContinue
        Add-Finding "Registry" "Affiliate marker: $path (subkeys: $($subkeys.Count))"
        if (-not $DryRun) {
            Remove-Item $path -Recurse -Force
            Add-Removed "Registry key $path"
        }
    }
}

# 2c. Scheduled tasks
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $action = $_.Actions | Select-Object -ExpandProperty Execute -ErrorAction SilentlyContinue
    $args   = $_.Actions | Select-Object -ExpandProperty Arguments -ErrorAction SilentlyContinue
    ($action -like "*deno*") -or ($args -like "*ms-telemetry*") -or ($args -like "*acca66ea*")
}
foreach ($t in $tasks) {
    Add-Finding "Scheduled task" "$($t.TaskName) -> $($t.Actions.Execute) $($t.Actions.Arguments)"
    if (-not $DryRun) {
        Unregister-ScheduledTask -TaskName $t.TaskName -Confirm:$false
        Add-Removed "Scheduled task '$($t.TaskName)'"
    }
}

# ──────────────────────────────────────────────────
# STEP 3: Delete malware files
# ──────────────────────────────────────────────────
Write-Status "--" "Step 3/6: Scanning for malware files..."

$searchDirs = @($env:TEMP, $env:LOCALAPPDATA, "$env:LOCALAPPDATA\Temp", "$env:APPDATA", "$env:USERPROFILE\Downloads")
foreach ($dir in $searchDirs) {
    if (-not (Test-Path $dir)) { continue }

    # .js files containing malware patterns
    Get-ChildItem $dir -Filter "*.js" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Where-Object {
        $_.Length -gt 5000 -and $_.Length -lt 50000
    } | ForEach-Object {
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        $match = $false
        foreach ($pat in $malwareJsPatterns) {
            if ($content -match [regex]::Escape($pat)) { $match = $true; break }
        }
        if ($match) {
            Add-Finding "Payload" "$($_.FullName) ($($_.Length) bytes)"
            if (-not $DryRun) {
                Remove-Item $_.FullName -Force
                Add-Removed $_.FullName
            }
        }
    }

    # .cmd / .ps1 with malware signatures
    Get-ChildItem $dir -Include "*.cmd","*.ps1" -Recurse -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object {
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match "ms-telemetry|lima26|kilo_piece|Alpha29") {
            Add-Finding "Script" "$($_.FullName)"
            if (-not $DryRun) {
                Remove-Item $_.FullName -Force
                Add-Removed $_.FullName
            }
        }
    }
}

# MSI installation folders
foreach ($name in $msiProductNames) {
    foreach ($base in @($env:LOCALAPPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:APPDATA, $env:USERPROFILE)) {
        $path = Join-Path $base $name
        if (Test-Path $path) {
            Add-Finding "MSI folder" $path
            if (-not $DryRun) {
                Remove-Item $path -Recurse -Force
                Add-Removed "Folder $path"
            }
        }
    }
}

# Temp MSI from original installation
$tempMsi = Join-Path $env:TEMP "s.msi"
if (Test-Path $tempMsi) {
    Add-Finding "Installer" $tempMsi
    if (-not $DryRun) {
        Remove-Item $tempMsi -Force
        Add-Removed $tempMsi
    }
}

# ──────────────────────────────────────────────────
# STEP 4: Uninstall MSI products
# ──────────────────────────────────────────────────
Write-Status "--" "Step 4/6: Checking installed MSI products..."

try {
    $msiProducts = Get-CimInstance Win32_Product -ErrorAction SilentlyContinue | Where-Object {
        $msiProductNames -contains $_.Name -or $affiliateKeys -contains $_.Vendor
    }
    foreach ($prod in $msiProducts) {
        Add-Finding "MSI product" "$($prod.Name) by $($prod.Vendor)"
        if (-not $DryRun) {
            $prod | Invoke-CimMethod -MethodName Uninstall | Out-Null
            Add-Removed "MSI product '$($prod.Name)'"
        }
    }
} catch {
    Write-Status "??" "MSI query skipped (WMI unavailable)"
}

# ──────────────────────────────────────────────────
# STEP 5: Remove Deno (optional)
# ──────────────────────────────────────────────────
if ($RemoveDeno) {
    Write-Status "--" "Step 5/6: Removing Deno installation..."

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget uninstall DenoLand.Deno --silent 2>$null | Out-Null
        Add-Removed "Deno via WinGet"
    }

    if (Get-Command scoop -ErrorAction SilentlyContinue) {
        scoop uninstall deno 2>$null | Out-Null
        Add-Removed "Deno via Scoop"
    }

    $denoPaths = @(
        "$env:USERPROFILE\.deno",
        "$env:LOCALAPPDATA\deno",
        "$env:LOCALAPPDATA\Programs\deno"
    )
    foreach ($dp in $denoPaths) {
        if (Test-Path $dp) {
            if (-not $DryRun) {
                Remove-Item $dp -Recurse -Force
                Add-Removed "Folder $dp"
            } else {
                Add-Finding "Deno remnant" $dp
            }
        }
    }

    # WinGet packages
    $wingetDeno = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Filter "DenoLand*" -Recurse -ErrorAction SilentlyContinue
    foreach ($d in $wingetDeno) {
        Add-Finding "Deno (WinGet)" $d.FullName
        if (-not $DryRun) {
            Remove-Item $d.FullName -Recurse -Force
            Add-Removed $d.FullName
        }
    }
} else {
    Write-Status "--" "Step 5/6: Deno removal skipped (use -RemoveDeno to enable)"
}

# ──────────────────────────────────────────────────
# STEP 6: Report
# ──────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Results" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($findings.Count -eq 0) {
    Write-Status "OK" "No malware traces found. Your system appears clean."
    Write-Host ""
    Write-Host "If you ran the scam command but nothing was found:"
    Write-Host "  - The malware may have already exfiltrated data before cleaning up"
    Write-Host "  - Change ALL your passwords anyway (see README.md)"
    Write-Host ""
} else {
    Write-Host "Found: $($findings.Count) indicators" -ForegroundColor Yellow
    if ($DryRun) {
        Write-Host "(DRY-RUN: nothing was deleted. Run without -DryRun to clean up.)" -ForegroundColor Yellow
    } else {
        Write-Host "Removed: $($removed.Count) items" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "IMPORTANT — even after removal:" -ForegroundColor Red
    Write-Host "  1. Change ALL browser-saved passwords" -ForegroundColor Red
    Write-Host "  2. Revoke Discord/Telegram sessions" -ForegroundColor Red
    Write-Host "  3. Move crypto funds to a NEW wallet" -ForegroundColor Red
    Write-Host "  4. Cancel credit cards stored in browser" -ForegroundColor Red
    Write-Host "  5. Enable 2FA everywhere" -ForegroundColor Red
    Write-Host ""
}

# Save report to desktop
$reportPath = Join-Path $env:USERPROFILE "Desktop\stealer_removal_report.txt"
$report = @()
$report += "=== ChatGPT Trial Stealer - Removal Report ==="
$report += "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$report += "Mode: $(if ($DryRun) {'DRY-RUN'} else {'LIVE'})"
$report += ""
$report += "--- Findings ---"
foreach ($f in $findings) { $report += "$($f.Category): $($f.Detail)" }
if (-not $DryRun) {
    $report += ""
    $report += "--- Removed ---"
    foreach ($r in $removed) { $report += $r }
}
$report | Out-File $reportPath -Encoding UTF8
Write-Status "--" "Report saved: $reportPath"
Write-Host ""

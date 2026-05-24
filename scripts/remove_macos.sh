#!/bin/bash
# ============================================================
#  ChatGPT Trial Stealer — macOS Removal Tool
# ============================================================
#
#  Removes the "ChatGPT Plus Free Trial" info-stealer:
#    1. Kills stealer processes
#    2. Deletes malware binaries from TMPDIR, Downloads, Desktop
#    3. Removes LaunchAgent/Daemon persistence
#    4. Checks crontab and shell profiles for injection
#    5. Checks active network connections to known C2 servers
#    6. Optionally removes Deno (if installed by the malware)
#    7. Generates a removal report on your Desktop
#
#  Usage:
#    chmod +x remove_macos.sh
#
#    # Dry run first (shows findings, deletes nothing):
#    sudo ./remove_macos.sh --dry-run
#
#    # Live removal:
#    sudo ./remove_macos.sh
#
#    # Also remove Deno (only if you did NOT install it yourself):
#    sudo ./remove_macos.sh --remove-deno
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DRY_RUN=false
REMOVE_DENO=false
FINDINGS=0
REMOVED=0
REPORT=""

for arg in "$@"; do
    case "$arg" in
        --dry-run)     DRY_RUN=true ;;
        --remove-deno) REMOVE_DENO=true ;;
        -h|--help)
            echo "Usage: sudo $0 [--dry-run] [--remove-deno]"
            echo "  --dry-run      Show findings without deleting anything"
            echo "  --remove-deno  Also uninstall Deno (skip if you use it legitimately)"
            exit 0 ;;
    esac
done

log_find()  { FINDINGS=$((FINDINGS+1)); echo -e "${RED}[!!]${NC} $1: $2"; REPORT="$REPORT\nFOUND: $1 — $2"; }
log_ok()    { REMOVED=$((REMOVED+1));   echo -e "${GREEN}[OK]${NC} Removed: $1"; REPORT="$REPORT\nREMOVED: $1"; }
log_info()  { echo -e "${CYAN}[--]${NC} $1"; }
log_clean() { echo -e "${GREEN}[OK]${NC} $1"; }

echo ""
echo -e "${RED}============================================================${NC}"
echo -e "${RED}  ChatGPT Trial Stealer — macOS Removal Tool${NC}"
echo -e "${RED}============================================================${NC}"
echo ""
if $DRY_RUN; then
    log_info "DRY-RUN mode: nothing will be deleted, findings only."
    echo ""
fi

# --- Known malware signatures ---
MALWARE_NAMES="claude tbot autotune finalcut logicpro kontakt8 zenology"
MALWARE_IPS="45.137.99.121"
MALWARE_DOMAINS="ms-telemetry-gateway-us.com ms-telemetry-gateway"
MALWARE_PATTERNS="ms-telemetry|45\.137\.99|acca66ea|proxyUrls|buildId|Alpha29"

# Real user (even when run with sudo)
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")

# ──────────────────────────────────────────────────
# STEP 1: Kill malware processes
# ──────────────────────────────────────────────────
log_info "Step 1/6: Scanning for malware processes..."

for name in $MALWARE_NAMES; do
    pids=$(pgrep -f "$name" 2>/dev/null | grep -v "$$" || true)
    if [ -n "$pids" ]; then
        for pid in $pids; do
            cmdline=$(ps -p "$pid" -o args= 2>/dev/null || true)
            # Don't kill ourselves
            if echo "$cmdline" | grep -q "remove_macos"; then continue; fi
            log_find "Process" "$name (PID $pid) — $cmdline"
            if ! $DRY_RUN; then
                kill -9 "$pid" 2>/dev/null && log_ok "Process $name PID $pid"
            fi
        done
    fi
done

# Deno processes with suspicious command lines
deno_pids=$(pgrep -f "deno.*-A" 2>/dev/null || true)
for pid in $deno_pids; do
    cmdline=$(ps -p "$pid" -o args= 2>/dev/null || true)
    if echo "$cmdline" | grep -qE "$MALWARE_PATTERNS"; then
        log_find "Process" "deno (PID $pid) — $cmdline"
        if ! $DRY_RUN; then
            kill -9 "$pid" 2>/dev/null && log_ok "Deno process PID $pid"
        fi
    fi
done

# Port 2744 (malware single-instance lock)
port_pid=$(lsof -ti tcp:2744 2>/dev/null || true)
if [ -n "$port_pid" ]; then
    port_name=$(ps -p "$port_pid" -o comm= 2>/dev/null || echo "unknown")
    log_find "Port lock" "TCP 2744 held by PID $port_pid ($port_name)"
    if ! $DRY_RUN; then
        kill -9 "$port_pid" 2>/dev/null && log_ok "Port-2744 process PID $port_pid"
    fi
fi

# ──────────────────────────────────────────────────
# STEP 2: Delete malware files
# ──────────────────────────────────────────────────
log_info "Step 2/6: Scanning for malware files..."

# 2a. Known binary names in typical directories
SEARCH_DIRS="$TMPDIR $REAL_HOME $REAL_HOME/Desktop $REAL_HOME/Downloads /tmp /var/tmp"
for dir in $SEARCH_DIRS; do
    [ -d "$dir" ] || continue
    for name in $MALWARE_NAMES; do
        filepath="$dir/$name"
        if [ -f "$filepath" ]; then
            filetype=$(file "$filepath" 2>/dev/null || echo "unknown")
            log_find "Malware binary" "$filepath ($filetype)"
            if ! $DRY_RUN; then
                rm -f "$filepath" && log_ok "$filepath"
            fi
        fi
    done
done

# 2b. Suspicious .js files (stage 2 payload)
find "$TMPDIR" "$REAL_HOME" /tmp -maxdepth 3 -name "*.js" -size +5k -size -50k 2>/dev/null | while read -r jsfile; do
    if grep -qlE "$MALWARE_PATTERNS" "$jsfile" 2>/dev/null; then
        log_find "JS payload" "$jsfile"
        if ! $DRY_RUN; then
            rm -f "$jsfile" && log_ok "$jsfile"
        fi
    fi
done

# 2c. Shell scripts from the GitHub lure
find "$TMPDIR" "$REAL_HOME/Downloads" /tmp -maxdepth 2 -name "*.sh" -size +100c -size -10k 2>/dev/null | while read -r shfile; do
    if grep -qlE "(45\.137\.99|ms-telemetry|xattr -c.*(claude|tbot|autotune))" "$shfile" 2>/dev/null; then
        log_find "Installer script" "$shfile"
        if ! $DRY_RUN; then
            rm -f "$shfile" && log_ok "$shfile"
        fi
    fi
done

# ──────────────────────────────────────────────────
# STEP 3: Remove LaunchAgent / Daemon persistence
# ──────────────────────────────────────────────────
log_info "Step 3/6: Checking LaunchAgents and LaunchDaemons..."

LAUNCH_DIRS=(
    "$REAL_HOME/Library/LaunchAgents"
    "/Library/LaunchAgents"
    "/Library/LaunchDaemons"
)

for dir in "${LAUNCH_DIRS[@]}"; do
    [ -d "$dir" ] || continue
    find "$dir" -name "*.plist" 2>/dev/null | while read -r plist; do
        if grep -qlE "$MALWARE_PATTERNS" "$plist" 2>/dev/null; then
            log_find "LaunchAgent" "$plist"
            echo "    Matching lines:"
            grep -E "$MALWARE_PATTERNS" "$plist" | head -5 | sed 's/^/      /'
            if ! $DRY_RUN; then
                launchctl unload "$plist" 2>/dev/null || true
                rm -f "$plist" && log_ok "$plist"
            fi
        fi
        # Also check for Deno executions in plists
        if grep -qlE "deno.*-A" "$plist" 2>/dev/null; then
            log_find "Deno LaunchAgent" "$plist"
            if ! $DRY_RUN; then
                launchctl unload "$plist" 2>/dev/null || true
                rm -f "$plist" && log_ok "$plist"
            fi
        fi
    done
done

# Login Items hint
log_info "Also check Login Items manually: System Settings > General > Login Items"
log_info "Remove anything you don't recognize."

# ──────────────────────────────────────────────────
# STEP 4: Check crontab and shell profiles
# ──────────────────────────────────────────────────
log_info "Step 4/6: Checking crontab and shell profiles..."

# Crontab
crontab_content=$(sudo -u "$REAL_USER" crontab -l 2>/dev/null || true)
if echo "$crontab_content" | grep -qE "$MALWARE_PATTERNS"; then
    log_find "Crontab" "Suspicious entries found!"
    echo "$crontab_content" | grep -E "$MALWARE_PATTERNS" | sed 's/^/      /'
    echo ""
    echo -e "    ${YELLOW}Remove manually: sudo -u $REAL_USER crontab -e${NC}"
    REPORT="$REPORT\nWARNING: Crontab entries must be removed manually."
else
    log_clean "Crontab is clean."
fi

# Shell profiles
for profile in "$REAL_HOME/.bash_profile" "$REAL_HOME/.bashrc" "$REAL_HOME/.zshrc" "$REAL_HOME/.zprofile" "$REAL_HOME/.profile"; do
    [ -f "$profile" ] || continue
    if grep -qE "$MALWARE_PATTERNS" "$profile" 2>/dev/null; then
        log_find "Shell profile" "$profile"
        echo "    Suspicious lines:"
        grep -nE "$MALWARE_PATTERNS" "$profile" | sed 's/^/      /'
        echo ""
        echo -e "    ${YELLOW}Remove manually: nano $profile${NC}"
        echo "    (Delete the lines shown above)"
        REPORT="$REPORT\nWARNING: $profile contains injected lines — remove manually."
    else
        log_clean "$profile is clean."
    fi
done

# ──────────────────────────────────────────────────
# STEP 5: Check active C2 connections
# ──────────────────────────────────────────────────
log_info "Step 5/6: Checking active network connections to known C2 servers..."

for ip in $MALWARE_IPS; do
    connections=$(lsof -i "@$ip" 2>/dev/null || true)
    if [ -n "$connections" ]; then
        log_find "Active connection" "Connection to $ip detected!"
        echo "$connections" | sed 's/^/      /'
    fi
done

for domain in $MALWARE_DOMAINS; do
    dns_check=$(lsof -i -n 2>/dev/null | grep -i "$domain" || true)
    if [ -n "$dns_check" ]; then
        log_find "Active connection" "Connection to $domain detected!"
    fi
done
log_clean "No active C2 connections found."

# ──────────────────────────────────────────────────
# STEP 6: Remove Deno (optional)
# ──────────────────────────────────────────────────
if $REMOVE_DENO; then
    log_info "Step 6/6: Removing Deno installation..."

    # Homebrew
    if command -v brew &>/dev/null; then
        if brew list deno &>/dev/null 2>&1; then
            if ! $DRY_RUN; then
                sudo -u "$REAL_USER" brew uninstall deno 2>/dev/null && log_ok "Deno via Homebrew"
            else
                log_find "Deno" "Installed via Homebrew"
            fi
        fi
    fi

    # Standard install directory
    DENO_DIR="$REAL_HOME/.deno"
    if [ -d "$DENO_DIR" ]; then
        log_find "Deno" "Install directory: $DENO_DIR"
        if ! $DRY_RUN; then
            rm -rf "$DENO_DIR" && log_ok "$DENO_DIR"
        fi
    fi

    log_info "If Deno is in your PATH, remove the corresponding line from your shell profile."
else
    log_info "Step 6/6: Deno removal skipped (use --remove-deno to enable)"
fi

# ──────────────────────────────────────────────────
# Results
# ──────────────────────────────────────────────────
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  Results${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

if [ "$FINDINGS" -eq 0 ]; then
    log_clean "No malware traces found. Your system appears clean."
    echo ""
    echo "If you ran the scam command but nothing was found:"
    echo "  - The malware may have already exfiltrated your data"
    echo "  - Change ALL your passwords anyway (see README.md)"
    echo ""
else
    echo -e "Found: ${YELLOW}$FINDINGS indicators${NC}"
    if $DRY_RUN; then
        echo -e "${YELLOW}(DRY-RUN: nothing was deleted. Run without --dry-run to clean up.)${NC}"
    else
        echo -e "Removed: ${GREEN}$REMOVED items${NC}"
    fi
    echo ""
    echo -e "${RED}IMPORTANT — even after removal:${NC}"
    echo -e "${RED}  1. Change ALL browser-saved passwords${NC}"
    echo -e "${RED}  2. Revoke Discord / Telegram sessions${NC}"
    echo -e "${RED}  3. Move crypto funds to a NEW wallet${NC}"
    echo -e "${RED}  4. Cancel credit cards saved in browser${NC}"
    echo -e "${RED}  5. Enable 2FA everywhere${NC}"
    echo ""
fi

# Save report to desktop
REPORT_FILE="$REAL_HOME/Desktop/stealer_removal_report.txt"
{
    echo "=== ChatGPT Trial Stealer — Removal Report ==="
    echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Mode: $(if $DRY_RUN; then echo 'DRY-RUN'; else echo 'LIVE'; fi)"
    echo ""
    echo "--- Details ---"
    echo -e "$REPORT"
} > "$REPORT_FILE"
chown "$REAL_USER" "$REPORT_FILE" 2>/dev/null || true
log_info "Report saved: $REPORT_FILE"
echo ""

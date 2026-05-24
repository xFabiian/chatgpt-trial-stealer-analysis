/*
 * YARA Rule — ChatGPT Trial Stealer (Cross-Platform Info-Stealer)
 *
 * Covers:
 *   - macOS Mach-O stealer binaries (claude, tbot, autotune, etc.)
 *   - Windows Deno-based JS loader (obfuscated)
 *   - PowerShell stage scripts (lima26.ps1 pattern)
 *
 * Author: Security Research — CC0 1.0
 * Date:   2026-05-24
 * Ref:    https://github.com/YOUR-USERNAME/chatgpt-trial-stealer-analysis
 */

rule ChatGPT_Trial_Stealer_MacOS_Binary {
    meta:
        description = "Detects the Mach-O stealer binary dropped by the ChatGPT Plus Free Trial scam"
        author = "Security Research"
        date = "2026-05-24"
        hash_claude   = "062d5fc1cfa93e0ad53c985c896017c72acc9e22c889ba3b43c9e238d6d9721d"
        hash_tbot     = "8fe79f33e0d7e01a6c269fdf06a09c918ed66651d92bd5e2da4f8777ca8fd28c"
        hash_autotune = "086cb1b17b6e2a2b57651448026d2e7d9af7d463a1374c59ca407bc3f6222abc"
        platform = "macOS"
        filetype = "Mach-O"
    strings:
        $macho_hdr_x86 = { CF FA ED FE }  // Mach-O x86_64 magic
        $macho_hdr_arm = { CE FA ED FE }  // Mach-O arm64 magic
        $macho_uni     = { CA FE BA BE }  // Universal binary (fat) magic

        // CommonCrypto APIs used by the stealer
        $cc_crypt   = "CCCrypt"    ascii wide
        $cc_pbkdf   = "CCKeyDerivationPBKDF" ascii wide

        // Revealing function imports
        $popen      = "_popen"    ascii
        $system     = "_system"   ascii
        $fork       = "_fork"     ascii
        $setsid     = "_setsid"   ascii
        $getpwuid   = "_getpwuid" ascii

        // Filesystem iteration
        $fs_iter    = "recursive_directory_iterator" ascii wide

        // Suspicious: extremely small __cstring section
        // (we detect by absence — the strings below should be sparse)

        // C2-related strings (encrypted at rest, may appear partially)
        $curl_cmd   = "curl"      ascii wide
        $tmp_prefix = "/tmp/"     ascii

    condition:
        // Must be Mach-O
        any of ($macho_hdr_*) and
        // Must have BOTH CommonCrypto AND process-creation APIs
        (all of ($cc_*) and all of ($popen, $fork, $setsid)) and
        // Filesystem iteration confirms directory crawling
        $fs_iter
}

rule ChatGPT_Trial_Stealer_Windows_JSLoader {
    meta:
        description = "Detects the obfuscated Deno-based Stage 2 JavaScript loader"
        author = "Security Research"
        date = "2026-05-24"
        hash_loader = "eefdd9558952183ed3d02a3e277fb8de410e73f08b9508e31642eefc033869f5"
        platform = "Windows"
        filetype = "JavaScript (obfuscated)"
    strings:
        // C2 domain and identifiers (these survive obfuscation)
        $c2_domain  = "ms-telemetry-gateway-us.com" ascii wide
        $c2_ip      = "45.137.99.121" ascii wide
        $build_id   = "acca66ea4f9f6efe" ascii wide
        $user_id    = "600bf5e68c9cf61a" ascii wide
        $user_note  = "alex" ascii wide nocase

        // Deno-specific patterns
        $deno_allow = "-A" ascii
        $deno_run   = "Deno.run" ascii wide
        $deno_listen = "Deno.listen" ascii wide

        // Persistence mechanism
        $run_key    = "CurrentVersion\\\\Run" ascii wide
        $powershell = "powershell" ascii wide nocase

        // JWT-related
        $bearer     = "Bearer eyJ" ascii wide
        $auth_header = "Authorization" ascii wide

        // obfuscator.io fingerprint
        $obf_state  = "function _0x" ascii
        $obf_array  = "_0x" ascii

        // Port lock
        $port_2744  = "2744" ascii

        // Network patterns
        $proxy_urls = "proxyUrls" ascii wide
        $fetch_call = "fetch(" ascii wide
        $post_method = "\"POST\"" ascii wide

    condition:
        // Detect by C2 identifiers + Deno patterns
        (any of ($c2_*) or $build_id or $user_id) and
        (any of ($deno_*) or $run_key) and
        filesize < 50KB
}

rule ChatGPT_Trial_Stealer_PowerShell_Stage1 {
    meta:
        description = "Detects the PowerShell script that installs Deno and launches the Stage 2 loader"
        author = "Security Research"
        date = "2026-05-24"
        platform = "Windows"
        filetype = "PowerShell"
    strings:
        // Execution policy bypass
        $exec_bypass1 = "Set-ExecutionPolicy" ascii wide nocase
        $exec_bypass2 = "ExecutionPolicy Bypass" ascii wide nocase

        // Scoop installation
        $scoop_install = "get.scoop.sh" ascii wide nocase
        $scoop_cmd     = "scoop install" ascii wide nocase

        // Deno installation via WinGet
        $winget_deno   = "DenoLand.Deno" ascii wide nocase
        $winget_install = "winget install" ascii wide nocase

        // Stage 2 launch
        $deno_flag     = "-A" ascii
        $c2_url        = "ms-telemetry-gateway-us.com" ascii wide

    condition:
        // Must combine Scoop + Deno + C2 URL
        (any of ($scoop_*)) and
        (any of ($winget_*) or any of ($deno_*)) and
        $c2_url
}

rule ChatGPT_Trial_Stealer_MSI_Installer {
    meta:
        description = "Detects MSI installers used as Windows delivery mechanism"
        author = "Security Research"
        date = "2026-05-24"
        platform = "Windows"
        filetype = "MSI"
    strings:
        // MSI author/vendor fingerprint
        $author_alpha = "Alpha29" ascii wide
        $subject_echo = "echo_app" ascii wide

        // NATO phonetic naming in custom actions
        $cmd_lima     = "lima" ascii wide nocase
        $cmd_kilo     = "kilo" ascii wide nocase

        // msitools fingerprint (Linux build toolchain)
        $msitools     = "msitools" ascii wide

        // Custom action invocation
        $custom_action = "RunLauncher" ascii wide

    condition:
        // MSI magic + Alpha29 author + msitools
        ($author_alpha or $subject_echo) and
        (any of ($cmd_lima, $cmd_kilo))
}

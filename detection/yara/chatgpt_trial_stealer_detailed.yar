/*
 * YARA Rules — ChatGPT Trial Stealer (Detailed Code-Level Detection)
 *
 * Detailed rules for security researchers covering:
 *   - Stage 2 JS loader (obfuscated code patterns)
 *   - PowerShell Stage 1.5 (lima26.ps1 — Deno installation)
 *   - CMD Stage 1.2 (kilo_piece66.cmd — MSI Custom Action)
 *   - JWT authentication tokens
 *   - obfuscator.io fingerprint patterns
 *   - C2 communication patterns
 *   - Generic MaaS (Malware-as-a-Service) patterns
 *
 * Author: Security Research — CC0 1.0
 * Date:   2026-05-24
 * Ref:    https://github.com/xFabiian/chatgpt-trial-stealer-analysis
 */

/* ====================================================================
   STAGE 2 — Deno JS Loader (Detailed Obfuscated Code Detection)
   ==================================================================== */

rule ChatGPT_Stealer_JSLoader_Obfuscated {
    meta:
        description = "Detects the obfuscated Stage 2 JS loader by obfuscator.io fingerprints + C2 identifiers"
        author = "Security Research"
        date = "2026-05-24"
        hash = "eefdd9558952183ed3d02a3e277fb8de410e73f08b9508e31642eefc033869f5"
        platform = "Windows"
        filetype = "JavaScript"
        stage = "2"
    strings:
        // === obfuscator.io fingerprints ===
        $obf_func1    = "function _0x" ascii
        $obf_func2    = "var _0x" ascii
        $obf_state    = "['state']" ascii
        $obf_node     = "['node']" ascii
        $obf_array_rw = "function _0x" ascii wide
        $obf_rotate   = "push" ascii
        $obf_string_fn = "_0x" ascii

        // === C2 domain (survives obfuscation) ===
        $c2_domain    = "ms-telemetry-gateway-us.com" ascii wide
        $c2_domain_b64 = "bXMtdGVsZW1ldHJ5" ascii  // base64 of "ms-telemetry"

        // === Deno runtime API calls (partially obfuscated) ===
        $deno_read    = "readFile" ascii
        $deno_write   = "writeFile" ascii
        $deno_run     = "Deno.run" ascii wide
        $deno_listen  = "Deno.listen" ascii wide
        $deno_connect  = "Deno.connect" ascii wide
        $deno_env     = "Deno.env" ascii wide
        $deno_hostname = "hostname" ascii wide
        $deno_release = "release" ascii wide
        $deno_totalmem = "totalmem" ascii wide
        $deno_username = "username" ascii wide

        // === Persistence mechanism ===
        $reg_run_key  = "CurrentVersion" ascii wide
        $reg_run_sub  = "\\Run" ascii
        $ps_command   = "powershell" ascii wide nocase
        $ps_nologo    = "-NoLogo" ascii
        $ps_hidden    = "Hidden" ascii wide nocase

        // === JWT / Auth ===
        $jwt_bearer   = "Bearer eyJ" ascii wide
        $jwt_alg      = "HS256" ascii wide
        $auth_header  = "Authorization" ascii wide
        $module_id    = "x-module-id" ascii wide
        $machine_name = "x-machine-name" ascii wide
        $user_name_h  = "x-user-name" ascii wide

        // === Network patterns ===
        $fetch_call   = "fetch(" ascii wide
        $method_post  = "POST" ascii wide
        $method_get   = "GET" ascii wide
        $health_ep    = "/health" ascii wide
        $auth_ep      = "/auth/" ascii wide

        // === Port lock ===
        $port_2744    = "2744" ascii

        // === File operations ===
        $temp_path    = "Temp" ascii wide
        $hash_js      = ".js" ascii
        $localappdata = "LOCALAPPDATA" ascii wide nocase
        $appdata      = "APPDATA" ascii wide nocase

        // === Machine fingerprint ===
        $fingerprint  = "machine-id" ascii wide nocase
        $os_release   = "osRelease" ascii wide nocase
        $total_mem    = "totalMem" ascii wide nocase
        $os_uptime    = "uptime" ascii wide

    condition:
        // Must be obfuscated JS with C2 connection
        ($obf_func1 and $obf_func2) and
        (
            // C2 domain present
            $c2_domain or
            // OR: Deno API calls + persistence
            (any of ($deno_*) and $reg_run_key and $ps_command) or
            // OR: JWT auth + network
            ($jwt_bearer and any of ($auth_header, $module_id))
        ) and
        // File size range for Stage 2 loader (~16-20 KB)
        filesize > 5KB and filesize < 50KB
}

/* ====================================================================
   STAGE 2 — Deno JS Loader (Deobfuscated Logic Patterns)
   For researchers analyzing deobfuscated code
   ==================================================================== */

rule ChatGPT_Stealer_JSLoader_Logic {
    meta:
        description = "Detects the deobfuscated JS loader logic patterns (function names, control flow)"
        author = "Security Research"
        date = "2026-05-24"
        platform = "Windows"
        filetype = "JavaScript"
        stage = "2"
        analysis_type = "deobfuscated"
    strings:
        // === Build configuration ===
        $build_id     = "acca66ea4f9f6efe" ascii wide
        $build_type   = "msi" ascii wide nocase
        $build_note   = "kontakt8" ascii wide nocase
        $user_note    = "alex" ascii wide nocase
        $user_id      = "600bf5e68c9cf61a" ascii wide

        // === JWT structure ===
        $jwt_header   = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ascii wide  // base64({"alg":"HS256","typ":"JWT"})
        $access_hash  = "ba568b6bf32be2e10623622a7d6c327d20835524ed4f2dadd1c6d2e3b0d547d9" ascii wide
        $iat_value    = "1778944316" ascii wide  // 2026-05-16
        $exp_value    = "2094520316" ascii wide  // 2036

        // === Proxy / Gateway ===
        $proxy_url    = "proxyUrls" ascii wide nocase
        $proxy_array  = "[\"http://" ascii wide
        $gateway_us   = "gateway-us" ascii wide nocase

        // === Stage 3 execution ===
        $stage3_exec  = "--allow-all" ascii wide nocase
        $stage3_nocheck = "--no-check" ascii wide nocase
        $stage3_reload = "--reload" ascii wide nocase
        $stage3_run   = "deno run" ascii wide nocase

        // === Loop / Heartbeat ===
        $sleep_15s    = "16121" ascii wide  // ~15s sleep between iterations
        $interval_ms  = "setTimeout" ascii wide
        $sleep_fn     = "sleep" ascii wide nocase
        $delay_ms     = "delay" ascii wide nocase

        // === Single instance lock ===
        $port_lock    = "EADDRINUSE" ascii wide
        $listen_fail  = "Address already in use" ascii wide nocase

        // === Fingerprinting ===
        $hash_16char  = "substring" ascii wide
        $machine_hash = "machineId" ascii wide nocase

    condition:
        // JWT tokens OR build identifiers + Deno execution
        (
            ($jwt_header and $access_hash) or
            ($build_id and $user_id) or
            ($build_type and $build_note and $user_note)
        ) and
        (
            $proxy_url or
            $stage3_exec or
            $port_lock
        )
}

/* ====================================================================
   STAGE 1.5 — PowerShell Script (lima26.ps1 Detailed)
   ==================================================================== */

rule ChatGPT_Stealer_PowerShell_Detailed {
    meta:
        description = "Detects the lima26.ps1 Stage 1.5 script with high confidence"
        author = "Security Research"
        date = "2026-05-24"
        platform = "Windows"
        filetype = "PowerShell"
        stage = "1.5"
    strings:
        // === Execution policy bypass ===
        $exec_policy  = "Set-ExecutionPolicy" ascii wide nocase
        $exec_scope   = "Scope CurrentUser" ascii wide nocase
        $exec_force   = "-Force" ascii wide

        // === Scoop shim path ===
        $scoop_shims  = "scoop\\shims" ascii wide
        $scoop_path   = "scoop.sh" ascii wide nocase
        $scoop_irm    = "irm get.scoop.sh" ascii wide nocase
        $scoop_iex    = "iex" ascii wide nocase
        $scoop_admin  = "RunAsAdmin" ascii wide nocase

        // === Scoop install chain ===
        $scoop_winget = "scoop install winget" ascii wide nocase
        $scoop_deno   = "scoop install deno" ascii wide nocase

        // === WinGet Deno install ===
        $winget_id    = "--id DenoLand.Deno" ascii wide nocase
        $winget_exact = "-e" ascii wide
        $winget_accept_src = "--accept-source-agreements" ascii wide nocase
        $winget_accept_pkg = "--accept-package-agreements" ascii wide nocase
        $winget_silent = "--silent" ascii wide nocase

        // === Deno discovery ===
        $deno_command  = "Get-Command deno" ascii wide nocase
        $deno_source   = ".Source" ascii wide
        $deno_winget_path = "WinGet\\Packages" ascii wide nocase
        $deno_scoop_path  = "scoop" ascii wide nocase

        // === Final C2 execution ===
        $deno_exec    = "& $deno" ascii wide
        $deno_flag_a  = "-A" ascii
        $c2_url_full  = "http://ms-telemetry-gateway-us.com/" ascii wide nocase
        $c2_js_path   = ".js" ascii wide

        // === Path manipulation ===
        $path_prepend = "$env:Path = " ascii wide
        $env_scriptdir = "$env:SCRIPTDIR" ascii wide

    condition:
        // High-confidence detection: must combine ALL major stages
        ($exec_policy and $scoop_irm and $winget_id and $c2_url_full) and
        // AND at least one Deno discovery method
        (any of ($deno_command, $deno_winget_path, $deno_scoop_path))
}

/* ====================================================================
   STAGE 1.2 — CMD Batch Script (kilo_piece66.cmd)
   ==================================================================== */

rule ChatGPT_Stealer_CMD_Batch {
    meta:
        description = "Detects the kilo_piece66.cmd batch file from MSI Custom Action"
        author = "Security Research"
        date = "2026-05-24"
        platform = "Windows"
        filetype = "CMD/Batch"
        stage = "1.2"
    strings:
        // === Hidden PowerShell execution ===
        $ps_no_profile = "-NoProfile" ascii wide nocase
        $ps_exec_pol   = "ExecutionPolicy Bypass" ascii wide nocase
        $ps_window     = "WindowStyle Hidden" ascii wide nocase

        // === Process spawning ===
        $start_proc    = "Start-Process" ascii wide nocase
        $arg_list      = "-ArgumentList" ascii wide nocase

        // === SCRIPTDIR pattern ===
        $scriptdir_def = "%~dp0" ascii wide
        $scriptdir_env = "$env:SCRIPTDIR" ascii wide

        // === lima26.ps1 reference ===
        $lima_ref      = "lima26.ps1" ascii wide nocase

        // === Nested quotes pattern (specific to this malware) ===
        $nested_quotes = "\"\"'" ascii wide
        $file_concat   = "+ $env:SCRIPTDIR +" ascii wide

    condition:
        // Must have hidden PS + SCRIPTDIR + lima reference
        ($ps_no_profile and $ps_exec_pol and $ps_window) and
        ($start_proc and $scriptdir_def) and
        ($lima_ref and $file_concat) and
        filesize < 500
}

/* ====================================================================
   JWT Authentication Token Detection
   ==================================================================== */

rule ChatGPT_Stealer_JWT_Token {
    meta:
        description = "Detects the embedded JWT token used for C2 authentication"
        author = "Security Research"
        date = "2026-05-24"
        platform = "Cross-platform"
        filetype = "Any (looking for JWT strings)"
        category = "credential"
    strings:
        // === JWT Header (base64 encoded) ===
        $jwt_hdr_base64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ascii wide

        // === JWT Payload components (in JSON or base64) ===
        $payload_buildid  = "acca66ea4f9f6efe" ascii wide
        $payload_userid   = "600bf5e68c9cf61a" ascii wide
        $payload_buildnote = "kontakt8" ascii wide
        $payload_usernote = "alex" ascii wide
        $payload_iat      = "1778944316" ascii wide
        $payload_exp      = "2094520316" ascii wide

        // === JWT Signature ===
        $jwt_sig_base64   = "TU6PHxAow2ebqM3_oVgPLCJNbENiNBKqMEqLmwoJ5Ug" ascii wide

        // === HTTP Authorization header pattern ===
        $bearer_pattern   = "Bearer eyJhbGci" ascii wide
        $x_module_id      = "x-module-id" ascii wide nocase
        $x_machine_name   = "x-machine-name" ascii wide nocase
        $x_user_name      = "x-user-name" ascii wide nocase

        // === JSON structure (deobfuscated) ===
        $json_buildId     = "\"buildId\"" ascii wide
        $json_userId      = "\"userId\"" ascii wide
        $json_buildType   = "\"buildType\"" ascii wide
        $json_proxyUrls   = "\"proxyUrls\"" ascii wide
        $json_accessHash  = "\"accessTokenHash\"" ascii wide

    condition:
        // JWT header + at least 2 payload components
        $jwt_hdr_base64 and (
            ($payload_buildid and $payload_userid) or
            ($payload_buildid and $payload_iat) or
            ($payload_userid and $payload_usernote)
        ) and
        // OR: HTTP Authorization pattern
        (
            $bearer_pattern and ($x_module_id or $x_machine_name)
        )
}

/* ====================================================================
   C2 Communication Pattern Detection
   ==================================================================== */

rule ChatGPT_Stealer_C2_Communication {
    meta:
        description = "Detects C2 communication patterns in network captures or logged HTTP traffic"
        author = "Security Research"
        date = "2026-05-24"
        platform = "Cross-platform"
        filetype = "HTTP traffic / Log files"
        category = "network"
    strings:
        // === C2 Domains ===
        $c2_domain       = "ms-telemetry-gateway-us.com" ascii wide
        $c2_ip           = "45.137.99.121" ascii wide

        // === HTTP endpoints ===
        $endpoint_health = "GET /health" ascii wide
        $endpoint_auth   = "POST /auth/" ascii wide
        $endpoint_stage3 = ".js" ascii wide

        // === HTTP headers ===
        $header_bearer   = "Authorization: Bearer eyJ" ascii wide
        $header_module   = "x-module-id: " ascii wide nocase
        $header_machine  = "x-machine-name: " ascii wide nocase
        $header_user     = "x-user-name: " ascii wide nocase

        // === User-Agent patterns ===
        $useragent_deno  = "Deno/" ascii wide

        // === JSON response patterns ===
        $response_id     = "\"id\":" ascii wide
        $response_status = "\"status\":" ascii wide

        // === Drop server filenames ===
        $drop_claude     = "/claude" ascii wide
        $drop_tbot       = "/tbot" ascii wide
        $drop_autotune   = "/autotune" ascii wide
        $drop_finalcut   = "/finalcut" ascii wide
        $drop_logicpro   = "/logicpro" ascii wide
        $drop_kontakt8   = "/kontakt8" ascii wide
        $drop_zenology   = "/zenology" ascii wide

    condition:
        // C2 domain + at least one endpoint or header pattern
        ($c2_domain or $c2_ip) and (
            any of ($endpoint_*) or
            any of ($header_*) or
            $useragent_deno
        )
}

/* ====================================================================
   Generic MaaS (Malware-as-a-Service) Affiliate Pattern
   For detecting similar MaaS campaigns
   ==================================================================== */

rule Generic_MaaS_Affiliate_Pattern {
    meta:
        description = "Detects generic MaaS affiliate patterns (NATO naming, JWT auth, Deno loader)"
        author = "Security Research"
        date = "2026-05-24"
        platform = "Cross-platform"
        category = "generic"
        confidence = "low"
    strings:
        // === NATO phonetic naming convention ===
        $nato_alpha = "alpha" ascii wide nocase
        $nato_bravo = "bravo" ascii wide nocase
        $nato_charlie = "charlie" ascii wide nocase
        $nato_delta = "delta" ascii wide nocase
        $nato_echo  = "echo" ascii wide nocase
        $nato_foxtrot = "foxtrot" ascii wide nocase
        $nato_golf  = "golf" ascii wide nocase
        $nato_hotel = "hotel" ascii wide nocase
        $nato_india = "india" ascii wide nocase
        $nato_juliet = "juliet" ascii wide nocase
        $nato_kilo  = "kilo" ascii wide nocase
        $nato_lima  = "lima" ascii wide nocase
        $nato_mike  = "mike" ascii wide nocase
        $nato_november = "november" ascii wide nocase
        $nato_oscar = "oscar" ascii wide nocase
        $nato_papa  = "papa" ascii wide nocase
        $nato_quebec = "quebec" ascii wide nocase
        $nato_romeo = "romeo" ascii wide nocase
        $nato_sierra = "sierra" ascii wide nocase
        $nato_tango = "tango" ascii wide nocase
        $nato_uniform = "uniform" ascii wide nocase
        $nato_victor = "victor" ascii wide nocase
        $nato_whiskey = "whiskey" ascii wide nocase
        $nato_xray  = "xray" ascii wide nocase
        $nato_yankee = "yankee" ascii wide nocase
        $nato_zulu  = "zulu" ascii wide nocase

        // === Affiliate identifiers ===
        $affiliate_id = "userId" ascii wide nocase
        $affiliate_note = "userNote" ascii wide nocase

        // === Build identifiers ===
        $build_id_field = "buildId" ascii wide nocase
        $build_type_field = "buildType" ascii wide nocase
        $build_note_field = "buildNote" ascii wide nocase

        // === Deno execution ===
        $deno_exec_pattern = "deno.*-A" ascii wide nocase
        $deno_allow_all    = "--allow-all" ascii wide nocase

    condition:
        // Multiple NATO codewords in same file + affiliate/build identifiers
        (
            2 of ($nato_*) and
            ($affiliate_id or $build_id_field)
        ) and
        (
            $deno_exec_pattern or
            $build_type_field
        )
}

/* ====================================================================
   obfuscator.io Generic Detection
   For detecting any obfuscator.io-obfuscated JavaScript
   ==================================================================== */

rule Generic_obfuscator_io {
    meta:
        description = "Detects JavaScript obfuscated with obfuscator.io"
        author = "Security Research"
        date = "2026-05-24"
        platform = "Cross-platform"
        category = "generic"
        confidence = "high"
    strings:
        // === String array rotation ===
        $obf_string_array = "_0x" ascii
        $obf_hex_pattern  = "0x" ascii
        $obf_from_char_code = "fromCharCode" ascii
        $obf_string_fn    = "_0x" ascii wide

        // === Function structure ===
        $obf_function_def = "function _0x" ascii
        $obf_var_def      = "var _0x" ascii
        $obf_return_call  = "return _0x" ascii
        $obf_array_push   = ".push(" ascii

        // === Deobfuscation loop ===
        $obf_while_true   = "while (true)" ascii
        $obf_try_catch    = "try {" ascii
        $obf_break        = "break" ascii

        // === Character encoding ===
        $obf_atob         = "atob(" ascii wide
        $obf_btoa         = "btoa(" ascii wide
        $obf_decode       = "decode" ascii wide

    condition:
        // Multiple obfuscator.io indicators
        ($obf_string_array and $obf_function_def and $obf_from_char_code) and
        (
            $obf_while_true or
            $obf_try_catch or
            $obf_atob
        ) and
        // Must be JavaScript (file size and structure)
        filesize > 1KB and filesize < 500KB
}

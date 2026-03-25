/*
 * SPECTER C2 — Comprehensive Detection Rules
 *
 * These rules scan generated payloads for signatures that indicate
 * incomplete obfuscation, known C2 patterns, evasion artifacts, and
 * patterns that commercial AV/EDR products would flag.
 *
 * Severity levels:
 *   critical — CI build fails; payload must not ship
 *   high     — CI warns loudly; should be fixed before engagement
 *   medium   — CI warns; acceptable in some contexts
 *   info     — Informational; logged but no action required
 */

rule SPECTER_UnpatchedMarkers
{
    meta:
        description = "Detects SPECTER build markers that should have been scrubbed"
        severity = "critical"
        author = "SPECTER Team"

    strings:
        $marker1 = "SPECSTR"
        $marker2 = "SPECHASH"
        $marker3 = "SPECFLOW"
        $marker4 = "SPECCFGM"
        $marker5 = "SPECMGRD"
        $marker6 = "SPECHEAP"
        $marker7 = "SPECPICBLOB"
        $marker8 = "SPBF"
        $payload_marker = "SPECPAYLOADMARK"
        $config_magic = { 43 45 50 53 }  // "CEPS" — "SPEC" in little-endian = CONFIG_MAGIC default
        $config_marker = "CCCCCCCCCCCCCCCC"  // 16-byte config placeholder

    condition:
        any of them
}

rule SPECTER_C2Patterns
{
    meta:
        description = "Detects patterns common in C2 frameworks"
        severity = "high"
        author = "SPECTER Team"

    strings:
        $peb_walk = { 65 48 8B 04 25 60 00 00 00 }  // mov rax, gs:[0x60] — PEB access
        $syscall_gadget = { 0F 05 C3 }                // syscall; ret
        $djb2_init = { BD 05 15 00 00 }               // mov ebp, 5381 — DJB2 hash init
        $known_dll = "\\KnownDlls\\" wide

    condition:
        2 of them
}

rule SPECTER_EvasionStrings
{
    meta:
        description = "Detects evasion technique artifacts"
        severity = "medium"
        author = "SPECTER Team"

    strings:
        $etw1 = "EtwEventWrite" ascii wide
        $etw2 = "EtwEventWriteEx" ascii wide
        $amsi = "AmsiScanBuffer" ascii wide
        $ntdll_map = "ntdll.dll" ascii wide

    condition:
        3 of them
}

rule SPECTER_VendorDetection
{
    meta:
        description = "Patterns that commercial AV/EDR products would flag"
        severity = "info"
        author = "SPECTER Team"

    strings:
        $rwx_alloc = { 40 00 00 00 }       // PAGE_EXECUTE_READWRITE in little-endian
        $shellcode_marker = { CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC }  // INT3 sled / config marker
        $create_thread = { 4C 8D 0D }      // lea r9, [rip+...] — common in thread creation stubs

    condition:
        2 of them
}

rule SPECTER_KnownBadStrings
{
    meta:
        description = "Detects common strings that AV/EDR vendors flag"
        severity = "medium"
        author = "SPECTER Team"

    strings:
        $s1 = "This program cannot be run in DOS mode" ascii wide
        $s2 = "Invoke-Mimikatz" ascii wide nocase
        $s3 = "Invoke-Empire" ascii wide nocase

    condition:
        any of them
}

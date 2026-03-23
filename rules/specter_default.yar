/*
 * SPECTER C2 — Default YARA Rules
 *
 * These rules scan generated payloads before delivery. A match means the
 * payload contains a known-bad signature and should be regenerated with
 * different obfuscation settings or a different output format.
 *
 * Add custom rules to this directory. Files must have .yar or .yara extension.
 */

rule SPECTER_UnobfuscatedMarker
{
    meta:
        description = "Detects unobfuscated SPECTER build markers that should have been patched"
        severity = "high"
        author = "SPECTER Team"

    strings:
        $config_marker = "CCCCCCCCCCCCCCCC"
        $string_marker = "SPECSTR\x00"
        $hash_marker   = "SPECHASH"
        $cff_marker    = "SPECFLOW\x00"
        $payload_marker = "SPECPAYLOADMARK\x00"

    condition:
        any of them
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

param(
    [string]$OutputPath = "",
    [switch]$SkipPayloadScan
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceDir = Join-Path $RepoRoot "target\local-evidence"
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

if (-not $OutputPath) {
    $Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputPath = Join-Path $EvidenceDir "phase2-telemetry-evidence-$Stamp.md"
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$WorkingDirectory = $RepoRoot
    )

    $Start = Get-Date
    Push-Location $WorkingDirectory
    try {
        $PreviousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $RawOutput = & $FilePath @Arguments 2>&1
        $Output = ($RawOutput | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                $_.Exception.Message
            } else {
                $_.ToString()
            }
        }) -join [Environment]::NewLine
        $Code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PreviousErrorActionPreference
        Pop-Location
    }

    [pscustomobject]@{
        Name = $Name
        Command = "$FilePath $($Arguments -join ' ')"
        ExitCode = $Code
        DurationSeconds = [Math]::Round(((Get-Date) - $Start).TotalSeconds, 2)
        Output = $Output.TrimEnd()
    }
}

function Get-FirstCommand {
    param([Parameter(Mandatory = $true)][string[]]$Candidates)

    foreach ($Candidate in $Candidates) {
        $Resolved = Get-Command $Candidate -ErrorAction SilentlyContinue
        if ($Resolved) {
            return $Resolved.Source
        }
    }
    return $null
}

Set-Location $RepoRoot

$Results = New-Object System.Collections.Generic.List[object]

$Results.Add((Invoke-CheckedCommand `
    -Name "String key rotation tests" `
    -FilePath "cargo" `
    -Arguments @("test", "-p", "specter-server", "builder::obfuscation::tests::test_string_key_rotation", "--lib")))

$Results.Add((Invoke-CheckedCommand `
    -Name "API hash randomization tests" `
    -FilePath "cargo" `
    -Arguments @("test", "-p", "specter-server", "builder::obfuscation::tests::test_api_hash_randomization", "--lib")))

$Results.Add((Invoke-CheckedCommand `
    -Name "Junk padding replacement tests" `
    -FilePath "cargo" `
    -Arguments @("test", "-p", "specter-server", "builder::obfuscation::tests::test_junk_code", "--lib")))

$Results.Add((Invoke-CheckedCommand `
    -Name "DJB2 salt behavior tests" `
    -FilePath "cargo" `
    -Arguments @("test", "-p", "specter-server", "builder::obfuscation::tests::test_djb2_hash_different_salts", "--lib")))

$Python = Get-FirstCommand @("python", "python3")
if ($Python) {
    $Results.Add((Invoke-CheckedCommand `
        -Name "Implant hash constant audit" `
        -FilePath $Python `
        -Arguments @("implant/scripts/audit_hashes.py")))
}

$Pic = Join-Path $RepoRoot "implant\build\specter.bin"
$PayloadScanPath = Join-Path $EvidenceDir "phase2-payload-marker-scan.bin"
$PayloadFacts = @()
if (Test-Path $Pic) {
    $PicItem = Get-Item $Pic
    $PicHash = (Get-FileHash -Algorithm SHA256 $Pic).Hash
    $PayloadFacts += "- Current PIC: implant/build/specter.bin"
    $PayloadFacts += "- Current PIC size: $($PicItem.Length) bytes"
    $PayloadFacts += "- Current PIC SHA256: $PicHash"

    if (-not $SkipPayloadScan) {
        $Results.Add((Invoke-CheckedCommand `
            -Name "Payload builder marker/YARA scan" `
            -FilePath "cargo" `
            -Arguments @(
                "run", "-p", "specter-server", "--bin", "specter-build", "--",
                "--pic", "implant/build/specter.bin",
                "--format", "raw",
                "--channel", "http://127.0.0.1:8080",
                "--out", $PayloadScanPath,
                "--dump-markers"
            )))
    }
} else {
    $PayloadFacts += "- Current PIC: missing (implant/build/specter.bin not found)"
}

$SyscallHeader = Join-Path $RepoRoot "implant\core\include\syscalls.h"
$SyscallSource = Join-Path $RepoRoot "implant\core\src\syscalls.c"
$SyscallFacts = @()
if ((Test-Path $SyscallHeader) -and (Test-Path $SyscallSource)) {
    $Header = Get-Content $SyscallHeader -Raw
    $Source = Get-Content $SyscallSource -Raw
    $MaxGadgets = if ($Header -match '#define\s+MAX_GADGETS\s+(\d+)') { $Matches[1] } else { "unknown" }
    $RequiredCount = ([regex]::Matches($Source, 'HASH_NT[A-Z0-9_]+')).Count
    $HasPoolScan = $Source.Contains("sc_find_gadgets")
    $HasRandomAssignment = $Source.Contains("rdtsc") -and $Source.Contains("tick % table->gadget_count")
    $SyscallFacts += "- MAX_GADGETS: $MaxGadgets"
    $SyscallFacts += "- Required syscall hash references in syscalls.c: $RequiredCount"
    $SyscallFacts += "- Gadget pool scan present: $HasPoolScan"
    $SyscallFacts += "- Per-entry gadget selection present: $HasRandomAssignment"
}

$Os = Get-CimInstance Win32_OperatingSystem
$GitHead = (& git rev-parse --short HEAD 2>$null | Out-String).Trim()
$GitStatus = (& git status --short 2>$null | Out-String).TrimEnd()

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add("# Phase 2 Telemetry Evidence")
$Lines.Add("")
$Lines.Add("- Date: $(Get-Date -Format o)")
$Lines.Add("- Host OS: $($Os.Caption) $($Os.Version)")
$Lines.Add("- Git HEAD: $GitHead")
$Lines.Add("")
$Lines.Add("## Payload Facts")
$PayloadFacts | ForEach-Object { $Lines.Add($_) }
$Lines.Add("")
$Lines.Add("## Syscall Gadget Rotation Static Evidence")
$SyscallFacts | ForEach-Object { $Lines.Add($_) }
$Lines.Add("")
$Lines.Add("## Automated Checks")

$AnyFailed = $false
foreach ($Result in $Results) {
    $Status = if ($Result.ExitCode -eq 0) { "PASS" } else { "FAIL" }
    if ($Result.ExitCode -ne 0) { $AnyFailed = $true }
    $Lines.Add("")
    $Lines.Add("### $($Result.Name): $Status")
    $Lines.Add("")
    $Lines.Add("- Command: $($Result.Command)")
    $Lines.Add("- Exit code: $($Result.ExitCode)")
    $Lines.Add("- Duration: $($Result.DurationSeconds) seconds")
    if ($Result.Output) {
        $Lines.Add("")
        $Lines.Add('```text')
        $Lines.Add($Result.Output)
        $Lines.Add('```')
    }
}

$Lines.Add("")
$Lines.Add("## Lab-Only Gates Not Proven By This Script")
$Lines.Add("")
$Lines.Add("- Memory state while awake and sleeping")
$Lines.Add("- RW -> copy -> RX timing and memory-protection telemetry")
$Lines.Add("- Backing-file mismatch visibility for module overloading")
$Lines.Add("- PEB loader-entry consistency")
$Lines.Add("- .pdata unwind behavior under a stack-walking telemetry source")
$Lines.Add("- ETW-TI/kernel telemetry visibility")
$Lines.Add("- Syscall gadget diversity observed at runtime")
$Lines.Add("")
$Lines.Add("## Working Tree Snapshot")
$Lines.Add("")
if ($GitStatus) {
    $Lines.Add('```text')
    $Lines.Add($GitStatus)
    $Lines.Add('```')
} else {
    $Lines.Add("Clean working tree")
}

$Lines | Set-Content -Path $OutputPath -Encoding ascii
Write-Host "Report: $OutputPath"

if ($AnyFailed) {
    throw "One or more Phase 2 evidence checks failed. See $OutputPath"
}

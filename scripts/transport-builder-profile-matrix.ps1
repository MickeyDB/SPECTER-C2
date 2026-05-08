param(
    [string]$EvidenceDir = "target\local-evidence",
    [int]$TimeoutMs = 70000,
    [switch]$SkipClean,
    [switch]$SkipRustTests
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceRoot = Join-Path $RepoRoot $EvidenceDir
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Report = Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.md"

function Invoke-NativeCapture {
    param(
        [string]$Name,
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$StdoutPath,
        [string]$StderrPath
    )

    $Started = Get-Date
    Push-Location $RepoRoot
    $OldErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $FilePath @Arguments > $StdoutPath 2> $StderrPath
        $ExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $OldErrorActionPreference
        Pop-Location
    }
    $Ended = Get-Date
    if ($null -eq $ExitCode) {
        $ExitCode = 1
    }

    [pscustomobject]@{
        Name = $Name
        FilePath = $FilePath
        Arguments = $Arguments
        ExitCode = $ExitCode
        Started = $Started
        Ended = $Ended
        DurationSeconds = [Math]::Round(($Ended - $Started).TotalSeconds, 2)
        StdoutPath = $StdoutPath
        StderrPath = $StderrPath
    }
}

function Add-CommandResult {
    param([object]$Command)
    $script:Commands.Add($Command) | Out-Null
    return $Command
}

function Read-Text {
    param([string]$Path)
    if (Test-Path $Path) {
        return Get-Content -Path $Path -Raw
    }
    return ""
}

$Commands = New-Object System.Collections.Generic.List[object]
$Checks = New-Object System.Collections.Generic.List[object]

if (-not $SkipClean) {
    Add-CommandResult (Invoke-NativeCapture `
        -Name "Clean implant build outputs" `
        -FilePath "make" `
        -Arguments @("-C", "implant", "clean") `
        -StdoutPath (Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.make-clean.stdout.log") `
        -StderrPath (Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.make-clean.stderr.log")) | Out-Null
}

Add-CommandResult (Invoke-NativeCapture `
    -Name "Build implant PIC and loader" `
    -FilePath "make" `
    -Arguments @("-C", "implant", "DEV=1", "pic-loader", "all") `
    -StdoutPath (Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.make.stdout.log") `
    -StderrPath (Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.make.stderr.log")) | Out-Null

if (-not $SkipRustTests) {
    foreach ($TestName in @("builder_tests", "profile_tests", "profile_yaml_tests", "redirector_tests", "listener_tests")) {
        Add-CommandResult (Invoke-NativeCapture `
            -Name "Run Rust test $TestName" `
            -FilePath "cargo" `
            -Arguments @("test", "-p", "specter-server", "--test", $TestName) `
            -StdoutPath (Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.$TestName.stdout.log") `
            -StderrPath (Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.$TestName.stderr.log")) | Out-Null
    }
}

$BuildCases = @(
    @{ Name = "builder raw no-obfuscate scan"; Format = "raw"; Extra = @("--no-obfuscate", "--scan-only", "--dump-markers") },
    @{ Name = "builder raw default scan"; Format = "raw"; Extra = @("--scan-only", "--dump-markers") },
    @{ Name = "builder raw xor scan"; Format = "raw"; Extra = @("--xor", "--scan-only", "--dump-markers") },
    @{ Name = "builder dotnet wrapper build"; Format = "dotnet"; Extra = @("--no-obfuscate") },
    @{ Name = "builder service wrapper build"; Format = "service"; Extra = @("--no-obfuscate") }
)

foreach ($Case in $BuildCases) {
    $CaseSafeName = ($Case.Name -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLowerInvariant()
    $OutPath = Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.$CaseSafeName.bin"
    $Args = @(
        "run", "-p", "specter-server", "--bin", "specter-build", "--",
        "--pic", "implant/build/specter.bin",
        "--format", $Case.Format,
        "--channel", "http://127.0.0.1:8080/api/beacon",
        "--out", $OutPath
    ) + $Case.Extra

    $Command = Add-CommandResult (Invoke-NativeCapture `
        -Name $Case.Name `
        -FilePath "cargo" `
        -Arguments $Args `
        -StdoutPath (Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.$CaseSafeName.stdout.log") `
        -StderrPath (Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.$CaseSafeName.stderr.log"))

    $Stdout = Read-Text $Command.StdoutPath
    $MarkerClean = $Stdout -match "None found \(clean!\)"
    $Checks.Add([pscustomobject]@{
        Area = "Builder"
        Name = $Case.Name
        Result = if ($Command.ExitCode -eq 0) { "PASS" } else { "FAIL" }
        Detail = if ($Case.Extra -contains "--dump-markers") {
            if ($MarkerClean) { "marker scan clean" } else { "marker scan not clean or unavailable" }
        } else {
            "build/integrity check completed"
        }
    }) | Out-Null
}

$RuntimeCases = @(
    @{
        Name = "raw listener task smoke"
        Args = @("--legacy-only", "--task-command", "echo SPECTER_TRANSPORT_RAW_OK", "--min-result-bytes", "10")
    },
    @{
        Name = "builder-equivalent raw listener task smoke"
        Args = @("--legacy-only", "--builder-equivalent", "--task-command", "echo SPECTER_BUILDER_EQUIV_OK", "--min-result-bytes", "10")
    },
    @{
        Name = "profile-enabled default raw task smoke"
        Args = @("--task-command", "echo SPECTER_DEFAULT_PROFILE_OK", "--min-result-bytes", "10")
    },
    @{
        Name = "profile-enabled default raw module smoke"
        Args = @("--module-smoke", "--module-blob", "implant/build/modules/template.bin", "--module-name", "template", "--module-args", "ping", "--min-result-bytes", "4")
    },
    @{
        Name = "xor-wrapped raw task smoke"
        Args = @("--xor", "--task-command", "echo SPECTER_XOR_RUNTIME_OK", "--min-result-bytes", "10")
    },
    @{
        Name = "xor-wrapped raw module smoke"
        Args = @("--xor", "--module-smoke", "--module-blob", "implant/build/modules/template.bin", "--module-name", "template", "--module-args", "ping", "--min-result-bytes", "4")
    },
    @{
        Name = "profile transform task smoke"
        Args = @("--profile-mode", "--task-command", "echo SPECTER_PROFILE_MATRIX_OK", "--min-result-bytes", "10")
    },
    @{
        Name = "profile redirector soak"
        Args = @("--profile-mode", "--redirector-mode", "--min-profile-checkins", "5", "--task-command", "echo SPECTER_REDIRECTOR_MATRIX_OK", "--min-result-bytes", "10")
    }
)

foreach ($Case in $RuntimeCases) {
    $CaseSafeName = ($Case.Name -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLowerInvariant()
    $Payload = Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.$CaseSafeName.payload.bin"
    $Db = Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.$CaseSafeName.db"
    $LoaderLog = Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.$CaseSafeName.loader.log"
    $Args = @(
        "run", "-p", "specter-server", "--bin", "pic-listener-smoke", "--",
        "--pic", "implant/build/specter.bin",
        "--loader", "implant/build/tests/pic_loader.exe",
        "--out", $Payload,
        "--db", $Db,
        "--loader-log", $LoaderLog,
        "--timeout-ms", "$TimeoutMs"
    ) + $Case.Args

    $Command = Add-CommandResult (Invoke-NativeCapture `
        -Name $Case.Name `
        -FilePath "cargo" `
        -Arguments $Args `
        -StdoutPath (Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.$CaseSafeName.stdout.log") `
        -StderrPath (Join-Path $EvidenceRoot "transport-builder-profile-matrix-$Stamp.$CaseSafeName.stderr.log"))

    $Stdout = Read-Text $Command.StdoutPath
    $SmokePassed = $Stdout -match "PIC listener smoke: PASS"
    $ResultBytes = if ($Stdout -match "result_bytes=(\d+)") { $Matches[1] } else { "unknown" }
    $BeaconCheckins = if ($Stdout -match "beacon_checkins=(\d+)") { $Matches[1] } else { "unknown" }
    $ProfileCheckins = if ($Stdout -match "profile_checkins=(\d+)") { $Matches[1] } else { "unknown" }

    $Checks.Add([pscustomobject]@{
        Area = "Runtime"
        Name = $Case.Name
        Result = if (($Command.ExitCode -eq 0) -and $SmokePassed) { "PASS" } else { "FAIL" }
        Detail = "result_bytes=$ResultBytes; beacon_checkins=$BeaconCheckins; profile_checkins=$ProfileCheckins"
    }) | Out-Null
}

$AnyFailed = (($Commands | Where-Object { $_.ExitCode -ne 0 }).Count -gt 0) -or
    (($Checks | Where-Object { $_.Result -ne "PASS" }).Count -gt 0)

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add("# Transport Builder Profile Matrix")
$Lines.Add("")
$Lines.Add("- Date: $(Get-Date -Format o)")
$Lines.Add("- Result: $(if ($AnyFailed) { 'FAIL' } else { 'PASS' })")
$Lines.Add("- Runtime scope: local PIC loader, local listener, local reverse-proxy redirector")
$Lines.Add("- Operational external traffic exercised: False")
$Lines.Add("")
$Lines.Add("## Checks")
$Lines.Add("")
$Lines.Add("| Area | Check | Result | Detail |")
$Lines.Add("| --- | --- | --- | --- |")
foreach ($Check in $Checks) {
    $Tick = [char]96
    $Lines.Add("| $($Check.Area) | $Tick$($Check.Name)$Tick | $($Check.Result) | $($Check.Detail) |")
}
$Lines.Add("")
$Lines.Add("## Commands")
$Lines.Add("")
foreach ($Item in $Commands) {
    $Status = if ($Item.ExitCode -eq 0) { "PASS" } else { "FAIL" }
    $Tick = [char]96
    $CommandLine = "$($Item.FilePath) $($Item.Arguments -join ' ')"
    $Lines.Add("### $($Item.Name): $Status")
    $Lines.Add("")
    $Lines.Add("- Command: $Tick$CommandLine$Tick")
    $Lines.Add("- Exit code: $($Item.ExitCode)")
    $Lines.Add("- Duration: $($Item.DurationSeconds) seconds")
    $Lines.Add("- Stdout: $Tick$($Item.StdoutPath)$Tick")
    $Lines.Add("- Stderr: $Tick$($Item.StderrPath)$Tick")
    $Lines.Add("")
}
$Lines.Add("## Boundaries")
$Lines.Add("")
$Lines.Add("- This matrix validates local build outputs, profile transforms, listener tasking, and a local reverse-proxy redirector path.")
$Lines.Add("- It does not deploy cloud redirectors, exercise DNS/Azure/SMB/WebSocket channels end to end, or validate external network infrastructure.")
$Lines.Add("- PE wrapper runtime execution is covered by `scripts/wrapper-runtime-matrix.ps1`; scanner posture is covered by `scripts/phase2-memory-scanner-evidence.ps1`.")

$Lines | Set-Content -Path $Report -Encoding UTF8

Write-Host "Report: $Report"
if ($AnyFailed) {
    throw "Transport/builder/profile matrix failed. See $Report"
}

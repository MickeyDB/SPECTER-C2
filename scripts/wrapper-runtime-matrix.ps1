param(
    [string]$EvidenceDir = "target\local-evidence",
    [int]$TimeoutMs = 70000,
    [switch]$SkipClean,
    [switch]$SkipServiceScm
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceRoot = Join-Path $RepoRoot $EvidenceDir
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Report = Join-Path $EvidenceRoot "wrapper-runtime-matrix-$Stamp.md"

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

function Read-Text {
    param([string]$Path)
    if (Test-Path $Path) {
        return Get-Content -Path $Path -Raw
    }
    return ""
}

function Get-SmokeResult {
    param(
        [object]$Command,
        [bool]$AllowBlocked
    )

    $Stdout = Read-Text $Command.StdoutPath
    $Stderr = Read-Text $Command.StderrPath
    $Passed = $Stdout -match "PIC listener smoke: PASS"
    $ResultBytes = if ($Stdout -match "result_bytes=(\d+)") { $Matches[1] } else { "unknown" }
    $BeaconCheckins = if ($Stdout -match "beacon_checkins=(\d+)") { $Matches[1] } else { "unknown" }
    $SessionId = if ($Stdout -match "session_id=([^\s]+)") { $Matches[1] } else { "unknown" }
    $TaskId = if ($Stdout -match "task_id=([^\s]+)") { $Matches[1] } else { "unknown" }
    $Combined = "$Stdout`n$Stderr"

    $Blocked = $false
    if ($AllowBlocked -and -not $Passed) {
        $Blocked = $Combined -match "Access is denied|CreateService|OpenSCManager|StartService|requires elevation|administrator|SCM|service"
    }

    [pscustomobject]@{
        Result = if (($Command.ExitCode -eq 0) -and $Passed) { "PASS" } elseif ($Blocked) { "BLOCKED" } else { "FAIL" }
        ResultBytes = $ResultBytes
        BeaconCheckins = $BeaconCheckins
        SessionId = $SessionId
        TaskId = $TaskId
    }
}

$Commands = New-Object System.Collections.Generic.List[object]
$Checks = New-Object System.Collections.Generic.List[object]

if (-not $SkipClean) {
    $Commands.Add((Invoke-NativeCapture `
        -Name "Clean implant build outputs" `
        -FilePath "make" `
        -Arguments @("-C", "implant", "clean") `
        -StdoutPath (Join-Path $EvidenceRoot "wrapper-runtime-matrix-$Stamp.make-clean.stdout.log") `
        -StderrPath (Join-Path $EvidenceRoot "wrapper-runtime-matrix-$Stamp.make-clean.stderr.log"))) | Out-Null
}

$Commands.Add((Invoke-NativeCapture `
    -Name "Build implant PIC and loader" `
    -FilePath "make" `
    -Arguments @("-C", "implant", "DEV=1", "pic-loader", "all") `
    -StdoutPath (Join-Path $EvidenceRoot "wrapper-runtime-matrix-$Stamp.make.stdout.log") `
    -StderrPath (Join-Path $EvidenceRoot "wrapper-runtime-matrix-$Stamp.make.stderr.log"))) | Out-Null

$RuntimeCases = @(
    @{
        Name = "dotnet exe direct runtime smoke"
        ArtifactFormat = "dotnet"
        ServiceScm = $false
        AllowBlocked = $false
        TaskCommand = "echo SPECTER_DOTNET_WRAPPER_OK"
    }
)

if (-not $SkipServiceScm) {
    $RuntimeCases += @{
        Name = "service scm runtime smoke"
        ArtifactFormat = "service"
        ServiceScm = $true
        AllowBlocked = $true
        TaskCommand = "echo SPECTER_SERVICE_WRAPPER_OK"
    }
}

foreach ($Case in $RuntimeCases) {
    $CaseSafeName = ($Case.Name -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLowerInvariant()
    $Payload = Join-Path $EvidenceRoot "wrapper-runtime-matrix-$Stamp.$CaseSafeName.payload.exe"
    $Db = Join-Path $EvidenceRoot "wrapper-runtime-matrix-$Stamp.$CaseSafeName.db"
    $LoaderLog = Join-Path $EvidenceRoot "wrapper-runtime-matrix-$Stamp.$CaseSafeName.loader.log"
    $Args = @(
        "run", "-p", "specter-server", "--bin", "pic-listener-smoke", "--",
        "--pic", "implant/build/specter.bin",
        "--loader", "implant/build/tests/pic_loader.exe",
        "--artifact-format", $Case.ArtifactFormat,
        "--out", $Payload,
        "--db", $Db,
        "--loader-log", $LoaderLog,
        "--timeout-ms", "$TimeoutMs",
        "--legacy-only",
        "--task-command", $Case.TaskCommand,
        "--min-result-bytes", "10"
    )
    if ($Case.ServiceScm) {
        $Args += @("--service-scm", "--service-name", "SpecterWrapperSmoke")
    }

    $Command = Invoke-NativeCapture `
        -Name $Case.Name `
        -FilePath "cargo" `
        -Arguments $Args `
        -StdoutPath (Join-Path $EvidenceRoot "wrapper-runtime-matrix-$Stamp.$CaseSafeName.stdout.log") `
        -StderrPath (Join-Path $EvidenceRoot "wrapper-runtime-matrix-$Stamp.$CaseSafeName.stderr.log")
    $Commands.Add($Command) | Out-Null

    $Smoke = Get-SmokeResult -Command $Command -AllowBlocked $Case.AllowBlocked
    $Checks.Add([pscustomobject]@{
        Name = $Case.Name
        ArtifactFormat = $Case.ArtifactFormat
        Result = $Smoke.Result
        Detail = "result_bytes=$($Smoke.ResultBytes); beacon_checkins=$($Smoke.BeaconCheckins); session_id=$($Smoke.SessionId); task_id=$($Smoke.TaskId)"
    }) | Out-Null
}

$AnyFailed = (($Commands | Where-Object { $_.ExitCode -ne 0 -and $_.Name -notmatch "service scm" }).Count -gt 0) -or
    (($Checks | Where-Object { $_.Result -eq "FAIL" }).Count -gt 0)
$BlockedCount = ($Checks | Where-Object { $_.Result -eq "BLOCKED" }).Count

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add("# Wrapper Runtime Matrix")
$Lines.Add("")
$Lines.Add("- Date: $(Get-Date -Format o)")
$Lines.Add("- Result: $(if ($AnyFailed) { 'FAIL' } elseif ($BlockedCount -gt 0) { 'PARTIAL' } else { 'PASS' })")
$Lines.Add("- Runtime scope: local PE-template wrapper execution and optional Windows SCM service launch")
$Lines.Add("- Operational external traffic exercised: False")
$Lines.Add("")
$Lines.Add("## Checks")
$Lines.Add("")
$Lines.Add("| Check | Artifact format | Result | Detail |")
$Lines.Add("| --- | --- | --- | --- |")
foreach ($Check in $Checks) {
    $Tick = [char]96
    $Lines.Add("| $Tick$($Check.Name)$Tick | $Tick$($Check.ArtifactFormat)$Tick | $($Check.Result) | $($Check.Detail) |")
}
$Lines.Add("")
$Lines.Add("## Commands")
$Lines.Add("")
foreach ($Item in $Commands) {
    $Status = if ($Item.ExitCode -eq 0) { "PASS" } elseif ($Item.Name -match "service scm" -and $BlockedCount -gt 0) { "BLOCKED" } else { "FAIL" }
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
$Lines.Add("- Direct EXE wrapper runtime validates local PE-template execution through the normal listener/task path.")
$Lines.Add("- Service-SCM runtime requires local permission to create/start/delete a Windows service; lack of elevation is recorded as BLOCKED, not PASS.")
$Lines.Add("- This does not validate installer UX, persistence, external infrastructure, or EDR/provider telemetry.")

$Lines | Set-Content -Path $Report -Encoding UTF8

Write-Host "Report: $Report"
if ($AnyFailed) {
    throw "Wrapper runtime matrix failed. See $Report"
}

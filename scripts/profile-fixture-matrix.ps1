param(
    [string]$EvidenceDir = "target\local-evidence",
    [string[]]$Profiles = @("profiles\generic-https.yaml", "profiles\slack-webhook.yaml"),
    [int]$TimeoutMs = 180000,
    [switch]$SkipClean
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceRoot = Join-Path $RepoRoot $EvidenceDir
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Report = Join-Path $EvidenceRoot "profile-fixture-matrix-$Stamp.md"

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

function Convert-ToSafeName {
    param([string]$Value)
    return ($Value -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLowerInvariant()
}

$Commands = New-Object System.Collections.Generic.List[object]
$Checks = New-Object System.Collections.Generic.List[object]

if (-not $SkipClean) {
    $Commands.Add((Invoke-NativeCapture `
        -Name "Clean implant build outputs" `
        -FilePath "make" `
        -Arguments @("-C", "implant", "clean") `
        -StdoutPath (Join-Path $EvidenceRoot "profile-fixture-matrix-$Stamp.make-clean.stdout.log") `
        -StderrPath (Join-Path $EvidenceRoot "profile-fixture-matrix-$Stamp.make-clean.stderr.log"))) | Out-Null
}

$Commands.Add((Invoke-NativeCapture `
    -Name "Build implant PIC and loader" `
    -FilePath "make" `
    -Arguments @("-C", "implant", "DEV=1", "pic-loader", "all") `
    -StdoutPath (Join-Path $EvidenceRoot "profile-fixture-matrix-$Stamp.make.stdout.log") `
    -StderrPath (Join-Path $EvidenceRoot "profile-fixture-matrix-$Stamp.make.stderr.log"))) | Out-Null

foreach ($ProfilePath in $Profiles) {
    $ResolvedProfile = (Resolve-Path (Join-Path $RepoRoot $ProfilePath)).Path
    $ProfileName = [System.IO.Path]::GetFileNameWithoutExtension($ResolvedProfile)
    foreach ($Mode in @("profile", "redirector")) {
        $CaseName = "$ProfileName $Mode fixture smoke"
        $CaseSafeName = Convert-ToSafeName $CaseName
        $Payload = Join-Path $EvidenceRoot "profile-fixture-matrix-$Stamp.$CaseSafeName.payload.bin"
        $Db = Join-Path $EvidenceRoot "profile-fixture-matrix-$Stamp.$CaseSafeName.db"
        $LoaderLog = Join-Path $EvidenceRoot "profile-fixture-matrix-$Stamp.$CaseSafeName.loader.log"

        $Args = @(
            "run", "-p", "specter-server", "--bin", "pic-listener-smoke", "--",
            "--pic", "implant/build/specter.bin",
            "--loader", "implant/build/tests/pic_loader.exe",
            "--out", $Payload,
            "--db", $Db,
            "--loader-log", $LoaderLog,
            "--timeout-ms", "$TimeoutMs",
            "--profile-mode",
            "--profile-yaml", $ResolvedProfile,
            "--task-command", "echo SPECTER_PROFILE_FIXTURE_OK_$($ProfileName.ToUpperInvariant())_$($Mode.ToUpperInvariant())",
            "--min-result-bytes", "10"
        )
        if ($Mode -eq "redirector") {
            $Args += @("--redirector-mode", "--min-profile-checkins", "5")
        }

        $Command = Invoke-NativeCapture `
            -Name $CaseName `
            -FilePath "cargo" `
            -Arguments $Args `
            -StdoutPath (Join-Path $EvidenceRoot "profile-fixture-matrix-$Stamp.$CaseSafeName.stdout.log") `
            -StderrPath (Join-Path $EvidenceRoot "profile-fixture-matrix-$Stamp.$CaseSafeName.stderr.log")
        $Commands.Add($Command) | Out-Null

        $Stdout = Read-Text $Command.StdoutPath
        $Passed = $Stdout -match "PIC listener smoke: PASS"
        $ResultBytes = if ($Stdout -match "result_bytes=(\d+)") { $Matches[1] } else { "unknown" }
        $BeaconCheckins = if ($Stdout -match "beacon_checkins=(\d+)") { $Matches[1] } else { "unknown" }
        $ProfileCheckins = if ($Stdout -match "profile_checkins=(\d+)") { $Matches[1] } else { "unknown" }

        $Checks.Add([pscustomobject]@{
            Profile = $ProfileName
            Mode = $Mode
            Result = if (($Command.ExitCode -eq 0) -and $Passed) { "PASS" } else { "FAIL" }
            Detail = "result_bytes=$ResultBytes; beacon_checkins=$BeaconCheckins; profile_checkins=$ProfileCheckins"
        }) | Out-Null
    }
}

$AnyFailed = (($Commands | Where-Object { $_.ExitCode -ne 0 }).Count -gt 0) -or
    (($Checks | Where-Object { $_.Result -ne "PASS" }).Count -gt 0)

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add("# Profile Fixture Matrix")
$Lines.Add("")
$Lines.Add("- Date: $(Get-Date -Format o)")
$Lines.Add("- Result: $(if ($AnyFailed) { 'FAIL' } else { 'PASS' })")
$Lines.Add("- Profiles: $($Profiles -join ', ')")
$Lines.Add("- Runtime scope: local PIC loader, local profile listener, optional local reverse-proxy redirector")
$Lines.Add("- External operational traffic exercised: False")
$Lines.Add("")
$Lines.Add("## Checks")
$Lines.Add("")
$Lines.Add("| Profile | Mode | Result | Detail |")
$Lines.Add("| --- | --- | --- | --- |")
foreach ($Check in $Checks) {
    $Tick = [char]96
    $Lines.Add("| $Tick$($Check.Profile)$Tick | $Tick$($Check.Mode)$Tick | $($Check.Result) | $($Check.Detail) |")
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
$Lines.Add("- This validates checked-in profile YAML fixtures through local implant/listener tasking.")
$Lines.Add("- Redirector mode is still a local reverse proxy; no provider/cloud redirector is deployed.")
$Lines.Add("- Profiles with probabilistic response behavior may require longer or repeated runs in release gates.")

$Lines | Set-Content -Path $Report -Encoding UTF8

Write-Host "Report: $Report"
if ($AnyFailed) {
    throw "Profile fixture matrix failed. See $Report"
}

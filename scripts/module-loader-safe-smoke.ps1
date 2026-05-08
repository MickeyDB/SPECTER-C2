param(
    [string]$EvidenceDir = "target\local-evidence",
    [string[]]$Modules = @("exfil", "token", "inject", "lateral"),
    [string]$ModuleArgs = "__specter_safe_smoke__",
    [int]$MinResultBytes = 1,
    [int]$TimeoutMs = 60000,
    [switch]$SkipClean
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceRoot = Join-Path $RepoRoot $EvidenceDir
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Report = Join-Path $EvidenceRoot "module-loader-safe-smoke-$Stamp.md"

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

$Commands = New-Object System.Collections.Generic.List[object]
$Results = New-Object System.Collections.Generic.List[object]

if (-not $SkipClean) {
    $Commands.Add((Invoke-NativeCapture `
        -Name "Clean implant build outputs" `
        -FilePath "make" `
        -Arguments @("-C", "implant", "clean") `
        -StdoutPath (Join-Path $EvidenceRoot "module-loader-safe-smoke-$Stamp.make-clean.stdout.log") `
        -StderrPath (Join-Path $EvidenceRoot "module-loader-safe-smoke-$Stamp.make-clean.stderr.log"))) | Out-Null
}

$BuildCommand = Invoke-NativeCapture `
    -Name "Build barebone module-capable implant and modules" `
    -FilePath "make" `
    -Arguments @("-C", "implant", "DEV=1", "BAREBONE=1", "BAREBONE_MODULES=1", "pic-loader", "all", "modules") `
    -StdoutPath (Join-Path $EvidenceRoot "module-loader-safe-smoke-$Stamp.make.stdout.log") `
    -StderrPath (Join-Path $EvidenceRoot "module-loader-safe-smoke-$Stamp.make.stderr.log")
$Commands.Add($BuildCommand) | Out-Null

foreach ($Module in $Modules) {
    $ModuleBlob = "implant/build/modules/$Module.bin"
    $Payload = Join-Path $EvidenceRoot "$Module-module-loader-safe-smoke-$Stamp.bin"
    $Db = Join-Path $EvidenceRoot "$Module-module-loader-safe-smoke-$Stamp.db"
    $LoaderLog = Join-Path $EvidenceRoot "$Module-module-loader-safe-smoke-$Stamp.loader.log"
    $Stdout = Join-Path $EvidenceRoot "$Module-module-loader-safe-smoke-$Stamp.stdout.log"
    $Stderr = Join-Path $EvidenceRoot "$Module-module-loader-safe-smoke-$Stamp.stderr.log"

    $CargoArgs = @(
        "run", "-p", "specter-server", "--bin", "pic-listener-smoke", "--",
        "--pic", "implant/build/specter.bin",
        "--loader", "implant/build/tests/pic_loader.exe",
        "--module-smoke",
        "--module-blob", $ModuleBlob,
        "--module-name", $Module,
        "--module-args", $ModuleArgs,
        "--min-result-bytes", "$MinResultBytes",
        "--timeout-ms", "$TimeoutMs",
        "--out", $Payload,
        "--db", $Db,
        "--loader-log", $LoaderLog
    )

    $Command = Invoke-NativeCapture `
        -Name "Run $Module module loader safe smoke" `
        -FilePath "cargo" `
        -Arguments $CargoArgs `
        -StdoutPath $Stdout `
        -StderrPath $Stderr
    $Commands.Add($Command) | Out-Null

    $SmokeStdout = if (Test-Path $Stdout) { Get-Content -Path $Stdout -Raw } else { "" }
    $SmokePassed = $SmokeStdout -match "PIC listener smoke: PASS"
    $SessionId = if ($SmokeStdout -match "session_id=([^\s]+)") { $Matches[1] } else { "unknown" }
    $TaskId = if ($SmokeStdout -match "task_id=([^\s]+)") { $Matches[1] } else { "unknown" }
    $ResultBytes = if ($SmokeStdout -match "result_bytes=(\d+)") { $Matches[1] } else { "unknown" }
    $BeaconCheckins = if ($SmokeStdout -match "beacon_checkins=(\d+)") { $Matches[1] } else { "unknown" }

    $Results.Add([pscustomobject]@{
        Module = $Module
        Result = if (($Command.ExitCode -eq 0) -and $SmokePassed) { "PASS" } else { "FAIL" }
        ExitCode = $Command.ExitCode
        SessionId = $SessionId
        TaskId = $TaskId
        ResultBytes = $ResultBytes
        BeaconCheckins = $BeaconCheckins
        Payload = $Payload
        LoaderLog = $LoaderLog
        StdoutPath = $Stdout
        StderrPath = $Stderr
    }) | Out-Null
}

$AnyFailed = (($Commands | Where-Object { $_.ExitCode -ne 0 }).Count -gt 0) -or
    (($Results | Where-Object { $_.Result -ne "PASS" }).Count -gt 0)

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add("# Module Loader Safe Smoke")
$Lines.Add("")
$Lines.Add("- Date: $(Get-Date -Format o)")
$Lines.Add("- Result: $(if ($AnyFailed) { 'FAIL' } else { 'PASS' })")
$Lines.Add("- Modules: $($Modules -join ', ')")
$Lines.Add("- Module args: $ModuleArgs")
$Lines.Add("- Minimum result bytes: $MinResultBytes")
$Lines.Add("- Operational behavior exercised: False")
$Lines.Add("- Real implant tasking path exercised: True")
$Lines.Add("")
$Lines.Add("## Results")
$Lines.Add("")
$Lines.Add("| Module | Result | Result bytes | Beacon check-ins | Session ID | Task ID |")
$Lines.Add("| --- | --- | ---: | ---: | --- | --- |")
$Tick = [char]96
foreach ($Item in $Results) {
    $Lines.Add("| $Tick$($Item.Module)$Tick | $($Item.Result) | $($Item.ResultBytes) | $($Item.BeaconCheckins) | $Tick$($Item.SessionId)$Tick | $Tick$($Item.TaskId)$Tick |")
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

$Lines.Add("## Artifacts")
$Lines.Add("")
foreach ($Item in $Results) {
    $Tick = [char]96
    $Lines.Add("### $($Item.Module)")
    $Lines.Add("")
    $Lines.Add("- Payload: $Tick$($Item.Payload)$Tick")
    $Lines.Add("- Loader log: $Tick$($Item.LoaderLog)$Tick")
    $Lines.Add("- Stdout: $Tick$($Item.StdoutPath)$Tick")
    $Lines.Add("- Stderr: $Tick$($Item.StderrPath)$Tick")
    $Lines.Add("")
}

$Lines.Add("## Boundaries")
$Lines.Add("")
$Lines.Add("- This proves each listed module artifact can be packaged, dispatched, loaded, and completed through the local implant/listener tasking path.")
$Lines.Add("- The safe argument intentionally selects an unsupported subcommand so the module returns output before file, token, process, or remote-control behavior.")
$Lines.Add("- No file collection, credential use, process injection, lateral movement, listener, target connection, or data relay is exercised by this smoke.")

$Lines | Set-Content -Path $Report -Encoding UTF8

Write-Host "Report: $Report"
if ($AnyFailed) {
    throw "Module loader safe smoke failed. See $Report"
}

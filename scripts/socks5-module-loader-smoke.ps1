param(
    [string]$EvidenceDir = "target\local-evidence",
    [int]$TimeoutMs = 60000,
    [switch]$SkipClean
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceRoot = Join-Path $RepoRoot $EvidenceDir
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Payload = Join-Path $EvidenceRoot "socks5-module-loader-smoke-$Stamp.bin"
$Db = Join-Path $EvidenceRoot "socks5-module-loader-smoke-$Stamp.db"
$LoaderLog = Join-Path $EvidenceRoot "socks5-module-loader-smoke-$Stamp.loader.log"
$Stdout = Join-Path $EvidenceRoot "socks5-module-loader-smoke-$Stamp.stdout.log"
$Stderr = Join-Path $EvidenceRoot "socks5-module-loader-smoke-$Stamp.stderr.log"
$Report = Join-Path $EvidenceRoot "socks5-module-loader-smoke-$Stamp.md"

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

if (-not $SkipClean) {
    $Commands.Add((Invoke-NativeCapture `
        -Name "Clean implant build outputs" `
        -FilePath "make" `
        -Arguments @("-C", "implant", "clean") `
        -StdoutPath (Join-Path $EvidenceRoot "socks5-module-loader-smoke-$Stamp.make-clean.stdout.log") `
        -StderrPath (Join-Path $EvidenceRoot "socks5-module-loader-smoke-$Stamp.make-clean.stderr.log"))) | Out-Null
}

$Commands.Add((Invoke-NativeCapture `
    -Name "Build barebone module-capable implant and modules" `
    -FilePath "make" `
    -Arguments @("-C", "implant", "DEV=1", "BAREBONE=1", "BAREBONE_MODULES=1", "pic-loader", "all", "modules") `
    -StdoutPath (Join-Path $EvidenceRoot "socks5-module-loader-smoke-$Stamp.make.stdout.log") `
    -StderrPath (Join-Path $EvidenceRoot "socks5-module-loader-smoke-$Stamp.make.stderr.log"))) | Out-Null

$CargoArgs = @(
    "run", "-p", "specter-server", "--bin", "pic-listener-smoke", "--",
    "--pic", "implant/build/specter.bin",
    "--loader", "implant/build/tests/pic_loader.exe",
    "--module-smoke",
    "--module-blob", "implant/build/modules/socks5.bin",
    "--module-name", "socks5",
    "--module-args", "status",
    "--min-result-bytes", "1",
    "--timeout-ms", "$TimeoutMs",
    "--out", $Payload,
    "--db", $Db,
    "--loader-log", $LoaderLog
)

$Commands.Add((Invoke-NativeCapture `
    -Name "Run SOCKS5 module loader smoke" `
    -FilePath "cargo" `
    -Arguments $CargoArgs `
    -StdoutPath $Stdout `
    -StderrPath $Stderr)) | Out-Null

$SmokeStdout = if (Test-Path $Stdout) { Get-Content -Path $Stdout -Raw } else { "" }
$SmokePassed = $SmokeStdout -match "PIC listener smoke: PASS"
$SessionId = if ($SmokeStdout -match "session_id=([^\s]+)") { $Matches[1] } else { "unknown" }
$TaskId = if ($SmokeStdout -match "task_id=([^\s]+)") { $Matches[1] } else { "unknown" }
$ResultBytes = if ($SmokeStdout -match "result_bytes=(\d+)") { $Matches[1] } else { "unknown" }
$BeaconCheckins = if ($SmokeStdout -match "beacon_checkins=(\d+)") { $Matches[1] } else { "unknown" }
$AnyFailed = (($Commands | Where-Object { $_.ExitCode -ne 0 }).Count -gt 0) -or -not $SmokePassed

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add("# SOCKS5 Module Loader Smoke")
$Lines.Add("")
$Lines.Add("- Date: $(Get-Date -Format o)")
$Lines.Add("- Result: $(if ($AnyFailed) { 'FAIL' } else { 'PASS' })")
$Lines.Add("- Module: socks5")
$Lines.Add("- Module args: status")
$Lines.Add("- Operational SOCKS/proxy traffic exercised: False")
$Lines.Add("- SOCKS listener/data relay exercised: False")
$Lines.Add("- Real implant tasking path exercised: True")
$Lines.Add("- Session ID: $SessionId")
$Lines.Add("- Task ID: $TaskId")
$Lines.Add("- Result bytes: $ResultBytes")
$Lines.Add("- Beacon check-ins: $BeaconCheckins")
$Lines.Add("- Payload: $Payload")
$Lines.Add("- Loader log: $LoaderLog")
$Lines.Add("")
$Lines.Add("## Commands")
$Lines.Add("")
foreach ($Item in $Commands) {
    $Status = if ($Item.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }
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
$Lines.Add("- This proves the SOCKS5 module artifact can be packaged, dispatched, loaded, and completed through the local implant/listener tasking path.")
$Lines.Add("- This does not prove SOCKS5 connect, relay, close, throughput, or multi-connection behavior.")
$Lines.Add("- No SOCKS listener, target connection, or proxy data relay is exercised by this smoke.")

$Lines | Set-Content -Path $Report -Encoding UTF8

Write-Host "Report: $Report"
if ($AnyFailed) {
    throw "SOCKS5 module loader smoke failed. See $Report"
}

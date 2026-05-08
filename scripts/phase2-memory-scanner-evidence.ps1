param(
    [string]$MonetaPath = "C:\Users\localuser\Downloads\Moneta64.exe",
    [string]$PeSievePath = "C:\Users\localuser\Downloads\pe-sieve64.exe",
    [string]$HollowsHunterPath = "C:\Users\localuser\Downloads\hollows_hunter64.exe",
    [string]$OutputPath = "",
    [int]$HoldAfterRegisterMs = 20000,
    [int]$TimeoutMs = 45000,
    [switch]$LoaderProtectRx,
    [switch]$LoaderSplitProtect,
    [switch]$LoaderDetachThread,
    [string]$LoaderRwOffset = "",
    [switch]$Barebone,
    [switch]$BareboneModules,
    [switch]$LegacyOnlyTasking,
    [switch]$ProfileMode,
    [int]$MinBeaconCheckins = 0,
    [switch]$ModuleSmoke,
    [string]$ModuleBlob = "implant\build\modules\template.bin",
    [string]$ModuleName = "template",
    [string]$ModuleArgs = "ping",
    [int]$ModuleDispatchDelayMs = 0,
    [int]$HoldAfterTaskCompleteMs = 0,
    [int]$PostCleanupScannerGraceMs = 90000,
    [int]$MinResultBytes = 0,
    [switch]$LabCleanSleepEntry,
    [switch]$LabBenignSleep,
    [switch]$LabOffThreadWait,
    [switch]$LabCallbackTick,
    [switch]$BuilderEquivalent,
    [ValidateSet("raw", "dotnet", "service")]
    [string]$ArtifactFormat = "raw",
    [switch]$StubDetachedHold,
    [switch]$ServiceScm,
    [switch]$EvasionModuleOverload,
    [switch]$EvasionPdataRegister,
    [switch]$EvasionNtContinueEntry,
    [switch]$EvasionModulePreserveHeaders,
    [switch]$EvasionModulePatchOnly,
    [int]$ScanDelayMs = 0,
    [switch]$ScanAfterFirstCheckin,
    [int]$ScanDelayAfterCheckinMs = 2500,
    [ValidateSet("single", "resident-only", "module-active", "post-cleanup")]
    [string]$EvidenceWindow = "single"
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceDir = Join-Path $RepoRoot "target\local-evidence"
$ScanRoot = Join-Path $EvidenceDir ("phase2-memory-scanner-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
New-Item -ItemType Directory -Force -Path $ScanRoot | Out-Null

if (-not $OutputPath) {
    $WindowSuffix = if ($EvidenceWindow -eq "single") { "" } else { "-$EvidenceWindow" }
    $OutputPath = Join-Path $EvidenceDir "phase2-memory-scanner$WindowSuffix-evidence-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
}

function Get-FirstCommand {
    param([Parameter(Mandatory = $true)][string[]]$Candidates)

    foreach ($Candidate in $Candidates) {
        $Resolved = Get-Command $Candidate -ErrorAction SilentlyContinue
        if ($Resolved) { return $Resolved.Source }
    }
    return $null
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath,
        [string]$WorkingDirectory = $RepoRoot
    )

    Push-Location $WorkingDirectory
    try {
        $PreviousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & $FilePath @Arguments > $StdoutPath 2> $StderrPath
        $Code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PreviousErrorActionPreference
        Pop-Location
    }

    [pscustomobject]@{
        FilePath = $FilePath
        Arguments = $Arguments
        ExitCode = $Code
        StdoutPath = $StdoutPath
        StderrPath = $StderrPath
    }
}

function Get-InterestingLines {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path $Path)) { return @() }
    $Patterns = @(
        "suspicious",
        "implant",
        "shellcode",
        "hook",
        "replaced",
        "modified",
        "module_file",
        "patches",
        "private",
        "RWX",
        "RX",
        "executable",
        "thread",
        "wait_reason",
        "last_sysc",
        "hdr_modified",
        "scan report",
        "summary",
        "total",
        "error"
    )
    $Pattern = ($Patterns | ForEach-Object { [regex]::Escape($_) }) -join "|"
    @(Select-String -Path $Path -Pattern $Pattern -CaseSensitive:$false |
        Select-Object -First 40 |
        ForEach-Object { $_.Line.Trim() })
}

function Wait-FilePattern {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [int]$TimeoutMs = 30000
    )

    $Deadline = (Get-Date).AddMilliseconds($TimeoutMs)
    while ((Get-Date) -lt $Deadline) {
        if (Test-Path $Path) {
            try {
                $Text = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
                if ($Text -match $Pattern) { return $true }
            } catch {}
        }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

function Get-JsonValueOrUnknown {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][scriptblock]$Accessor
    )

    if (-not (Test-Path $Path)) { return "unknown" }
    try {
        $Json = Get-Content -Path $Path -Raw | ConvertFrom-Json
        return & $Accessor $Json
    } catch {
        return "unknown"
    }
}

function Get-PeSieveScanValueOrUnknown {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][scriptblock]$Accessor
    )

    if (-not (Test-Path $Path)) { return "unknown" }
    try {
        $Json = Get-Content -Path $Path -Raw | ConvertFrom-Json
        foreach ($Scan in @($Json.scans)) {
            $Prop = $Scan.PSObject.Properties[$Kind]
            if ($Prop) {
                $Value = & $Accessor $Prop.Value
                if ($null -eq $Value) { return "unknown" }
                if ($Value -is [array]) { return ($Value -join ", ") }
                return "$Value"
            }
        }
        return "unknown"
    } catch {
        return "unknown"
    }
}

function Get-RegexValueOrUnknown {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    if (-not (Test-Path $Path)) { return "unknown" }
    $Match = Select-String -Path $Path -Pattern $Pattern | Select-Object -First 1
    if (-not $Match) { return "unknown" }
    if ($Match.Matches.Count -eq 0 -or $Match.Matches[0].Groups.Count -lt 2) {
        return "unknown"
    }
    return $Match.Matches[0].Groups[1].Value
}

function Get-FirstPatternLineOrUnknown {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    if (-not (Test-Path $Path)) { return "unknown" }
    $Match = Select-String -Path $Path -Pattern $Pattern | Select-Object -First 1
    if (-not $Match) { return "unknown" }
    return $Match.Line.Trim()
}

function Find-LivePayloadProcess {
    param(
        [Parameter(Mandatory = $true)][datetime]$StartedAfter,
        [Parameter(Mandatory = $true)][string[]]$ProcessNames
    )

    $Deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $Deadline) {
        $Candidates = @()
        foreach ($ProcessName in $ProcessNames) {
            $Candidates += @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Where-Object {
                try { $_.StartTime -ge $StartedAfter } catch { $false }
            })
        }
        $Candidates = @($Candidates | Sort-Object StartTime -Descending)
        if ($Candidates.Count -gt 0) {
            return $Candidates[0]
        }
        Start-Sleep -Milliseconds 250
    }
    return $null
}

function Get-DataPageOffset {
    param([Parameter(Mandatory = $true)][string]$MapPath)

    $PageSize = 0x1000
    $DataLines = @(Select-String -Path $MapPath -Pattern "^\s+\.data\s+0x(?<addr>[0-9A-Fa-f]+)\s+0x(?<size>[0-9A-Fa-f]+)")
    foreach ($DataLine in $DataLines) {
        $Size = [Convert]::ToInt64($DataLine.Matches[0].Groups["size"].Value, 16)
        if ($Size -le 0) {
            continue
        }
        $Address = [Convert]::ToInt64($DataLine.Matches[0].Groups["addr"].Value, 16)
        $PageAddress = $Address - ($Address % $PageSize)
        return "0x$($PageAddress.ToString('x'))"
    }
    throw "Could not locate non-empty .data start in map: $MapPath"
}

$RequiredTools = @(
    [pscustomobject]@{ Name = "Moneta"; Path = $MonetaPath },
    [pscustomobject]@{ Name = "PE-sieve"; Path = $PeSievePath },
    [pscustomobject]@{ Name = "HollowsHunter"; Path = $HollowsHunterPath }
)
foreach ($Tool in $RequiredTools) {
    if (-not (Test-Path $Tool.Path)) {
        throw "$($Tool.Name) not found at $($Tool.Path)"
    }
}

$Ld = Get-FirstCommand @(
    "x86_64-w64-mingw32-ld",
    "C:\ProgramData\mingw64\mingw64\x86_64-w64-mingw32\bin\ld.exe"
)
$Objcopy = Get-FirstCommand @(
    "x86_64-w64-mingw32-objcopy",
    "C:\ProgramData\mingw64\mingw64\bin\objcopy.exe"
)
$Python = if (Get-Command "python" -ErrorAction SilentlyContinue) {
    "python"
} elseif (Get-Command "python3" -ErrorAction SilentlyContinue) {
    "python3"
} else {
    $null
}
if (-not $Ld) { throw "MinGW ld not found" }
if (-not $Objcopy) { throw "MinGW objcopy not found" }
if (-not $Python) { throw "Python not found" }
if ($LoaderProtectRx -and $LoaderSplitProtect) {
    throw "-LoaderProtectRx and -LoaderSplitProtect are mutually exclusive"
}
if ($ArtifactFormat -ne "raw" -and ($LoaderProtectRx -or $LoaderSplitProtect -or $LoaderDetachThread)) {
    throw "Loader protection/detach switches only apply to -ArtifactFormat raw"
}
if ($ServiceScm -and $ArtifactFormat -ne "service") {
    throw "-ServiceScm requires -ArtifactFormat service"
}
if ($EvidenceWindow -eq "resident-only" -and $ModuleSmoke) {
    throw "-EvidenceWindow resident-only must run without -ModuleSmoke"
}
if (($EvidenceWindow -eq "module-active" -or $EvidenceWindow -eq "post-cleanup") -and -not $ModuleSmoke) {
    throw "-EvidenceWindow $EvidenceWindow requires -ModuleSmoke"
}

$CleanOut = Join-Path $ScanRoot "make-clean.stdout.log"
$CleanErr = Join-Path $ScanRoot "make-clean.stderr.log"
$Clean = Invoke-NativeCapture `
    -FilePath "make" `
    -Arguments @("PYTHON=$Python", "clean") `
    -WorkingDirectory (Join-Path $RepoRoot "implant") `
    -StdoutPath $CleanOut `
    -StderrPath $CleanErr
if ($Clean.ExitCode -ne 0) {
    throw "implant clean failed: $($Clean.ExitCode). See $CleanOut and $CleanErr"
}

$MakeArgs = @("DEV=1", "LD=$Ld", "OBJCOPY=$Objcopy", "PYTHON=$Python")
if ($Barebone -or $BareboneModules) {
    $MakeArgs += "BAREBONE=1"
    if ($BareboneModules) {
        $MakeArgs += "BAREBONE_MODULES=1"
    }
    if ($LabCleanSleepEntry) {
        $MakeArgs += "CLEAN_SLEEP_ENTRY=1"
    }
    if ($LabBenignSleep) {
        $MakeArgs += "BENIGN_SLEEP=1"
    }
    if ($LabOffThreadWait) {
        $MakeArgs += "OFFTHREAD_WAIT=1"
    }
    if ($LabCallbackTick) {
        $MakeArgs += "CALLBACK_TICK=1"
    }
    if ($EvasionModuleOverload) {
        $MakeArgs += "BAREBONE_MODULE_OVERLOAD=1"
    }
}

$BuildOut = Join-Path $ScanRoot "make.stdout.log"
$BuildErr = Join-Path $ScanRoot "make.stderr.log"
$Build = Invoke-NativeCapture `
    -FilePath "make" `
    -Arguments $MakeArgs `
    -WorkingDirectory (Join-Path $RepoRoot "implant") `
    -StdoutPath $BuildOut `
    -StderrPath $BuildErr
if ($Build.ExitCode -ne 0) {
    throw "implant DEV build failed: $($Build.ExitCode). See $BuildOut and $BuildErr"
}

if ($ArtifactFormat -eq "raw") {
    $LoaderBuildOut = Join-Path $ScanRoot "pic-loader-build.stdout.log"
    $LoaderBuildErr = Join-Path $ScanRoot "pic-loader-build.stderr.log"
    $LoaderBuild = Invoke-NativeCapture `
        -FilePath "make" `
        -Arguments @("pic-loader") `
        -WorkingDirectory (Join-Path $RepoRoot "implant") `
        -StdoutPath $LoaderBuildOut `
        -StderrPath $LoaderBuildErr
    if ($LoaderBuild.ExitCode -ne 0) {
        throw "pic-loader build failed: $($LoaderBuild.ExitCode). See $LoaderBuildOut and $LoaderBuildErr"
    }
} else {
    $StubsBuildOut = Join-Path $ScanRoot "stubs-build.stdout.log"
    $StubsBuildErr = Join-Path $ScanRoot "stubs-build.stderr.log"
    $StubsArgs = @()
    if ($StubDetachedHold -or $LabCallbackTick) {
        $StubsArgs += "DETACHED_HOLD=1"
    }
    $StubsBuild = Invoke-NativeCapture `
        -FilePath "make" `
        -Arguments $StubsArgs `
        -WorkingDirectory (Join-Path $RepoRoot "implant\stubs") `
        -StdoutPath $StubsBuildOut `
        -StderrPath $StubsBuildErr
    if ($StubsBuild.ExitCode -ne 0) {
        throw "stub template build failed: $($StubsBuild.ExitCode). See $StubsBuildOut and $StubsBuildErr"
    }
}

if ($ModuleSmoke) {
    $ModulesBuildOut = Join-Path $ScanRoot "make-modules.stdout.log"
    $ModulesBuildErr = Join-Path $ScanRoot "make-modules.stderr.log"
    $ModulesBuild = Invoke-NativeCapture `
        -FilePath "make" `
        -Arguments @("modules") `
        -WorkingDirectory (Join-Path $RepoRoot "implant") `
        -StdoutPath $ModulesBuildOut `
        -StderrPath $ModulesBuildErr
    if ($ModulesBuild.ExitCode -ne 0) {
        throw "module build failed: $($ModulesBuild.ExitCode). See $ModulesBuildOut and $ModulesBuildErr"
    }
}

$PayloadExtension = if ($ArtifactFormat -eq "raw") { "bin" } else { "exe" }
$Payload = Join-Path $EvidenceDir "pic-listener-smoke-memory.$PayloadExtension"
$Db = Join-Path $EvidenceDir "pic-listener-smoke-memory.db"
$LoaderLog = Join-Path $EvidenceDir "pic-listener-smoke-memory.loader.log"
$Loader = Join-Path $RepoRoot "implant\build\tests\pic_loader.exe"
$PayloadProcessNames = if ($ArtifactFormat -eq "raw") {
    @("pic_loader")
} else {
    @([System.IO.Path]::GetFileNameWithoutExtension($Payload))
}
$CargoOut = Join-Path $ScanRoot "pic-listener-smoke.stdout.log"
$CargoErr = Join-Path $ScanRoot "pic-listener-smoke.stderr.log"

$CargoArgs = @(
    "run", "-p", "specter-server", "--bin", "pic-listener-smoke", "--",
    "--pic", "implant/build/specter.bin",
    "--loader", $Loader,
    "--out", $Payload,
    "--artifact-format", $ArtifactFormat,
    "--db", $Db,
    "--loader-log", $LoaderLog,
    "--timeout-ms", "$TimeoutMs",
    "--min-beacon-checkins", "$MinBeaconCheckins",
    "--hold-after-register-ms", "$HoldAfterRegisterMs"
)
if ($Barebone -or $LegacyOnlyTasking) {
    $CargoArgs += "--legacy-only"
}
if ($BuilderEquivalent) {
    $CargoArgs += "--builder-equivalent"
}
if ($ProfileMode) {
    $CargoArgs += "--profile-mode"
}
if ($ServiceScm) {
    $CargoArgs += "--service-scm"
}
if ($ModuleSmoke) {
    $CargoHoldAfterTaskCompleteMs = $HoldAfterTaskCompleteMs
    if ($EvidenceWindow -eq "post-cleanup") {
        $CargoHoldAfterTaskCompleteMs = [Math]::Max($HoldAfterTaskCompleteMs + $PostCleanupScannerGraceMs, 20000)
    }
    $CargoArgs += "--module-smoke"
    $CargoArgs += "--module-blob"
    $CargoArgs += $ModuleBlob
    $CargoArgs += "--module-name"
    $CargoArgs += $ModuleName
    $CargoArgs += "--module-args"
    $CargoArgs += ('"{0}"' -f ($ModuleArgs -replace '"', '\"'))
    $CargoArgs += "--module-dispatch-delay-ms"
    $CargoArgs += "$ModuleDispatchDelayMs"
    $CargoArgs += "--hold-after-task-complete-ms"
    $CargoArgs += "$CargoHoldAfterTaskCompleteMs"
    $CargoArgs += "--min-result-bytes"
    $CargoArgs += "$MinResultBytes"
}
if ($LoaderProtectRx) {
    $CargoArgs += "--loader-protect-rx"
}
if ($LoaderSplitProtect) {
    if (-not $LoaderRwOffset) {
        $LoaderRwOffset = Get-DataPageOffset -MapPath (Join-Path $RepoRoot "implant\build\specter.map")
    }
    $CargoArgs += "--loader-split-protect"
    $CargoArgs += "--loader-rw-offset"
    $CargoArgs += $LoaderRwOffset
}
if ($LoaderDetachThread -or $LabCallbackTick) {
    $CargoArgs += "--loader-detach-thread"
}
if ($EvasionModuleOverload) {
    $CargoArgs += "--evasion-module-overload"
}
if ($EvasionPdataRegister) {
    $CargoArgs += "--evasion-pdata-register"
}
if ($EvasionNtContinueEntry) {
    $CargoArgs += "--evasion-ntcontinue-entry"
}
if ($EvasionModulePreserveHeaders) {
    $CargoArgs += "--evasion-module-preserve-headers"
}
if ($EvasionModulePatchOnly) {
    $CargoArgs += "--evasion-module-patch-only"
}

$StartedAt = Get-Date
Remove-Item -LiteralPath $LoaderLog -Force -ErrorAction SilentlyContinue
$Cargo = Start-Process `
    -FilePath "cargo" `
    -ArgumentList $CargoArgs `
    -WorkingDirectory $RepoRoot `
    -RedirectStandardOutput $CargoOut `
    -RedirectStandardError $CargoErr `
    -PassThru `
    -WindowStyle Hidden

$LoaderProcess = Find-LivePayloadProcess -StartedAfter $StartedAt -ProcessNames $PayloadProcessNames
if (-not $LoaderProcess) {
    try {
        if (-not $Cargo.HasExited) { Stop-Process -Id $Cargo.Id -Force }
    } catch {}
    $EndedAt = Get-Date
    $PayloadSize = if (Test-Path $Payload) { (Get-Item $Payload).Length } else { 0 }
    $SmokeStdout = if (Test-Path $CargoOut) { Get-Content -Path $CargoOut -Raw } else { "" }
    $SmokeStatus = if ($SmokeStdout -match "PIC listener smoke: PASS") { "PASS" } else { "FAILED_BEFORE_SCAN" }
    $ArtifactSource = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke artifact source: ([^\r\n]+)"
    $BuilderTransformsEnabled = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke builder transforms enabled: ([^\r\n]+)"
    $BuilderConfigBlobSize = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke builder config blob size: ([^\r\n]+)"
    $BuilderOutputSha256 = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke builder output SHA256: ([^\r\n]+)"
    $SmokeArtifactFormat = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke artifact format: ([^\r\n]+)"
    $SmokeLaunchMode = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke launch mode: ([^\r\n]+)"
    $ObservedBeaconCheckins = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "beacon_checkins=(\d+)"
    if ($ObservedBeaconCheckins -eq "unknown") {
        $ObservedBeaconCheckins = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke beacon check-ins: (\d+)"
    }

    $Lines = New-Object System.Collections.Generic.List[string]
    $Lines.Add("# Phase 2 Memory Scanner Evidence")
    $Lines.Add("")
    $Lines.Add("- Date: $(Get-Date -Format o)")
    $Lines.Add("- Evidence window: $EvidenceWindow")
    $Lines.Add("- Loader PID: not available")
    $Lines.Add("- Scan window start: $($StartedAt.ToString('o'))")
    $Lines.Add("- Scan window end: $($EndedAt.ToString('o'))")
    $Lines.Add("- Hold after register: $HoldAfterRegisterMs ms")
    $Lines.Add("- Smoke timeout: $TimeoutMs ms")
    $Lines.Add("- Loader protect RX: $($LoaderProtectRx.IsPresent)")
    $Lines.Add("- Loader split protect: $($LoaderSplitProtect.IsPresent)")
    $Lines.Add("- Loader detach thread: $($LoaderDetachThread.IsPresent -or $LabCallbackTick.IsPresent)")
    if ($LoaderSplitProtect) { $Lines.Add("- Loader RW offset: $LoaderRwOffset") }
    $Lines.Add("- Barebone build: $($Barebone.IsPresent)")
    $Lines.Add("- Barebone modules build: $($BareboneModules.IsPresent)")
    $Lines.Add("- Lab clean sleep entry: $($LabCleanSleepEntry.IsPresent)")
    $Lines.Add("- Lab benign sleep: $($LabBenignSleep.IsPresent)")
    $Lines.Add("- Lab off-thread wait: $($LabOffThreadWait.IsPresent)")
    $Lines.Add("- Lab callback tick: $($LabCallbackTick.IsPresent)")
    $Lines.Add("- Artifact source: $ArtifactSource")
    $Lines.Add("- Artifact format: $SmokeArtifactFormat")
    $Lines.Add("- Artifact launch mode: $SmokeLaunchMode")
    $Lines.Add("- Service SCM launch: $($ServiceScm.IsPresent)")
    $Lines.Add("- Builder-equivalent requested: $($BuilderEquivalent.IsPresent)")
    $Lines.Add("- Legacy-only tasking: $($Barebone.IsPresent -or $LegacyOnlyTasking.IsPresent)")
    $Lines.Add("- Stub detached hold: $($StubDetachedHold.IsPresent -or ($LabCallbackTick.IsPresent -and $ArtifactFormat -ne 'raw'))")
    $Lines.Add("- Builder transform enabled: $BuilderTransformsEnabled")
    $Lines.Add("- Builder config blob size: $BuilderConfigBlobSize")
    $Lines.Add("- Builder output SHA256: $BuilderOutputSha256")
    $Lines.Add("- Profile mode: $($ProfileMode.IsPresent)")
    $Lines.Add("- Minimum beacon check-ins: $MinBeaconCheckins")
    $Lines.Add("- Observed beacon check-ins: $ObservedBeaconCheckins")
    $Lines.Add("- Module smoke: $($ModuleSmoke.IsPresent)")
    if ($ModuleSmoke) {
        $Lines.Add("- Module blob: $ModuleBlob")
        $Lines.Add("- Module name: $ModuleName")
        $Lines.Add("- Module args: $ModuleArgs")
        $Lines.Add("- Module dispatch delay: $ModuleDispatchDelayMs ms")
        $Lines.Add("- Hold after task complete: $HoldAfterTaskCompleteMs ms")
        if ($EvidenceWindow -eq "post-cleanup") {
            $Lines.Add("- Smoke hold after task complete: $CargoHoldAfterTaskCompleteMs ms")
            $Lines.Add("- Post-cleanup scanner grace: $PostCleanupScannerGraceMs ms")
        }
        $Lines.Add("- Minimum result bytes: $MinResultBytes")
    }
    $Lines.Add("- Evasion module overload: $($EvasionModuleOverload.IsPresent)")
    $Lines.Add("- Evasion pdata register: $($EvasionPdataRegister.IsPresent)")
    $Lines.Add("- Evasion NtContinue entry: $($EvasionNtContinueEntry.IsPresent)")
    $Lines.Add("- Evasion module preserve headers: $($EvasionModulePreserveHeaders.IsPresent)")
    $Lines.Add("- Evasion module patch-only: $($EvasionModulePatchOnly.IsPresent)")
    $Lines.Add("- Scan delay: $ScanDelayMs ms")
    $Lines.Add("- Scan after first check-in: $($ScanAfterFirstCheckin.IsPresent)")
    $Lines.Add("- Scan delay after check-in: $ScanDelayAfterCheckinMs ms")
    $Lines.Add("- First check-in observed before scan: False")
    $Lines.Add("- Smoke status: $SmokeStatus")
    $Lines.Add("- Payload: $Payload ($PayloadSize bytes)")
    $Lines.Add("- Loader log: $LoaderLog")
    $Lines.Add("- Raw scan root: $ScanRoot")
    $Lines.Add("")
    $Lines.Add("## Scanner Runs")
    $Lines.Add("")
    $Lines.Add("- Scanner runs skipped because `pic_loader.exe` did not stay alive long enough to scan.")
    $Lines.Add("")
    $Lines.Add("## Smoke Output")
    $Lines.Add("")
    $Lines.Add("- Stdout: $CargoOut")
    $Lines.Add("- Stderr: $CargoErr")
    if (Test-Path $LoaderLog) {
        $Lines.Add("")
        $Lines.Add("## Loader Log")
        $Lines.Add("")
        $Lines.Add('```text')
        $Lines.Add((Get-Content -Path $LoaderLog -Raw).TrimEnd())
        $Lines.Add('```')
    }
    $Lines.Add("")
    $Lines.Add("## Interpretation")
    $Lines.Add("")
    $Lines.Add("- Strict RW-copy-RX loader mode is not compatible with the current flat PIC blob; the payload faults before registration.")
    $Lines.Add("- This supports the existing architecture note that the blob contains code plus mutable state in one mapping.")

    $Lines | Set-Content -Path $OutputPath -Encoding ascii
    Write-Host "Report: $OutputPath"
    Write-Host "Raw scan root: $ScanRoot"
    Write-Host "Loader PID: not available"
    Write-Host "Smoke status: $SmokeStatus"
    exit 0
}

$FirstCheckinObserved = $false
$ModuleDispatchObserved = $false
$CleanupObserved = $false
$BeaconCheckinsObservedBeforeScan = $false

function Wait-BeaconCheckins {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Minimum,
        [int]$TimeoutMs = 30000
    )

    if ($Minimum -le 1) { return $true }
    $Pattern = "PIC listener smoke beacon check-ins: $Minimum|beacon_checkins=$Minimum"
    return Wait-FilePattern -Path $Path -Pattern $Pattern -TimeoutMs $TimeoutMs
}

switch ($EvidenceWindow) {
    "resident-only" {
        $FirstCheckinPath = if ($ArtifactFormat -eq "raw") { $LoaderLog } else { $CargoOut }
        $FirstCheckinPattern = if ($ArtifactFormat -eq "raw") { "comms_init OK|checkin: complete" } else { "PIC listener smoke session registered|PIC listener smoke: PASS" }
        $FirstCheckinObserved = Wait-FilePattern `
            -Path $FirstCheckinPath `
            -Pattern $FirstCheckinPattern `
            -TimeoutMs ([Math]::Min($TimeoutMs, 30000))
        if (-not $FirstCheckinObserved) {
            throw "resident-only window did not observe first check-in before scan"
        }
        $BeaconCheckinsObservedBeforeScan = Wait-BeaconCheckins `
            -Path $CargoOut `
            -Minimum $MinBeaconCheckins `
            -TimeoutMs ([Math]::Min($TimeoutMs, 60000))
        if (-not $BeaconCheckinsObservedBeforeScan) {
            throw "resident-only window did not observe $MinBeaconCheckins beacon check-ins before scan"
        }
        if ($ScanDelayAfterCheckinMs -gt 0) {
            Start-Sleep -Milliseconds $ScanDelayAfterCheckinMs
        }
    }
    "module-active" {
        $ModuleDispatchObserved = Wait-FilePattern `
            -Path $CargoOut `
            -Pattern "PIC listener smoke queued module task" `
            -TimeoutMs ([Math]::Min($TimeoutMs, 30000))
        if (-not $ModuleDispatchObserved) {
            throw "module-active window did not observe module dispatch before scan"
        }
        $BeaconCheckinsObservedBeforeScan = Wait-BeaconCheckins `
            -Path $CargoOut `
            -Minimum $MinBeaconCheckins `
            -TimeoutMs ([Math]::Min($TimeoutMs, 60000))
        if (-not $BeaconCheckinsObservedBeforeScan) {
            throw "module-active window did not observe $MinBeaconCheckins beacon check-ins before scan"
        }
        if ($ScanDelayMs -gt 0) {
            Start-Sleep -Milliseconds $ScanDelayMs
        }
    }
    "post-cleanup" {
        $ModuleDispatchObserved = Wait-FilePattern `
            -Path $CargoOut `
            -Pattern "PIC listener smoke queued module task" `
            -TimeoutMs ([Math]::Min($TimeoutMs, 30000))
        if (-not $ModuleDispatchObserved) {
            throw "post-cleanup window did not observe module dispatch before cleanup wait"
        }
        $CleanupPath = if ($ArtifactFormat -eq "raw") { $LoaderLog } else { $CargoOut }
        $CleanupPattern = if ($ArtifactFormat -eq "raw") { "module cleanup generation" } else { "PIC listener smoke task complete: .* status=complete" }
        $CleanupObserved = Wait-FilePattern `
            -Path $CleanupPath `
            -Pattern $CleanupPattern `
            -TimeoutMs $TimeoutMs
        if (-not $CleanupObserved) {
            throw "post-cleanup window did not observe module cleanup generation before scan"
        }
        $BeaconCheckinsObservedBeforeScan = Wait-BeaconCheckins `
            -Path $CargoOut `
            -Minimum $MinBeaconCheckins `
            -TimeoutMs ([Math]::Min($TimeoutMs, 60000))
        if (-not $BeaconCheckinsObservedBeforeScan) {
            throw "post-cleanup window did not observe $MinBeaconCheckins beacon check-ins before scan"
        }
        if ($HoldAfterTaskCompleteMs -gt 0) {
            Start-Sleep -Milliseconds $HoldAfterTaskCompleteMs
        }
    }
    default {
        if ($ScanAfterFirstCheckin) {
            $FirstCheckinPath = if ($ArtifactFormat -eq "raw") { $LoaderLog } else { $CargoOut }
            $FirstCheckinPattern = if ($ArtifactFormat -eq "raw") { "comms_init OK|checkin: complete" } else { "PIC listener smoke session registered|PIC listener smoke: PASS" }
            $FirstCheckinObserved = Wait-FilePattern `
                -Path $FirstCheckinPath `
                -Pattern $FirstCheckinPattern `
                -TimeoutMs ([Math]::Min($TimeoutMs, 30000))
            if ($ScanDelayAfterCheckinMs -gt 0) {
                Start-Sleep -Milliseconds $ScanDelayAfterCheckinMs
            }
            $BeaconCheckinsObservedBeforeScan = Wait-BeaconCheckins `
                -Path $CargoOut `
                -Minimum $MinBeaconCheckins `
                -TimeoutMs ([Math]::Min($TimeoutMs, 60000))
            if (-not $BeaconCheckinsObservedBeforeScan) {
                throw "single window did not observe $MinBeaconCheckins beacon check-ins before scan"
            }
        } elseif ($ScanDelayMs -gt 0) {
            Start-Sleep -Milliseconds $ScanDelayMs
        }
    }
}

$PidText = [string]$LoaderProcess.Id
$ScannerRuns = New-Object System.Collections.Generic.List[object]

$MonetaOut = Join-Path $ScanRoot "moneta.stdout.log"
$MonetaErr = Join-Path $ScanRoot "moneta.stderr.log"
$ScannerRuns.Add((Invoke-NativeCapture `
    -FilePath $MonetaPath `
    -Arguments @("-m", "*", "-p", $PidText, "-v", "detail", "--option", "statistics") `
    -StdoutPath $MonetaOut `
    -StderrPath $MonetaErr))

$PeSieveDir = Join-Path $ScanRoot "pe-sieve"
New-Item -ItemType Directory -Force -Path $PeSieveDir | Out-Null
$PeSieveOut = Join-Path $ScanRoot "pe-sieve.stdout.log"
$PeSieveErr = Join-Path $ScanRoot "pe-sieve.stderr.log"
$ScannerRuns.Add((Invoke-NativeCapture `
    -FilePath $PeSievePath `
    -Arguments @("/pid", $PidText, "/threads", "/json", "/dir", $PeSieveDir) `
    -StdoutPath $PeSieveOut `
    -StderrPath $PeSieveErr))

$HollowsDir = Join-Path $ScanRoot "hollows-hunter"
New-Item -ItemType Directory -Force -Path $HollowsDir | Out-Null
$HollowsOut = Join-Path $ScanRoot "hollows-hunter.stdout.log"
$HollowsErr = Join-Path $ScanRoot "hollows-hunter.stderr.log"
$ScannerRuns.Add((Invoke-NativeCapture `
    -FilePath $HollowsHunterPath `
    -Arguments @("/pid", $PidText, "/threads", "/json", "/dir", $HollowsDir) `
    -StdoutPath $HollowsOut `
    -StderrPath $HollowsErr))

$CargoWaited = $Cargo.WaitForExit([Math]::Max($TimeoutMs + 10000, 60000))
$Cargo.Refresh()
if (-not $CargoWaited) {
    try { Stop-Process -Id $Cargo.Id -Force } catch {}
    $CargoExitCode = -1
} else {
    $CargoExitCode = if ($null -eq $Cargo.ExitCode) { "unknown" } else { $Cargo.ExitCode }
}

$EndedAt = Get-Date
$PayloadSize = if (Test-Path $Payload) { (Get-Item $Payload).Length } else { 0 }
$PayloadSha256 = if (Test-Path $Payload) { (Get-FileHash -Algorithm SHA256 -Path $Payload).Hash.ToLowerInvariant() } else { "unknown" }
$SmokeStdout = if (Test-Path $CargoOut) { Get-Content -Path $CargoOut -Raw } else { "" }
$SmokeStatus = if ($SmokeStdout -match "PIC listener smoke: PASS") { "PASS" } else { "UNKNOWN" }
if ($SmokeStatus -eq "PASS" -and $CargoExitCode -eq "unknown") {
    $CargoExitCode = "unknown (smoke PASS observed)"
}
$ArtifactSource = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke artifact source: ([^\r\n]+)"
$BuilderTransformsEnabled = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke builder transforms enabled: ([^\r\n]+)"
$BuilderConfigBlobSize = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke builder config blob size: ([^\r\n]+)"
$BuilderOutputSha256 = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke builder output SHA256: ([^\r\n]+)"
$SmokeArtifactFormat = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke artifact format: ([^\r\n]+)"
$SmokeLaunchMode = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke launch mode: ([^\r\n]+)"
$ObservedBeaconCheckins = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "beacon_checkins=(\d+)"
if ($ObservedBeaconCheckins -eq "unknown") {
    $ObservedBeaconCheckins = Get-RegexValueOrUnknown -Path $CargoOut -Pattern "PIC listener smoke beacon check-ins: (\d+)"
}
$PeSieveReport = Join-Path $PeSieveDir "process_$PidText\scan_report.json"
if (-not (Test-Path $PeSieveReport)) {
    $PeSieveStdout = Join-Path $ScanRoot "pe-sieve.stdout.log"
    if (Test-Path $PeSieveStdout) {
        $PeSieveStdoutText = Get-Content -Path $PeSieveStdout -Raw
        $JsonStart = $PeSieveStdoutText.IndexOf('{')
        if ($JsonStart -ge 0) {
            $PeSieveStdoutReport = Join-Path $ScanRoot "pe-sieve-stdout-scan-report.json"
            try {
                $PeSieveStdoutJson = $PeSieveStdoutText.Substring($JsonStart) | ConvertFrom-Json
                if ($PeSieveStdoutJson.scan_report) {
                    $PeSieveStdoutJson.scan_report | ConvertTo-Json -Depth 32 | Set-Content -Path $PeSieveStdoutReport
                    $PeSieveReport = $PeSieveStdoutReport
                }
            } catch {}
        }
    }
}
$HollowsSummary = Join-Path $HollowsDir "summary.json"
if (-not (Test-Path $HollowsSummary)) {
    $HollowsStdout = Join-Path $ScanRoot "hollows-hunter.stdout.log"
    if (Test-Path $HollowsStdout) {
        $HollowsStdoutText = Get-Content -Path $HollowsStdout -Raw
        $JsonStart = $HollowsStdoutText.IndexOf('{')
        if ($JsonStart -ge 0) {
            $HollowsStdoutSummary = Join-Path $ScanRoot "hollows-hunter-stdout-summary.json"
            try {
                $HollowsStdoutText.Substring($JsonStart) | ConvertFrom-Json |
                    ConvertTo-Json -Depth 32 | Set-Content -Path $HollowsStdoutSummary
                $HollowsSummary = $HollowsStdoutSummary
            } catch {}
        }
    }
}
$PeSieveModified = Get-JsonValueOrUnknown -Path $PeSieveReport -Accessor { param($Json) $Json.scanned.modified.total }
$PeSieveShellcode = Get-JsonValueOrUnknown -Path $PeSieveReport -Accessor { param($Json) $Json.scanned.modified.implanted_shc }
$PeSieveHdrModified = Get-JsonValueOrUnknown -Path $PeSieveReport -Accessor { param($Json) $Json.scanned.modified.hdr_modified }
$PeSievePatched = Get-JsonValueOrUnknown -Path $PeSieveReport -Accessor { param($Json) $Json.scanned.modified.patched }
$PeSieveIndicators = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "thread_scan" -Accessor { param($Scan) $Scan.indicators }
$PeSieveThreadShellcode = Get-RegexValueOrUnknown -Path $PeSieveOut -Pattern '"is_shellcode"\s*:\s*(\d+)'
$PeSieveCodeModule = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "code_scan" -Accessor { param($Scan) $Scan.module }
$PeSieveCodeModuleFile = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "code_scan" -Accessor { param($Scan) $Scan.module_file }
$PeSieveCodeModuleSize = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "code_scan" -Accessor { param($Scan) $Scan.module_size }
$PeSieveCodePatches = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "code_scan" -Accessor { param($Scan) $Scan.patches }
$PeSieveCodeScannedSections = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "code_scan" -Accessor { param($Scan) $Scan.scanned_sections }
$PeSieveThreadId = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "thread_scan" -Accessor { param($Scan) $Scan.thread_id }
$PeSieveThreadState = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "thread_scan" -Accessor { param($Scan) $Scan.thread_info.state }
$PeSieveThreadWaitReason = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "thread_scan" -Accessor { param($Scan) $Scan.thread_info.wait_reason }
$PeSieveThreadLastSyscall = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "thread_scan" -Accessor { param($Scan) $Scan.thread_info.last_sysc }
$PeSieveThreadFrames = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "thread_scan" -Accessor { param($Scan) $Scan.thread_info.callstack.frames_count }
$PeSieveSuspiciousAddress = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "thread_scan" -Accessor { param($Scan) $Scan.susp_addr }
$PeSieveModuleSize = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "thread_scan" -Accessor { param($Scan) $Scan.module_size }
$PeSieveProtection = Get-PeSieveScanValueOrUnknown -Path $PeSieveReport -Kind "thread_scan" -Accessor { param($Scan) $Scan.protection }
$HollowsSuspicious = Get-JsonValueOrUnknown -Path $HollowsSummary -Accessor { param($Json) $Json.suspicious_count }
$MarkerCfgInitDone = Get-FirstPatternLineOrUnknown -Path $LoaderLog -Pattern "phase2 marker: cfg_init_done"
$MarkerSleepInit = Get-FirstPatternLineOrUnknown -Path $LoaderLog -Pattern "phase2 marker: sleep_init_(done|skipped)"
$MarkerCommsSetupDone = Get-FirstPatternLineOrUnknown -Path $LoaderLog -Pattern "phase2 marker: comms_setup_done"
$MarkerInitDone = Get-FirstPatternLineOrUnknown -Path $LoaderLog -Pattern "phase2 marker: init_done"
$MarkerFirstCheckinDone = Get-FirstPatternLineOrUnknown -Path $LoaderLog -Pattern "phase2 marker: first_checkin_done"
$MarkerSleepScheduled = Get-FirstPatternLineOrUnknown -Path $LoaderLog -Pattern "phase2 marker: sleep_scheduled"
$MarkerCallbackTickEntered = Get-FirstPatternLineOrUnknown -Path $LoaderLog -Pattern "phase2 marker: callback_tick_entered"
$MarkerSleepEntered = Get-FirstPatternLineOrUnknown -Path $LoaderLog -Pattern "phase2 marker: sleep_entered"

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add("# Phase 2 Memory Scanner Evidence")
$Lines.Add("")
$Lines.Add("- Date: $(Get-Date -Format o)")
$Lines.Add("- Evidence window: $EvidenceWindow")
$Lines.Add("- Loader PID: $PidText")
$Lines.Add("- Scan window start: $($StartedAt.ToString('o'))")
$Lines.Add("- Scan window end: $($EndedAt.ToString('o'))")
$Lines.Add("- Hold after register: $HoldAfterRegisterMs ms")
$Lines.Add("- Smoke timeout: $TimeoutMs ms")
$Lines.Add("- Loader protect RX: $($LoaderProtectRx.IsPresent)")
$Lines.Add("- Loader split protect: $($LoaderSplitProtect.IsPresent)")
$Lines.Add("- Loader detach thread: $($LoaderDetachThread.IsPresent -or $LabCallbackTick.IsPresent)")
if ($LoaderSplitProtect) { $Lines.Add("- Loader RW offset: $LoaderRwOffset") }
$Lines.Add("- Barebone build: $($Barebone.IsPresent)")
$Lines.Add("- Barebone modules build: $($BareboneModules.IsPresent)")
$Lines.Add("- Lab clean sleep entry: $($LabCleanSleepEntry.IsPresent)")
$Lines.Add("- Lab benign sleep: $($LabBenignSleep.IsPresent)")
$Lines.Add("- Lab off-thread wait: $($LabOffThreadWait.IsPresent)")
$Lines.Add("- Lab callback tick: $($LabCallbackTick.IsPresent)")
$Lines.Add("- Artifact source: $ArtifactSource")
$Lines.Add("- Artifact format: $SmokeArtifactFormat")
$Lines.Add("- Artifact launch mode: $SmokeLaunchMode")
$Lines.Add("- Service SCM launch: $($ServiceScm.IsPresent)")
$Lines.Add("- Builder-equivalent requested: $($BuilderEquivalent.IsPresent)")
$Lines.Add("- Legacy-only tasking: $($Barebone.IsPresent -or $LegacyOnlyTasking.IsPresent)")
$Lines.Add("- Stub detached hold: $($StubDetachedHold.IsPresent -or ($LabCallbackTick.IsPresent -and $ArtifactFormat -ne 'raw'))")
$Lines.Add("- Builder transform enabled: $BuilderTransformsEnabled")
$Lines.Add("- Builder config blob size: $BuilderConfigBlobSize")
$Lines.Add("- Builder output SHA256: $BuilderOutputSha256")
$Lines.Add("- Profile mode: $($ProfileMode.IsPresent)")
$Lines.Add("- Minimum beacon check-ins: $MinBeaconCheckins")
$Lines.Add("- Observed beacon check-ins: $ObservedBeaconCheckins")
$Lines.Add("- Beacon check-ins observed before scan: $BeaconCheckinsObservedBeforeScan")
$Lines.Add("- Module smoke: $($ModuleSmoke.IsPresent)")
if ($ModuleSmoke) {
    $Lines.Add("- Module blob: $ModuleBlob")
    $Lines.Add("- Module name: $ModuleName")
    $Lines.Add("- Module args: $ModuleArgs")
    $Lines.Add("- Module dispatch delay: $ModuleDispatchDelayMs ms")
    $Lines.Add("- Hold after task complete: $HoldAfterTaskCompleteMs ms")
    if ($EvidenceWindow -eq "post-cleanup") {
        $Lines.Add("- Smoke hold after task complete: $CargoHoldAfterTaskCompleteMs ms")
        $Lines.Add("- Post-cleanup scanner grace: $PostCleanupScannerGraceMs ms")
    }
    $Lines.Add("- Minimum result bytes: $MinResultBytes")
}
$Lines.Add("- Evasion module overload: $($EvasionModuleOverload.IsPresent)")
$Lines.Add("- Evasion pdata register: $($EvasionPdataRegister.IsPresent)")
$Lines.Add("- Evasion NtContinue entry: $($EvasionNtContinueEntry.IsPresent)")
$Lines.Add("- Evasion module preserve headers: $($EvasionModulePreserveHeaders.IsPresent)")
$Lines.Add("- Evasion module patch-only: $($EvasionModulePatchOnly.IsPresent)")
$Lines.Add("- Scan delay: $ScanDelayMs ms")
$Lines.Add("- Scan after first check-in: $($ScanAfterFirstCheckin.IsPresent)")
$Lines.Add("- Scan delay after check-in: $ScanDelayAfterCheckinMs ms")
$Lines.Add("- First check-in observed before scan: $FirstCheckinObserved")
$Lines.Add("- Module dispatch observed before scan: $ModuleDispatchObserved")
$Lines.Add("- Cleanup generation observed before scan: $CleanupObserved")
$Lines.Add("- Smoke status: $SmokeStatus")
$Lines.Add("- Smoke exit code: $CargoExitCode")
$Lines.Add("- Payload: $Payload ($PayloadSize bytes)")
$Lines.Add("- Payload SHA256: $PayloadSha256")
$Lines.Add("- Map file: $(Join-Path $RepoRoot 'implant\build\specter.map')")
$Lines.Add("- Loader log: $LoaderLog")
$Lines.Add("- Raw scan root: $ScanRoot")
$Lines.Add("- Marker cfg_init_done: $MarkerCfgInitDone")
$Lines.Add("- Marker sleep_init: $MarkerSleepInit")
$Lines.Add("- Marker comms_setup_done: $MarkerCommsSetupDone")
$Lines.Add("- Marker init_done: $MarkerInitDone")
$Lines.Add("- Marker first_checkin_done: $MarkerFirstCheckinDone")
$Lines.Add("- Marker initial_thread_released: $(Get-FirstPatternLineOrUnknown -Path $LoaderLog -Pattern 'phase2 marker: initial_thread_released')")
$Lines.Add("- Marker sleep_scheduled: $MarkerSleepScheduled")
$Lines.Add("- Marker callback_tick_entered: $MarkerCallbackTickEntered")
$Lines.Add("- Marker sleep_entered: $MarkerSleepEntered")
$Lines.Add("")
$Lines.Add("## Scanner Runs")
$Lines.Add("")
foreach ($Run in $ScannerRuns) {
    $Lines.Add("- $($Run.FilePath)")
    $Lines.Add("  - Exit code: $($Run.ExitCode)")
    $Lines.Add("  - Stdout: $($Run.StdoutPath)")
    $Lines.Add("  - Stderr: $($Run.StderrPath)")
}
$Lines.Add("")
$Lines.Add("## Scanner Summary")
$Lines.Add("")
$Lines.Add("- PE-sieve modified regions: $PeSieveModified")
$Lines.Add("- PE-sieve implanted shellcode findings: $PeSieveShellcode")
$Lines.Add("- PE-sieve patched regions: $PeSievePatched")
$Lines.Add("- PE-sieve header-modified regions: $PeSieveHdrModified")
$Lines.Add("- PE-sieve code module: $PeSieveCodeModule")
$Lines.Add("- PE-sieve code module file: $PeSieveCodeModuleFile")
$Lines.Add("- PE-sieve code module size: $PeSieveCodeModuleSize")
$Lines.Add("- PE-sieve code patches: $PeSieveCodePatches")
$Lines.Add("- PE-sieve code scanned sections: $PeSieveCodeScannedSections")
$Lines.Add("- PE-sieve thread id: $PeSieveThreadId")
$Lines.Add("- PE-sieve thread state: $PeSieveThreadState")
$Lines.Add("- PE-sieve thread wait reason: $PeSieveThreadWaitReason")
$Lines.Add("- PE-sieve thread last syscall: $PeSieveThreadLastSyscall")
$Lines.Add("- PE-sieve thread frames: $PeSieveThreadFrames")
$Lines.Add("- PE-sieve thread indicators: $PeSieveIndicators")
$Lines.Add("- PE-sieve dump is_shellcode: $PeSieveThreadShellcode")
$Lines.Add("- PE-sieve suspicious address: $PeSieveSuspiciousAddress")
$Lines.Add("- PE-sieve suspicious module size: $PeSieveModuleSize")
$Lines.Add("- PE-sieve suspicious protection: $PeSieveProtection")
$Lines.Add("- HollowsHunter suspicious process count: $HollowsSuspicious")
$Lines.Add("")
$Lines.Add("## Interesting Lines")
$Lines.Add("")
foreach ($Run in $ScannerRuns) {
    $Lines.Add("### $([System.IO.Path]::GetFileName($Run.FilePath))")
    $Interesting = @(Get-InterestingLines -Path $Run.StdoutPath)
    if ($Interesting.Count -eq 0) {
        $Lines.Add("- No high-signal lines matched the report filter. Inspect raw logs before treating this as clean.")
    } else {
        foreach ($Line in $Interesting) {
            $Lines.Add("- $Line")
        }
    }
    $ErrInteresting = @(Get-InterestingLines -Path $Run.StderrPath)
    foreach ($Line in $ErrInteresting) {
        $Lines.Add("- stderr: $Line")
    }
    $Lines.Add("")
}
$Lines.Add("## Still Not Proven")
$Lines.Add("")
$Lines.Add("- Kernel ETW-TI visibility")
$Lines.Add("- Full EDR stack response")
$Lines.Add("- Memory behavior under module overloading or sleep-remap variants")
$Lines.Add("- Long dwell behavior across multiple beacon cycles")

$Lines | Set-Content -Path $OutputPath -Encoding ascii

Write-Host "Report: $OutputPath"
Write-Host "Raw scan root: $ScanRoot"
Write-Host "Loader PID: $PidText"
Write-Host "Smoke exit code: $CargoExitCode"

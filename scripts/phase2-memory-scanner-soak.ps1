param(
    [string]$MonetaPath = "C:\Users\localuser\Downloads\Moneta64.exe",
    [string]$PeSievePath = "C:\Users\localuser\Downloads\pe-sieve64.exe",
    [string]$HollowsHunterPath = "C:\Users\localuser\Downloads\hollows_hunter64.exe",
    [ValidateSet("resident-only", "post-cleanup")]
    [string]$EvidenceWindow = "resident-only",
    [int]$Runs = 3,
    [int]$MinBeaconCheckins = 5,
    [int]$HoldAfterRegisterMs = 60000,
    [int]$HoldAfterTaskCompleteMs = 0,
    [int]$PostCleanupScannerGraceMs = 90000,
    [int]$TimeoutMs = 120000,
    [int]$ArtifactUnlockTimeoutMs = 30000,
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

if ($Runs -lt 1) {
    throw "-Runs must be at least 1"
}
if ($MinBeaconCheckins -lt 0) {
    throw "-MinBeaconCheckins must be non-negative"
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceDir = Join-Path $RepoRoot "target\local-evidence"
$EvidenceScript = Join-Path $PSScriptRoot "phase2-memory-scanner-evidence.ps1"
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

if (-not $OutputPath) {
    $OutputPath = Join-Path $EvidenceDir "phase2-memory-scanner-soak-$EvidenceWindow-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
}

function Get-ReportValue {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $EscapedLabel = [regex]::Escape($Label)
    foreach ($Line in $Lines) {
        if ($Line -match "^- $EscapedLabel`: (.*)$") {
            return $Matches[1]
        }
    }
    return "unknown"
}

function Get-ReportSummary {
    param([Parameter(Mandatory = $true)][string]$ReportPath)

    if (-not (Test-Path $ReportPath)) {
        return [pscustomobject]@{
            Report = $ReportPath
            Smoke = "missing_report"
            ObservedBeaconCheckins = "unknown"
            BeaconGate = "unknown"
            ModuleDispatch = "unknown"
            CleanupGeneration = "unknown"
            PeSieveModified = "unknown"
            PeSieveShellcode = "unknown"
            HollowsSuspicious = "unknown"
        }
    }

    $Lines = Get-Content -Path $ReportPath
    return [pscustomobject]@{
        Report = $ReportPath
        Smoke = Get-ReportValue -Lines $Lines -Label "Smoke status"
        ObservedBeaconCheckins = Get-ReportValue -Lines $Lines -Label "Observed beacon check-ins"
        BeaconGate = Get-ReportValue -Lines $Lines -Label "Beacon check-ins observed before scan"
        ModuleDispatch = Get-ReportValue -Lines $Lines -Label "Module dispatch observed before scan"
        CleanupGeneration = Get-ReportValue -Lines $Lines -Label "Cleanup generation observed before scan"
        PeSieveModified = Get-ReportValue -Lines $Lines -Label "PE-sieve modified regions"
        PeSieveShellcode = Get-ReportValue -Lines $Lines -Label "PE-sieve implanted shellcode findings"
        HollowsSuspicious = Get-ReportValue -Lines $Lines -Label "HollowsHunter suspicious process count"
    }
}

function Test-PathUnlocked {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path $Path)) { return $true }
    $Stream = $null
    try {
        $Stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        return $true
    } catch {
        return $false
    } finally {
        if ($Stream) { $Stream.Dispose() }
    }
}

function Wait-ForReusableArtifactPaths {
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $Paths = @(
        (Join-Path $EvidenceDir "pic-listener-smoke-memory.exe"),
        (Join-Path $EvidenceDir "pic-listener-smoke-memory.db"),
        (Join-Path $EvidenceDir "pic-listener-smoke-memory.loader.log")
    )
    $Deadline = (Get-Date).AddMilliseconds($TimeoutMs)
    while ((Get-Date) -lt $Deadline) {
        $Locked = @($Paths | Where-Object { -not (Test-PathUnlocked -Path $_) })
        if ($Locked.Count -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

$Rows = New-Object System.Collections.Generic.List[object]
$Failures = New-Object System.Collections.Generic.List[string]
$Warnings = New-Object System.Collections.Generic.List[string]

for ($Index = 1; $Index -le $Runs; $Index++) {
    if (-not (Wait-ForReusableArtifactPaths -TimeoutMs $ArtifactUnlockTimeoutMs)) {
        $Warnings.Add("Run ${Index}: reusable smoke artifact paths remained locked after $ArtifactUnlockTimeoutMs ms before launch") | Out-Null
    }

    $ReportPath = Join-Path $EvidenceDir "phase2-memory-scanner-soak-$EvidenceWindow-run$Index-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
    Write-Host "[$Index/$Runs] Running $EvidenceWindow service SCM dwell evidence..."

    $EvidenceParams = @{
        MonetaPath = $MonetaPath
        PeSievePath = $PeSievePath
        HollowsHunterPath = $HollowsHunterPath
        OutputPath = $ReportPath
        TimeoutMs = $TimeoutMs
        MinBeaconCheckins = $MinBeaconCheckins
        LabCallbackTick = $true
        BuilderEquivalent = $true
        ArtifactFormat = "service"
        ServiceScm = $true
        EvidenceWindow = $EvidenceWindow
    }

    if ($EvidenceWindow -eq "resident-only") {
        $EvidenceParams.Barebone = $true
        $EvidenceParams.HoldAfterRegisterMs = $HoldAfterRegisterMs
        $EvidenceParams.ScanDelayAfterCheckinMs = 0
    } else {
        $EvidenceParams.BareboneModules = $true
        $EvidenceParams.ModuleSmoke = $true
        $EvidenceParams.HoldAfterTaskCompleteMs = $HoldAfterTaskCompleteMs
        $EvidenceParams.PostCleanupScannerGraceMs = $PostCleanupScannerGraceMs
    }

    try {
        & $EvidenceScript @EvidenceParams
        $ExitCode = 0
    } catch {
        $ExitCode = 1
        $Failures.Add("Run ${Index}: $($_.Exception.Message)") | Out-Null
    }

    $Summary = Get-ReportSummary -ReportPath $ReportPath
    if ($Summary.Smoke -ne "PASS") {
        $Failures.Add("Run ${Index}: smoke status was $($Summary.Smoke)") | Out-Null
    }
    if ($Summary.BeaconGate -ne "True") {
        $Failures.Add("Run ${Index}: beacon gate was $($Summary.BeaconGate)") | Out-Null
    }
    if ($Summary.PeSieveModified -ne "0" -or $Summary.PeSieveShellcode -ne "0" -or $Summary.HollowsSuspicious -ne "0") {
        $Failures.Add("Run ${Index}: scanner summary was PE-sieve modified=$($Summary.PeSieveModified), implanted_shc=$($Summary.PeSieveShellcode), HollowsHunter=$($Summary.HollowsSuspicious)") | Out-Null
    }
    $Rows.Add([pscustomobject]@{
        Run = $Index
        ExitCode = $ExitCode
        Report = $Summary.Report
        Smoke = $Summary.Smoke
        ObservedBeaconCheckins = $Summary.ObservedBeaconCheckins
        BeaconGate = $Summary.BeaconGate
        ModuleDispatch = $Summary.ModuleDispatch
        CleanupGeneration = $Summary.CleanupGeneration
        PeSieveModified = $Summary.PeSieveModified
        PeSieveShellcode = $Summary.PeSieveShellcode
        HollowsSuspicious = $Summary.HollowsSuspicious
    }) | Out-Null
}

$CleanRows = @($Rows | Where-Object {
    $_.ExitCode -eq 0 -and
    $_.Smoke -eq "PASS" -and
    $_.BeaconGate -eq "True" -and
    $_.PeSieveModified -eq "0" -and
    $_.PeSieveShellcode -eq "0" -and
    $_.HollowsSuspicious -eq "0"
})

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add("# Phase 2 Memory Scanner Soak")
$Lines.Add("")
$Lines.Add("- Date: $(Get-Date -Format o)")
$Lines.Add("- Evidence window: $EvidenceWindow")
$Lines.Add("- Runs requested: $Runs")
$Lines.Add("- Runs clean: $($CleanRows.Count)")
$Lines.Add("- Minimum beacon check-ins: $MinBeaconCheckins")
$Lines.Add("- Hold after register: $HoldAfterRegisterMs ms")
$Lines.Add("- Hold after task complete: $HoldAfterTaskCompleteMs ms")
$Lines.Add("- Post-cleanup scanner grace: $PostCleanupScannerGraceMs ms")
$Lines.Add("- Timeout: $TimeoutMs ms")
$Lines.Add("- Artifact unlock timeout: $ArtifactUnlockTimeoutMs ms")
$Lines.Add("- Artifact format: service")
$Lines.Add("- Launch mode: SCM")
$Lines.Add("- Lab callback tick: True")
$Lines.Add("- Builder-equivalent requested: True")
$Lines.Add("")
$Lines.Add("## Runs")
$Lines.Add("")
$Lines.Add("| Run | Exit | Report | Smoke | Check-ins | Beacon gate | Module dispatch | Cleanup | PE-sieve modified | PE-sieve implanted_shc | HollowsHunter suspicious |")
$Lines.Add("| ---: | ---: | --- | --- | ---: | --- | --- | --- | ---: | ---: | ---: |")
foreach ($Row in $Rows) {
    $RelativeReport = Resolve-Path -Path $Row.Report -Relative -ErrorAction SilentlyContinue
    if (-not $RelativeReport) { $RelativeReport = $Row.Report }
    $RelativeReport = $RelativeReport -replace "^\.\\", ""
    $Lines.Add("| $($Row.Run) | $($Row.ExitCode) | ``$RelativeReport`` | $($Row.Smoke) | $($Row.ObservedBeaconCheckins) | $($Row.BeaconGate) | $($Row.ModuleDispatch) | $($Row.CleanupGeneration) | $($Row.PeSieveModified) | $($Row.PeSieveShellcode) | $($Row.HollowsSuspicious) |")
}

if ($Failures.Count -gt 0) {
    $Lines.Add("")
    $Lines.Add("## Failures")
    $Lines.Add("")
    foreach ($Failure in $Failures) {
        $Lines.Add("- $Failure")
    }
}

if ($Warnings.Count -gt 0) {
    $Lines.Add("")
    $Lines.Add("## Warnings")
    $Lines.Add("")
    foreach ($Warning in $Warnings) {
        $Lines.Add("- $Warning")
    }
}

$Lines | Set-Content -Path $OutputPath -Encoding ascii
Write-Host "Soak summary: $OutputPath"

if ($CleanRows.Count -ne $Runs) {
    exit 1
}

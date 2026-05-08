param(
    [string]$OutputPath = "",
    [string]$RawJsonPath = "",
    [ValidateSet("resident-only", "post-cleanup")]
    [string]$EvidenceWindow = "resident-only",
    [int]$MinBeaconCheckins = 5,
    [int]$HoldAfterRegisterMs = 60000,
    [int]$HoldAfterTaskCompleteMs = 30000,
    [int]$PostCleanupScannerGraceMs = 90000,
    [int]$TimeoutMs = 180000
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceDir = Join-Path $RepoRoot "target\local-evidence"
$EvidenceScript = Join-Path $PSScriptRoot "phase2-memory-scanner-evidence.ps1"
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

if (-not $OutputPath) {
    $OutputPath = Join-Path $EvidenceDir "phase2-service-scm-telemetry-evidence-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
}
if (-not $RawJsonPath) {
    $RawJsonPath = [System.IO.Path]::ChangeExtension($OutputPath, ".json")
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

function Convert-EventRecord {
    param(
        [Parameter(Mandatory = $true)]$Event,
        [Parameter(Mandatory = $true)][string]$LogName
    )

    $Xml = [xml]$Event.ToXml()
    $Data = @{}
    foreach ($Node in $Xml.Event.EventData.Data) {
        if ($Node.Name) {
            $Data[$Node.Name] = [string]$Node.'#text'
        }
    }

    [pscustomobject]@{
        TimeCreated = $Event.TimeCreated
        LogName = $LogName
        Provider = $Event.ProviderName
        EventId = $Event.Id
        RecordId = $Event.RecordId
        LevelDisplayName = $Event.LevelDisplayName
        Message = $Event.FormatDescription()
        Data = $Data
    }
}

function Test-RelevantEvent {
    param([Parameter(Mandatory = $true)]$EventObject)

    $Needles = @(
        "SpecterSvc",
        "pic-listener-smoke-memory.exe",
        "pic-listener-smoke-memory.db",
        "SPECTER-C2",
        "specter-server",
        "pic-listener-smoke"
    )

    $Text = @(
        $EventObject.Provider,
        $EventObject.Message,
        ($EventObject.Data.Values -join " ")
    ) -join " "

    foreach ($Needle in $Needles) {
        if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Get-LogStatus {
    param([Parameter(Mandatory = $true)][string]$LogName)

    try {
        $Log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        return [pscustomobject]@{
            LogName = $LogName
            Exists = $true
            IsEnabled = $Log.IsEnabled
            RecordCount = $Log.RecordCount
            LogMode = $Log.LogMode
            MaximumSizeInBytes = $Log.MaximumSizeInBytes
            Error = ""
        }
    } catch {
        return [pscustomobject]@{
            LogName = $LogName
            Exists = $false
            IsEnabled = $false
            RecordCount = 0
            LogMode = ""
            MaximumSizeInBytes = 0
            Error = $_.Exception.Message
        }
    }
}

$CandidateLogs = @(
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Threat-Intelligence/Operational",
    "Microsoft-Windows-Security-Mitigations/UserMode",
    "Microsoft-Windows-Security-Mitigations/KernelMode",
    "System",
    "Application"
)

$LogStatuses = @($CandidateLogs | ForEach-Object { Get-LogStatus -LogName $_ })
$EnabledLogs = @($LogStatuses | Where-Object { $_.Exists -and $_.IsEnabled } | ForEach-Object { $_.LogName })

$RunReport = Join-Path $EvidenceDir "phase2-service-scm-telemetry-run-$EvidenceWindow-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
$CollectionStart = (Get-Date).AddSeconds(-3)

$EvidenceParams = @{
    OutputPath = $RunReport
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

$EvidenceError = ""
try {
    & $EvidenceScript @EvidenceParams
} catch {
    $EvidenceError = $_.Exception.Message
}

$CollectionEnd = (Get-Date).AddSeconds(5)
Start-Sleep -Seconds 2

$RunLines = if (Test-Path $RunReport) { Get-Content -Path $RunReport } else { @() }
$SmokeStatus = Get-ReportValue -Lines $RunLines -Label "Smoke status"
$Checkins = Get-ReportValue -Lines $RunLines -Label "Observed beacon check-ins"
$PeSieveModified = Get-ReportValue -Lines $RunLines -Label "PE-sieve modified regions"
$PeSieveShellcode = Get-ReportValue -Lines $RunLines -Label "PE-sieve implanted shellcode findings"
$HollowsSuspicious = Get-ReportValue -Lines $RunLines -Label "HollowsHunter suspicious process count"

$Events = New-Object System.Collections.Generic.List[object]
foreach ($LogName in $EnabledLogs) {
    $LogEvents = @(Get-WinEvent -FilterHashtable @{
        LogName = $LogName
        StartTime = $CollectionStart
        EndTime = $CollectionEnd
    } -ErrorAction SilentlyContinue)
    foreach ($Event in $LogEvents) {
        $Converted = Convert-EventRecord -Event $Event -LogName $LogName
        if (Test-RelevantEvent -EventObject $Converted) {
            $Events.Add($Converted) | Out-Null
        }
    }
}

$SortedEvents = @($Events | Sort-Object TimeCreated, RecordId)
$SortedEvents | ConvertTo-Json -Depth 8 | Set-Content -Path $RawJsonPath -Encoding ascii

$ByLog = $SortedEvents | Group-Object LogName | Sort-Object Name
$ByProviderId = $SortedEvents |
    Group-Object { "$($_.Provider)#$($_.EventId)" } |
    Sort-Object Count -Descending

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add("# Phase 2 Service SCM Telemetry Evidence")
$Lines.Add("")
$Lines.Add("- Date: $(Get-Date -Format o)")
$Lines.Add("- Evidence window: $EvidenceWindow")
$Lines.Add("- Collection start: $($CollectionStart.ToString('o'))")
$Lines.Add("- Collection end: $($CollectionEnd.ToString('o'))")
$Lines.Add("- Run report: $RunReport")
$Lines.Add("- Raw event JSON: $RawJsonPath")
$Lines.Add("- Evidence error: $(if ($EvidenceError) { $EvidenceError } else { 'none' })")
$Lines.Add("- Smoke status: $SmokeStatus")
$Lines.Add("- Observed beacon check-ins: $Checkins")
$Lines.Add("- PE-sieve modified regions: $PeSieveModified")
$Lines.Add("- PE-sieve implanted shellcode findings: $PeSieveShellcode")
$Lines.Add("- HollowsHunter suspicious process count: $HollowsSuspicious")
$Lines.Add("")
$Lines.Add("## Log Availability")
$Lines.Add("")
foreach ($Status in $LogStatuses) {
    $Lines.Add("- $($Status.LogName): exists=$($Status.Exists), enabled=$($Status.IsEnabled), records=$($Status.RecordCount), error=$($Status.Error)")
}
$Lines.Add("")
$Lines.Add("## Scoped Event Counts")
$Lines.Add("")
$Lines.Add("- Scoped event count: $($SortedEvents.Count)")
if ($ByLog.Count -eq 0) {
    $Lines.Add("- No scoped events matched the service/payload filters.")
} else {
    foreach ($Group in $ByLog) {
        $Lines.Add("- $($Group.Name): $($Group.Count)")
    }
}
$Lines.Add("")
$Lines.Add("## Provider/Event Counts")
$Lines.Add("")
foreach ($Group in ($ByProviderId | Select-Object -First 20)) {
    $Lines.Add("- $($Group.Name): $($Group.Count)")
}
$Lines.Add("")
$Lines.Add("## Selected Events")
$Lines.Add("")
foreach ($EventObject in ($SortedEvents | Select-Object -First 80)) {
    $Summary = ($EventObject.Message -replace "\s+", " ").Trim()
    if ($Summary.Length -gt 240) {
        $Summary = $Summary.Substring(0, 240) + "..."
    }
    $Lines.Add("- $($EventObject.TimeCreated.ToString('o')) [$($EventObject.LogName)] $($EventObject.Provider)#$($EventObject.EventId): $Summary")
}
$Lines.Add("")
$Lines.Add("## Interpretation")
$Lines.Add("")
if (($LogStatuses | Where-Object { $_.LogName -eq "Microsoft-Windows-Threat-Intelligence/Operational" -and $_.Exists -and $_.IsEnabled }).Count -eq 0) {
    $Lines.Add("- Microsoft-Windows-Threat-Intelligence/Operational is not available/enabled on this host, so this run cannot close the ETW-TI gate by itself.")
} else {
    $Lines.Add("- Threat-Intelligence operational log was available; inspect raw JSON for scoped provider events.")
}
$Lines.Add("- This report is a local telemetry capture for the service-SCM lab shape. EDR product-specific validation still requires running the same harness under the target sensor stack.")

$Lines | Set-Content -Path $OutputPath -Encoding ascii
Write-Host "Report: $OutputPath"
Write-Host "Raw JSON: $RawJsonPath"

if ($EvidenceError) {
    throw "Service SCM evidence run failed: $EvidenceError"
}
if ($SmokeStatus -ne "PASS") {
    throw "Service SCM evidence run did not pass. See $RunReport"
}

param(
    [string]$OutputPath = "",
    [string]$RawJsonPath = "",
    [switch]$SkipSmoke
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceDir = Join-Path $RepoRoot "target\local-evidence"
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

if (-not $OutputPath) {
    $OutputPath = Join-Path $EvidenceDir "phase2-sysmon-pic-telemetry-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
}
if (-not $RawJsonPath) {
    $RawJsonPath = [System.IO.Path]::ChangeExtension($OutputPath, ".json")
}

$SysmonLog = "Microsoft-Windows-Sysmon/Operational"
$Log = Get-WinEvent -ListLog $SysmonLog -ErrorAction Stop
if (-not $Log.IsEnabled) {
    throw "Sysmon log is not enabled: $SysmonLog"
}

function Convert-SysmonEvent {
    param([Parameter(Mandatory = $true)]$Event)

    $Xml = [xml]$Event.ToXml()
    $Data = @{}
    foreach ($Node in $Xml.Event.EventData.Data) {
        $Data[$Node.Name] = [string]$Node.'#text'
    }

    [pscustomobject]@{
        TimeCreated = $Event.TimeCreated
        RecordId = $Event.RecordId
        EventId = $Event.Id
        Provider = $Event.ProviderName
        Data = $Data
    }
}

function Get-EventValue {
    param(
        [Parameter(Mandatory = $true)]$EventObject,
        [Parameter(Mandatory = $true)][string]$Key
    )
    if ($EventObject.Data.ContainsKey($Key)) {
        return $EventObject.Data[$Key]
    }
    return ""
}

function Test-RelevantEvent {
    param([Parameter(Mandatory = $true)]$EventObject)

    $Needles = @(
        "pic_loader.exe",
        "specter-server.exe",
        "specter-build.exe",
        "phase2-payload-marker-scan.bin",
        "pic-listener-smoke.bin",
        "pic-listener-smoke.db",
        "SPECTER-C2"
    )

    $Fields = @(
        "Image",
        "ParentImage",
        "CommandLine",
        "ParentCommandLine",
        "TargetFilename",
        "ImageLoaded",
        "TargetImage",
        "SourceImage"
    )

    foreach ($Field in $Fields) {
        $Value = Get-EventValue $EventObject $Field
        if (-not $Value) { continue }
        foreach ($Needle in $Needles) {
            if ($Value.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $true
            }
        }
    }

    $DestinationIp = Get-EventValue $EventObject "DestinationIp"
    $SourceIp = Get-EventValue $EventObject "SourceIp"
    if ($DestinationIp -in @("127.0.0.1", "::1") -or $SourceIp -in @("127.0.0.1", "::1")) {
        $Image = Get-EventValue $EventObject "Image"
        if ($Image -match "pic_loader|specter-server|specter-build|target\\debug|SPECTER-C2") {
            return $true
        }
    }

    return $false
}

function Invoke-Smoke {
    function Invoke-Native {
        param(
            [Parameter(Mandatory = $true)][string]$FilePath,
            [Parameter(Mandatory = $true)][string[]]$Arguments,
            [string]$WorkingDirectory = $RepoRoot
        )

        Push-Location $WorkingDirectory
        try {
            $PreviousErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            $Output = & $FilePath @Arguments 2>&1
            $Code = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $PreviousErrorActionPreference
            Pop-Location
        }

        [pscustomobject]@{
            ExitCode = $Code
            Output = (($Output | ForEach-Object {
                if ($_ -is [System.Management.Automation.ErrorRecord]) {
                    $_.Exception.Message
                } else {
                    $_.ToString()
                }
            }) -join [Environment]::NewLine).TrimEnd()
        }
    }

    $PreviousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $SmokeOutput = New-Object System.Collections.Generic.List[string]

        function Get-FirstCommand {
            param([Parameter(Mandatory = $true)][string[]]$Candidates)
            foreach ($Candidate in $Candidates) {
                $Resolved = Get-Command $Candidate -ErrorAction SilentlyContinue
                if ($Resolved) { return $Resolved.Source }
            }
            return $null
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

        $Build = Invoke-Native `
            -FilePath "make" `
            -Arguments @("DEV=1", "LD=$Ld", "OBJCOPY=$Objcopy", "PYTHON=$Python") `
            -WorkingDirectory (Join-Path $RepoRoot "implant")
        $SmokeOutput.Add("## make DEV=1")
        $SmokeOutput.Add($Build.Output)
        if ($Build.ExitCode -ne 0) {
            return [pscustomobject]@{ ExitCode = $Build.ExitCode; Output = ($SmokeOutput -join [Environment]::NewLine) }
        }

        $LoaderBuild = Invoke-Native `
            -FilePath "make" `
            -Arguments @("pic-loader") `
            -WorkingDirectory (Join-Path $RepoRoot "implant")
        $SmokeOutput.Add("## make pic-loader")
        $SmokeOutput.Add($LoaderBuild.Output)
        if ($LoaderBuild.ExitCode -ne 0) {
            return [pscustomobject]@{ ExitCode = $LoaderBuild.ExitCode; Output = ($SmokeOutput -join [Environment]::NewLine) }
        }

        $Payload = Join-Path $EvidenceDir "pic-listener-smoke.bin"
        $Db = Join-Path $EvidenceDir "pic-listener-smoke.db"
        $LoaderLog = Join-Path $EvidenceDir "pic-listener-smoke.loader.log"
        $Loader = Join-Path $RepoRoot "implant\build\tests\pic_loader.exe"

        $Smoke = Invoke-Native `
            -FilePath "cargo" `
            -Arguments @(
                "run", "-p", "specter-server", "--bin", "pic-listener-smoke", "--",
                "--pic", "implant/build/specter.bin",
                "--loader", $Loader,
                "--out", $Payload,
                "--db", $Db,
                "--loader-log", $LoaderLog,
                "--timeout-ms", "20000"
            )
        $SmokeOutput.Add("## cargo pic-listener-smoke")
        $SmokeOutput.Add($Smoke.Output)
        $Code = $Smoke.ExitCode
    }
    finally {
        $ErrorActionPreference = $PreviousErrorActionPreference
    }

    [pscustomobject]@{
        ExitCode = $Code
        Output = ($SmokeOutput -join [Environment]::NewLine).TrimEnd()
    }
}

$StartTime = (Get-Date).AddSeconds(-2)
$SmokeResult = [pscustomobject]@{ ExitCode = 0; Output = "Skipped by -SkipSmoke" }
if (-not $SkipSmoke) {
    Push-Location $RepoRoot
    try {
        $SmokeResult = Invoke-Smoke
    }
    finally {
        Pop-Location
    }
    if ($SmokeResult.ExitCode -ne 0) {
        throw "PIC listener smoke failed with exit code $($SmokeResult.ExitCode)"
    }
}
$EndTime = (Get-Date).AddSeconds(3)
Start-Sleep -Seconds 2

$Events = Get-WinEvent -FilterHashtable @{
    LogName = $SysmonLog
    StartTime = $StartTime
    EndTime = $EndTime
} -ErrorAction SilentlyContinue | ForEach-Object { Convert-SysmonEvent $_ }

$ScopedEvents = @($Events | Where-Object { Test-RelevantEvent $_ } | Sort-Object TimeCreated, RecordId)
$ScopedEvents | ConvertTo-Json -Depth 8 | Set-Content -Path $RawJsonPath -Encoding ascii

$ById = $ScopedEvents | Group-Object EventId | Sort-Object {[int]$_.Name}
$ByImage = $ScopedEvents |
    ForEach-Object { Get-EventValue $_ "Image" } |
    Where-Object { $_ } |
    Group-Object |
    Sort-Object Count -Descending

$InterestingEvents = $ScopedEvents | Where-Object {
    $_.EventId -in 1,3,7,8,10,11,12,13,15,22,23,25,26
}

$Findings = New-Object System.Collections.Generic.List[string]
if (($ScopedEvents | Where-Object { $_.EventId -eq 1 -and (Get-EventValue $_ "Image") -match "pic_loader.exe" }).Count -gt 0) {
    $Findings.Add("pic_loader.exe process creation observed -> Sysmon Event ID 1 -> expected baseline loader signal -> accept for local harness")
}
if (($ScopedEvents | Where-Object { $_.EventId -eq 3 -and (Get-EventValue $_ "Image") -match "pic_loader.exe" }).Count -gt 0) {
    $Findings.Add("pic_loader.exe localhost network connection observed -> Sysmon Event ID 3 -> expected beacon callback signal -> accept for local harness")
}
if (($ScopedEvents | Where-Object { $_.EventId -eq 10 -and (Get-EventValue $_ "Image") -match "pic_loader.exe" }).Count -gt 0) {
    $Findings.Add("process access involving loader observed -> Sysmon Event ID 10 -> inspect in telemetry lab before enabling injection-style features -> defer")
}
if (($ScopedEvents | Where-Object { $_.EventId -eq 8 -and (Get-EventValue $_ "Image") -match "pic_loader.exe" }).Count -gt 0) {
    $Findings.Add("remote thread involving loader observed -> Sysmon Event ID 8 -> high-signal behavior if present -> investigate")
}
if ($Findings.Count -eq 0) {
    $Findings.Add("No scoped high-signal loader findings beyond collected event counts -> Sysmon source active, but memory-specific gates still need dedicated tooling")
}

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add("# Phase 2 Sysmon PIC Telemetry")
$Lines.Add("")
$Lines.Add("- Date: $(Get-Date -Format o)")
$Lines.Add("- Sysmon log: $SysmonLog")
$Lines.Add("- Collection start: $($StartTime.ToString('o'))")
$Lines.Add("- Collection end: $($EndTime.ToString('o'))")
$Lines.Add("- Smoke command: scripts/pic-listener-smoke.ps1")
$Lines.Add("- Smoke exit code: $($SmokeResult.ExitCode)")
$Lines.Add("- Scoped event count: $($ScopedEvents.Count)")
$Lines.Add("- Raw scoped JSON: $RawJsonPath")
$Lines.Add("")
$Lines.Add("## Smoke Output")
$Lines.Add("")
$Lines.Add('```text')
$Lines.Add($SmokeResult.Output)
$Lines.Add('```')
$Lines.Add("")
$Lines.Add("## Event Counts")
$Lines.Add("")
if ($ById.Count -eq 0) {
    $Lines.Add("- No scoped Sysmon events collected.")
} else {
    foreach ($Group in $ById) {
        $Lines.Add("- Event ID $($Group.Name): $($Group.Count)")
    }
}
$Lines.Add("")
$Lines.Add("## Images")
$Lines.Add("")
foreach ($Group in ($ByImage | Select-Object -First 12)) {
    $Lines.Add("- $($Group.Name): $($Group.Count)")
}
$Lines.Add("")
$Lines.Add("## Findings")
$Lines.Add("")
foreach ($Finding in $Findings) {
    $Lines.Add("- $Finding")
}
$Lines.Add("")
$Lines.Add("## Selected Events")
$Lines.Add("")
foreach ($EventObject in ($InterestingEvents | Select-Object -First 80)) {
    $Image = Get-EventValue $EventObject "Image"
    $CommandLine = Get-EventValue $EventObject "CommandLine"
    $DestinationIp = Get-EventValue $EventObject "DestinationIp"
    $DestinationPort = Get-EventValue $EventObject "DestinationPort"
    $TargetFilename = Get-EventValue $EventObject "TargetFilename"
    $ImageLoaded = Get-EventValue $EventObject "ImageLoaded"
    $SummaryBits = @()
    if ($Image) { $SummaryBits += "Image=$Image" }
    if ($DestinationIp) { $SummaryBits += "Dst=$DestinationIp`:$DestinationPort" }
    if ($TargetFilename) { $SummaryBits += "Target=$TargetFilename" }
    if ($ImageLoaded) { $SummaryBits += "Loaded=$ImageLoaded" }
    if ($CommandLine -and $EventObject.EventId -eq 1) { $SummaryBits += "Cmd=$CommandLine" }
    $Lines.Add("- $($EventObject.TimeCreated.ToString('o')) Event $($EventObject.EventId): $($SummaryBits -join '; ')")
}
$Lines.Add("")
$Lines.Add("## Still Not Proven")
$Lines.Add("")
$Lines.Add("- Memory region type/protection while awake and sleeping")
$Lines.Add("- RW -> copy -> RX transition timing")
$Lines.Add("- Backing-file mismatch visibility for module overloading")
$Lines.Add("- PEB loader-entry consistency")
$Lines.Add("- .pdata unwind behavior under stack walking")
$Lines.Add("- ETW-TI/kernel telemetry visibility")

$Lines | Set-Content -Path $OutputPath -Encoding ascii
Write-Host "Report: $OutputPath"
Write-Host "Raw JSON: $RawJsonPath"

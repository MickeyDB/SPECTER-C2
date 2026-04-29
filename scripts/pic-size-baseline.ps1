param(
    [switch]$Barebone
)

# Build the DEV PIC blob and record a local size baseline for Phase 2/OPSEC work.
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceDir = Join-Path $RepoRoot "target\local-evidence"
$BuildLabel = if ($Barebone) { "Barebone" } else { "Full" }
$ReportName = if ($Barebone) { "pic-size-barebone.txt" } else { "pic-size-baseline.txt" }
$Report = Join-Path $EvidenceDir $ReportName

New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
Set-Location $RepoRoot

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

Push-Location implant
try {
    make clean
    if ($LASTEXITCODE -ne 0) { throw "implant clean failed: $LASTEXITCODE" }

    $CoreArgs = @("DEV=1", "LD=$Ld", "OBJCOPY=$Objcopy", "PYTHON=$Python")
    if ($Barebone) {
        $CoreArgs = @("DEV=1", "BAREBONE=1", "LD=$Ld", "OBJCOPY=$Objcopy", "PYTHON=$Python")
    }

    make @CoreArgs
    if ($LASTEXITCODE -ne 0) { throw "implant DEV build failed: $LASTEXITCODE" }

    make modules "LD=$Ld" "OBJCOPY=$Objcopy" "PYTHON=$Python"
    if ($LASTEXITCODE -ne 0) { throw "implant module build failed: $LASTEXITCODE" }
}
finally {
    Pop-Location
}

$Pic = Join-Path $RepoRoot "implant\build\specter.bin"
if (-not (Test-Path $Pic)) { throw "PIC blob not found: $Pic" }

$PicSize = (Get-Item $Pic).Length
$TargetSize = 20 * 1024
$OverBy = [Math]::Max(0, $PicSize - $TargetSize)

$ModuleLines = Get-ChildItem (Join-Path $RepoRoot "implant\build\modules") -Filter *.bin |
    Sort-Object Name |
    ForEach-Object { "  {0}: {1} bytes" -f $_.Name, $_.Length }

$Lines = @(
    "SPECTER PIC Size Baseline ($BuildLabel)",
    "Date: $(Get-Date -Format o)",
    "PIC: implant/build/specter.bin",
    "Build: $BuildLabel DEV",
    "PIC size: $PicSize bytes",
    "Target size: $TargetSize bytes",
    "Over target: $OverBy bytes",
    "",
    "Modules:"
) + $ModuleLines

$Lines | Set-Content -Path $Report -Encoding ascii
$Lines | ForEach-Object { Write-Host $_ }
Write-Host ""
Write-Host "Report: $Report"

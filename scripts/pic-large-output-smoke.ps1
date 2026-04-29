# Build and execute a raw PIC payload against an in-process listener, then
# queue a shell command that returns more than 64 KiB over encrypted /api/beacon.
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceDir = Join-Path $RepoRoot "target\local-evidence"
$Payload = Join-Path $EvidenceDir "pic-large-output-smoke.bin"
$Db = Join-Path $EvidenceDir "pic-large-output-smoke.db"
$LoaderLog = Join-Path $EvidenceDir "pic-large-output-smoke.loader.log"
$Loader = Join-Path $RepoRoot "implant\build\tests\pic_loader.exe"

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
    make DEV=1 "LD=$Ld" "OBJCOPY=$Objcopy" "PYTHON=$Python"
    if ($LASTEXITCODE -ne 0) { throw "implant DEV build failed: $LASTEXITCODE" }

    make pic-loader
    if ($LASTEXITCODE -ne 0) { throw "pic-loader build failed: $LASTEXITCODE" }
}
finally {
    Pop-Location
}

$LargeCommand = 'for /l %i in (1,1,1800) do @echo SPECTER-LARGE-LINE-%i-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

cargo run -p specter-server --bin pic-listener-smoke -- `
    --pic implant/build/specter.bin `
    --loader $Loader `
    --out $Payload `
    --db $Db `
    --loader-log $LoaderLog `
    --timeout-ms 60000 `
    --task-command $LargeCommand `
    --min-result-bytes 71680 `
    --legacy-only
if ($LASTEXITCODE -ne 0) { throw "PIC large-output smoke failed: $LASTEXITCODE" }

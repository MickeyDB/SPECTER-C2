# Build and execute a configured raw PIC payload in the local loader.
#
# This is a lab smoke, not a full C2 integration test yet. The builder CLI
# creates its own temporary server key, so this validates that the configured
# PIC reaches runtime under the loader without an access violation; listener
# key-aligned beaconing is the next evidence step.
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceDir = Join-Path $RepoRoot "target\local-evidence"
$Payload = Join-Path $EvidenceDir "pic-runtime-smoke.bin"
$LoaderLog = Join-Path $EvidenceDir "pic-runtime-smoke.loader.log"

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

cargo run -p specter-server --bin specter-build -- `
    --pic implant/build/specter.bin `
    --format raw `
    --channel http://127.0.0.1:9/api/checkin `
    --out $Payload `
    --debug `
    --skip-aa `
    --no-obfuscate
if ($LASTEXITCODE -ne 0) { throw "payload build failed: $LASTEXITCODE" }

$Loader = Join-Path $RepoRoot "implant\build\tests\pic_loader.exe"
& $Loader $Payload --timeout-ms 12000 *> $LoaderLog
$LoaderExit = $LASTEXITCODE

Write-Host "PIC runtime smoke loader exit: $LoaderExit"
Write-Host "Loader log: $LoaderLog"

if ($LoaderExit -eq 0xEE) {
    throw "PIC runtime smoke crashed; see $LoaderLog"
}

if ($LoaderExit -eq 124) {
    Write-Host "PIC runtime smoke: PASS (payload executed without exception until timeout)"
    exit 0
}

Write-Host "PIC runtime smoke: PASS (payload exited before timeout with code $LoaderExit)"

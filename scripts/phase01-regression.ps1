# Phase 0.1 local regression evidence runner.
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )

    Write-Host ""
    Write-Host "=== $Name ==="
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

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

Invoke-Step "Rust workspace tests" { cargo test --workspace }

Push-Location web
try {
    Invoke-Step "Web type-check" { npm run type-check }
    Invoke-Step "Web lint" { npm run lint }
    Invoke-Step "Web tests" { npm run test }
    Invoke-Step "Web build" { npm run build }
}
finally {
    Pop-Location
}

Push-Location implant
try {
    Invoke-Step "Implant DEV blob build" {
        make DEV=1 "LD=$Ld" "OBJCOPY=$Objcopy" "PYTHON=$Python"
    }
    Invoke-Step "Implant native tests" { make test }
    Invoke-Step "Implant module build" {
        make modules "LD=$Ld" "OBJCOPY=$Objcopy" "PYTHON=$Python"
    }
}
finally {
    Pop-Location
}

Invoke-Step "Diff whitespace check" { git diff --check }

Write-Host ""
Write-Host "Phase 0.1 regression: PASS"

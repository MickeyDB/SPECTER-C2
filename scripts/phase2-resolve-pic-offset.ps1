param(
    [Parameter(Mandatory = $true)][string]$Offset,
    [string]$ElfPath = "implant\build\specter.elf",
    [string]$MapPath = "implant\build\specter.map",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ElfFullPath = Join-Path $RepoRoot $ElfPath
$MapFullPath = Join-Path $RepoRoot $MapPath
$EvidenceDir = Join-Path $RepoRoot "target\local-evidence"
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

if (-not $OutputPath) {
    $OutputPath = Join-Path $EvidenceDir "phase2-pic-offset-$($Offset -replace '[^0-9A-Fa-f]', '')-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
}

function Resolve-Tool {
    param([Parameter(Mandatory = $true)][string[]]$Candidates)
    foreach ($Candidate in $Candidates) {
        $Command = Get-Command $Candidate -ErrorAction SilentlyContinue
        if ($Command) { return $Command.Source }
        if (Test-Path $Candidate) { return (Resolve-Path $Candidate).Path }
    }
    return $null
}

function Parse-Offset {
    param([Parameter(Mandatory = $true)][string]$Text)
    $Clean = $Text.Trim()
    if ($Clean.StartsWith("0x", [System.StringComparison]::OrdinalIgnoreCase)) {
        return [Convert]::ToInt64($Clean.Substring(2), 16)
    }
    return [Convert]::ToInt64($Clean, 16)
}

$OffsetValue = Parse-Offset $Offset
$Nm = Resolve-Tool @(
    "x86_64-w64-mingw32-nm",
    "nm",
    "C:\ProgramData\mingw64\mingw64\x86_64-w64-mingw32\bin\nm.exe"
)
$Objdump = Resolve-Tool @(
    "x86_64-w64-mingw32-objdump",
    "objdump",
    "C:\ProgramData\mingw64\mingw64\x86_64-w64-mingw32\bin\objdump.exe",
    "C:\ProgramData\mingw64\mingw64\bin\objdump.exe"
)

if (-not $Nm) { throw "nm not found" }
if (-not $Objdump) { throw "objdump not found" }
if (-not (Test-Path $ElfFullPath)) { throw "ELF not found: $ElfFullPath" }
if (-not (Test-Path $MapFullPath)) { throw "Map not found: $MapFullPath" }

$Symbols = New-Object System.Collections.Generic.List[object]
& $Nm -n $ElfFullPath | ForEach-Object {
    if ($_ -match "^(?<addr>[0-9A-Fa-f]+)\s+(?<kind>[A-Za-z])\s+(?<name>.+)$") {
        $Symbols.Add([pscustomobject]@{
            Address = [Convert]::ToInt64($Matches.addr, 16)
            Kind = $Matches.kind
            Name = $Matches.name.Trim()
        })
    }
}

$Nearest = $Symbols |
    Where-Object { $_.Address -le $OffsetValue } |
    Sort-Object Address -Descending |
    Select-Object -First 1
$Next = $Symbols |
    Where-Object { $_.Address -gt $OffsetValue } |
    Sort-Object Address |
    Select-Object -First 1

$MapLines = Get-Content -Path $MapFullPath
$SectionHits = @()
for ($i = 0; $i -lt $MapLines.Count; $i++) {
    $Line = $MapLines[$i]
    if ($Line -match "^\s+(?<section>\.[A-Za-z0-9_$.*]+)\s+0x(?<addr>[0-9A-Fa-f]+)\s+0x(?<size>[0-9A-Fa-f]+)") {
        $Start = [Convert]::ToInt64($Matches.addr, 16)
        $Size = [Convert]::ToInt64($Matches.size, 16)
        if ($OffsetValue -ge $Start -and $OffsetValue -lt ($Start + $Size)) {
            $SectionHits += [pscustomobject]@{
                Section = $Matches.section
                Start = $Start
                Size = $Size
                Line = $Line.Trim()
            }
        }
    }
}

$WindowStart = [Math]::Max(0, $OffsetValue - 64)
$WindowEnd = $OffsetValue + 96
$Disasm = & $Objdump -d -Mintel "--start-address=0x$($WindowStart.ToString('x'))" "--stop-address=0x$($WindowEnd.ToString('x'))" $ElfFullPath

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add("# Phase 2 PIC Offset Resolution")
$Lines.Add("")
$Lines.Add("- Date: $(Get-Date -Format o)")
$Lines.Add("- Offset: 0x$($OffsetValue.ToString('x'))")
$Lines.Add("- ELF: $ElfFullPath")
$Lines.Add("- Map: $MapFullPath")
$Lines.Add("- nm: $Nm")
$Lines.Add("- objdump: $Objdump")
$Lines.Add("")
$Lines.Add("## Symbol")
$Lines.Add("")
if ($Nearest) {
    $Delta = $OffsetValue - $Nearest.Address
    $Lines.Add(("- Nearest symbol: {0} at 0x{1} (+0x{2})" -f $Nearest.Name, $Nearest.Address.ToString('x'), $Delta.ToString('x')))
    $Lines.Add(("- Symbol kind: {0}" -f $Nearest.Kind))
} else {
    $Lines.Add("- No preceding symbol found.")
}
if ($Next) {
    $Lines.Add(("- Next symbol: {0} at 0x{1}" -f $Next.Name, $Next.Address.ToString('x')))
}
$Lines.Add("")
$Lines.Add("## Map Section")
$Lines.Add("")
if ($SectionHits.Count -eq 0) {
    $Lines.Add("- No map section matched the offset.")
} else {
    foreach ($Hit in $SectionHits) {
        $Lines.Add(("- {0} start=0x{1} size=0x{2}" -f $Hit.Section, $Hit.Start.ToString('x'), $Hit.Size.ToString('x')))
    }
}
$Lines.Add("")
$Lines.Add("## Disassembly Window")
$Lines.Add("")
$Lines.Add('```text')
$Lines.Add(($Disasm -join [Environment]::NewLine).TrimEnd())
$Lines.Add('```')
$Lines.Add("")
$Lines.Add("## Interpretation")
$Lines.Add("")
if ($Nearest -and $Nearest.Name -eq "spec_memset") {
    $Lines.Add("- The faulting instruction is the byte store inside `spec_memset`.")
    $Lines.Add("- In the strict RX run, the first observed call path is `implant_entry` zeroing `g_ctx`, so the current flat blob needs writable global state before registration.")
} else {
    $Lines.Add("- Inspect the nearest symbol and call path before drawing an architecture conclusion.")
}

$Lines | Set-Content -Path $OutputPath -Encoding ascii
Write-Host "Report: $OutputPath"

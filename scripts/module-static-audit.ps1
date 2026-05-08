param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceDir = Join-Path $RepoRoot "target\local-evidence"
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

if (-not $OutputPath) {
    $OutputPath = Join-Path $EvidenceDir "module-static-audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
}

$ModuleRoot = Join-Path $RepoRoot "implant\modules"
$ModuleFiles = Get-ChildItem -Path $ModuleRoot -Directory |
    Where-Object { $_.Name -ne "include" } |
    ForEach-Object { Get-ChildItem -Path $_.FullName -Filter "*.c" | Select-Object -First 1 } |
    Where-Object { $_ } |
    Sort-Object FullName

function Get-Matches {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    @([regex]::Matches($Text, $Pattern) | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
}

function Format-CodeList {
    param([object[]]$Items)

    if (-not $Items -or $Items.Count -eq 0) {
        return "none"
    }
    return '`' + ($Items -join '`, `') + '`'
}

$Rows = New-Object System.Collections.Generic.List[object]
foreach ($File in $ModuleFiles) {
    $Text = Get-Content -Path $File.FullName -Raw
    $Module = Split-Path (Split-Path $File.FullName -Parent) -Leaf
    $Subcommands = @(Get-Matches -Text $Text -Pattern 'spec_strcmp\s*\(\s*subcmd\s*,\s*"([^"]+)"\s*\)')
    $BusCalls = @(Get-Matches -Text $Text -Pattern 'api->([A-Za-z0-9_]+)')
    $Resolves = @(Get-Matches -Text $Text -Pattern 'api->resolve\s*\(\s*"([^"]+)"\s*,')
    $HasLongLoop = $Text -match 'while\s*\(\s*1\s*\)|while\s*\(\s*state\.running\s*\)'
    $ErrorReturns = ([regex]::Matches($Text, 'return\s+MODULE_ERR_')).Count
    $AllocCount = ([regex]::Matches($Text, 'api->mem_alloc')).Count
    $FreeCount = ([regex]::Matches($Text, 'api->mem_free')).Count

    $Rows.Add([pscustomobject]@{
        Module = $Module
        File = $File.FullName
        Lines = (Get-Content -Path $File.FullName | Measure-Object -Line).Lines
        Size = $File.Length
        Subcommands = $Subcommands
        BusCalls = $BusCalls
        Resolves = $Resolves
        HasLongLoop = $HasLongLoop
        ErrorReturns = $ErrorReturns
        AllocCount = $AllocCount
        FreeCount = $FreeCount
    }) | Out-Null
}

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add("# Module Static Audit")
$Lines.Add("")
$Lines.Add("- Date: $(Get-Date -Format o)")
$Lines.Add("- Purpose: static inventory for review and validation planning")
$Lines.Add("- Operational behavior exercised: False")
$Lines.Add("")
$Lines.Add("## Summary")
$Lines.Add("")
$Lines.Add("| Module | Lines | Subcommands | Bus APIs | Resolve DLLs | Long loop | Alloc/Free | Error returns |")
$Lines.Add("| --- | ---: | --- | --- | --- | --- | --- | ---: |")
foreach ($Row in $Rows) {
    $Subcommands = Format-CodeList $Row.Subcommands
    $BusCalls = Format-CodeList $Row.BusCalls
    $Resolves = Format-CodeList $Row.Resolves
    $Lines.Add("| $($Row.Module) | $($Row.Lines) | $Subcommands | $BusCalls | $Resolves | $($Row.HasLongLoop) | $($Row.AllocCount)/$($Row.FreeCount) | $($Row.ErrorReturns) |")
}
$Lines.Add("")
$Lines.Add("## Review Notes")
$Lines.Add("")
$Lines.Add("- Modules with long loops need explicit lifecycle and cancellation validation.")
$Lines.Add("- Modules with allocation/free imbalance in this static count require manual review; not every count mismatch is a leak, but every mismatch should be explainable.")
$Lines.Add("- Modules with sensitive bus APIs or high-impact subcommands should remain outside promotion decisions until they have feature-specific tests and approved lab evidence.")
$Lines.Add("- This audit is intentionally static and non-operational.")

$Lines | Set-Content -Path $OutputPath -Encoding ascii
Write-Host "Report: $OutputPath"

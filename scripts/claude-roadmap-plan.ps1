#Requires -Version 5.1
<#
.SYNOPSIS
  Run Claude Code CLI to review docs/roadmap.md and emit a delta plan.

.PARAMETER MaxBudgetUsd
  Cap for API spend (Claude Code --max-budget-usd).

.PARAMETER PromptFile
  Override prompt path (default: claude-roadmap-plan-prompt.txt next to this script).
#>
param(
    [decimal]$MaxBudgetUsd = 5,
    [string]$PromptFile = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
if (-not $PromptFile) {
    $PromptFile = Join-Path $ScriptDir "claude-roadmap-plan-prompt.txt"
}
if (-not (Test-Path -LiteralPath $PromptFile)) {
    Write-Error "Prompt file not found: $PromptFile"
}
Set-Location $RepoRoot
$prompt = Get-Content -LiteralPath $PromptFile -Raw
$budgetArg = "--max-budget-usd", ([string]$MaxBudgetUsd)
& claude -p $prompt --permission-mode bypassPermissions --output-format text @budgetArg

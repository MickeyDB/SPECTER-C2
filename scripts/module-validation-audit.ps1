param(
    [string]$OutputPath = "",
    [switch]$SkipBuild,
    [switch]$SkipRustTests
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EvidenceDir = Join-Path $RepoRoot "target\local-evidence"
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

if (-not $OutputPath) {
    $OutputPath = Join-Path $EvidenceDir "module-validation-audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
}

function Invoke-Capture {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$WorkingDirectory = $RepoRoot
    )

    $StartedAt = Get-Date
    Push-Location $WorkingDirectory
    try {
        $PreviousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $RawOutput = & $FilePath @Arguments 2>&1
        $ExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $PreviousErrorActionPreference
        Pop-Location
    }

    $Output = ($RawOutput | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $_.Exception.Message
        } else {
            $_.ToString()
        }
    }) -join [Environment]::NewLine

    [pscustomobject]@{
        Name = $Name
        Command = "$FilePath $($Arguments -join ' ')"
        ExitCode = $ExitCode
        DurationSeconds = [Math]::Round(((Get-Date) - $StartedAt).TotalSeconds, 2)
        Output = $Output.TrimEnd()
    }
}

$Commands = New-Object System.Collections.Generic.List[object]

if (-not $SkipBuild) {
    $Commands.Add((Invoke-Capture `
        -Name "Build implant modules" `
        -FilePath "make" `
        -Arguments @("-C", "implant", "modules"))) | Out-Null
}

if (-not $SkipRustTests) {
    $Commands.Add((Invoke-Capture `
        -Name "SOCKS manager tests" `
        -FilePath "cargo" `
        -Arguments @("test", "-p", "specter-server", "--test", "socks_tests", "--", "--nocapture"))) | Out-Null
    $Commands.Add((Invoke-Capture `
        -Name "Module repository tests" `
        -FilePath "cargo" `
        -Arguments @("test", "-p", "specter-server", "--test", "module_repo_tests", "--", "--nocapture"))) | Out-Null
}

$ModuleDir = Join-Path $RepoRoot "implant\build\modules"
$Modules = @()
if (Test-Path $ModuleDir) {
    $Modules = Get-ChildItem -Path $ModuleDir -Filter "*.bin" |
        Sort-Object BaseName |
        ForEach-Object {
            [pscustomobject]@{
                Name = $_.BaseName
                Path = $_.FullName
                Size = $_.Length
                SHA256 = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
            }
        }
}

$ExpectedModules = @("collect", "exfil", "inject", "lateral", "smoke", "socks5", "template", "token")
$MissingModules = @($ExpectedModules | Where-Object { $_ -notin @($Modules | ForEach-Object { $_.Name }) })
$AnyFailed = (($Commands | Where-Object { $_.ExitCode -ne 0 }).Count -gt 0) -or ($MissingModules.Count -gt 0)

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add("# Module Validation Audit")
$Lines.Add("")
$Lines.Add("- Date: $(Get-Date -Format o)")
$Lines.Add("- Purpose: non-operational module build/test inventory")
$Lines.Add("- Operational SOCKS/proxy traffic exercised: False")
$Lines.Add("- Implant service-SCM execution exercised by this script: False")
$Lines.Add("- Missing expected modules: $(if ($MissingModules.Count) { $MissingModules -join ', ' } else { 'none' })")
$Lines.Add("")
$Lines.Add("## Module Artifacts")
$Lines.Add("")
$Lines.Add("| Module | Size | SHA256 | Build artifact |")
$Lines.Add("| --- | ---: | --- | --- |")
foreach ($Module in $Modules) {
    $Relative = Resolve-Path -Path $Module.Path -Relative
    $Relative = $Relative -replace "^\.\\", ""
    $Lines.Add(("| {0} | {1} | `{2}` | `{3}` |" -f $Module.Name, $Module.Size, $Module.SHA256, $Relative))
}
$Lines.Add("")
$Lines.Add("## Checks")
foreach ($Command in $Commands) {
    $Status = if ($Command.ExitCode -eq 0) { "PASS" } else { "FAIL" }
    $Lines.Add("")
    $Lines.Add("### $($Command.Name): $Status")
    $Lines.Add("")
    $Lines.Add("- Command: $($Command.Command)")
    $Lines.Add("- Exit code: $($Command.ExitCode)")
    $Lines.Add("- Duration: $($Command.DurationSeconds) seconds")
    if ($Command.Output) {
        $Lines.Add("")
        $Lines.Add('```text')
        $Lines.Add($Command.Output)
        $Lines.Add('```')
    }
}
$Lines.Add("")
$Lines.Add("## Validation Boundaries")
$Lines.Add("")
$Lines.Add("- This script proves module artifacts build and selected server-side module/SOCKS manager tests pass.")
$Lines.Add("- It does not prove real module execution inside an implant.")
$Lines.Add("- It does not prove SOCKS5 end-to-end pivoting, remote connection handling, or data relay.")
$Lines.Add("- It does not perform stealth, evasion, or OPSEC optimization.")

$Lines | Set-Content -Path $OutputPath -Encoding ascii
Write-Host "Report: $OutputPath"

if ($AnyFailed) {
    throw "Module validation audit failed. See $OutputPath"
}

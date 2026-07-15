param(
    [string]$Distribution = "Ubuntu-24.04",
    [string[]]$Test = @()
)

$ErrorActionPreference = "Stop"
function Convert-ToWslPath([string]$Path) {
    $resolved = (Resolve-Path $Path).Path
    if ($resolved -notmatch '^([A-Za-z]):\\(.*)$') {
        throw "Only local Windows drive paths are supported: $resolved"
    }
    $drive = $Matches[1].ToLowerInvariant()
    $tail = $Matches[2].Replace('\', '/')
    return "/mnt/$drive/$tail"
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$wslRepo = Convert-ToWslPath $repo
$arguments = @("-d", $Distribution, "-u", "root", "--cd", $wslRepo, "--", "bash", "scripts/run_packetdrill.sh")
foreach ($path in $Test) {
    $arguments += Convert-ToWslPath $path
}

& wsl @arguments
exit $LASTEXITCODE

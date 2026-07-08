param(
    [int]$Duration = 15,
    [int]$Parallel = 1,
    [string]$ServerAddress = "127.0.0.1",
    [int]$ServerPort = 5201,
    [string]$ProxyAddress = "10.1.0.2",
    [int]$Warmup = 3,
    [switch]$Reverse,
    [switch]$Json,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

function Assert-Command($Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name not found in PATH"
    }
}

$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "tcp_proxy creates a TUN device; rerun this script from an Administrator PowerShell."
}

Assert-Command cargo
Assert-Command iperf3

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

if (-not $SkipBuild) {
    cargo build --release --example tcp_proxy --features global-ip-stack
}

$ProxyBin = Join-Path $RepoRoot "target\release\examples\tcp_proxy.exe"
if (-not (Test-Path $ProxyBin)) {
    throw "tcp_proxy binary not found: $ProxyBin"
}

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutDir = Join-Path $RepoRoot "target\proxy-perf\$Timestamp"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$ServerLog = Join-Path $OutDir "iperf3-server.log"
$ServerErr = Join-Path $OutDir "iperf3-server.err.log"
$ProxyLog = Join-Path $OutDir "tcp_proxy.log"
$ProxyErr = Join-Path $OutDir "tcp_proxy.err.log"
$WarmupLog = Join-Path $OutDir "warmup.txt"
$ResultFile = Join-Path $OutDir "result.txt"
if ($Json) {
    $ResultFile = Join-Path $OutDir "result.json"
}

$OldRustLog = $env:RUST_LOG
if (-not $env:RUST_LOG) {
    $env:RUST_LOG = "warn"
}

$ServerProcess = $null
$ProxyProcess = $null

try {
    $ServerProcess = Start-Process `
        -FilePath "iperf3" `
        -ArgumentList @("-s", "-B", $ServerAddress, "-p", $ServerPort) `
        -RedirectStandardOutput $ServerLog `
        -RedirectStandardError $ServerErr `
        -WindowStyle Hidden `
        -PassThru

    $ProxyProcess = Start-Process `
        -FilePath $ProxyBin `
        -ArgumentList @("--server-addr", "${ServerAddress}:$ServerPort") `
        -RedirectStandardOutput $ProxyLog `
        -RedirectStandardError $ProxyErr `
        -WindowStyle Hidden `
        -PassThru

    Start-Sleep -Seconds 2

    $IperfArgs = @("-c", $ProxyAddress, "-p", $ServerPort, "-P", $Parallel)
    if ($Reverse) {
        $IperfArgs += "-R"
    }

    if ($Warmup -gt 0) {
        Write-Host "warmup: iperf3 $($IperfArgs -join ' ') -t $Warmup"
        & iperf3 @IperfArgs -t $Warmup | Tee-Object -FilePath $WarmupLog
    }

    Write-Host "measured: iperf3 $($IperfArgs -join ' ') -t $Duration"
    if ($Json) {
        & iperf3 @IperfArgs -t $Duration -J | Tee-Object -FilePath $ResultFile
    } else {
        & iperf3 @IperfArgs -t $Duration | Tee-Object -FilePath $ResultFile
    }

    Write-Host "logs: $OutDir"
}
finally {
    if ($ProxyProcess -and -not $ProxyProcess.HasExited) {
        Stop-Process -Id $ProxyProcess.Id -Force
    }
    if ($ServerProcess -and -not $ServerProcess.HasExited) {
        Stop-Process -Id $ServerProcess.Id -Force
    }
    $env:RUST_LOG = $OldRustLog
}

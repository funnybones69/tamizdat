param(
    [int]$Seconds = 45,
    [int]$IntervalMs = 500,
    [string]$DebugVarsUrl = "http://127.0.0.1:16062/debug/vars",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Continue"

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutDir = Join-Path ([Environment]::GetFolderPath("Desktop")) "tamizdat-h2-diag-$stamp"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Save-Command {
    param(
        [string]$Name,
        [scriptblock]$Block
    )
    $path = Join-Path $OutDir $Name
    try {
        & $Block *>&1 | Out-File -FilePath $path -Encoding UTF8
    } catch {
        "ERROR: $($_.Exception.Message)" | Out-File -FilePath $path -Encoding UTF8
    }
}

function Copy-IfExists {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $safe = ($Path -replace "^[A-Za-z]:\\", "" -replace "[\\/:*?`"<>|]", "_")
        Copy-Item -LiteralPath $Path -Destination (Join-Path $OutDir $safe) -Force
        try {
            Get-FileHash -Algorithm SHA256 -LiteralPath $Path |
                Format-List |
                Out-File -Append -FilePath (Join-Path $OutDir "file-hashes.txt") -Encoding UTF8
        } catch {
        }
    }
}

$metaPath = Join-Path $OutDir "meta.txt"
@(
    "timestamp=$((Get-Date).ToString("o"))"
    "computer=$env:COMPUTERNAME"
    "user=$env:USERNAME"
    "seconds=$Seconds"
    "interval_ms=$IntervalMs"
    "debug_vars_url=$DebugVarsUrl"
) | Set-Content -Path $metaPath -Encoding UTF8

Save-Command "processes.txt" {
    Get-CimInstance Win32_Process |
        Where-Object { $_.Name -like "tamizdat*" } |
        Select-Object Name, ProcessId, ParentProcessId, CommandLine, ExecutablePath, CreationDate |
        Format-List
}
Save-Command "routes-route-print.txt" { route print }
Save-Command "routes-netroute-v4.txt" {
    Get-NetRoute -AddressFamily IPv4 |
        Sort-Object DestinationPrefix, RouteMetric, InterfaceIndex |
        Format-Table -AutoSize
}
Save-Command "interfaces-v4.txt" {
    Get-NetIPInterface -AddressFamily IPv4 |
        Sort-Object InterfaceMetric, InterfaceIndex |
        Format-Table -AutoSize InterfaceAlias, InterfaceIndex, AddressFamily, NlMtu, InterfaceMetric, ConnectionState, Dhcp
}
Save-Command "adapters.txt" {
    Get-NetAdapter |
        Sort-Object Name |
        Format-Table -AutoSize Name, InterfaceDescription, ifIndex, Status, LinkSpeed, MacAddress
}
Save-Command "adapter-stats-before.txt" {
    Get-NetAdapterStatistics |
        Sort-Object Name |
        Format-Table -AutoSize Name, ReceivedBytes, SentBytes, ReceivedDiscardedPackets, OutboundDiscardedPackets, ReceivedPacketErrors, OutboundPacketErrors
}
Save-Command "netstat-before.txt" { netstat -ano }

$desktop = [Environment]::GetFolderPath("Desktop")
Copy-IfExists (Join-Path $desktop "tamizdat-tray\config.json")
Copy-IfExists (Join-Path $desktop "tamizdat-tray\tamizdat-tray.log")
Copy-IfExists (Join-Path $env:APPDATA "tamizdat\config.json")
Copy-IfExists (Join-Path $env:LOCALAPPDATA "Tamizdat-Tray\tamizdat-tun-windows.exe")

$cpuPath = Join-Path $OutDir "cpu-samples.csv"
"ts,process,id,cpu_delta_s,cpu_percent_one_core,working_set_mb" |
    Set-Content -Path $cpuPath -Encoding UTF8
$debugVarsPath = Join-Path $OutDir "debug-vars.ndjson"
$prev = @{}
$endAt = (Get-Date).AddSeconds($Seconds)

while ((Get-Date) -lt $endAt) {
    $now = Get-Date
    $procs = Get-Process -Name "tamizdat*" -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        $key = [string]$p.Id
        $cpu = 0.0
        if ($null -ne $p.CPU) {
            $cpu = [double]$p.CPU
        }
        $delta = 0.0
        $pct = 0.0
        if ($prev.ContainsKey($key)) {
            $elapsed = ($now - $prev[$key].Time).TotalSeconds
            if ($elapsed -gt 0) {
                $delta = $cpu - $prev[$key].CPU
                if ($delta -lt 0) { $delta = 0 }
                $pct = ($delta / $elapsed) * 100.0
            }
        }
        $prev[$key] = [pscustomobject]@{ CPU = $cpu; Time = $now }
        $line = "{0},{1},{2},{3:N6},{4:N2},{5:N2}" -f $now.ToString("o"), $p.ProcessName, $p.Id, $delta, $pct, ($p.WorkingSet64 / 1MB)
        Add-Content -Path $cpuPath -Value $line -Encoding UTF8
    }

    try {
        $resp = Invoke-WebRequest -Uri $DebugVarsUrl -UseBasicParsing -TimeoutSec 1
        ([pscustomobject]@{
            ts = $now.ToString("o")
            ok = $true
            status = [int]$resp.StatusCode
            body = $resp.Content
        } | ConvertTo-Json -Compress) | Add-Content -Path $debugVarsPath -Encoding UTF8
    } catch {
        ([pscustomobject]@{
            ts = $now.ToString("o")
            ok = $false
            error = $_.Exception.Message
        } | ConvertTo-Json -Compress) | Add-Content -Path $debugVarsPath -Encoding UTF8
    }

    Start-Sleep -Milliseconds $IntervalMs
}

Save-Command "adapter-stats-after.txt" {
    Get-NetAdapterStatistics |
        Sort-Object Name |
        Format-Table -AutoSize Name, ReceivedBytes, SentBytes, ReceivedDiscardedPackets, OutboundDiscardedPackets, ReceivedPacketErrors, OutboundPacketErrors
}
Save-Command "netstat-after.txt" { netstat -ano }

$zipPath = "$OutDir.zip"
try {
    Compress-Archive -Path (Join-Path $OutDir "*") -DestinationPath $zipPath -Force
    "zip=$zipPath" | Add-Content -Path $metaPath -Encoding UTF8
} catch {
    "zip_error=$($_.Exception.Message)" | Add-Content -Path $metaPath -Encoding UTF8
}

Write-Host "Diagnostics saved to: $OutDir"
if (Test-Path -LiteralPath $zipPath) {
    Write-Host "Archive: $zipPath"
}

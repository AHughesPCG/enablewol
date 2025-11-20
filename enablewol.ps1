<# 
    Enable-WOL.ps1
    Enables Wake on LAN options on Windows NICs where possible.
#>

# Must be admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Must run as administrator"
    exit 1
}

$logPath = "C:\Logs"
if (-not (Test-Path $logPath)) {
    New-Item -Path $logPath -ItemType Directory -Force | Out-Null
}
$logFile = Join-Path $logPath "Enable-WOL.log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp`t$Message" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

Write-Log "========== Starting Enable-WOL =========="

# Get physical, enabled adapters
$adapters = Get-NetAdapter -Physical | Where-Object {
    $_.Status -ne "Disabled" -and $_.HardwareInterface
}

if (-not $adapters) {
    Write-Log "No physical adapters found"
    exit 0
}

# Common WOL property names
$wolProps = @(
    "Wake on Magic Packet",
    "Wake on magic packet",
    "Wake on pattern match",
    "Shutdown Wake-On-Lan",
    "Wake From Shutdown",
    "Wake on LAN",
    "*WakeOnMagicPacket",
    "*WakeOnPattern"
)

foreach ($nic in $adapters) {
    Write-Log "Processing adapter: $($nic.Name) - $($nic.InterfaceDescription)"

    try {
        $adv = Get-NetAdapterAdvancedProperty -Name $nic.Name -ErrorAction Stop
    }
    catch {
        Write-Log "  Could not read advanced properties: $($_.Exception.Message)"
        continue
    }

    foreach ($pattern in $wolProps) {
        $matches = $adv | Where-Object {
            $_.DisplayName -like $pattern -or $_.RegistryKeyword -like $pattern
        }

        foreach ($p in $matches) {
            try {
                Set-NetAdapterAdvancedProperty -Name $nic.Name `
                    -RegistryKeyword $p.RegistryKeyword `
                    -RegistryValue "Enabled" `
                    -NoRestart -ErrorAction Stop
                Write-Log "  Enabled $($p.DisplayName) ($($p.RegistryKeyword))"
            }
            catch {
                Write-Log "  Failed to set $($p.DisplayName): $($_.Exception.Message)"
            }
        }
    }

    try {
        powercfg /deviceenablewake "$($nic.Name)" | Out-Null
        Write-Log "  powercfg /deviceenablewake successful"
    }
    catch {
        Write-Log "  powercfg failed: $($_.Exception.Message)"
    }
}

Write-Log "========== Enable-WOL complete =========="

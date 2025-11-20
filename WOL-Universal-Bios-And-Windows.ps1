<# 
    WOL-Universal-Bios-And-Windows.ps1

    1. Ensures local PartnersCG admin account exists:
       - Username: partnersadmin
       - Local admin group membership
       - If created, prints and logs the password

    2. Detects vendor and model

    3. Attempts to enable Wake on LAN in BIOS on supported systems
       - Lenovo (ThinkCentre, ThinkPad, ThinkStation) via Lenovo WMI
       - Dell with DCIM BIOS WMI
       - HP with Instrumented BIOS WMI

    4. Configures Windows side WOL for all physical NICs

    5. Disables Fast Startup

    6. Logs everything to C:\Logs\WOL-Universal.log
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
$logFile = Join-Path $logPath "WOL-Universal.log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp`t$Message" | Tee-Object -FilePath $logFile -Append
}

Write-Log "========== Starting WOL Universal BIOS + Windows Config =========="

# --------------------------------------------------------------------
# 0. Ensure partnersadmin local admin account exists
# --------------------------------------------------------------------
Write-Log "[Account] Checking for local account 'partnersadmin'"

try {
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue | Out-Null
} catch { }

$partnerUser = $null
try {
    $partnerUser = Get-LocalUser -Name "partnersadmin" -ErrorAction SilentlyContinue
} catch {
    Write-Log "[Account] Get-LocalUser not available: $($_.Exception.Message)"
}

$genericPasswordPlain = "P@rtner5!W0L"   # You can change this later if you want
$genericPassword = ConvertTo-SecureString $genericPasswordPlain -AsPlainText -Force

if (-not $partnerUser) {
    Write-Log "[Account] 'partnersadmin' does not exist. Creating account."
    try {
        $partnerUser = New-LocalUser -Name "partnersadmin" -Password $genericPassword -PasswordNeverExpires:$true -UserMayNotChangePassword:$false -AccountNeverExpires:$true
        Write-Log "[Account] Created local user 'partnersadmin' with default password."
        Write-Host "Created local admin account: partnersadmin / $genericPasswordPlain"
    } catch {
        Write-Log "[Account] FAILED to create 'partnersadmin': $($_.Exception.Message)"
    }
} else {
    Write-Log "[Account] 'partnersadmin' already exists."
    if (-not $partnerUser.Enabled) {
        try {
            Enable-LocalUser -Name "partnersadmin"
            Write-Log "[Account] Enabled 'partnersadmin' account."
        } catch {
            Write-Log "[Account] FAILED to enable 'partnersadmin': $($_.Exception.Message)"
        }
    }
}

# Make sure partnersadmin is local admin
try {
    $isAdmin = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*\partnersadmin" })
    if (-not $isAdmin) {
        Add-LocalGroupMember -Group "Administrators" -Member "partnersadmin" -ErrorAction Stop
        Write-Log "[Account] Added 'partnersadmin' to local Administrators group."
    } else {
        Write-Log "[Account] 'partnersadmin' is already in local Administrators group."
    }
} catch {
    Write-Log "[Account] FAILED to ensure 'partnersadmin' is local admin: $($_.Exception.Message)"
}

# NOTE: Script continues running as the current admin context.
# If you ever want to explicitly re-run under partnersadmin, you can
# do that from your RMM / ScreenConnect using those credentials.

# --------------------------------------------------------------------
# 1. Detect system vendor/model
# --------------------------------------------------------------------
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $vendor = $cs.Manufacturer
    $model  = $cs.Model
    Write-Log "System vendor: $vendor"
    Write-Log "System model:  $model"
    Write-Log "BIOS version:  $($bios.SMBIOSBIOSVersion)"
} catch {
    Write-Log "Failed to read basic system information: $($_.Exception.Message)"
}

# Mini PC / Beelink-style detection hint
if ($vendor -match "Micro Computer" -or $vendor -match "Beelink" -or $model -match "Venus" -or $model -match "Mini PC") {
    Write-Log "[MiniPC] Detected small form factor / white-label board. These often DO NOT support WOL from full shutdown (S5) even when Windows and NIC are configured."
    Write-Log "[MiniPC] Expect WOL from SLEEP to work, but WOL from SHUTDOWN may be blocked by firmware (no NIC standby power, ErP-like behavior)."
}

# --------------------------------------------------------------------
# 2. BIOS-side helper functions
# --------------------------------------------------------------------
function Enable-BiosWolLenovo {
    Write-Log "[Lenovo] Attempting Lenovo BIOS WMI WOL enable"

    $lenovoSave = Get-WmiObject -Namespace root\wmi -Class Lenovo_SaveBiosSettings -ErrorAction SilentlyContinue
    if (-not $lenovoSave) {
        Write-Log "[Lenovo] Lenovo_SaveBiosSettings not found. Lenovo BIOS WMI not available. Cannot change BIOS from Windows."
        return
    }

    $settings = Get-WmiObject -Namespace root\wmi -Class Lenovo_BiosSetting -ErrorAction SilentlyContinue |
        Where-Object { $_.CurrentSetting -like "WakeOnLAN*" }

    if ($settings) {
        foreach ($s in $settings) {
            Write-Log "[Lenovo] Current WOL BIOS setting: $($s.CurrentSetting)"
        }
    } else {
        Write-Log "[Lenovo] WakeOnLAN BIOS setting not found in Lenovo_BiosSetting."
    }

    $setBios = Get-WmiObject -Namespace root\wmi -Class Lenovo_SetBiosSetting -ErrorAction SilentlyContinue
    if (-not $setBios) {
        Write-Log "[Lenovo] Lenovo_SetBiosSetting not found. Cannot change BIOS from Windows."
        return
    }

    $wolValues = @(
        "WakeOnLAN,Enabled",
        "WakeOnLAN,Primary",
        "WakeOnLAN,ACOnly",
        "WakeOnLAN,Secondary"
    )

    $success = $false
    foreach ($val in $wolValues) {
        try {
            $result = $setBios.SetBiosSetting($val)
            if ($result.Return -eq 0) {
                Write-Log "[Lenovo] Successfully applied BIOS setting: $val"
                $success = $true
                break
            } else {
                Write-Log "[Lenovo] Failed to set $val. Return code: $($result.Return)"
            }
        } catch {
            Write-Log ("[Lenovo] Exception while setting {0}: {1}" -f $val, $_.Exception.Message)
        }
    }

    if (-not $success) {
        Write-Log "[Lenovo] Could not set any WakeOnLAN BIOS value. BIOS may be locked or unsupported."
        return
    }

    try {
        $save = $lenovoSave.SaveBiosSettings()
        if ($save.Return -eq 0) {
            Write-Log "[Lenovo] BIOS settings saved successfully. Reboot required for WOL BIOS change."
        } else {
            Write-Log "[Lenovo] Failed to save BIOS settings. Return code: $($save.Return)"
        }
    } catch {
        Write-Log "[Lenovo] Exception while saving BIOS settings: $($_.Exception.Message)"
    }
}

function Enable-BiosWolDell {
    Write-Log "[Dell] Attempting Dell BIOS WMI WOL enable"

    $biosService = Get-WmiObject -Namespace root\dcim\sysman -Class DCIM_BIOSService -ErrorAction SilentlyContinue
    $biosEnum    = Get-WmiObject -Namespace root\dcim\sysman -Class DCIM_BIOSEnumeration -ErrorAction SilentlyContinue

    if (-not $biosService -or -not $biosEnum) {
        Write-Log "[Dell] DCIM BIOS WMI provider not found. Dell Command BIOS provider is not installed or not available."
        Write-Log "[Dell] You may need Dell Command Configure or Dell BIOS provider to manage BIOS from Windows."
        return
    }

    $wolAttr = $biosEnum | Where-Object {
        $_.AttributeName -like "*Wake*Lan*" -or
        $_.AttributeName -like "*WakeOnLan*" -or
        $_.AttributeName -like "*WakeOnLAN*"
    }

    if (-not $wolAttr) {
        Write-Log "[Dell] No WakeOnLan-like attribute found in DCIM_BIOSEnumeration."
        return
    }

    foreach ($attr in $wolAttr) {
        Write-Log "[Dell] Found WOL attribute: $($attr.AttributeName). Possible values: $($attr.PossibleValues -join ', ')"
    }

    $target = $wolAttr | Select-Object -First 1
    $valueToSet = $null

    if ($target.PossibleValues -contains "Enabled") {
        $valueToSet = "Enabled"
    } elseif ($target.PossibleValues -contains "On") {
        $valueToSet = "On"
    } elseif ($target.PossibleValues -contains "Enable") {
        $valueToSet = "Enable"
    }

    if (-not $valueToSet) {
        Write-Log "[Dell] No obvious enable value for WOL attribute. Skipping BIOS change."
        return
    }

    try {
        $attrNames  = @($target.AttributeName)
        $attrValues = @($valueToSet)
        $result = $biosService.SetBIOSAttributes($attrNames, $attrValues)
        if ($result.ReturnValue -eq 0) {
            Write-Log "[Dell] Successfully set $($target.AttributeName) to $valueToSet. Reboot required."
        } else {
            Write-Log "[Dell] Failed to set $($target.AttributeName). Return: $($result.ReturnValue)"
        }
    } catch {
        Write-Log "[Dell] Exception while setting BIOS WOL: $($_.Exception.Message)"
    }
}

function Enable-BiosWolHP {
    Write-Log "[HP] Attempting HP BIOS WMI WOL enable"

    $biosInterface = Get-WmiObject -Namespace root\HP\InstrumentedBIOS -Class HP_BIOSSettingInterface -ErrorAction SilentlyContinue
    if (-not $biosInterface) {
        Write-Log "[HP] HP_BIOSSettingInterface not found. HP Instrumented BIOS is not available."
        Write-Log "[HP] You may need HP BIOS Configuration Utility or HP WMI provider to manage BIOS from Windows."
        return
    }

    $settings = $biosInterface.GetBIOSSettings().BIOSSettings
    $wolSetting = $settings | Where-Object { $_ -like "WakeOnLAN,*" }

    if ($wolSetting) {
        foreach ($s in $wolSetting) {
            Write-Log "[HP] Current WOL BIOS entry: $s"
        }
    } else {
        Write-Log "[HP] No WakeOnLAN setting found in HP BIOS settings."
    }

    $targetValues = @(
        "WakeOnLAN,Enable",
        "WakeOnLAN,Enabled",
        "WakeOnLAN,PowerOnBoot"
    )

    $setSuccess = $false
    foreach ($tv in $targetValues) {
        try {
            $res = $biosInterface.SetBIOSSetting($tv)
            if ($res.Return -eq 0) {
                Write-Log "[HP] Successfully applied BIOS setting: $tv"
                $setSuccess = $true
                break
            } else {
                Write-Log "[HP] Failed to set BIOS setting $tv. Return: $($res.Return)"
            }
        } catch {
            Write-Log "[HP] Exception while setting BIOS WOL: $($_.Exception.Message)"
        }
    }

    if ($setSuccess) {
        try {
            $apply = $biosInterface.SaveBIOSSettings()
            if ($apply.Return -eq 0) {
                Write-Log "[HP] BIOS settings saved successfully. Reboot required."
            } else {
                Write-Log "[HP] Failed to save BIOS settings. Return: $($apply.Return)"
            }
        } catch {
            Write-Log "[HP] Exception while saving BIOS settings: $($_.Exception.Message)"
        }
    } else {
        Write-Log "[HP] Could not set any WOL BIOS value. BIOS may be locked or unsupported."
    }
}

# --------------------------------------------------------------------
# 3. Call vendor specific BIOS functions (if supported)
# --------------------------------------------------------------------
if ($vendor -match "Lenovo") {
    Enable-BiosWolLenovo
} elseif ($vendor -match "Dell") {
    Enable-BiosWolDell
} elseif ($vendor -match "Hewlett-Packard" -or $vendor -match "HP") {
    Enable-BiosWolHP
} else {
    Write-Log "[Generic] Vendor not recognized as Lenovo, Dell, or HP. BIOS WOL change skipped."
}

# --------------------------------------------------------------------
# 4. Windows side WOL config
# --------------------------------------------------------------------
Write-Log "[Windows] Disabling Fast Startup"
try {
    powercfg -h off
    Write-Log "[Windows] Fast Startup disabled."
} catch {
    Write-Log "[Windows] Failed to disable Fast Startup: $($_.Exception.Message)"
}

Write-Log "[Windows] Configuring NIC WOL settings"

$adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -ne "Disabled" -and $_.HardwareInterface }

if (-not $adapters) {
    Write-Log "[Windows] No physical adapters found. WOL will not work."
} else {
    $wolKeywords = @(
        "Wake on Magic Packet",
        "*WakeOnMagicPacket",
        "Wake on pattern match",
        "*WakeOnPattern",
        "Shutdown Wake-On-Lan",
        "Wake From Shutdown",
        "Wake on Link Change"
    )

    foreach ($nic in $adapters) {
        Write-Log "[Windows] Processing NIC: $($nic.Name) - $($nic.InterfaceDescription)"

        try {
            $props = Get-NetAdapterAdvancedProperty -Name $nic.Name -ErrorAction Stop
        } catch {
            Write-Log "[Windows]   Cannot read advanced properties: $($_.Exception.Message)"
            continue
        }

        foreach ($kw in $wolKeywords) {
            $match = $props | Where-Object { $_.DisplayName -like $kw -or $_.RegistryKeyword -like $kw }

            foreach ($p in $match) {
                $value = $null
                if ($p.DisplayValue -contains "Enabled") {
                    $value = "Enabled"
                } elseif ($p.DisplayValue -contains "On") {
                    $value = "On"
                } elseif ($p.DisplayValue -contains "1") {
                    $value = 1
                } else {
                    $value = 1
                }

                try {
                    Set-NetAdapterAdvancedProperty -Name $nic.Name -RegistryKeyword $p.RegistryKeyword -RegistryValue $value -NoRestart -ErrorAction Stop
                    Write-Log "[Windows]   Enabled $($p.DisplayName) ($($p.RegistryKeyword)) with value $value"
                } catch {
                    Write-Log "[Windows]   FAILED enabling $($p.DisplayName): $($_.Exception.Message)"
                }
            }
        }

        try {
            powercfg /deviceenablewake "$($nic.Name)" | Out-Null
            Write-Log "[Windows]   powercfg allowed wake for this NIC."
        } catch {
            Write-Log "[Windows]   FAILED powercfg deviceenablewake: $($_.Exception.Message)"
        }
    }
}

Write-Log "[Windows] Running wake diagnostics"

try {
    $armed = powercfg -devicequery wake_armed
    $prog  = powercfg -devicequery wake_programmable
    $any   = powercfg -devicequery wake_from_any

    Write-Log "[Diag] Wake Armed Devices: $($armed -join ', ')"
    Write-Log "[Diag] Wake Programmable Devices: $($prog -join ', ')"
    Write-Log "[Diag] Wake From Any Devices: $($any -join ', ')"

    if ($armed -notmatch "Ethernet" -and $prog -notmatch "Ethernet") {
        Write-Log "[Diag] CRITICAL: No NIC is armed or programmable for wake. BIOS may still be blocking WOL or NIC has no standby power."
    }
} catch {
    Write-Log "[Diag] Failed to run powercfg diagnostics: $($_.Exception.Message)"
}

Write-Log "========== WOL Universal BIOS + Windows Config Complete =========="
Write-Host "Done. Check C:\Logs\WOL-Universal.log"
Write-Host "If 'partnersadmin' was created, default password is: $genericPasswordPlain"

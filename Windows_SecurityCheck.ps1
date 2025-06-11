#requires -Version 5.1
#requires -RunAsAdministrator

# PowerShell script to audit Windows security misconfigurations in enterprise environments

# Initialize output file
$outputDir = "C:\Temp"
$outputFile = Join-Path $outputDir "SecurityAuditReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$report = @()
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$report += "Windows Security Configuration Audit Report"
$report += "Generated on: $currentDateTime"
$report += "----------------------------------------"

# Function to write to both console and report
function Write-Report {
    param($Message)
    Write-Host $Message
    $script:report += $Message
}

# Create output directory if it doesn't exist
if (-not (Test-Path $outputDir)) {
    try {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        Write-Report "Created output directory: $outputDir"
    } catch {
        Write-Warning "Failed to create output directory: $_"
        exit
    }
}

try {
    # 1. Guest Account Status
    Write-Report "`n[1] Checking Guest Account Status..."
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
        if ($guest.Enabled) {
            Write-Report "WARNING: Guest account is ENABLED. Recommended to disable it with: Disable-LocalUser -Name 'Guest'"
        } else {
            Write-Report "PASS: Guest account is disabled."
        }
    } catch {
        Write-Report "PASS: Guest account not found or does not exist."
    }

    # 2. UAC Configuration
    Write-Report "`n[2] Checking User Account Control (UAC) Configuration..."
    try {
        $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction Stop
        if ($uac.EnableLUA -eq 1) {
            Write-Report "PASS: UAC is enabled."
        } else {
            Write-Report "WARNING: UAC is disabled. Recommended to enable it via: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f"
        }
    } catch {
        Write-Report "ERROR: Failed to check UAC configuration: $_"
    }

    # 3. SMBv1 Status
    Write-Report "`n[3] Checking SMBv1 Status..."
    try {
        $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
        if ($smbv1.State -eq "Enabled") {
            Write-Report "WARNING: SMBv1 is enabled. Recommended to disable it due to security vulnerabilities with: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
        } else {
            Write-Report "PASS: SMBv1 is disabled."
        }
    } catch {
        Write-Report "ERROR: Failed to check SMBv1 status: $_"
    }

    # 4. RDP Settings
    Write-Report "`n[4] Checking Remote Desktop (RDP) Settings..."
    try {
        $rdp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop
        $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction Stop
        if ($rdp.fDenyTSConnections -eq 0) {
            Write-Report "WARNING: RDP is enabled."
            if ($nla.UserAuthentication -eq 1) {
                Write-Report "PASS: Network Level Authentication (NLA) is enabled for RDP."
            } else {
                Write-Report "WARNING: Network Level Authentication (NLA) is disabled for RDP. Recommended to enable it via: reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' /v UserAuthentication /t REG_DWORD /d 1 /f"
            }
        } else {
            Write-Report "PASS: RDP is disabled."
        }
    } catch {
        Write-Report "ERROR: Failed to check RDP settings: $_"
    }

    # 5. Admin Shares
    Write-Report "`n[5] Checking Admin Shares..."
    try {
        $adminShares = Get-SmbShare | Where-Object { $_.Name -match "^(ADMIN\$|C\$|IPC\$)" } -ErrorAction Stop
        if ($adminShares) {
            $names = $adminShares | Select-Object -ExpandProperty Name
            Write-Report "WARNING: Admin shares found: $($names -join ', '). Recommended to disable unnecessary shares via registry or Group Policy."
        } else {
            Write-Report "PASS: No admin shares detected."
        }
    } catch {
        Write-Report "ERROR: Failed to check admin shares: $_"
    }

    # 6. Firewall Status
    Write-Report "`n[6] Checking Windows Firewall Status..."
    try {
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($profile in $firewallProfiles) {
            if ($profile.Enabled) {
                Write-Report "PASS: Firewall profile '$($profile.Name)' is enabled."
            } else {
                Write-Report "WARNING: Firewall profile '$($profile.Name)' is disabled. Recommended to enable it with: Set-NetFirewallProfile -Name $($profile.Name) -Enabled True"
            }
        }
    } catch {
        Write-Report "ERROR: Failed to check firewall status: $_"
    }

    # 7. Antivirus Status
    Write-Report "`n[7] Checking Antivirus Status..."
    try {
        $av = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
        if ($av) {
            foreach ($product in $av) {
                $status = if ($product.productState -band 0x1000) { "Enabled" } else { "Disabled" }
                Write-Report "Antivirus: $($product.displayName) - Status: $status"
                if ($status -eq "Disabled") {
                    Write-Report "WARNING: Antivirus $($product.displayName) is disabled. Recommended to enable it."
                }
            }
        } else {
            Write-Report "WARNING: No antivirus product detected."
        }
    } catch {
        Write-Report "ERROR: Failed to check antivirus status: $_"
    }

    # 8. Auto-Login Settings
    Write-Report "`n[8] Checking Auto-Login Settings..."
    try {
        $autoLogin = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
        if ($autoLogin -and $autoLogin.AutoAdminLogon -eq "1") {
            Write-Report "WARNING: Auto-Login is enabled. Recommended to disable it via: reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v AutoAdminLogon /f"
        } else {
            Write-Report "PASS: Auto-Login is disabled or not configured."
        }
    } catch {
        Write-Report "ERROR: Failed to check auto-login settings: $_"
    }

    # 9. Password Policy
    Write-Report "`n[9] Checking Password Policy..."
    try {
        $secpolFile = "$env:TEMP\secpol_$(Get-Date -Format 'yyyyMMdd_HHmmss').cfg"
        secedit /export /cfg $secpolFile /quiet | Out-Null
        if (Test-Path $secpolFile) {
            $policy = Get-Content $secpolFile -ErrorAction Stop
            $minLengthMatch = $policy | Select-String "MinimumPasswordLength"
            $maxAgeMatch = $policy | Select-String "MaximumPasswordAge"
            $complexityMatch = $policy | Select-String "PasswordComplexity"

            $minLength = if ($minLengthMatch) { $minLengthMatch.Line -replace ".*= *(\d+).*", '$1' } else { "Not set" }
            $maxAge = if ($maxAgeMatch) { $maxAgeMatch.Line -replace ".*= *(\d+).*", '$1' } else { "Not set" }
            $complexity = if ($complexityMatch) { $complexityMatch.Line -replace ".*= *(\d+).*", '$1' } else { "Not set" }

            if ($minLength -eq "Not set" -or [int]$minLength -lt 8) {
                Write-Report "WARNING: Minimum password length is $minLength. Recommended to set to at least 8 via Group Policy."
            } else {
                Write-Report "PASS: Minimum password length is $minLength characters."
            }

            if ($maxAge -eq "Not set" -or [int]$maxAge -gt 90 -or $maxAge -eq "0") {
                Write-Report "WARNING: Maximum password age is $maxAge days. Recommended to set to 90 days or less via Group Policy."
            } else {
                Write-Report "PASS: Maximum password age is $maxAge days."
            }

            if ($complexity -eq "Not set" -or $complexity -eq "0") {
                Write-Report "WARNING: Password complexity is disabled. Recommended to enable it via Group Policy."
            } else {
                Write-Report "PASS: Password complexity is enabled."
            }
            Remove-Item $secpolFile -Force -ErrorAction SilentlyContinue
        } else {
            Write-Report "ERROR: Failed to export security policy."
        }
    } catch {
        Write-Report "ERROR: Failed to check password policy: $_"
    }

    # 10. Unquoted Service Paths
    Write-Report "`n[10] Checking Unquoted Service Paths..."
    try {
        $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s' } -ErrorAction Stop
        if ($services) {
            Write-Report "WARNING: Found services with unquoted paths vulnerable to exploitation:"
            foreach ($service in $services) {
                Write-Report "  - Service: $($service.Name), Path: $($service.PathName)"
            }
        } else {
            Write-Report "PASS: No services with unquoted paths found."
        }
    } catch {
        Write-Report "ERROR: Failed to check unquoted service paths: $_"
    }

    # 11. Windows Update Settings
    Write-Report "`n[11] Checking Windows Update Settings..."
    try {
        $wuPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
        $enabled = if ($wuPolicy -and $wuPolicy.NoAutoUpdate -eq 1) { "No" } else { "Yes" }
        Write-Report "Automatic Updates Enabled: $enabled"
        if ($enabled -eq "No") {
            Write-Report "WARNING: Automatic updates are disabled. Recommended to enable them via Group Policy or registry settings."
        } else {
            Write-Report "PASS: Automatic updates are enabled."
        }
    } catch {
        Write-Report "ERROR: Failed to check Windows Update settings: $_"
    }

    # 12. Last 5 Installed Updates
    Write-Report "`n[12] Checking Last 5 Installed Updates..."
    try {
        $updates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 -ErrorAction Stop
        if ($updates) {
            foreach ($update in $updates) {
                Write-Report "Installed KB: $($update.HotFixID) - Installed On: $($update.InstalledOn)"
            }
        } else {
            Write-Report "WARNING: No recent updates found."
        }
    } catch {
        Write-Report "ERROR: Failed to check installed updates: $_"
    }

    # 13. Windows Update Services
    Write-Report "`n[13] Checking Windows Update Services..."
    $servicesToCheck = @("wuauserv", "bits")
    foreach ($svcName in $servicesToCheck) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction Stop
            if ($svc) {
                Write-Report "Service: $svcName - Status: $($svc.Status)"
                if ($svc.Status -ne "Running") {
                    Write-Report "WARNING: Service $svcName is not running. Recommended to start it with: Start-Service -Name $svcName"
                } else {
                    Write-Report "PASS: Service $svcName is running."
                }
            } else {
                Write-Report "ERROR: Service $svcName not found."
            }
        } catch {
            Write-Report "ERROR: Failed to check service $svcName - $_"
        }
    }

    # 14. BitLocker Status
    Write-Report "`n[14] Checking BitLocker Status..."
    try {
        $vols = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if ($vols) {
            foreach ($vol in $vols) {
                Write-Report "BitLocker - $($vol.MountPoint): Protection $($vol.ProtectionStatus)"
                if ($vol.ProtectionStatus -eq "Off") {
                    Write-Report "WARNING: BitLocker is disabled for $($vol.MountPoint). Recommended to enable it via: Enable-BitLocker -MountPoint $($vol.MountPoint)"
                }
            }
        } else {
            Write-Report "WARNING: BitLocker not supported or not enabled."
        }
    } catch {
        Write-Report "ERROR: Failed to check BitLocker status: $_"
    }

    # 15. Startup Items
    Write-Report "`n[15] Checking Startup Items..."
    try {
        $startupPaths = @(
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        $startupFound = $false
        foreach ($path in $startupPaths) {
            if (Test-Path $path -ErrorAction Stop) {
                $items = Get-ChildItem $path -ErrorAction Stop
                foreach ($item in $items) {
                    Write-Report "Startup Item: $($item.Name)"
                    $startupFound = $true
                }
            }
        }
        if (-not $startupFound) {
            Write-Report "PASS: No startup items found."
        }
    } catch {
        Write-Report "ERROR: Failed to check startup items: $_"
    }

    # 16. Scheduled Tasks
    Write-Report "`n[16] Checking Scheduled Tasks..."
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' } -ErrorAction Stop
        if ($tasks) {
            foreach ($task in $tasks) {
                Write-Report "Scheduled Task: $($task.TaskName) (Path: $($task.TaskPath))"
            }
        } else {
            Write-Report "PASS: No non-Microsoft scheduled tasks found."
        }
    } catch {
        Write-Report "ERROR: Failed to check scheduled tasks: $_"
    }

    # 17. Installed Applications
    Write-Report "`n[17] Checking Installed Applications..."
    try {
        $apps = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } | Sort-Object DisplayName
        if ($apps) {
            foreach ($app in $apps) {
                Write-Report "Installed App: $($app.DisplayName)"
            }
        } else {
            Write-Report "WARNING: No installed applications found."
        }
    } catch {
        Write-Report "ERROR: Failed to check installed applications: $_"
    }

    # Save report to file
    Write-Report "`nAudit completed. Report saved to: $outputFile"
    $report | Out-File -FilePath $outputFile -Encoding UTF8

} catch {
    Write-Report "ERROR: Script execution failed: $_"
    $report | Out-File -FilePath $outputFile -Encoding UTF8
}
# WindowsSecurityCheck
A PowerShell script to audit common Windows security misconfigurations in enterprise environments, checking Guest account status, UAC, SMBv1, RDP, admin shares, firewall, antivirus, auto-login, password policy, unquoted service paths, Windows Update, BitLocker, startup items, scheduled tasks, and installed applications.

# Features
The script audits the following security configurations:
  - Guest Account Status: Checks if the Guest account is enabled.
  - User Account Control (UAC): Verifies if UAC is enabled.
  - SMBv1 Status: Detects if the vulnerable SMBv1 protocol is enabled.
  - Remote Desktop (RDP) Settings: Checks RDP status and Network Level Authentication (NLA).
  - Admin Shares: Identifies enabled administrative shares (e.g., ADMIN$, C$, IPC$).
  - Firewall Status: Validates the status of Windows Firewall profiles.
  - Antivirus Status: Reports on installed antivirus products and their status.
  - Auto-Login Settings: Checks for automatic login configurations.
  - Password Policy: Audits minimum password length, maximum password age, and complexity.
  - Unquoted Service Paths: Detects services with unquoted paths vulnerable to exploitation.
  - Windows Update Settings: Verifies automatic update configuration.
  - Recent Updates: Lists the last five installed Windows updates.
  - Windows Update Services: Checks the status of wuauserv and bits services.
  - BitLocker Status: Reports on BitLocker encryption for drives.
  - Startup Items: Lists programs in startup folders.
  - Scheduled Tasks: Identifies non-Microsoft scheduled tasks.
  - Installed Applications: Lists installed software.

The script outputs a timestamped report to C:\Temp and displays results in the console, including actionable remediation commands for identified issues.

# Prerequisites
Operating System: Windows 10/11 Pro/Enterprise or Windows Server 2016/2019/2022.
PowerShell Version: PowerShell 5.1 or later (run Get-Host | Select-Object Version to verify).
Administrative Privileges: The script must be run as Administrator.
Modules: No additional modules are required, but the BitLocker check requires the BitLocker module (unavailable on Windows Home editions).

# Installation
Download the Script:
Clone the repository or download Windows_Audit.ps1 from the GitHub releases.
it clone https://github.com/DeshanFer94/WindowsSecurityCheck.git
Save the Script:
Place Windows_Audit.ps1 in a directory (e.g., D:\Checklists\Windows_Audit\).

# Usage
Set Execution Policy:

Open PowerShell as Administrator and allow script execution:
  #> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force

Run the Script:
Navigate to the script directory and execute:
  #> Set-Location -Path "<Path-to-script>"
  #>.\Windows_Audit.ps1

Review Output:
The script generates a report in C:\Temp (e.g., SecurityAuditReport_20250611_140000.txt).

Results are also displayed in the PowerShell console.

Output
The report includes:
  Header: Timestamp and report title.
  Sections: One for each audited configuration (e.g., Guest Account, UAC).
  Status: PASS, WARNING, or ERROR for each check.
  Details: Descriptions of findings and remediation commands (e.g., Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol for SMBv1).

File Location: Saved as a UTF-8 encoded text file in C:\Temp.

# Example output snippet:

[1] Checking Guest Account Status...
PASS: Guest account is disabled.

[2] Checking User Account Control (UAC) Configuration...
PASS: UAC is enabled.

[3] Checking SMBv1 Status...
WARNING: SMBv1 is enabled. Recommended to disable it due to security vulnerabilities with: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Troubleshooting

Script Fails to Run:
Ensure PowerShell is running as Administrator.
Verify PowerShell version (Get-Host | Select-Object Version).
Check execution policy (Get-ExecutionPolicy).
BitLocker Warning:
On Windows Home editions, BitLocker is not supported, and a warning is expected.

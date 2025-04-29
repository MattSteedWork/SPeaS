# PowerShellPeas-Pro.ps1
# Full Advanced WinPEAS Clone

Write-Host "====== PowerShellPeas-Pro Starting ======"

# Check if Admin
function Check-Admin {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "[-] Not running as Administrator"
    } else {
        Write-Host "[+] Running as Administrator"
    }
}
Check-Admin

# Basic User & System Info
Write-Host "`n[*] User & System Info:"
whoami
whoami /priv
whoami /groups
hostname
(Get-WmiObject Win32_OperatingSystem).Caption
(Get-WmiObject Win32_OperatingSystem).OSArchitecture
(Get-WmiObject Win32_ComputerSystem).Domain
(Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime)

# UAC Settings
Write-Host "`n[*] UAC Settings:"
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System | `
Select-Object ConsentPromptBehaviorAdmin, PromptOnSecureDesktop, EnableLUA

# AlwaysInstallElevated
Write-Host "`n[*] AlwaysInstallElevated Policy Check:"
$policies = @(
    "HKLM:\Software\Policies\Microsoft\Windows\Installer",
    "HKCU:\Software\Policies\Microsoft\Windows\Installer"
)
foreach ($path in $policies) {
    Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Select-Object AlwaysInstallElevated
}

# Scheduled Tasks
Write-Host "`n[*] Scheduled Tasks:"
schtasks /query /fo LIST /v

# Installed Programs
Write-Host "`n[*] Installed Programs:"
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

# Running Processes
Write-Host "`n[*] Top Running Processes:"
Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 10

# Listening Ports
Write-Host "`n[*] Listening Ports:"
netstat -ano | findstr LISTENING

# Firewall Rules
Write-Host "`n[*] Firewall Rules:"
Get-NetFirewallRule -Enabled True | Select-Object DisplayName, Direction, Action

# Services - Unquoted Paths and Weak Permissions
Write-Host "`n[*] Checking Services for Unquoted Paths and Permissions:"

$services = Get-WmiObject win32_service | Where-Object {
    $_.StartMode -eq "Auto" -and
    $_.PathName -ne $null
}

foreach ($service in $services) {
    $path = $service.PathName.Trim('"')
    if ($path -match '\s' -and $path -notmatch '^".*"$') {
        Write-Host "[!] Unquoted Path: $($service.Name) -> $($service.PathName)"
    }
}

# ACL Checks on Services
Write-Host "`n[*] Checking Service Permissions:"
$services = Get-WmiObject Win32_Service
foreach ($service in $services) {
    $svc = Get-Service $service.Name -ErrorAction SilentlyContinue
    if ($svc) {
        $path = "HKLM:\System\CurrentControlSet\Services\$($svc.Name)"
        $acl = Get-Acl $path -ErrorAction SilentlyContinue
        if ($acl) {
            foreach ($access in $acl.Access) {
                if ($access.IdentityReference -match 'Everyone|Users|Authenticated Users') {
                    Write-Host "[!] Service $($svc.Name) is writable by $($access.IdentityReference)"
                }
            }
        }
    }
}

# Searching for Credentials
Write-Host "`n[*] Searching Files for Credentials:"
$interesting = @("*.config", "*.ini", "*.xml", "*.txt", "*.bat", "*.ps1")
foreach ($pattern in $interesting) {
    Get-ChildItem -Path C:\ -Include $pattern -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -lt 3MB } |
    ForEach-Object {
        if (Select-String -Path $_.FullName -Pattern "password|user|credential" -SimpleMatch -Quiet) {
            Write-Host "[!] Possible credential in: $($_.FullName)"
        }
    }
}

# Registry Credential Hunt
Write-Host "`n[*] Searching Registry for Stored Credentials:"
reg query HKCU\Software\Microsoft\IdentityCRL\StoredIdentities 2>$null
reg query HKCU\Software\Microsoft\Office\16.0\Common\Identity\Identities 2>$null
reg query HKLM\SECURITY\Policy\Secrets 2>$null

# Interesting Files Search
Write-Host "`n[*] Searching for interesting files on filesystem:"
$paths = @(
    "C:\Users\*\Desktop\*",
    "C:\Users\*\Documents\*",
    "C:\Windows\System32\config\*",
    "C:\Windows\System32\drivers\etc\*"
)
foreach ($path in $paths) {
    Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Where-Object {
        $_.Extension -match '\.(config|ini|xml|txt|bat|ps1|psm1|vbs|asp|aspx|php|json|yml|yaml|cred)'
    } | Select-Object FullName
}

# Quick Exploit Suggestions
Write-Host "`n[*] Quick Exploit Suggestions:"
if ((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1 -or
    (Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1) {
    Write-Host "[+] AlwaysInstallElevated enabled => Possible MSI Privilege Escalation!"
}

if ((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA -eq 0) {
    Write-Host "[+] UAC Disabled => Direct Privilege Escalation Possible!"
}

Write-Host "`n====== PowerShellPeas-Pro Finished ======"

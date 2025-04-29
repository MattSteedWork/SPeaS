# PowerShellPeas-Pro-v2.ps1
# Full Advanced WinPEAS Clone (Fixed)

Write-Host "====== SPeaS Starting ======"

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
try {
    whoami
    whoami /priv
    whoami /groups
    hostname
    (Get-CimInstance Win32_OperatingSystem).Caption
    (Get-CimInstance Win32_OperatingSystem).OSArchitecture
    (Get-CimInstance Win32_ComputerSystem).Domain
    (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
} catch { Write-Warning "[-] Error retrieving system info" }

# UAC Settings
Write-Host "`n[*] UAC Settings:"
try {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System | `
    Select-Object ConsentPromptBehaviorAdmin, PromptOnSecureDesktop, EnableLUA
} catch { Write-Host "[-] Unable to retrieve UAC settings." }

# AlwaysInstallElevated
Write-Host "`n[*] AlwaysInstallElevated Policy Check:"
$policies = @(
    "HKLM:\Software\Policies\Microsoft\Windows\Installer",
    "HKCU:\Software\Policies\Microsoft\Windows\Installer"
)
foreach ($path in $policies) {
    try {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Select-Object AlwaysInstallElevated
    } catch {}
}

# Scheduled Tasks
Write-Host "`n[*] Scheduled Tasks:"
try {
    schtasks /query /fo LIST /v
} catch { Write-Host "[-] No scheduled tasks found or insufficient permissions." }

# Installed Programs
Write-Host "`n[*] Installed Programs:"
try {
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
} catch { Write-Host "[-] No installed programs found." }

# Running Processes
Write-Host "`n[*] Top Running Processes:"
try {
    Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 10
} catch { Write-Host "[-] Could not retrieve processes." }

# Listening Ports
Write-Host "`n[*] Listening Ports:"
try {
    $ports = netstat -ano | findstr LISTENING
    if ($ports) { $ports } else { Write-Host "[-] No listening ports found." }
} catch { Write-Host "[-] Error checking ports." }

# Firewall Rules
Write-Host "`n[*] Firewall Rules:"
try {
    $fwRules = Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue
    if ($fwRules) {
        $fwRules | Select-Object DisplayName, Direction, Action
    } else {
        Write-Host "[-] No enabled firewall rules found."
    }
} catch { Write-Host "[-] Firewall rules could not be retrieved." }

# Unquoted Service Paths (Proper)
Write-Host "`n[*] Checking for Real Unquoted Service Path Vulnerabilities..."
$excludedPaths = @(
    "C:\Windows\System32\svchost.exe",
    "C:\Windows\System32\services.exe",
    "C:\Windows\System32\lsass.exe",
    "C:\Windows\System32\wininit.exe",
    "C:\Windows\System32\smss.exe",
    "C:\Windows\System32\winlogon.exe"
)
try {
    $services = Get-CimInstance Win32_Service | Where-Object {
        $_.StartMode -eq "Auto" -and
        $_.PathName -ne $null -and
        $_.PathName -match '\s' -and
        $_.PathName -notmatch '^".*"$'
    }

    foreach ($service in $services) {
        $binaryPath = $service.PathName.Split(' ')[0]
        if ($excludedPaths -notcontains $binaryPath) {
            Write-Host "[!] Vulnerable Unquoted Path Detected:"
            Write-Host "    Service Name : $($service.Name)"
            Write-Host "    Binary Path  : $($service.PathName)"
        }
    }
} catch { Write-Host "[-] Error checking service paths." }

# Weak ACLs on Services
Write-Host "`n[*] Checking Service Permissions (Weak ACLs):"
try {
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
} catch { Write-Host "[-] Error checking service ACLs." }

<# # Searching for Credentials
Write-Host "`n[*] Searching Files for Credentials:"
$interesting = @("*.config", "*.ini", "*.xml", "*.txt", "*.bat", "*.ps1")
foreach ($pattern in $interesting) {
    try {
        Get-ChildItem -Path C:\ -Include $pattern -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 3MB } |
        ForEach-Object {
            if (Select-String -Path $_.FullName -Pattern "password|user|credential" -SimpleMatch -Quiet) {
                Write-Host "[!] Possible credential in: $($_.FullName)"
            }
        }
    } catch {}
} #>

# Registry Credential Hunt
Write-Host "`n[*] Searching Registry for Stored Credentials:"
try {
    reg query HKCU\Software\Microsoft\IdentityCRL\StoredIdentities 2>$null
    reg query HKCU\Software\Microsoft\Office\16.0\Common\Identity\Identities 2>$null
    reg query HKLM\SECURITY\Policy\Secrets 2>$null
} catch { Write-Host "[-] Could not read registry secrets." }

# Interesting Files
Write-Host "`n[*] Searching for Interesting Files:"
$paths = @(
    "C:\Users\*\Desktop\*",
    "C:\Users\*\Documents\*",
    "C:\Windows\System32\config\*",
    "C:\Windows\System32\drivers\etc\*"
)
foreach ($path in $paths) {
    try {
        Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Where-Object {
            $_.Extension -match '\.(config|ini|xml|txt|bat|ps1|psm1|vbs|asp|aspx|php|json|yml|yaml|cred)'
        } | Select-Object FullName
    } catch {}
}

# Quick Exploit Suggestions
Write-Host "`n[*] Quick Exploit Suggestions:"
try {
    $aiElevated = (
        (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1 -or
        (Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1
    )
    $uacDisabled = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).EnableLUA -eq 0

    if ($aiElevated) {
        Write-Host "[+] AlwaysInstallElevated enabled => Possible MSI Privilege Escalation!"
    }
    if ($uacDisabled) {
        Write-Host "[+] UAC Disabled => Direct Privilege Escalation Possible!"
    }
} catch {}

Write-Host "`n====== PowerShellPeas-Pro-v2 Finished ======"

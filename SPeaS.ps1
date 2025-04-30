
<#
.SYNOPSIS
  Comprehensive Privilege Escalation Check Script for Windows
.DESCRIPTION
  Performs a variety of checks similar to WinPEAS, including system info, user enumeration,
  credentials, services, file permissions, scheduled tasks, and more.
#>

########################## SYSTEM INFORMATION ##########################

function Check-SystemInfo {
    Write-Host "[+] System Information" -ForegroundColor Cyan
    systeminfo
    Write-Host "`n[+] Environment Variables" -ForegroundColor Cyan
    Get-ChildItem Env:
    Write-Host "`n[+] Installed Hotfixes" -ForegroundColor Cyan
    Get-HotFix | Sort-Object InstalledOn -Descending
}

########################## USER ENUMERATION ##########################

function Check-Users {
    Write-Host "`n[+] Current User Info" -ForegroundColor Cyan
    whoami /all
    Write-Host "`n[+] Local Users" -ForegroundColor Cyan
    Get-LocalUser
    Write-Host "`n[+] Local Groups and Members" -ForegroundColor Cyan
    Get-LocalGroup | ForEach-Object {
        Write-Host "`nGroup: $($_.Name)"
        Get-LocalGroupMember -Group $_.Name | Select-Object Name, ObjectClass
    }
    Write-Host "`n[+] Logged-On Users" -ForegroundColor Cyan
    try { quser } catch { Write-Host "quser not available." }
    Write-Host "`n[+] Password Policies" -ForegroundColor Cyan
    net accounts
}

########################## CREDENTIAL GATHERING ##########################

function Check-Credentials {
    Write-Host "`n[+] Stored Credentials (cmdkey)" -ForegroundColor Cyan
    cmdkey /list
    Write-Host "`n[+] Credential Manager Entries" -ForegroundColor Cyan
    Get-StoredCredential -ErrorAction SilentlyContinue
    Write-Host "`n[+] DPAPI Master Keys (Roaming)" -ForegroundColor Cyan
    Get-ChildItem "$env:APPDATA\Microsoft\Protect" -Recurse -ErrorAction SilentlyContinue
    Write-Host "`n[+] DPAPI Master Keys (Local)" -ForegroundColor Cyan
    Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Protect" -Recurse -ErrorAction SilentlyContinue
    Write-Host "`n[+] SAM & SYSTEM Hive Accessibility" -ForegroundColor Cyan
    Get-Item -Path C:\Windows\System32\config\SAM -ErrorAction SilentlyContinue
    Get-Item -Path C:\Windows\System32\config\SYSTEM -ErrorAction SilentlyContinue
}

########################## SERVICES & REGISTRY ##########################

function Check-ServicesAndRegistry {

    Write-Host "`n[+] AlwaysInstallElevated" -ForegroundColor Cyan
    Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue
    Get-ItemProperty HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue
    Write-Host "`n[+] Registry Autoruns" -ForegroundColor Cyan
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue
    Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue
}


########################## NETWORK INFORMATION ##########################

function Check-Network {
    Write-Host "`n[+] IP Configuration" -ForegroundColor Cyan
    ipconfig /all
    Write-Host "`n[+] Open Network Connections" -ForegroundColor Cyan
    netstat -ano
    Write-Host "`n[+] Firewall Rules" -ForegroundColor Cyan
    netsh advfirewall firewall show rule name=all
    Write-Host "`n[+] Shared Resources" -ForegroundColor Cyan
    Get-SmbShare | Get-SmbShareAccess
}

########################## SCHEDULED TASKS AND AUTORUN ##########################

function Check-ScheduledTasks {
    Write-Host "`n[+] Scheduled Tasks" -ForegroundColor Cyan
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" }
    Write-Host "`n[+] Startup Programs" -ForegroundColor Cyan
    Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location
}

########################## MISC CHECKS ##########################

function Check-Misc {
    Write-Host "`n[+] Installed Applications" -ForegroundColor Cyan
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    Write-Host "`n[+] Running Processes" -ForegroundColor Cyan
    Get-Process | Select-Object Name, Id, Path
    Write-Host "`n[+] Clipboard Contents" -ForegroundColor Cyan
    Add-Type -AssemblyName PresentationCore
    [Windows.Clipboard]::GetText()
}

########################## RUN ALL ##########################

function Run-AllChecks {
    Check-SystemInfo
    Check-Users
    Check-Credentials
    Check-ServicesAndRegistry
    Check-Network
    Check-ScheduledTasks
    Check-Misc
}

Run-AllChecks

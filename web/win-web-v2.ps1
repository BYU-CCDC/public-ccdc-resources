# =============================================================================
# MenuDrivenHardening.ps1
# =============================================================================
# This script provides a menu-driven interface to run individual hardening 
# and enumeration modules:
#
#   1. IIS Hardening – Sets minimal application pool privileges, disables
#      directory browsing, disables anonymous authentication, and deletes
#      custom error pages.
#
#   2. PII File Scan – Scans a given directory (recursively) for files that 
#      contain patterns matching PII (phone numbers, addresses, etc.).
#
#   3. SMB Hardening & System Enumeration – Performs SMB and network hardening,
#      enumerates computer and network information, and optionally patches 
#      EternalBlue (or disables SMB1).
#
# Run this script as Administrator.
# =============================================================================

# --------------------------
# Display the Main Menu
# --------------------------
function Show-Menu {
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host " Windows Hardening & Enumeration Menu" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "1. IIS Hardening"
    Write-Host "2. PII File Scan"
    Write-Host "3. SMB Hardening & System Enumeration"
    Write-Host "4. Exit"
}

# --------------------------
# Module 1: IIS Hardening
# --------------------------
function Invoke-IISHardening {
    Write-Host "`nStarting IIS Hardening..." -ForegroundColor Cyan
    try {
        Import-Module WebAdministration -ErrorAction Stop
        Import-Module IIS-Administration -ErrorAction Stop
    }
    catch {
        Write-Host "Unable to load IIS modules. Make sure IIS is installed." -ForegroundColor Red
        return
    }
    
    # Set Application Pool privileges to minimal
    foreach ($item in Get-ChildItem IIS:\AppPools) {
        $tempPath = "IIS:\AppPools\$($item.Name)"
        Set-ItemProperty -Path $tempPath -Name processModel.identityType -Value 4 -ErrorAction SilentlyContinue
    }
    
    # Disable directory browsing on all sites
    foreach ($site in Get-ChildItem IIS:\Sites) {
        $tempPath = "IIS:\Sites\$($site.Name)"
        Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath $tempPath -Value $false -ErrorAction SilentlyContinue
    }
    
    # Allow PowerShell to modify anonymousAuthentication before locking it down
    Set-WebConfiguration -Filter "//system.webServer/security/authentication/anonymousAuthentication" -Metadata overrideMode -Value Allow -PSPath IIS:/ -ErrorAction SilentlyContinue
    
    # Disable anonymous authentication on each site
    foreach ($site in Get-ChildItem IIS:\Sites) {
        $tempPath = "IIS:\Sites\$($site.Name)"
        Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication -PSPath $tempPath -Value 0 -ErrorAction SilentlyContinue
    }
    
    # Deny further override of anonymousAuthentication
    Set-WebConfiguration -Filter "//system.webServer/security/authentication/anonymousAuthentication" -Metadata overrideMode -Value Deny -PSPath IIS:/ -ErrorAction SilentlyContinue

    # Delete custom error pages
    $sysDrive = $Env:SystemDrive
    $tempPath = (Get-WebConfiguration "//httperrors/error" -ErrorAction SilentlyContinue | Select-Object -First 1).prefixLanguageFilePath
    if ($tempPath) {
        $relativePath = $tempPath.Substring($tempPath.IndexOf('\')+1)
        $fullPath = Join-Path $sysDrive $relativePath
        Get-ChildItem -Path $fullPath -Include *.* -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { 
            try { $_.Delete() } catch {} 
        }
    }
    Write-Host "`nIIS Hardening complete." -ForegroundColor Green
    Pause
}

# --------------------------
# Module 2: PII File Scan
# --------------------------
function Invoke-PIIScan {
    param(
        [String]$ScanPath = "C:\"
    )
    Write-Host "`nStarting PII File Scan on path: $ScanPath" -ForegroundColor Cyan
    $ErrorActionPreference = "SilentlyContinue"
    
    # Define patterns to match PII (phone numbers, addresses, etc.)
    $patterns = @(
        '\b\d{3}[)]?[-| |.]\d{3}[-| |.]\d{4}\b', 
        '\b\d{3}[-| |.]\d{2}[-| |.]\d{4}\b',
        '\b\d+\s+[\w\s]+\s+(?:road|street|avenue|boulevard|court)\b'
    )
    # File extensions to scan
    $fileExtensions = "\.docx|\.doc|\.odt|\.xlsx|\.xls|\.ods|\.pptx|\.ppt|\.odp|\.pdf|\.mdb|\.accdb|\.sqlite3?|\.eml|\.msg|\.txt|\.csv|\.html?|\.xml|\.json"
    
    Get-ChildItem -Recurse -Force -Path $ScanPath -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -match $fileExtensions } | 
    ForEach-Object {
        if ($pii = Select-String -Path $_.FullName -Pattern $patterns -ErrorAction SilentlyContinue) {
            Write-Host "`nPII found in file: $($_.FullName)" -ForegroundColor Red
            $pii | Select-Object -ExpandProperty Matches | Sort-Object Value -Unique | ForEach-Object {
                Write-Host $_.Value -ForegroundColor Yellow
            }
        }
    }
    Write-Host "`nPII File Scan complete." -ForegroundColor Green
    Pause
}

# --------------------------
# Module 3: SMB Hardening & System Enumeration
# --------------------------
function Invoke-SMBSecurity {
    Write-Host "`nStarting SMB Hardening & System Enumeration..." -ForegroundColor Cyan
    $Error.Clear()
    $ErrorActionPreference = "Continue"
    
    # Local helper for colored output
    function Write-ColorOutput($ForegroundColor, $Message) {
        $originalColor = $host.UI.RawUI.ForegroundColor
        $host.UI.RawUI.ForegroundColor = $ForegroundColor
        Write-Output $Message
        $host.UI.RawUI.ForegroundColor = $originalColor
    }
    
    Write-ColorOutput Green "------------- SMB -------------"
    
    # Display operating system and computer information
    $osVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
    Write-Host "`nOperating System: $osVersion"
    Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select-Object Name, Domain
    
    # Display network adapter information
    Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IpAddress -ne $null } | ForEach-Object {
        Write-Host "`nService: $($_.ServiceName)"
        Write-Host "IP(s): $((($_.IPAddress) -join ', '))"
    }
    
    # Manage shares (delete admin shares if they exist)
    net share C$ /delete | Out-Null
    net share ADMIN$ /delete | Out-Null
    net share
    
    # Configure Security Signature settings via registry
    reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
    
    # Additional Hardening Registry Tweaks
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RejectUnencryptedAccess /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AnnounceServer /t REG_DWORD /d 0 /f | Out-Null
    
    # Patch EternalBlue or disable SMB1 based on user input
    try {
        $userInput = Read-Host "`nType 'blue' to leave SMB1 enabled or press Enter to disable SMB1 and apply the patch"
        if ($userInput -eq "blue") {
            Write-Host "SMB1 is required. Downloading EternalBlue patch..."
            $patchURL = switch -Regex ($osVersion) {
                '(?i)Vista'  { "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.0-kb4012598-x64_6a186ba2b2b98b2144b50f88baf33a5fa53b5d76.msu" }
                'Windows 7'  { "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x64_2decefaa02e2058dcd965702509a992d8c4e92b3.msu" }
                'Windows 8'  { "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x64_5b24b9ca5a123a844ed793e0f2be974148520349.msu" }
                '2008 R2'    { "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x64_2decefaa02e2058dcd965702509a992d8c4e92b3.msu" }
                '2008'       { "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.0-kb4012598-x64_6a186ba2b2b98b2144b50f88baf33a5fa53b5d76.msu" }
                '2012 R2'    { "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x64_5b24b9ca5a123a844ed793e0f2be974148520349.msu" }
                '2012'       { "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8-rt-kb4012214-x64_b14951d29cb4fd880948f5204d54721e64c9942b.msu" }
                default { throw "Unsupported OS version: $osVersion" }
            }
            $downloadPath = "$env:TEMP\eternalblue_patch.msu"
            Write-Host "Downloading patch file to $downloadPath"
            $wc = New-Object Net.WebClient
            $wc.DownloadFile($patchURL, $downloadPath)
            Start-Process -Wait -FilePath "wusa.exe" -ArgumentList "$downloadPath /quiet /norestart"
            Remove-Item -Path $downloadPath -Force
            # Reenable SMB1 if necessary
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 1 /f | Out-Null
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v SMB1 /t REG_DWORD /d 1 /f | Out-Null
            Write-ColorOutput Green "`nEternalBlue patch applied! Good luck!"
        }
        else {
            throw "Disabling SMB1"
        }
    }
    catch {
        Write-ColorOutput Green "`n$($_.Exception.Message)"
        # Disable SMB1
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f | Out-Null
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v SMB1 /t REG_DWORD /d 0 /f | Out-Null
        # Set minimum SMB version (SMB2)
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB2 /t REG_DWORD /d 2 /f | Out-Null
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v SMB2 /t REG_DWORD /d 2 /f | Out-Null
        Write-ColorOutput Green "`nSMB1 disabled."
    }
    Write-Host "`n$Env:ComputerName SMB secured." -ForegroundColor Green
    Pause
}

# --------------------------
# Main Loop: Display Menu and Process Input
# --------------------------
do {
    Show-Menu
    $choice = Read-Host "Enter your selection (1-4)"
    switch ($choice) {
        "1" { Invoke-IISHardening }
        "2" {
            # Prompt for a path to scan; default to "C:\" if none provided.
            $scanPath = Read-Host "Enter directory to scan for PII (default: C:\)"
            if ([string]::IsNullOrWhiteSpace($scanPath)) { $scanPath = "C:\" }
            Invoke-PIIScan -ScanPath $scanPath
        }
        "3" { Invoke-SMBSecurity }
        "4" { Write-Host "`nExiting..."; break }
        default { Write-Host "`nInvalid selection. Please choose a valid option." -ForegroundColor Red }
    }
    Write-Host ""
} while ($choice -ne "4")

<#
.SYNOPSIS
    Windows Web Hardening and System Enumeration Script

.DESCRIPTION
    This script performs several hardening and enumeration tasks:
      - IIS hardening (minimal pool privileges, disables directory browsing, and disables anonymous authentication)
      - PII file scanning in common user and system directories
      - Enumerates network shares, OS details, firewall status, Defender settings, network adapters, local shares, installed software, and service statuses
      - (Optional) Exchange Security configuration backup and hardening (requires Exchange Management Shell)
      - (Optional) Process Monitor – alerts you when a new process starts and prompts you to allow or terminate it
      - (Optional) Service Monitor – alerts you when a new service is detected running and offers to stop it
      
    To run the optional monitors, use the switches -RunProcessMonitor and/or -RunServiceMonitor.
    This script must be run as Administrator.
    
.NOTES
    Author: Malachi Reynolds / Tyler (and others)
    Date: Spring 2024 / 01/26/25
#>

[CmdletBinding()]
param(
    [switch]$RunProcessMonitor,
    [switch]$RunServiceMonitor
)

# =====================================================
# 1. IIS Hardening
# =====================================================
Import-Module WebAdministration
Import-Module IIS-Administration

# Set application pool privileges to minimum
foreach ($item in Get-ChildItem IIS:\AppPools) {
    $tempPath = "IIS:\AppPools\$($item.Name)"
    Set-ItemProperty -Path $tempPath -Name processModel.identityType -Value 4
}

# Disable directory browsing on all sites
foreach ($item in Get-ChildItem IIS:\Sites) {
    $tempPath = "IIS:\Sites\$($item.Name)"
    Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath $tempPath -Value $false
}

# Allow PowerShell to write the anonymousAuthentication value
Set-WebConfiguration -Filter "//system.webServer/security/authentication/anonymousAuthentication" -Metadata overrideMode -Value Allow -PSPath IIS:/
# Disable Anonymous Authentication for each site
foreach ($item in Get-ChildItem IIS:\Sites) {
    $tempPath = "IIS:\Sites\$($item.Name)"
    Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication -PSPath $tempPath -Value 0
}
# Deny further override of anonymousAuthentication
Set-WebConfiguration -Filter "//system.webServer/security/authentication/anonymousAuthentication" -Metadata overrideMode -Value Deny -PSPath IIS:/

# Delete Custom Error Pages
$sysDrive = $Env:SystemDrive
$tempPath = (Get-WebConfiguration "//httperrors/error").prefixLanguageFilePath | Select-Object -First 1
$tempPath = $tempPath.Substring($tempPath.IndexOf('\')+1)
$fullPath = Join-Path $sysDrive $tempPath
Get-ChildItem -Path $fullPath -Include *.* -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $_.Delete() }

Write-Host "IIS hardening complete." -ForegroundColor Green

# =====================================================
# 2. PII File Scan
# =====================================================
$format = @(
    "\d{3}[)]?[-| |.]\d{3}[-| |.]\d{4}",
    "\d{3}[-| |.]\d{2}[-| |.]\d{4}",
    "\s[Aa]ve[\s|.]",
    "[Aa]venue",
    "\s[Ss]t[\s|.]",
    "[Ss]treet",
    "\s[Bb]lvd[\s|.]",
    "[Bb]oulevard",
    "\s[Rr]d[\s|.]",
    "[Rr]oad",
    "\s[Dd]r[\s|.]",
    "[Dd]rive",
    "[Cc]ourt",
    "\s[Cc]t[\s|.]",
    "[Ll]ane",
    "[Ll]n[\s|.]",
    "[Ww]ay"
)
$ErrorActionPreference = "SilentlyContinue"

$os = (Get-CimInstance Win32_OperatingSystem).Version
if ($os -ge '10.0.17134') {
    $recBin = 'C:\$Recycle.Bin'
} elseif ($os -ge '6.2.9200') {
    $recBin = 'C:\$Recycle.Bin'
} else {
    $recBin = 'C:\RECYCLER'
}
Write-Host "`nOS Version: $os`nRecycle Bin: $recBin" -ForegroundColor Blue

$netShares = Get-WmiObject Win32_Share | Where-Object { $_.Path -notlike 'C:\' -and $_.Path -notlike 'C:\Windows' -and $_.Path -ne '' } | Select-Object -ExpandProperty Path
Write-Host "`nNetwork Shares:" -ForegroundColor Blue
if ($netShares.Count -eq 0) {
    Write-Host "No network shares available." -ForegroundColor Yellow
} else {
    foreach ($share in $netShares) {
        Write-Host $share -ForegroundColor Blue
    }
}

Write-Host "`nScanning for PII files. This may take a few minutes..." -ForegroundColor Blue
$localPaths = @("C:\Users\*\Downloads", "C:\Users\*\Documents", "C:\Users\*\Desktop", "C:\inetpub", "C:\Users\*\Pictures", "C:\Windows\Temp", "$recBin")
$paths = $localPaths + $netShares | Select-Object -Unique
$printedFiles = @{}

foreach ($path in $paths) {
    foreach ($pattern in $format) {
        Get-ChildItem -Recurse -Force -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
            try {
                $matches = Select-String -Path $_.FullName -Pattern $pattern -ErrorAction SilentlyContinue
                if ($matches -and -not $printedFiles.ContainsKey($_.FullName)) {
                    Write-Host "`"$($matches.Matches.Value)`" - $($_.FullName)" -ForegroundColor Red
                    $printedFiles[$_.FullName] = $true
                }
            }
            catch {
                # Ignore files that cannot be read
            }
        }
    }
    Write-Host "$path scan completed." -ForegroundColor Green
}
$itemCount = $printedFiles.Count
if ($itemCount -gt 0) {
    Write-Host "`nFound $itemCount PII files." -ForegroundColor Green
} else {
    Write-Host "`nNo PII files found." -ForegroundColor Red
}

# =====================================================
# 3. Service Enumeration and System Info
# =====================================================
$ServiceInfo = @(
    # Web Servers
    @{ Name = "IIS Web"; Path = "C:\inetpub\wwwroot"; Port = 80 },
    @{ Name = "Apache Web"; Path = "C:\Program Files\Apache Group\Apache2"; Port = 80 },
    @{ Name = "Nginx Web"; Path = "C:\nginx"; Port = 80 },
    @{ Name = "HTTPS"; Path = "C:\inetpub\wwwroot"; Port = 443 },
    @{ Name = "XAMPP"; Path = "C:\xampp"; Port = 80 },

    # File Sharing Services
    @{ Name = "FTP Server"; Path = "C:\inetpub\ftproot"; Port = 21 },
    @{ Name = "FileZilla"; Path = "C:\Program Files\FileZilla Server\FileZilla server.exe"; Port = 21 },
    @{ Name = "SMB"; Path = "C:\Windows\System32\drivers\srv.sys"; Port = 445 },

    # Remote Access Services
    @{ Name = "RDP"; Path = "C:\Windows\System32\mstsc.exe"; Port = 3389 },
    @{ Name = "Telnet"; Path = "C:\Windows\System32\tlntsvr.exe"; Port = 23 },
    @{ Name = "OpenSSH"; Path = "C:\Program Files\OpenSSH"; Port = 22 },

    # Database Servers
    @{ Name = "MySQL"; Path = "C:\Program Files\MySQL\MySQL Server *"; Port = 3306 },
    @{ Name = "MicrosoftSQL"; Path = "C:\Program Files\Microsoft SQL Server"; Port = 1433 },
    @{ Name = "PostgreSQL"; Path = "C:\Program Files\PostgreSQL"; Port = 5432 },
    @{ Name = "MongoDB"; Path = "C:\Program Files\MongoDB\Server"; Port = 27017 },
    @{ Name = "Redis"; Path = "C:\Program Files\Redis"; Port = 6379 },

    # Mail Services
    @{ Name = "SMTP Server"; Path = "C:\Windows\System32\smtpsvc.dll"; Port = 25 },
    @{ Name = "POP3 Mail"; Path = "C:\Program Files\POP3 Service"; Port = 110 },
    @{ Name = "IMAP Mail"; Path = "C:\Program Files\IMAP Service"; Port = 143 },

    # DNS Services
    @{ Name = "DNS"; Path = "C:\Windows\System32\dns.exe"; Port = 53 },

    # Virtualization and Containerization
    @{ Name = "Docker"; Path = "C:\Program Files\Docker"; Port = 2375 },
    @{ Name = "Kubernetes"; Path = "C:\kubernetes"; Port = 10250 },

    # Other Common Services
    @{ Name = "LDAP"; Path = "C:\Windows\System32\ntds.dit"; Port = 389 },
    @{ Name = "SNMP"; Path = "C:\Windows\System32\snmp.exe"; Port = 161 },
    @{ Name = "NTP"; Path = "C:\Windows\System32\w32time.dll"; Port = 123 },
    @{ Name = "VNC Server"; Path = "C:\Program Files\RealVNC\VNC Server"; Port = 5900 },
    @{ Name = "WinRM"; Path = "C:\Windows\System32\winrm.cmd"; Port = 5985 },
    @{ Name = "Syslog"; Path = "C:\Program Files\Syslog"; Port = 514 }
)

$StartTime = Get-Date

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "`nError: This script must be run as Administrator for full enumeration." -ForegroundColor Red
}

Write-Output "`n===================================="
Write-Output "==> Operating System Information <=="
Write-Output "===================================="

$OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
try {
    $Domain = (Get-ADDomain -ErrorAction Stop).DNSRoot
    $DC = if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') { $true } else { $false }
} catch {
    $Domain = "N/A"
    $DC = $false
}

[PSCustomObject]@{
    "Name"         = $OSInfo.CSName
    "OS"           = ($OSInfo.Caption -replace "Microsoft ", "")
    "Domain"       = $Domain
    "DC"           = $DC
    "Version"      = $OSInfo.Version
    "Build Number" = $OSInfo.BuildNumber
} | Format-Table -AutoSize

Write-Output "`n===================================="
Write-Output "======> Host Firewall Status <======"
Write-Output "====================================`n"

$lines = (netsh advfirewall show allprofiles state) -split "`r`n"
$profiles = @("Domain Profile", "Private Profile", "Public Profile")
foreach ($profile in $profiles) {
    $profileLine = $lines | Where-Object { $_ -match "$profile Settings:" }
    if ($profileLine) {
        $profileIndex = $lines.IndexOf($profileLine)
        for ($i = 1; $i -le 3; $i++) {
            if ($profileIndex + $i -lt $lines.Count) {
                $stateLine = $lines[$profileIndex + $i]
                if ($stateLine -match "State\s+(\w+)") {
                    $state = $matches[1]
                    if ($state -eq "ON") {
                        Write-Host "$profile`: $state" -ForegroundColor Green
                    } elseif ($state -eq "OFF") {
                        Write-Host "$profile`: $state" -ForegroundColor Red
                    } else {
                        Write-Host "$profile`: Unknown ($state)" -ForegroundColor Yellow
                    }
                    break
                }
            }
        }
    } else {
        Write-Host "$profile`: N\A" -ForegroundColor Yellow
    }
}

Write-Output "`n===================================="
Write-Output "===> Defender Antivirus Status <===="
Write-Output "====================================`n"

try {
    $defenderExceptions = @{
        Processes   = (Get-MpPreference).ExclusionProcess
        Paths       = (Get-MpPreference).ExclusionPath
        Extensions  = (Get-MpPreference).ExclusionExtension
        IPAddresses = (Get-MpPreference).ExclusionIpAddress
    }
    $defenderStatus = Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, AntispywareEnabled
    Write-Host "Windows Defender Status:" -ForegroundColor Cyan
    $defenderStatus.PSObject.Properties | ForEach-Object {
        $color = if ($_.Value -eq $true) { "Green" } else { "Red" }
        Write-Host "$($_.Name): $($_.Value)" -ForegroundColor $color
    }
    Write-Host "`nWindows Defender Exceptions:" -ForegroundColor Cyan
    $defenderExceptions.GetEnumerator() | ForEach-Object {
        Write-Host "`n$($_.Key) Exceptions:" -ForegroundColor Yellow
        if ($_.Value) {
            $_.Value | ForEach-Object { Write-Host "- $_" -ForegroundColor White }
        } else {
            Write-Host "No exceptions found." -ForegroundColor Gray
        }
    }
}
catch {
    Write-Host "Defender returned an error. Likely not working." -ForegroundColor Red
}

Write-Output "`n===================================="
Write-Output "=====> Network Configuration <======"
Write-Output "===================================="

$NetworkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
$NetworkAdapters | Select-Object Name, @{Name="IP"; Expression={ (Get-NetIPAddress -InterfaceAlias $_.Name -AddressFamily IPv4).IPAddress }}, MacAddress | Format-Table -AutoSize

Write-Output "`n===================================="
Write-Output "==========> Local Shares <=========="
Write-Output "===================================="
$shares = Get-WmiObject -Class Win32_Share -ComputerName $env:COMPUTERNAME | Where-Object { $_.Name -notlike "*$" }
if ($shares) {
    $shares | Format-Table Name, Path -AutoSize
} else {
    Write-Host "`nNo local shares found." -ForegroundColor Yellow
}

Write-Output "`n===================================="
Write-Output "=======> Installed Software <======="
Write-Output "===================================="
$InstalledPrograms = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* , HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" -and $_.DisplayName -notmatch "Microsoft \.NET|Microsoft Visual C\+\+|Microsoft Windows Desktop Runtime" } |
    Select-Object DisplayName, DisplayVersion
$InstalledPrograms | Sort-Object DisplayName | Format-Table -AutoSize

$ActivePorts = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' -or $_.State -eq 'Established' } | Select-Object -ExpandProperty LocalPort

$Results = @()
foreach ($Service in $ServiceInfo) {
    $PathExists = Test-Path -Path $Service.Path
    $IsPortActive = $ActivePorts -contains $Service.Port
    $Results += [PSCustomObject]@{
        "Name"      = $Service.Name
        "Exists"    = $PathExists
        "Listening" = $IsPortActive
        "Port"      = $Service.Port
        "Filepath"  = $Service.Path
        "Status"    = if ($PathExists -and $IsPortActive) { "Running" }
                       elseif ($PathExists) { "Not Running" }
                       elseif ($IsPortActive) { "Not Installed" }
                       else { "Not Found" }
    }
}
Write-Output "`n===================================="
Write-Output "========> Service Status <=========="
Write-Output "===================================="
$Results | Format-Table -AutoSize

Write-Host "`nEnumeration Complete!" -ForegroundColor Green
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Error: This script must be run as Administrator for full enumeration." -ForegroundColor Red
}

$EndTime = Get-Date
Write-Output "`nScript Execution Time: $(($EndTime - $StartTime).TotalSeconds) seconds`n`n"

# =====================================================
# 4. Exchange Security Configuration (Optional)
# =====================================================
<# 
NOTE: To use the Exchange configuration section, ensure that the Exchange Management Shell is installed,
      and then uncomment this block and run the script as Administrator.
      
$ErrorActionPreference = "Stop"

function Write-Log {
    param($Message)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Write-Host $logMessage
    Add-Content -Path "C:\ExchangeSecurityLog.txt" -Value $logMessage
}

function Backup-ExchangeConfig {
    $backupTime = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFolder = "C:\ExchangeBackup_$backupTime"
    
    Write-Log "Creating backup folder: $backupFolder"
    New-Item -ItemType Directory -Path $backupFolder -Force | Out-Null

    try {
        Write-Log "Backing up Organization Configuration..."
        Get-OrganizationConfig | Export-Clixml "$backupFolder\OrganizationConfig.xml"

        Write-Log "Backing up Transport Configuration..."
        Get-TransportConfig | Export-Clixml "$backupFolder\TransportConfig.xml"

        Write-Log "Backing up Virtual Directories..."
        Get-OwaVirtualDirectory | Export-Clixml "$backupFolder\OwaVirtualDirectory.xml"
        Get-EcpVirtualDirectory | Export-Clixml "$backupFolder\EcpVirtualDirectory.xml"
        Get-WebServicesVirtualDirectory | Export-Clixml "$backupFolder\WebServicesVirtualDirectory.xml"
        Get-PowerShellVirtualDirectory | Export-Clixml "$backupFolder\PowerShellVirtualDirectory.xml"

        Write-Log "Backing up Malware Filter Settings..."
        Get-MalwareFilterPolicy | Export-Clixml "$backupFolder\MalwareFilterPolicy.xml"

        Write-Log "Backing up Authentication Settings..."
        Get-AuthConfig | Export-Clixml "$backupFolder\AuthConfig.xml"

        Write-Log "Backing up Transport Rules..."
        Get-TransportRule | Export-Clixml "$backupFolder\TransportRules.xml"

        $restoreScript = @"
# Exchange Configuration Restore Script
Write-Host "Restoring Exchange Configuration from backup $backupTime"
Import-Clixml "$backupFolder\OrganizationConfig.xml" | Set-OrganizationConfig
Import-Clixml "$backupFolder\TransportConfig.xml" | Set-TransportConfig
Import-Clixml "$backupFolder\AuthConfig.xml" | Set-AuthConfig
Write-Host "Configuration restored. Please review settings."
"@
        $restoreScript | Out-File "$backupFolder\RestoreConfig.ps1"

        Write-Log "Backup completed successfully to: $backupFolder"
        Write-Log "Restore script created at: $backupFolder\RestoreConfig.ps1"
        
        return $backupFolder
    }
    catch {
        Write-Log "Error during backup: $_"
        throw "Backup failed. Aborting configuration changes."
    }
}

try {
    $exchServer = Get-ExchangeServer
    Write-Log "Exchange Management Shell verified"
} catch {
    Write-Host "Error: Exchange Management Shell not loaded. Please run 'Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn' first." -ForegroundColor Red
    exit
}

$config = @{}

Write-Host "`nExchange Security Configuration" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan

function Get-UserInput {
    param ($prompt, $default)
    $usrinput = Read-Host "$prompt [Default: $default]"
    if ([string]::IsNullOrWhiteSpace($usrinput)) { return $default }
    return $usrinput
}

$performBackup = Get-UserInput "Create backup before making changes? (yes/no)" "yes"
if ($performBackup -eq "yes") {
    $backupLocation = Backup-ExchangeConfig
    Write-Host "Backup created at: $backupLocation" -ForegroundColor Green
    Write-Host "To restore configuration, run RestoreConfig.ps1 from the backup folder" -ForegroundColor Yellow
}

$config.DomainName = Get-UserInput "Enter external domain (e.g., mail.company.com)" "mail.company.com"
$config.EnableModernAuth = Get-UserInput "Enable Modern Authentication? (true/false)" "true"
$config.DisableLegacyAuth = Get-UserInput "Disable Legacy Authentication? (true/false)" "true"

try {
    Write-Log "Starting Exchange security configuration..."
    if ($config.EnableModernAuth -eq "true") {
        Write-Log "Enabling Modern Authentication..."
        Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
    }
    if ($config.DisableLegacyAuth -eq "true") {
        Write-Log "Disabling Legacy Authentication..."
        Get-VirtualDirectory | Set-VirtualDirectory -BasicAuthentication $false -DigestAuthentication $false
        Get-VirtualDirectory | Set-VirtualDirectory -WindowsAuthentication $true
    }
    Write-Log "Enabling Audit Logging..."
    Set-AdminAuditLogConfig -AdminAuditLogEnabled $true -AdminAuditLogCmdlets * -AdminAuditLogParameters *
    Write-Log "Configuring Transport Security..."
    Set-TransportConfig -ExternalDNSServersEnabled $false
    Write-Log "Configuring Malware Filter..."
    $malwareConfig = Get-MalwareFilterPolicy Default
    if ($malwareConfig) {
        Set-MalwareFilterPolicy Default -EnableFileFilter $true -ZapEnabled $true
    } else {
        Write-Log "Warning: Default malware filter policy not found"
    }
    Write-Log "Configuring External URLs..."
    $serverName = $env:COMPUTERNAME
    try {
        Set-OwaVirtualDirectory "$serverName\OWA (Default Web Site)" -ExternalUrl "https://$($config.DomainName)/owa" -Force
        Set-EcpVirtualDirectory "$serverName\ECP (Default Web Site)" -ExternalUrl "https://$($config.DomainName)/ecp" -Force
    } catch {
        Write-Log "Warning: Could not set virtual directory URLs. Error: $_"
    }
    Write-Log "Exporting configuration..."
    $finalConfig = @{
        "ModernAuth" = (Get-OrganizationConfig).OAuth2ClientProfileEnabled
        "AuditLogging" = (Get-AdminAuditLogConfig).AdminAuditLogEnabled
        "ExternalDNSDisabled" = (Get-TransportConfig).ExternalDNSServersEnabled
    }
    $finalConfig | Export-Clixml "C:\ExchangeSecurityConfig.xml"
    Write-Log "Configuration exported to C:\ExchangeSecurityConfig.xml"
    Write-Log "Configuration completed successfully"
    Write-Host "`nRemember: Your configuration backup is located at: $backupLocation" -ForegroundColor Green
} catch {
    Write-Log "Error occurred: $_"
    Write-Host "Script encountered an error. Check C:\ExchangeSecurityLog.txt for details" -ForegroundColor Red
    Write-Host "To restore previous configuration, run RestoreConfig.ps1 from: $backupLocation" -ForegroundColor Yellow
}
#>

# =====================================================
# 5. Optional: Process Monitor (Requires RunAsAdministrator)
# =====================================================
if ($RunProcessMonitor) {
    Write-Host "`nStarting Process Monitor..." -ForegroundColor Cyan
    $script:allowedProcesses = @{}
    Get-Process | ForEach-Object { $script:allowedProcesses[$_.Name] = $true }
    $popupTimeout = 15  
    $buttonYes = 6     
    $buttonNo = 7      
    $action = {
        $processName = $event.SourceEventArgs.NewEvent.ProcessName
        $processId   = $event.SourceEventArgs.NewEvent.ProcessId

        if (-not $script:allowedProcesses.ContainsKey($processName)) {
            $popupMessage = @"
ALARM! NEW PROCESS HAS STARTED!
Name: $processName
PID: $processId

Allow this process?
"@
            $wshell   = New-Object -ComObject WScript.Shell
            $response = $wshell.Popup($popupMessage, $popupTimeout, "Security Control - $processName", 0x34 -bor 0x1000)
            switch ($response) {
                $buttonYes {
                    $script:allowedProcesses[$processName] = $true
                    Write-Host "[ALLOWED] $processName (PID: $processId)"
                }
                default {
                    Write-Host "[TERMINATING] $processName (PID: $processId)"
                    Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
    $query = "SELECT * FROM Win32_ProcessStartTrace"
    $eventParams = @{
        Query            = $query
        Action           = $action
        SourceIdentifier = "ProcessMonitor"
        ErrorAction      = "Stop"
    }
    Register-CimIndicationEvent @eventParams | Out-Null

    Write-Host "Process Monitor Active (Ctrl+C to exit)..." -ForegroundColor Yellow
    Write-Host "Allowed processes: $($script:allowedProcesses.Count)" -ForegroundColor Yellow
    try {
        while ($true) { Start-Sleep -Seconds 1 }
    }
    finally {
        Unregister-Event -SourceIdentifier "ProcessMonitor"
        Get-EventSubscriber | Where-Object SourceIdentifier -eq "ProcessMonitor" | Unregister-Event
    }
}

# =====================================================
# 6. Optional: Service Monitor (Requires RunAsAdministrator)
# =====================================================
if ($RunServiceMonitor) {
    Write-Host "`nStarting Service Monitor..." -ForegroundColor Cyan
    while ($true) {
        $Cmp = Get-Service | Where-Object { $_.Status -eq "Running" }
        while ($true) {
            $Cmp2 = Get-Service | Where-Object { $_.Status -eq "Running" }
            $diff = Compare-Object -ReferenceObject $Cmp -DifferenceObject $Cmp2 -Property Name
            if ($diff -ne $null) {
                $tmp = Get-WmiObject Win32_Service | Where-Object { $_.Name -like $diff.Name } | Select-Object Name, DisplayName, State, PathName
                if ($tmp.State -eq "Stopped") { break }
                Write-Output '!!!!!!!!!! A SERVICE HAS STARTED !!!!!!!!!!'
                Write-Output ('Display Name: ' + $tmp.DisplayName)
                Write-Output ('Name: ' + $tmp.Name)
                Write-Output ('State: ' + $tmp.State)
                Write-Output ('Path: ' + $tmp.PathName)
                Write-Output '!!!!!!!!!! A SERVICE HAS STARTED !!!!!!!!!!'
                Write-Output 'Kill? (y/n)'
                $Return = Read-Host
                if ($Return -match "^(y|Y)$") {
                    Stop-Service -Name $diff.Name -Force -NoWait  
                    Write-Output 'Kerblam! Service has been eliminated...'
                    Write-Output 'Might want to search for some bad guys around here'
                }
                elseif ($Return -match "^(n|N)$") {
                    Write-Output 'Letting that service slide...for now...'
                    break
                }
            }
            Start-Sleep -Seconds 1
        }
    }
}

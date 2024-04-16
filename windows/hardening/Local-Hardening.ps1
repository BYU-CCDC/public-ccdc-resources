
# Taken from Stanford Repo. Edited by BYU
# SCHOOL: DSU

#Enable-PSRemoting -Force
Set-ExecutionPolicy RemoteSigned -Force


# Start the Windows Firewall service
Invoke-Expression "net start mpssvc"

# Set multicastbroadcastresponse to disable for all profiles
Invoke-Expression "netsh advfirewall firewall set multicastbroadcastresponse disable"
Invoke-Expression "netsh advfirewall firewall set multicastbroadcastresponse mode=disable profile=all"

# Set logging settings for Domain, Private, and Public profiles
Invoke-Expression "netsh advfirewall set Domainprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log"
Invoke-Expression "netsh advfirewall set Domainprofile logging maxfilesize 20000"
Invoke-Expression "netsh advfirewall set Privateprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log"
Invoke-Expression "netsh advfirewall set Privateprofile logging maxfilesize 20000"
Invoke-Expression "netsh advfirewall set Publicprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log"
Invoke-Expression "netsh advfirewall set Publicprofile logging maxfilesize 20000"
Invoke-Expression "netsh advfirewall set Publicprofile logging droppedconnections enable"
Invoke-Expression "netsh advfirewall set Publicprofile logging allowedconnections enable"
Invoke-Expression "netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log"
Invoke-Expression "netsh advfirewall set currentprofile logging maxfilesize 4096"
Invoke-Expression "netsh advfirewall set currentprofile logging droppedconnections enable"
Invoke-Expression "netsh advfirewall set currentprofile logging allowedconnections enable"

# Start Defender Service
Start-Service -Name WinDefend

# Set Defender Policies
$defenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$defenderScanPath = "$defenderPath\Scan"
$defenderRealTimeProtectionPath = "$defenderPath\Real-Time Protection"
$defenderReportingPath = "$defenderPath\Reporting"
$defenderSpynetPath = "$defenderPath\Spynet"
$defenderFeaturesPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"

# Create or set registry values for Defender policies
New-ItemProperty -Path $defenderPath -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path $defenderPath -Name "DisableAntiVirus" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path $defenderPath -Name "ServiceKeepAlive" -Value 1 -PropertyType DWORD -Force
New-ItemProperty -Path $defenderScanPath -Name "DisableHeuristics" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value 3 -PropertyType DWORD -Force
New-ItemProperty -Path $defenderRealTimeProtectionPath -Name "DisableRealtimeMonitoring" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path $defenderScanPath -Name "CheckForSignaturesBeforeRunningScan" -Value 1 -PropertyType DWORD -Force
New-ItemProperty -Path $defenderRealTimeProtectionPath -Name "DisableBehaviorMonitoring" -Value 1 -PropertyType DWORD -Force
New-ItemProperty -Path $defenderReportingPath -Name "DisableGenericRePorts" -Value 1 -PropertyType DWORD -Force
New-ItemProperty -Path $defenderSpynetPath -Name "LocalSettingOverrideSpynetReporting" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path $defenderSpynetPath -Name "SubmitSamplesConsent" -Value 2 -PropertyType DWORD -Force
New-ItemProperty -Path $defenderSpynetPath -Name "DisableBlockAtFirstSeen" -Value 1 -PropertyType DWORD -Force
New-ItemProperty -Path $defenderSpynetPath -Name "SpynetReporting" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path $defenderFeaturesPath -Name "TamperProtection" -Value 5 -PropertyType DWORD -Force

# Start Windows Update Service and set startup type to automatic
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# Windows Update registry keys
$windowsUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$windowsUpdateAUPath = "$windowsUpdatePath\AU"
$windowsUpdateAutoUpdatePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"

New-ItemProperty -Path $windowsUpdateAUPath -Name "AutoInstallMinorUpdates" -Value 1 -PropertyType DWORD -Force
New-ItemProperty -Path $windowsUpdateAUPath -Name "NoAutoUpdate" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path $windowsUpdateAUPath -Name "AUOptions" -Value 4 -PropertyType DWORD -Force
New-ItemProperty -Path $windowsUpdateAutoUpdatePath -Name "AUOptions" -Value 4 -PropertyType DWORD -Force
New-ItemProperty -Path $windowsUpdatePath -Name "ElevateNonAdmins" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWindowsUpdate" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWindowsUpdate" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SYSTEM\Internet Communication Management\Internet Communication" -Name "DisableWindowsUpdateAccess" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path $windowsUpdateAutoUpdatePath -Name "IncludeRecommendedUpdates" -Value 1 -PropertyType DWORD -Force
New-ItemProperty -Path $windowsUpdateAutoUpdatePath -Name "ScheduledInstallTime" -Value 22 -PropertyType DWORD -Force
New-ItemProperty -Path $windowsUpdatePath -Name "DeferFeatureUpdates" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path $windowsUpdatePath -Name "DeferQualityUpdates" -Value 0 -PropertyType DWORD -Force

# Delete netlogon fullsecurechannelprotection then add a new key with it enabled
Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Value 1 -PropertyType DWORD -Force

# Disable the print spooler and make it never start
Get-Service -Name Spooler | Stop-Service -Force
Set-Service -Name Spooler -StartupType Disabled -Status Stopped

# DISM commands to disable insecure and unnecessary features
# These commands are called within CMD from PowerShell
Invoke-Expression 'cmd /c "dism /online /disable-feature /featurename:TFTP /NoRestart"'
Invoke-Expression 'cmd /c "dism /online /disable-feature /featurename:TelnetClient /NoRestart"'
Invoke-Expression 'cmd /c "dism /online /disable-feature /featurename:TelnetServer /NoRestart"'
Invoke-Expression 'cmd /c "dism /online /disable-feature /featurename:SMB1Protocol /NoRestart"'

# Disables editing registry remotely
Get-Service -Name RemoteRegistry | Stop-Service -Force
Set-Service -Name RemoteRegistry -StartupType Disabled -Status Stopped -Confirm:$false

# Remove sticky keys
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /f
Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\sethc.exe" -NoNewWindow -Wait
Start-Process icacls.exe -ArgumentList "C:\Windows\System32\sethc.exe /grant administrators:F" -NoNewWindow -Wait
Remove-Item -Path "C:\Windows\System32\sethc.exe" -Force

# Delete utility manager (backdoor)
Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\Utilman.exe" -NoNewWindow -Wait
Start-Process icacls.exe -ArgumentList "C:\Windows\System32\Utilman.exe /grant administrators:F" -NoNewWindow -Wait
Remove-Item -Path "C:\Windows\System32\Utilman.exe" -Force

# Delete on-screen keyboard (backdoor)
Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\osk.exe" -NoNewWindow -Wait
Start-Process icacls.exe -ArgumentList "C:\Windows\System32\osk.exe /grant administrators:F" -NoNewWindow -Wait
Remove-Item -Path "C:\Windows\System32\osk.exe" -Force

# Delete narrator (backdoor)
Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\Narrator.exe" -NoNewWindow -Wait
Start-Process icacls.exe -ArgumentList "C:\Windows\System32\Narrator.exe /grant administrators:F" -NoNewWindow -Wait
Remove-Item -Path "C:\Windows\System32\Narrator.exe" -Force

# Delete magnify (backdoor)
Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\Magnify.exe" -NoNewWindow -Wait
Start-Process icacls.exe -ArgumentList "C:\Windows\System32\Magnify.exe /grant administrators:F" -NoNewWindow -Wait
Remove-Item -Path "C:\Windows\System32\Magnify.exe" -Force

#Delete ScheduledTasks
Get-ScheduledTask | Unregister-ScheduledTask -Confirm:$false

#Disable Guest user
net user Guest /active:no

#Make sure DEP is allowed (Triple Negative)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f

#Only privileged groups can add or delete printer drivers
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

#Don't execute autorun commands
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

#Don't allow empty password login
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

#Only local sessions can control the CD/Floppy
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f

# Enable logging for EVERYTHING
auditpol /set /category:* /success:enable /failure:enable

# Set specific subcategory policies
$auditCategories = @(
    "Security State Change", "Security System Extension", "System Integrity", "IPsec Driver", "Other System Events",
    "Logon", "Logoff", "Account Lockout", "IPsec Main Mode", "IPsec Quick Mode", "IPsec Extended Mode", "Special Logon",
    "Other Logon/Logoff Events", "Network Policy Server", "User / Device Claims", "Group Membership", "File System",
    "Registry", "Kernel Object", "SAM", "Certification Services", "Application Generated", "Handle Manipulation",
    "File Share", "Filtering Platform Packet Drop", "Filtering Platform Connection", "Other Object Access Events",
    "Detailed File Share", "Removable Storage", "Central Policy Staging", "Sensitive Privilege Use",
    "Non Sensitive Privilege Use", "Other Privilege Use Events", "Process Creation", "Process Termination", "DPAPI Activity",
    "RPC Events", "Plug and Play Events", "Token Right Adjusted Events", "Audit Policy Change",
    "Authentication Policy Change", "Authorization Policy Change", "MPSSVC Rule-Level Policy Change",
    "Filtering Platform Policy Change", "Other Policy Change Events", "User Account Management", "Computer Account Management",
    "Security Group Management", "Distribution Group Management", "Application Group Management",
    "Other Account Management Events", "Directory Service Access", "Directory Service Changes",
    "Directory Service Replication", "Detailed Directory Service Replication", "Credential Validation",
    "Kerberos Service Ticket Operations", "Other Account Logon Events", "Kerberos Authentication Service"
)

foreach ($category in $auditCategories) {
    auditpol /set /subcategory:"$category" /success:enable /failure:enable
}

#Flush DNS Lookup Cache
ipconfig /flushdns

#Enable UAC popups if software trys to make changes
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

#Require admin authentication for operations that requires elevation of privileges
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorAdmin /T REG_DWORD /D 1 /F
#Does not allow user to run elevates privileges
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorUser /T REG_DWORD /D 0 /F
#Built-in administrator account is placed into Admin Approval Mode, admin approval is required for administrative tasks
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V FilterAdministratorToken /T REG_DWORD /D 1 /F

#Disable Multiple Avenues for Backdoors
reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f
reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f

#Don't allow Windows Search and Cortana to search cloud sources (OneDrive, SharePoint, etc.)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f
#Disable Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
#Disable Cortana when locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
#Disable location permissions for windows search
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f

#start-process powershell.exe -argument '-nologo -noprofile -executionpolicy bypass -command [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Set-MpPreference -ThreatIDDefaultAction_Ids "2147597781" -ThreatIDDefaultAction_Actions "6"; Invoke-WebRequest -Uri https://github.com/ION28/BLUESPAWN/releases/download/v0.5.1-alpha/BLUESPAWN-client-x64.exe -OutFile BLUESPAWN-client-x64.exe; & .\BLUESPAWN-client-x64.exe --monitor -a Normal --log=console,xml'


#start-process powershell.exe -argument '-nologo -noprofile -executionpolicy bypass -command [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri https://download.comodo.com/cce/download/setups/cce_public_x64.zip?track=5890 -OutFile cce_public_x64.zip; Expand-Archive cce_public_x64.zip; .\cce_public_x64\cce_2.5.242177.201_x64\cce_x64\cce.exe -u; read-host "CCE Continue When Updated"; .\cce_public_x64\cce_2.5.242177.201_x64\cce_x64\cce.exe -s \"m;f;r\" -d "c"; read-host "CCE Finished"'

sc.exe config trustedinstaller start= auto
DISM /Online /Cleanup-Image /RestoreHealth
sfc /scannow

# SCHOOL: CPP

$Error.Clear()
$ErrorActionPreference = "Continue"


Write-Output "#########################"
Write-Output "#                       #"
Write-Output "#         Hard          #"
Write-Output "#                       #"
Write-Output "#########################"


Write-Output "#########################"
Write-Output "#    Hostname/Domain    #"
Write-Output "#########################"
Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select-Object Name, Domain
Write-Output "#########################"
Write-Output "#          IP           #"
Write-Output "#########################"
Get-WmiObject Win32_NetworkAdapterConfiguration | ? {$_.IpAddress -ne $null} | % {$_.ServiceName + "`n" + $_.IPAddress + "`n"}

$DC = $false
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    $DC = $true
    Import-Module ActiveDirectory
}

# Disable storage of the LM hash for passwords less than 15 characters
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f | Out-Null
# https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/enable-ntlm-2-authentication
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
# Disable storage of plaintext creds in WDigest
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
# Enable remote UAC for Local accounts
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f | Out-Null
# Enable LSASS Protection
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
# Enable LSASSS process auditing
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null
Write-Output "$Env:ComputerName [INFO] PTH Mitigation complete"
######### Defender #########

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 3 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v MpCloudBlockLevel /t REG_DWORD /d 6 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v "ForceDefenderPassiveMode" /t REG_DWORD /d 0 /f | Out-Null
Write-Output "$Env:ComputerName [INFO] Set Defender options" 

try {
    # Block Office applications from injecting code into other processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Office applications from creating executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block all Office applications from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block JavaScript or VBScript from launching downloaded executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block execution of potentially obfuscated scripts
    Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block executable content from email client and webmail
    Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Win32 API calls from Office macro
    Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block process creations originating from PSExec and WMI commands
    Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block untrusted and unsigned processes that run from USB
    Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Use advanced protection against ransomware
    Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Office communication application from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Adobe Reader from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block persistence through WMI event subscription
    Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    Write-Output "$Env:ComputerName [INFO] Defender Attack Surface Reduction rules enabled" 
    ForEach ($ExcludedASR in (Get-MpPreference).AttackSurfaceReductionOnlyExclusions) {
        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $ExcludedASR | Out-Null
    }
}
catch {
    Write-Output "$Env:ComputerName [INFO] Old defender version detected, skipping ASR rules" 
}
ForEach ($ExcludedExt in (Get-MpPreference).ExclusionExtension) {
    Remove-MpPreference -ExclusionExtension $ExcludedExt | Out-Null
}
ForEach ($ExcludedIp in (Get-MpPreference).ExclusionIpAddress) {
    Remove-MpPreference -ExclusionIpAddress $ExcludedIp | Out-Null
}
ForEach ($ExcludedDir in (Get-MpPreference).ExclusionPath) {
    Remove-MpPreference -ExclusionPath $ExcludedDir | Out-Null
}
ForEach ($ExcludedProc in (Get-MpPreference).ExclusionProcess) {
    Remove-MpPreference -ExclusionProcess $ExcludedProc | Out-Null
}
Write-Output "$Env:ComputerName [INFO] Defender exclusions removed" 
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 5 /f | Out-Null

######### Service Lockdown #########
# RDP NLA
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP" /v UserAuthentication /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f | Out-Null

if ($DC) {
    # Add-ADGroupMember -Identity "Protected Users" -Members "Domain Users"
    # CVE-2020-1472 (Zerologon)
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "vulnerablechannelallowlist" -Force | Out-Null
    # CVE-2021-42278 & CVE-2021-42287 (noPac)
    Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota"="0"} | Out-Null
}


net stop spooler | Out-Null
sc.exe config spooler start=disabled | Out-Null
Write-Output "$Env:ComputerName [INFO] Services locked down" 

# CVE-2021-34527 (PrintNightmare)
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f | Out-Null
reg delete "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /f | Out-Null
reg delete "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v UpdatePromptSettings /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f | Out-Null
# Network security: LDAP client signing requirements
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f | Out-Null
# Domain Controller: LDAP Server signing requirements
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f | Out-Null
# Disable BITS transfers
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 1 /f | Out-Null
Write-Output "$Env:ComputerName [INFO] BITS locked down"
# UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f | Out-Null
Write-Output "$Env:ComputerName [INFO] UAC enabled"

$Error | Out-File $env:USERPROFILE\Desktop\hard.txt -Append -Encoding utf8
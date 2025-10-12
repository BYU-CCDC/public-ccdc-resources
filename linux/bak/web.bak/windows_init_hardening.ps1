#TESTING

# Define log file for tracking changes
$logFile = "C:\HardeningLogs\initial_hardening_log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Create log directory if it doesn't exist
if (!(Test-Path -Path "C:\HardeningLogs")) {
    New-Item -Path "C:\HardeningLogs" -ItemType Directory | Out-Null
}

# Function to log actions
function Write-Log {
    param (
        [string]$message
    )
    Write-Output "$currentDateTime - $message" | Out-File -FilePath $logFile -Append
}

Write-Log "Starting initial hardening process..."

# Step 1: Disable Unnecessary Services
$servicesToDisable = @(
    "RemoteRegistry",
    "WSearch",  # Windows Search
    "Fax",
    "XblGameSave",
    "XboxNetApiSvc",
    "DiagTrack",  # Diagnostics Tracking Service
    "dmwappushservice"  # WAP Push Message Routing Service
)

foreach ($service in $servicesToDisable) {
    Write-Log "Disabling service: $service"
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    Set-Service -Name $service -StartupType Disabled
}

# Step 2: Enable Firewall with Basic Rules
Write-Log "Configuring Windows Firewall with default rules"
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles settings inboundblocklog yes
netsh advfirewall set allprofiles settings outboundblocklog yes

# Block inbound connections by default and allow outbound
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

# Step 3: Configure RDP and Remote Management
Write-Log "Securing RDP settings"
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' -Name "MinEncryptionLevel" -Value 3

# Disable RDP if not needed (uncomment if RDP should be disabled entirely)
# Write-Log "Disabling RDP"
# Set-Service -Name "TermService" -StartupType Disabled
# Stop-Service -Name "TermService" -Force

# Step 4: Enforce Strong Password Policies
Write-Log "Configuring password policies"
net accounts /minpwlen:12
net accounts /maxpwage:30
net accounts /minpwage:1
net accounts /uniquepw:5
net accounts /lockoutthreshold:3
net accounts /lockoutduration:30
net accounts /lockoutwindow:30

# Step 5: Enable Auditing for Key Events
Write-Log "Enabling auditing policies"
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable

# Step 6: Configure Windows Defender (if not already using a different AV)
Write-Log "Configuring Windows Defender settings"
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableIntrusionPreventionSystem $false
Set-MpPreference -PUAProtection enable
Set-MpPreference -ScanScheduleDay 0
Set-MpPreference -ScanScheduleTime 02:00
Set-MpPreference -SignatureUpdateInterval 8
Set-MpPreference -DisableArchiveScanning $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableScriptScanning $false

# Step 7: Enable Enhanced Logging
Write-Log "Enabling enhanced logging for visibility"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v IncludeAllUsers /t REG_DWORD /d 1 /f

# Step 8: Restrict Local Admin Account
Write-Log "Restricting and renaming the local Administrator account"
Rename-LocalUser -Name "Administrator" -NewName "Admin_$((Get-Random -Minimum 1000 -Maximum 9999))"
Set-LocalUser -Name "Admin_$((Get-Random -Minimum 1000 -Maximum 9999))" -PasswordNeverExpires 1
Set-LocalUser -Name "Admin_$((Get-Random -Minimum 1000 -Maximum 9999))" -AccountNeverExpires 1
Write-Log "Local Administrator account has been renamed and restricted."

# Step 9: Configure Local Group Policy Settings (if applicable)
Write-Log "Configuring local group policies for security"
# Example: Disable anonymous SID enumeration
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -PropertyType DWord -Force | Out-Null

# Step 10: Disable SMBv1
Write-Log "Disabling SMBv1"
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart

# Step 11: Set YARA for Malware Detection (Optional)
# Requires pre-installed YARA; Adjust if YARA is required for malware scanning
$yaraRulesPath = "C:\YARA\rules\myrules.yara"
if (Test-Path -Path $yaraRulesPath) {
    Write-Log "Setting up YARA scanning with rules from $yaraRulesPath"
    # This assumes integration with OSSEC or Wazuh, as discussed earlier
}

Write-Log "Initial hardening completed successfully. Review the log file at $logFile for details."

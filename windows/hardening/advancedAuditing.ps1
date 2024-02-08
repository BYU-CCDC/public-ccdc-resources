# Check if .NET Framework 4.7 or later is installed
if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue).Release -ge 461808) {
    Write-Output ".NET Framework 4.7 or later is already installed."
}
else {
    # .NET Framework 4.7 or later is not installed; install it
    Write-Output "Installing .NET Framework 4.7 or later..."
    Install-WindowsFeature -Name "NET-Framework-45-Features" -IncludeAllSubFeature -Source "C:\sources\sxs"
    Write-Output ".NET Framework 4.7 or later has been installed."
}

#This script enables auditing for various event categories on a Windows system

# Enable auditing of successful and failed logon events
Write-Host "Enabling auditing of successful and failed logon events..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditLogonEvents" -Value 3

# Enable auditing of successful and failed account logon events
Write-Host "Enabling auditing of successful and failed account logon events..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditAccountLogon" -Value 3

# Enable auditing of account management events
Write-Host "Enabling auditing of account management events..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditAccountManage" -Value 3

# Enable auditing of directory service access events
Write-Host "Enabling auditing of directory service access events..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Diagnostics' -Name "16 Directory Service Access" -Value 2

# Enable auditing of object access events
Write-Host "Enabling auditing of object access events..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Object Access" -Value 3

# Enable auditing of detailed tracking events
Write-Host "Enabling auditing of detailed tracking events..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditDetailedTracking" -Value 3

# Enable auditing of kernel object events
Write-Host "Enabling auditing of kernel object events..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditKernelObject" -Value 3

# Enable auditing of changes to Active Directory objects
Write-Host "Enabling auditing of changes to Active Directory objects..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' -Name "DSA Heuristics" -Value 0000001000000000

# Enable auditing of changes to registry keys
Write-Host "Enabling auditing of changes to registry keys..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths' -Name "Machine" -Value "@"

# Enable auditing of changes to file system objects
Write-Host "Enabling auditing of changes to file system objects..."
$driveLetters = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object -ExpandProperty DeviceID
ForEach ($driveLetter in $driveLetters) {
    $acl = Get-Acl -Path $driveLetter
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","CreateFiles","Success")
    $acl.SetAuditRule($rule)
    Set-Acl -Path $driveLetter -AclObject $acl
}

# Enable auditing of policy change events
Write-Host "Enabling auditing of policy change events..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditPolicyChange" -Value 3

#Enable auditing of changes to the local security policy
Write-Host "Enabling auditing of changes to the local security policy..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Security System Extension" -Value 3

#Enable auditing of changes to audit policies
Write-Host "Enabling auditing of changes to audit policies..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Audit Policy Change" -Value 3

#Enable auditing of changes to user rights assignments
Write-Host "Enabling auditing of changes to user rights assignments..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Security State Change" -Value 3

#Enable auditing of privilege use events
Write-Host "Enabling auditing of privilege use events..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditPrivilegeUse" -Value 3

#Enable auditing of process tracking events
Write-Host "Enabling auditing of process tracking events..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Process Creation" -Value 3
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Process Termination" -Value 3
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Detailed File Share" -Value 3

#Enable auditing of system integrity events
Write-Host "Enabling auditing of system integrity events..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Audit System Integrity" -Value 3

#Enable auditing of firewall events
Write-Host "Enabling auditing of firewall events..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Audit Firewall Rule Changes" -Value 3

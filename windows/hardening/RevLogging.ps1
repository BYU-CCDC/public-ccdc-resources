# Disable auditing settings set in the advancedAuditing.ps1

# Note: Disabling auditing completely may not be desirable. This script sets the values to zero, but you may want to set them to their original values or to another desired configuration.

# Reset auditing of successful and failed logon events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditLogonEvents" -Value 0

# Reset auditing of successful and failed account logon events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditAccountLogon" -Value 0

# Reset auditing of account management events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditAccountManage" -Value 0

# Reset auditing of directory service access events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Diagnostics' -Name "16 Directory Service Access" -Value 0

# Reset auditing of object access events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Object Access" -Value 0

# Reset auditing of detailed tracking events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditDetailedTracking" -Value 0

# Reset auditing of kernel object events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditKernelObject" -Value 0

# Reset auditing of changes to Active Directory objects
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' -Name "DSA Heuristics" -Value 0

# Reset auditing of changes to registry keys
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths' -Name "Machine" -Value 0

# Reset auditing of changes to file system objects
$driveLetters = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object -ExpandProperty DeviceID
ForEach ($driveLetter in $driveLetters) {
    $acl = Get-Acl -Path $driveLetter
    if ($acl.Audit.Count -gt 0) {
        $acl.Audit | ForEach-Object { $acl.RemoveAuditRule($_) }
        Set-Acl -Path $driveLetter -AclObject $acl
    }
}

# Reset auditing of policy change events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditPolicyChange" -Value 0

# Reset auditing of changes to the local security policy
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Security System Extension" -Value 0

# Reset auditing of changes to audit policies
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Audit Policy Change" -Value 0

# Reset auditing of changes to user rights assignments
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Security State Change" -Value 0

# Reset auditing of privilege use events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "AuditPrivilegeUse" -Value 0

# Reset auditing of process tracking events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Process Creation" -Value 0
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Process Termination" -Value 0
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Detailed File Share" -Value 0

# Reset auditing of system integrity events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Audit System Integrity" -Value 0

# Reset auditing of firewall events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\eventlog\Security' -Name "Audit Firewall Rule Changes" -Value 0

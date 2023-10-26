# Enable auditing of account logon events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditAccountLogon" -Value 2

# Enable auditing of account management events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditAccountManage" -Value 2

# Enable auditing of directory service access events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditDSAccess" -Value 2

# Enable auditing of logon events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditLogonEvents" -Value 2

# Enable auditing of object access events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditObjectAccess" -Value 2

# Enable auditing of policy change events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditPolicyChange" -Value 2

# Enable auditing of privilege use events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditPrivilegeUse" -Value 2

# Enable auditing of process tracking events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditProcessTracking" -Value 2

# Enable auditing of system events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditSystemEvents" -Value 2

# Enable auditing of kernel object events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditKernelObject" -Value 2

# Enable auditing of SAM and security system extension events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditSAM" -Value 2
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditSecuritySystemExtension" -Value 2

# Enable auditing of registry events
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditRegistry" -Value 2

# Enable auditing of file system object changes on all drives
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object {$_.DriveType -eq 'Fixed'}
foreach ($drive in $drives) {
    $acl = Get-Acl -Path $drive.Root
    $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "CreateFiles", "Success")
    $acl.AddAuditRule($auditRule)
    Set-Acl -Path $drive.Root -AclObject $acl
}

Write-Output "Audit policies have been configured successfully."
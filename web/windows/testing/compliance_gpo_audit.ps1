# Define log file
$logFile = "C:\WebBackups\Security_Policy_Enforcement_Log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# 1. Configuration Compliance Check
function Check-ConfigurationCompliance {
    Write-Output "$currentDateTime - Starting Configuration Compliance Check..." | Out-File -FilePath $logFile -Append

    # Check if HTTPS is enforced
    $sites = Get-WebBinding | Where-Object { $_.protocol -eq "https" }
    if ($sites.Count -eq 0) {
        Write-Output "$currentDateTime - Warning: No HTTPS bindings found for websites. Consider enabling HTTPS." | Out-File -FilePath $logFile -Append
    } else {
        Write-Output "$currentDateTime - HTTPS is enabled for some websites." | Out-File -FilePath $logFile -Append
    }

    # Check for strong cipher suites (TLS 1.2 and above)
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    $enabled = (Get-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if ($enabled -ne 1) {
        Write-Output "$currentDateTime - Warning: TLS 1.2 is not enforced. Updating registry to enable TLS 1.2." | Out-File -FilePath $logFile -Append
        New-Item -Path $regPath -Force | Out-Null
        Set-ItemProperty -Path $regPath -Name "Enabled" -Value 1
        Write-Output "$currentDateTime - TLS 1.2 enforcement applied." | Out-File -FilePath $logFile -Append
    } else {
        Write-Output "$currentDateTime - TLS 1.2 is enforced." | Out-File -FilePath $logFile -Append
    }

    # Check directory permissions for web root folder
    $webRoot = "C:\inetpub\wwwroot"
    $acl = Get-Acl $webRoot
    $expectedPermissions = "IIS_IUSRS", "Administrators", "SYSTEM"
    $permissionsValid = $true

    foreach ($access in $acl.Access) {
        if ($expectedPermissions -notcontains $access.IdentityReference.Value) {
            $permissionsValid = $false
            Write-Output "$currentDateTime - Warning: Unexpected permission found: $($access.IdentityReference)" | Out-File -FilePath $logFile -Append
        }
    }

    if ($permissionsValid) {
        Write-Output "$currentDateTime - Directory permissions for $webRoot are correctly set." | Out-File -FilePath $logFile -Append
    }

    Write-Output "$currentDateTime - Configuration Compliance Check completed." | Out-File -FilePath $logFile -Append
}

# 2. GPO & Policy Validation
function Validate-Policies {
    Write-Output "$currentDateTime - Starting GPO & Policy Validation..." | Out-File -FilePath $logFile -Append

    # Check if Windows Firewall is enabled
    $firewallStatus = Get-NetFirewallProfile -All | Select-Object -ExpandProperty Enabled
    if ($firewallStatus -contains $false) {
        Write-Output "$currentDateTime - Warning: Windows Firewall is not enabled on all profiles. Enabling it." | Out-File -FilePath $logFile -Append
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Write-Output "$currentDateTime - Windows Firewall enabled for all profiles." | Out-File -FilePath $logFile -Append
    } else {
        Write-Output "$currentDateTime - Windows Firewall is enabled on all profiles." | Out-File -FilePath $logFile -Append
    }

    # Check password policies (e.g., minimum password length)
    $minPasswordLength = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordLength" -ErrorAction SilentlyContinue).MinimumPasswordLength
    if ($minPasswordLength -lt 12) {
        Write-Output "$currentDateTime - Warning: Minimum password length is less than recommended. Updating to 12 characters." | Out-File -FilePath $logFile -Append
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordLength" -Value 12
        Write-Output "$currentDateTime - Minimum password length policy updated to 12 characters." | Out-File -FilePath $logFile -Append
    } else {
        Write-Output "$currentDateTime - Minimum password length policy is correctly set." | Out-File -FilePath $logFile -Append
    }

    # Audit Policy Settings - Ensuring auditing for critical events
    $auditSettings = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "AuditBaseObjects" -ErrorAction SilentlyContinue
    if ($auditSettings.AuditBaseObjects -ne 1) {
        Write-Output "$currentDateTime - Warning: Auditing for critical events not enabled. Enabling audit base objects." | Out-File -FilePath $logFile -Append
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "AuditBaseObjects" -Value 1
        Write-Output "$currentDateTime - Audit base objects enabled." | Out-File -FilePath $logFile -Append
    } else {
        Write-Output "$currentDateTime - Critical event auditing is already enabled." | Out-File -FilePath $logFile -Append
    }

    Write-Output "$currentDateTime - GPO & Policy Validation completed." | Out-File -FilePath $logFile -Append
}

# Run both functions
try {
    Check-ConfigurationCompliance
    Validate-Policies
    Write-Output "$currentDateTime - Security Policy Enforcement completed successfully." | Out-File -FilePath $logFile -Append
} catch {
    Write-Output "$currentDateTime - An error occurred: $_" | Out-File -FilePath $logFile -Append
}

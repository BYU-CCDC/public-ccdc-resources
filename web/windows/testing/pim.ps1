# Privileged Identity Management:

# Define authorized groups and essential users for auditing
$authorizedGroups = @("Administrators", "WebAdmins", "ITSupport")  # Modify as per your organization
$essentialUsers = @("AdminUser1", "CriticalUser")  # Define essential users who should always have access

# Log location
$logFile = "C:\WebBackups\User_Audit_Log.txt"

# Function: User Auditing Script
function Audit-UserAccounts {
    Write-Output "Starting User Audit..." | Out-File -FilePath $logFile -Append
    $currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Get all users on the system
    $allUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }

    foreach ($user in $allUsers) {
        $userGroups = (Get-LocalGroupMember -Member $user.Name).Group

        # Check if the user belongs to any authorized groups
        $isAuthorized = $false
        foreach ($group in $userGroups) {
            if ($authorizedGroups -contains $group.Name) {
                $isAuthorized = $true
                break
            }
        }

        # Log and remove unauthorized users if specified
        if (-not $isAuthorized -and -not ($essentialUsers -contains $user.Name)) {
            $logMessage = "$currentDateTime - Unauthorized user detected: $($user.Name)"
            Write-Output $logMessage | Out-File -FilePath $logFile -Append

            # Optional: Uncomment the line below to remove unauthorized users
            # Remove-LocalUser -Name $user.Name
            Write-Output "Unauthorized user $($user.Name) identified and flagged for review."
        }
    }
    Write-Output "User Audit Completed." | Out-File -FilePath $logFile -Append
}

# Function: Lockdown Accounts Script
function Lockdown-NonEssentialAccounts {
    Write-Output "Starting Account Lockdown..." | Out-File -FilePath $logFile -Append
    $currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Get all users on the system
    $allUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }

    foreach ($user in $allUsers) {
        # Check if the user is in the essential users list
        if (-not ($essentialUsers -contains $user.Name)) {
            # Disable non-essential account
            Disable-LocalUser -Name $user.Name
            $logMessage = "$currentDateTime - Disabled non-essential account: $($user.Name)"
            Write-Output $logMessage | Out-File -FilePath $logFile -Append
        }
    }
    Write-Output "Account Lockdown Completed." | Out-File -FilePath $logFile -Append
}

# Script Execution Logic
try {
    # Run User Audit
    Audit-UserAccounts

    # Lockdown Non-Essential Accounts if in high alert
    # Uncomment the line below to enable lockdown during high-alert situations
    # Lockdown-NonEssentialAccounts

    Write-Output "User Management Automation completed successfully." | Out-File -FilePath $logFile -Append
} catch {
    Write-Output "An error occurred: $_" | Out-File -FilePath $logFile -Append
}

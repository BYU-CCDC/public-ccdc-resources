function Add-RDPUsers {
    [CmdletBinding()]
    param(
        [string[]]$Users,
        [switch]$Force
    )

    Invoke-HardeningOperation -OperationName 'Add RDP Users' -ScriptBlock {
        Write-Banner "Add Users to Remote Desktop Users Group" -Style Inline

        $isDC = $script:HardeningContext.OS.IsDomainController
        $usernames = @()

        if ($Users -and $Users.Count -gt 0) {
            $usernames = $Users
        } elseif ($Force) {
            Write-Status "-Force specified with no users; nothing to add."
            return
        } else {
            $usernames = Read-Choice -Prompt "Usernames to add to Remote Desktop Users" -Multiple -AllowCustom -AllowQuit
            if ($null -eq $usernames) {
                throw [System.OperationCanceledException]::new("Cancelled by user")
            }
        }

        $successCount = 0
        $failedCount = 0

        foreach ($username in $usernames) {
            if ([string]::IsNullOrWhiteSpace($username)) {
                Write-Status -Level Warning "Username was empty, skipping..."
                $failedCount++
                continue
            }

            try {
                if ($isDC) {
                    Add-ADGroupMember -Identity 'Remote Desktop Users' -Members $username -ErrorAction Stop
                } else {
                    Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $username -ErrorAction Stop
                }
                Write-Status -Level Success "Added user '$username' to Remote Desktop Users group"
                $successCount++
            } catch {
                $errorMessage = $_.Exception.Message
                Write-Status -Level Error "Could not add user '$username' to Remote Desktop Users group: $errorMessage"
                $failedCount++

                if ($errorMessage -like '*not found*' -or $errorMessage -like '*does not exist*') {
                    Write-Status "The user '$username' does not exist on the local system or domain."
                } elseif ($errorMessage -like '*already*' -or $errorMessage -like '*member*') {
                    Write-Status "The user '$username' is already a member of the Remote Desktop Users group."
                }
            }
        }

        Write-Banner "Summary" -Style Inline
        Write-Host "  Successfully added: $successCount user(s)" -ForegroundColor Green
        if ($failedCount -gt 0) {
            Write-Host "  Failed to add: $failedCount user(s)" -ForegroundColor Red
        }
        Write-Host ""
        Write-Status -Level Success "RDP user addition process completed." -LogMessage "Add RDP Users completed: $successCount succeeded, $failedCount failed"
    }
}

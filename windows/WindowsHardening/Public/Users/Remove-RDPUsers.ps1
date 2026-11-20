function Remove-RDPUsers {
    [CmdletBinding()]
    param()

    Invoke-HardeningOperation -OperationName "Remove RDP Users" -ScriptBlock {
        Write-Status "Removing all users from Remote Desktop Users group"
        $ExclusionList = @("ccdcuser1", "ccdcuser2")
        $isDC = $script:HardeningContext.OS.IsDomainController

        try {
            if ($isDC) {
                $rdpGroupMembers = Get-ADGroupMember -Identity "Remote Desktop Users" -ErrorAction SilentlyContinue
            } else {
                $rdpGroupMembers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
            }

            if ($null -eq $rdpGroupMembers -or $rdpGroupMembers.Count -eq 0) {
                Write-Status "Remote Desktop Users group is already empty"
            } else {
                $removedCount = 0
                foreach ($member in $rdpGroupMembers) {
                    try {
                        if ($isDC) {
                            $username = $member.SAMAccountName
                        } else {
                            $username = $member.Name.Split('\')[-1]
                        }

                        if ($ExclusionList -contains $username) {
                            Write-Status -Level Skip "Skipping $username (Protected Account)" -LogMessage "Skipped removal of $username from RDP group"
                            continue
                        }

                        if ($isDC) {
                            Remove-ADGroupMember -Identity "Remote Desktop Users" -Members $username -Confirm:$false -ErrorAction Stop
                        } else {
                            Remove-LocalGroupMember -Group "Remote Desktop Users" -Member $member -Confirm:$false -ErrorAction Stop
                        }

                        Write-Status -Level Success "Removed $username from Remote Desktop Users group"
                        $removedCount++
                    } catch {
                        $displayName = if ($isDC) { $member.SAMAccountName } else { $member.Name }
                        Write-Status -Level Warning "Could not remove $displayName from Remote Desktop Users group: $($_.Exception.Message)"
                    }
                }
                Write-Status "Removed $removedCount user(s) from Remote Desktop Users group"
            }

            Write-Status -Level Success "RDP users removed successfully - Remote Desktop Users group has been reset" -LogMessage "RDP users removal completed - Remote Desktop Users group reset"
        } catch {
            Write-Status -Level Error "Failed to remove RDP users: $($_.Exception.Message)"
            throw
        }
    }
}

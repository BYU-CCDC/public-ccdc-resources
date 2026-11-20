# The built-in Administrator account (RID 500), matched by SID so a renamed account is
# still protected. Domain Admins is also preserved as a member of the DC's built-in
# Administrators group; other administrator memberships are still cleaned below.
function Test-BuiltInAdminPrincipal {
    param($Member)
    "$($Member.SID)" -match '-500$'
}

function Remove-AdminUsers {
    [CmdletBinding()]
    param()

    Invoke-HardeningOperation -OperationName "Remove Admin Users" -ScriptBlock {
        $isDC = $script:HardeningContext.OS.IsDomainController

        if ($isDC) {
            Write-Status "Cleaning administrator memberships on the domain while preserving Domain Admins in BUILTIN\Administrators"
            Write-Status -Level Warning "Afterwards, add back any users the competition scenario needs as admins" -NoLog

            $ExclusionList = @("Administrator", "ccdcuser3")
            $domainAdminsGroupSid = "$((Get-ADDomain -ErrorAction Stop).DomainSID.Value)-512"

            $adminGroupList = @("Domain Admins", "Enterprise Admins", "Administrators")
            foreach ($groupName in $adminGroupList) {
                try {
                    $adminMembers = Get-ADGroupMember -Identity $GroupName -ErrorAction SilentlyContinue

                    if ($null -eq $adminMembers -or $adminMembers.Count -eq 0) {
                        Write-Status "${GroupName} group is empty (Unexpected)" -LogMessage "${GroupName} group is already empty"
                    } else {
                        $removedCount = 0
                        foreach ($member in $adminMembers) {
                            try {
                                $username = $member.SAMAccountName

                                if ($ExclusionList -contains $username -or (Test-BuiltInAdminPrincipal $member)) {
                                    Write-Status -Level Skip "Skipping ${username} (Protected Admin)" -LogMessage "Skipped removal of ${username} from ${GroupName} group"
                                    continue
                                }

                                if ($groupName -eq 'Administrators' -and "$($member.SID)" -eq $domainAdminsGroupSid) {
                                    Write-Status -Level Skip "Preserving Domain Admins in BUILTIN\Administrators" `
                                        -LogMessage 'Skipped removal of the Domain Admins group from BUILTIN\Administrators'
                                    continue
                                }

                                Remove-ADGroupMember -Identity $GroupName -Members $username -Confirm:$false -ErrorAction Stop

                                Write-Status -Level Success "Removed ${username} from ${GroupName}"
                                $removedCount++
                            } catch {
                                $msg = $_.Exception.Message
                                Write-Status -Level Warning "Could not remove $($member.Name): $msg" -LogMessage "Could not remove $($member.Name) from ${GroupName}: $msg"
                            }
                        }
                        Write-Status "Removed $removedCount unauthorized admin(s)"
                    }

                    Write-Status -Level Success "Administrator group hardening complete" -LogMessage "Administrators group reset completed"
                } catch {
                    Write-Status -Level Error "Failed to harden Administrators: $($_.Exception.Message)"
                    throw
                }
            }
        } else {
            Write-Status "Cleaning local Administrators group"

            $ExclusionList = @("Administrator", "ccdcuser1")

            try {
                $GroupName = "Administrators"
                $adminMembers = Get-LocalGroupMember -Group $GroupName -ErrorAction SilentlyContinue

                if ($null -eq $adminMembers -or $adminMembers.Count -eq 0) {
                    Write-Status "${GroupName} group is empty (Unexpected)" -LogMessage "${GroupName} group is already empty"
                } else {
                    $removedCount = 0
                    foreach ($member in $adminMembers) {
                        try {
                            $username = $member.Name.Split('\')[-1]

                            if ($ExclusionList -contains $username -or (Test-BuiltInAdminPrincipal $member)) {
                                Write-Status -Level Skip "Skipping ${username} (Protected Admin)" -LogMessage "Skipped removal of ${username} from ${GroupName} group"
                                continue
                            }

                            Remove-LocalGroupMember -Group $GroupName -Member $member -Confirm:$false -ErrorAction Stop

                            Write-Status -Level Success "Removed ${username} from ${GroupName}"
                            $removedCount++
                        } catch {
                            $msg = $_.Exception.Message
                            Write-Status -Level Warning "Could not remove $($member.Name): $msg" -LogMessage "Could not remove $($member.Name) from ${GroupName}: $msg"
                        }
                    }
                    Write-Status "Removed $removedCount unauthorized admin(s)"
                }

                Write-Status -Level Success "Administrator group hardening complete" -LogMessage "Administrators group reset completed"
            } catch {
                Write-Status -Level Error "Failed to harden Administrators: $($_.Exception.Message)"
                throw
            }
        }
    }
}

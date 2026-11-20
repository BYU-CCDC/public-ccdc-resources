#Requires -Version 5.1

# Show-Users.ps1 - Lists enabled and disabled users (local or AD) with their groups.

function Show-Users {
    [CmdletBinding()]
    param()

    Initialize-System

    try {
        $output = @()
        $isDC = $script:HardeningContext.OS.IsDomainController

        Write-Banner "Enabled Users" -Style Inline -Color Green
        $enabledUsersOutput = "==== Enabled Users ===="

        if ($isDC) {
            $enabledUsers = Get-ADUser -Filter * | Where-Object { $_.Enabled -eq $true -and $_.ObjectClass -eq "User" }
        } else {
            $enabledUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
        }

        $enabledUsers | ForEach-Object {
            Write-Host "User: $($_.Name)"
            $enabledUsersOutput += "`nUser: $($_.Name)"
            $user = $_
            $userSID = $user.SID

            if ($isDC) {
                $groups = Get-ADGroup -Filter * | Where-Object {
                    $groupMembers = Get-ADGroupMember -Identity $_.Name -ErrorAction SilentlyContinue
                    if ($groupMembers) {
                        $userSID -in ($groupMembers | Select-Object -ExpandProperty "SID")
                    }
                } | Select-Object -ExpandProperty "Name"
            } else {
                $groups = Get-LocalGroup | Where-Object {
                    $groupMembers = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue
                    if ($groupMembers) {
                        $userSID -in ($groupMembers | Select-Object -ExpandProperty "SID")
                    }
                } | Select-Object -ExpandProperty "Name"
            }

            $groupString = "Groups: $($groups -join ', ')"
            Write-Host $groupString
            $enabledUsersOutput += "`n$groupString"
            [System.GC]::Collect()
        }
        $output += $enabledUsersOutput

        Write-Banner "Disabled Users" -Style Inline -Color Red
        $disabledUsersOutput = "==== Disabled Users ===="

        if ($isDC) {
            $disabledUsers = Get-ADUser -Filter * | Where-Object { $_.Enabled -eq $false }
        } else {
            $disabledUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $false }
        }

        $disabledUsers | ForEach-Object {
            Write-Host "User: $($_.Name)"
            $disabledUsersOutput += "`nUser: $($_.Name)"
            $user = $_
            $userSID = $user.SID

            if ($isDC) {
                $groups = Get-ADGroup -Filter * | Where-Object {
                    $groupMembers = Get-ADGroupMember -Identity $_.Name -ErrorAction SilentlyContinue
                    if ($groupMembers) {
                        $userSID -in ($groupMembers | Select-Object -ExpandProperty "SID")
                    }
                } | Select-Object -ExpandProperty "Name"
            } else {
                $groups = Get-LocalGroup | Where-Object {
                    $groupMembers = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue
                    if ($groupMembers) {
                        $userSID -in ($groupMembers | Select-Object -ExpandProperty "SID")
                    }
                } | Select-Object -ExpandProperty "Name"
            }

            $groupString = "Groups: $($groups -join ', ')"
            Write-Host $groupString
            $disabledUsersOutput += "`n$groupString"
            [System.GC]::Collect()
        }
        $output += $disabledUsersOutput

        return $output
    } catch {
        Write-Status -Level Error "Error in Show-Users: $($_.Exception.Message)"
        return $null
    }
}

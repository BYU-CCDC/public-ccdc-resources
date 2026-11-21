#Requires -Version 5.1

# UserManagement.ps1 - Password changes and competition-account setup.

function New-ADUserAccount {
    param(
        [string]$Name,
        [string]$SamAccountName
    )
    # Create the AD user under the domain's official Users container. New-ADUser with
    # only -Name/-SamAccountName (no -Path) on a freshly promoted forest root can place
    # the object where it is not resolvable via -Identity, so always target the container.
    $path = $null
    if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {
        try {
            $path = (Get-ADDomain -ErrorAction Stop).UsersContainer
        } catch {
            try { $path = "CN=Users,$((Get-ADRootDSE -ErrorAction Stop).defaultNamingContext)" } catch { $path = $null }
        }
    }
    if ($path) {
        New-ADUser -Name $Name -SamAccountName $SamAccountName -Path $path
    } else {
        New-ADUser -Name $Name -SamAccountName $SamAccountName
    }
}

function Set-UserPassword {
    <#
    .SYNOPSIS
        Sets a local or AD account's password; optionally adds the account to the admin group.
    .DESCRIPTION
        The password comes from -Password, or is derived from -SaltPhrase + -WordlistData
        (Zulu), or is typed at a prompt. Throws if the account does not exist, or if a
        given/derived password cannot be set, so callers can count the failure. Only a typed
        password is re-prompted after a failure (e.g. complexity rules); an empty entry gives up.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,

        [string]$PasswordPrompt,

        [string]$Password,

        [string[]]$WordlistData,

        [string]$SaltPhrase,

        [switch]$AddToAdmins
    )

    $isDC = (Get-OperatingSystemInfo).IsDomainController

    # Check first: setting a password on a missing account can never succeed.
    $exists = if ($isDC) {
        [bool](Get-ADUser -Filter "SamAccountName -eq '$Username'")
    } else {
        [bool](Get-LocalUser -Name $Username -ErrorAction Ignore)
    }
    if (-not $exists) {
        throw "User '$Username' does not exist"
    }

    if (-not $Password -and $SaltPhrase -and $WordlistData) {
        # Non-interactive: derive a deterministic password from the salt phrase. Required
        # over WinRM, where Read-Host is unavailable.
        $Password = New-Password -Username $Username -SeedPhrase $SaltPhrase -WordlistData $WordlistData
    }
    $prompted = -not $Password

    while ($true) {
        if ($prompted) {
            $Password = Read-SecretInput $PasswordPrompt
            if (-not $Password) {
                throw "No password entered for '$Username'"
            }
            if ($Password -ne (Read-SecretInput "Confirm password: ")) {
                Write-Status -Level Warning "Passwords do not match. Try again (Enter to give up)."
                continue
            }
        }

        $securePassword = ConvertTo-SecureString -AsPlainText $Password -Force
        try {
            if ($isDC) {
                Set-ADAccountPassword -Identity $Username -Reset -NewPassword $securePassword -ErrorAction Stop
            } else {
                Set-LocalUser -Name $Username -Password $securePassword -ErrorAction Stop
            }
            break
        } catch {
            if (-not $prompted) {
                throw "Could not set password for '$Username': $($_.Exception.Message)"
            }
            Write-Status -Level Error "Could not set password for ${Username}: $($_.Exception.Message)"
            Write-Status -Level Warning "Try a different password (likely complexity requirements), or press Enter to give up."
        }
    }

    if ($AddToAdmins) {
        # Already being a member is fine; anything else is reported but does not undo the password.
        try {
            if ($isDC) {
                Add-ADGroupMember -Identity "Domain Admins" -Members $Username -ErrorAction Stop
            } else {
                Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction Stop
            }
        } catch {
            if ($_.Exception.Message -notmatch 'already a member|member of the group') {
                Write-Status -Level Warning "Could not add $Username to the admin group: $($_.Exception.Message)"
            }
        }
    }
}

function Get-CompetitionWordlistData {
    $wordlistFile = Join-Path $script:DataPath 'wordlist.txt'
    if (-not (Test-Path $wordlistFile)) {
        $wordlistUrl = "$script:CcdcRepoUrl/wordlist.txt"
        Write-Status "Downloading wordlist from $wordlistUrl"
        if (-not (Get-FileFromUrl -Url $wordlistUrl -OutputPath $wordlistFile)) {
            throw "Failed to download wordlist from $wordlistUrl"
        }
    }
    return @(Get-Content $wordlistFile)
}

function Set-AdministratorPassword {
    <#
    .SYNOPSIS
        Changes the built-in Administrator account password.
    .DESCRIPTION
        Prompts for the new password when -SaltPhrase is omitted. When a salt phrase is
        supplied, derives the password from the bundled Zulu wordlist for unattended runs.
    #>
    [CmdletBinding()]
    param([string]$SaltPhrase)

    Invoke-HardeningOperation -OperationName 'Change Administrator Password' -ScriptBlock {
        $passwordArgs = @{}
        if ($SaltPhrase) {
            if ($SaltPhrase.Length -lt 8) { throw 'Salt phrase must be at least 8 characters long.' }
            $passwordArgs.WordlistData = Get-CompetitionWordlistData
            $passwordArgs.SaltPhrase = $SaltPhrase
        }
        Set-UserPassword -Username 'Administrator' -PasswordPrompt 'Enter new password for Administrator: ' @passwordArgs
    }
}

function Create-CCDCUsers {
    <#
    .SYNOPSIS
        Creates the standard competition accounts for this machine.
    .DESCRIPTION
        DC: domain users ccdcuser2 (standard) and ccdcuser3 (Domain Admin).
        Otherwise: local users ccdcuser1 (Administrators) and ccdcuser2. Each account is
        handled independently. With -SaltPhrase, passwords are derived; otherwise each
        account password is entered directly.
    #>
    [CmdletBinding()]
    param([string]$SaltPhrase)

    Invoke-HardeningOperation -OperationName 'Add Competition Users' -ScriptBlock {
        $isDC = (Get-OperatingSystemInfo).IsDomainController
        $failed = 0
        $passwordArgs = @{}
        if ($SaltPhrase) {
            if ($SaltPhrase.Length -lt 8) { throw 'Salt phrase must be at least 8 characters long.' }
            $passwordArgs.WordlistData = Get-CompetitionWordlistData
            $passwordArgs.SaltPhrase = $SaltPhrase
        }

        if ($isDC) {
            # ccdcuser2 (standard) and ccdcuser3 (Domain Admin) in AD; ccdcuser1 is local-only.
            Write-Status "Setting up domain users ccdcuser2 and ccdcuser3"
            foreach ($u in @('ccdcuser2', 'ccdcuser3')) {
                try {
                    if (-not (Get-ADUser -Filter "SamAccountName -eq '$u'")) {
                        New-ADUserAccount -Name $u -SamAccountName $u
                    }
                    Set-UserPassword -Username $u -PasswordPrompt "Enter password for ${u}: " -AddToAdmins:($u -eq 'ccdcuser3') @passwordArgs
                    Enable-ADAccount -Identity $u -ErrorAction Stop
                    Write-Status -Level Success "$u ready"
                } catch {
                    $failed++
                    Write-Status -Level Warning "Domain user '$u' not set up: $($_.Exception.Message)" -LogMessage "Domain user '$u' setup failed: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Status "Setting up local users ccdcuser1 and ccdcuser2"
            foreach ($u in @('ccdcuser1', 'ccdcuser2')) {
                try {
                    if (-not (Get-LocalUser -Name $u -ErrorAction Ignore)) {
                        New-LocalUser -Name $u -NoPassword -ErrorAction Stop | Out-Null
                    }
                    Set-UserPassword -Username $u -PasswordPrompt "Enter password for ${u}: " -AddToAdmins:($u -eq 'ccdcuser1') @passwordArgs
                    Write-Status -Level Success "$u ready"
                } catch {
                    $failed++
                    Write-Status -Level Warning "Local user '$u' not set up: $($_.Exception.Message)" -LogMessage "Local user '$u' setup failed: $($_.Exception.Message)"
                }
            }
        }

        if ($failed -gt 0) {
            Set-OperationStatus 'Add Competition Users' "Failed for $failed account(s) - see log"
            throw "Failed to create or configure $failed competition account(s)"
        }
        Set-OperationStatus 'Add Competition Users' 'Executed successfully'
    }
}

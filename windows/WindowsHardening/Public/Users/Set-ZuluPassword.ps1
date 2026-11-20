function Set-ZuluPassword {
    [CmdletBinding()]
    param(
        [Alias("h")][switch]$Help,
        [string]$User,
        # -U (and -u: aliases ignore case) mean -UsersFile, not -User.
        [Alias("U")][string]$UsersFile,
        [Alias("g")][switch]$GenerateOnly,
        [Alias("s", "Seed")][string]$SaltPhrase,

        [Parameter(HelpMessage = "If we need to download the wordlist, this is the URL to get it from")]
        [Alias("url")]
        [string]$WordlistUrl = "$script:CcdcRepoUrl/wordlist.txt",

        # Where zulu.log and users_zulu.csv are written. Default: the module's log directory.
        [string]$OutputDirectory
    )

    process {
        if ($Help) {
            Write-Host "Usage: Set-ZuluPassword [options]" -ForegroundColor Green
            Write-Host "Default behavior asks for a seed phrase and changes passwords for all auto-detected users minus excluded users." -ForegroundColor Green
            Write-Host "`nOptions:" -ForegroundColor Yellow
            @(
                "  -Help, -h          Show this help message",
                "  -User              Change password for a single user",
                "  -UsersFile, -U     Change passwords for newline-separated users in a file (-u also means this)",
                "  -GenerateOnly, -g  Generate/print passwords only, do not change them",
                "  -SaltPhrase, -s    Salt phrase (non-interactive; skips prompt). Alias: -Seed",
                "  -url <url>         The url to the wordlist (used only if Data\wordlist.txt is missing)",
                "  -OutputDirectory   Where zulu.log / users_zulu.csv go (default: log directory)"
            ) | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
            return
        }

        # Changing passwords runs as the "Zulu Passwords" operation: counted in the run
        # summary, logged (Invoke-HardeningOperation runs Initialize-System first), and a
        # failure does not stop the caller. -GenerateOnly changes nothing and needs no admin
        # rights or log, so it runs directly.
        $zulu = {
            # Script configuration
            $isWindowsPlatform = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
            $writeLinuxGenerateCsv = $GenerateOnly -and -not $isWindowsPlatform
            if (-not $OutputDirectory) {
                $OutputDirectory = if ($writeLinuxGenerateCsv) {
                    (Get-Location).Path
                } elseif ($script:HardeningContext.LogPath) {
                    $script:HardeningContext.LogPath
                } else {
                    $script:DefaultLogPath
                }
            }
            if ((-not $GenerateOnly -or $writeLinuxGenerateCsv) -and -not (Test-Path $OutputDirectory)) {
                New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
            }

            # Use System.IO.Path::Combine to avoid Join-Path resolving PSDrive names ("C:\") on non-Windows
            $ExportUsersFile = [System.IO.Path]::Combine($OutputDirectory, "users_zulu.csv")
            $LogFile = [System.IO.Path]::Combine($OutputDirectory, "zulu.log")
            $WordlistFile = [System.IO.Path]::Combine($script:DataPath, "wordlist.txt")
            $ExcludedUsers = @("Administrator", "ccdcuser1", "ccdcuser2", "ccdcuser3")

            Write-Status "Starting Zulu password generator"
            Write-ZuluLog -Message "Script started at $(Get-Date)" -LogFile $LogFile -GenerateOnly:$GenerateOnly
            Write-Status "Users excluded from rotation: $($ExcludedUsers -join ', ')"

            # Generating passwords needs no admin rights; changing them does.
            if (-not $GenerateOnly) {
                Test-Prerequisites
            }

            $IsDomainController = (Get-OperatingSystemInfo).IsDomainController
            if ($IsDomainController) {
                Write-Status "Domain Controller detected - AD password operations will be used"
            }


            # Salt phrase: -SaltPhrase if given (non-interactive), otherwise prompt.
            if ($SaltPhrase) {
                if ($SaltPhrase.Length -lt 8) {
                    throw "Salt phrase must be at least 8 characters long."
                }
                $seedPhrase = $SaltPhrase
            } else {
                while ($true) {
                    $seedPhrase = Read-SecretInput "Enter seed phrase: "
                    $confirmSeedPhrase = Read-SecretInput "Confirm seed phrase: "

                    if ($seedPhrase -ne $confirmSeedPhrase) {
                        Write-Status -Level Warning "Seed phrases do not match. Please retry." -NoLog
                        continue
                    }
                    if ($seedPhrase.Length -lt 8) {
                        Write-Status -Level Warning "Seed phrase must be at least 8 characters long. Please retry." -NoLog
                        continue
                    }
                    break
                }
            }

            if (-not (Test-Path $WordlistFile)) {
                Write-Status "Downloading wordlist from $WordlistUrl"
                if (-not (Get-FileFromUrl -Url $WordlistUrl -OutputPath $WordlistFile)) {
                    throw "Failed to download wordlist from $WordlistUrl"
                }
            }
            $wordlistData = @(Get-Content $WordlistFile)

            $rawUsers = if ($User) { @($User) }
                        elseif ($UsersFile) {
                            if (-not (Test-Path $UsersFile)) { throw "Users file not found: $UsersFile" }
                            Get-Content $UsersFile
                        }
                        elseif ($IsDomainController) {
                            Get-ADUser -Filter * -Properties Enabled | Where-Object { $_.Enabled } | Select-Object -ExpandProperty SamAccountName
                        }
                        else {
                            Get-LocalUser | Where-Object { $_.Enabled } | Select-Object -ExpandProperty Name
                        }

            $users = $rawUsers | Where-Object { $_ -notin $ExcludedUsers }

            Write-Status "Generating passwords for $(@($users).Count) user(s)"

            $failedUsers = 0
            $generatedRows = @()

            if (-not $GenerateOnly -or $writeLinuxGenerateCsv) {
                Remove-Item $ExportUsersFile -ErrorAction Ignore
                if (-not $writeLinuxGenerateCsv) {
                    New-Item -ItemType File -Path $ExportUsersFile -Force | Out-Null
                }
            }

            foreach ($username in $users) {
                $password = New-Password -Username $username -SeedPhrase $seedPhrase -WordlistData $wordlistData

                if ($writeLinuxGenerateCsv) {
                    $generatedRows += [PSCustomObject]@{
                        Username = $username
                        Password = $password
                    }
                }

                if (-not $GenerateOnly) {
                    try {
                        Set-UserPassword -Username $username -Password $password
                        if ($IsDomainController) {
                            Write-Status -Level Success "Changed AD password for ${username}"
                            Write-ZuluLog -Message "Successfully changed AD password for ${username}." -LogFile $LogFile -GenerateOnly:$GenerateOnly
                        } else {
                            Write-Status -Level Success "Changed password for ${username}"
                            Write-ZuluLog -Message "Successfully changed password for ${username}." -LogFile $LogFile -GenerateOnly:$GenerateOnly
                        }
                        Add-Content -Path $ExportUsersFile -Value $username
                    } catch {
                        $failedUsers++
                        Write-Status -Level Error "Failed to change password for ${username}: $($_.Exception.Message)"
                        Write-ZuluLog -Message "Failed to change password for ${username}.: $($_.Exception.Message)" -LogFile $LogFile -GenerateOnly:$GenerateOnly
                    }
                } else {
                    # Screen only: generated passwords must never reach the log file.
                    Write-Host "Generated password for user '${username}': ${password}"
                }
            }

            if ($writeLinuxGenerateCsv) {
                $csvHeader = 'Username,Password'
                if ($generatedRows.Count -gt 0) {
                    Set-Content -LiteralPath $ExportUsersFile -Value $csvHeader -Encoding UTF8 -Force
                    foreach ($row in $generatedRows) {
                        Add-Content -LiteralPath $ExportUsersFile -Value "$($row.Username),$($row.Password)" -Encoding UTF8
                    }
                } else {
                    $csvHeader | Set-Content -LiteralPath $ExportUsersFile -Encoding UTF8 -Force
                }
                Write-Status "Generated password CSV: $ExportUsersFile" -LogMessage "Generated password CSV at $ExportUsersFile"
            }

            if ($GenerateOnly) {
                Set-OperationStatus "Change Passwords" "Generated only (no changes)"
            } elseif ($failedUsers -gt 0) {
                Set-OperationStatus "Change Passwords" "Failed for $failedUsers of $(@($users).Count) user(s)"
            } else {
                Set-OperationStatus "Change Passwords" "Executed successfully"
            }

            Write-Host "`nDone!" -ForegroundColor Green
            # Fail the "Zulu Passwords" operation (after every user was attempted) so the run
            # summary counts it; the per-user details are in the log and zulu.log.
            $problems = @()
            if ($failedUsers -gt 0) { $problems += "password change failed for $failedUsers of $(@($users).Count) user(s)" }
            if ($problems) { throw ($problems -join '; ') }
        }

        if ($GenerateOnly) {
            & $zulu
        } else {
            Invoke-HardeningOperation -OperationName "Zulu Passwords" -ScriptBlock $zulu
        }
    }
}

function Write-ZuluLog {
    param(
        [string]$Message,
        [string]$LogFile,
        [switch]$GenerateOnly
    )
    if (-not $GenerateOnly -and $LogFile) {
        Add-Content -Path $LogFile -Value $Message
    }
}

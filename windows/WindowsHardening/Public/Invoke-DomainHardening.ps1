function Invoke-DomainHardening {
    <#
    .SYNOPSIS
        Hardens a domain controller and links the competition GPOs for the domain.
    .DESCRIPTION
        Imports the Group Policy and Active Directory modules, prepares the GPO backup
        archive, then runs the account and policy sequence. Domain firewall and baseline
        GPOs are linked to the selected domain scopes; role GPOs are security
        filtered to the selected computer accounts. The run ends by refreshing policy,
        configuring Splunk when requested, and creating CCDC accounts.

        Role policies are linked at the domain root and filtered to the exact selected
        computer accounts. The common MSSQL, web server, WinRM, SSH, RDP, FTP, SMB, and
        mail roles are prompted interactively, followed by an optional additional-GPO
        picker. Domain Splunk
        outbound applies to Domain Computers and Domain Controllers, scoped to the
        specified Splunk address. The domain firewall policy (default Block in and out, plus
        NTP) applies to every computer; the combined DC baseline adds AD and SYSVOL
        replication rules plus DC-only directory-service settings. The domain-wide links are enforced so
        OU-linked GPOs and Block Inheritance cannot override them.
        WinRM is left running by this sequence.
    .PARAMETER SkipPasswordChange
        Skip the Administrator password change, Zulu rotation, and CCDC account creation.
    .PARAMETER SkipAdminUserRemoval
        Skip administrator-group membership cleanup without skipping GPO processing.
    .PARAMETER SaltPhrase
        Salt phrase for generated passwords. If omitted, password functions prompt.
    .PARAMETER GpoZipPath
        Deprecated legacy archive parameter. Invoke-DomainHardening does not use the
        legacy GPO archive. Use -GpoDraftPath or -GpoDraftUri.
    .PARAMETER GpoCachePath
        Folder used for downloaded packages and extracted backups.
    .PARAMETER GpoDraftPath
        Local expanded gpo-v1 package folder, its Backups folder, or a ZIP package.
    .PARAMETER GpoDraftUri
        URI from which to download a full gpo-v1 draft ZIP. If omitted, the runner downloads
        the core split archive from public-ccdc-resources and downloads the additional archive
        only when an optional profile or named firewall-port exception is selected. No legacy
        archive fallback is used.
    .PARAMETER GpoBackupPath
        Parent folder for the timestamped backup of the domain's existing GPOs.
        Defaults to the hardening log folder.
    .PARAMETER RoleServers
        Hashtable mapping role names to computer names. Prompts cover MSSQL (Database),
        Web, WinRM, SSH, RDP, FTP, SMB, and Mail. Optional roles can be selected in the
        additional-GPO prompt or supplied explicitly. Web browsing is automatically
        linked to all Domain Computers and Domain Controllers.
        Each service role imports a draft GPO containing its static firewall, registry,
        service-startup, and security-template settings where supported. Web and Mail use
        their bundled GPOs. RDP, SSH, and WinRM add Domain Users to their native local
        access groups. The optional LinuxSSH entry links a GPO containing the Remote
        Interactive logon right for Domain Users and Domain Admins. SSSD can evaluate this
        right for SSH when AD GPO access control is enabled on the Linux computer.
        SQL logins, share ACLs, certificate-template enrollment rights, and application
        access remain product-specific. XAMPP opens TCP 80/443; MySQLMariaDB opens TCP
        3306 and 33060. These two roles are firewall-only and do not configure services.
        If omitted, the run offers computer selections for each common role, then asks
        whether to link additional GPO profiles. Use -NoPrompt to skip role assignments
        when running unattended.
    .PARAMETER NoPrompt
        Skip server role selection prompts. If Splunk is not skipped, pass -SplunkIP.
    .PARAMETER SplunkIP
        Splunk indexer address. Prompts if omitted and Splunk installation is enabled.
    .PARAMETER SkipSplunk
        Skip the final Splunk installation step.
    .PARAMETER SkipSplunkOutbound
        Skip linking the domain Splunk outbound firewall GPO without changing the final
        Splunk installation step. It does not remove an existing GPO link.
    .PARAMETER FirewallPortRulesToAdd
        Optional hashtables passed to Add-DomainFirewallPortRule. Each needs Name,
        ComputerName, and Port (ports and/or ranges such as '50000-50100'); Protocol,
        Direction, and RemoteAddress are optional.
    .PARAMETER FirewallPortRulesToRemove
        Names of previously added domain port rules to remove.
    .PARAMETER LogPath
        Path for log files. Default: C:\Windows\Logs\Hardening.
    .EXAMPLE
        Invoke-DomainHardening -SaltPhrase 'competition seed phrase' -SkipSplunk
        # Runs on a DC and interactively selects servers for role firewall policies.
    .EXAMPLE
        Invoke-DomainHardening -NoPrompt -RoleServers @{ Database = @('DB01'); Web = @('WEB01') } -SplunkIP '10.0.0.20'
        # Supplies server roles and Splunk address without prompts.
    .EXAMPLE
        Invoke-DomainHardening -SkipSplunkOutbound -SkipSplunk
        # Skips both the domain Splunk egress GPO link and Splunk installation.
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipPasswordChange,
        [string]$SaltPhrase,
        [string]$GpoZipPath,
        [string]$GpoCachePath,
        [string]$GpoDraftPath,
        [string]$GpoDraftUri,
        [string]$GpoBackupPath,
        [hashtable]$RoleServers = @{},
        [switch]$SkipAdminUserRemoval,
        [switch]$NoPrompt,
        [string]$SplunkIP,
        [switch]$SkipSplunk,
        [switch]$SkipSplunkOutbound,
        [hashtable[]]$FirewallPortRulesToAdd = @(),
        [string[]]$FirewallPortRulesToRemove = @(),
        [string]$LogPath
    )

    if (-not $script:HardeningContext.OS -or -not $script:HardeningContext.OS.IsDomainController) {
        throw 'Invoke-DomainHardening must be run on a domain controller.'
    }
    if ($NoPrompt -and -not $SkipSplunk -and -not $SplunkIP) {
        throw 'Pass -SplunkIP or -SkipSplunk when using -NoPrompt.'
    }
    if ($SplunkIP -and -not (Test-HostAddress ($SplunkIP -replace ':\d+$', ''))) {
        throw "Invalid -SplunkIP '$SplunkIP': not an IP address or host name"
    }

    $errorCountAtStart = $global:Error.Count
    Write-Banner 'Domain Hardening'
    Initialize-System -Force -LogPath $LogPath

    try {
        Test-Prerequisites
    } catch {
        Write-Status -Level Error "Domain hardening pre-flight failed: $($_.Exception.Message)"
        throw
    }

    if ($GpoZipPath) {
        Write-Status -Level Warning 'GpoZipPath is ignored by draft-only domain hardening; use GpoDraftPath or GpoDraftUri.'
    }

    if ($SkipPasswordChange) {
        Write-Status -Level Skip 'Administrator password change, Zulu rotation, and CCDC account creation skipped (-SkipPasswordChange)'
    } else {
        $script:NextStepLabel = 'Domain 1/15'
        Set-AdministratorPassword -SaltPhrase $SaltPhrase
        $script:NextStepLabel = 'Domain 2/15'
        Set-ZuluPassword -SaltPhrase $SaltPhrase
    }

    # Run password operations before downloading the draft GPO package or
    # explicitly importing the GroupPolicy/ActiveDirectory modules for GPO setup.
    $gpoReady = $false
    try {
        $backupRoot = Initialize-CcdcGpoDraftEnvironment -DraftUri $GpoDraftUri -DraftPath $GpoDraftPath -CachePath $GpoCachePath
        $script:CcdcGpoActiveBackupRoot = $backupRoot
        $domainGpoBackup = Backup-DomainGpos -Path $GpoBackupPath
        Write-Status "Pre-hardening domain GPO backup: $domainGpoBackup"
        $gpoReady = $true
    } catch {
        Write-Status -Level Warning "Draft GPO source unavailable; skipping GPO linking. Non-GPO hardening will continue. $($_.Exception.Message)"
    }

    $script:NextStepLabel = 'Domain 3/15'
    if ($SkipAdminUserRemoval) {
        Write-Status -Level Skip 'Administrator-group membership cleanup skipped (-SkipAdminUserRemoval)'
    } else {
        Remove-AdminUsers
    }

    Write-Banner 'Pre-linking VSS snapshot' -Style Inline -Log
    $null = New-HardeningVssSnapshot

    $roleDefinitions = @(
        @{ Role = 'Database'; Label = 'MSSQL database'; Step = 'Domain 10/15' }
        @{ Role = 'Web';      Label = 'Web server'; Step = 'Domain 10/15' }
        @{ Role = 'WinRM';    Label = 'WinRM management'; Step = 'Domain 10/15' }
        @{ Role = 'SSH';      Label = 'SSH'; Step = 'Domain 10/15' }
        @{ Role = 'RDP';      Label = 'RDP'; Step = 'Domain 10/15' }
        @{ Role = 'FTP';      Label = 'FTP (IIS FTP service)'; Step = 'Domain 10/15' }
        @{ Role = 'SMB';      Label = 'SMB file sharing'; Step = 'Domain 10/15' }
        @{ Role = 'Mail';     Label = 'Mail'; Step = 'Domain 10/15' }
    )
    $selectedCoreRoleServers = @{}
    if ($gpoReady) {
        foreach ($definition in $roleDefinitions) {
            $servers = @()
            $roleKey = $definition.Role
            if ($RoleServers.ContainsKey($roleKey)) {
                $servers = @($RoleServers[$roleKey] | Where-Object { $_ })
            } elseif (-not $NoPrompt) {
                $computers = @(Get-ADComputer -Filter * -Properties OperatingSystem, Enabled, PrimaryGroupID -ErrorAction Stop |
                    Where-Object {
                        if (-not $_.Enabled) { return $false }
                        return $_.OperatingSystem -match '^Windows (Server|10|11)\b'
                    } |
                    Sort-Object Name)
                if ($computers.Count -gt 0) {
                    $optionNumber = 0
                    $options = @($computers | ForEach-Object {
                        $optionNumber++
                        $dcMarker = if ($_.PrimaryGroupID -eq 516) { ' - domain controller' } else { '' }
                        @{ Key = "$optionNumber"; Label = "{0}{1}{2}" -f $_.Name, $(if ($_.OperatingSystem) { " - $($_.OperatingSystem)" } else { '' }), $dcMarker; Value = $_.Name }
                    })
                    $servers = Read-Choice -Title "$($definition.Label) servers" `
                        -Prompt "Select computers that need the $($definition.Label) policy" `
                        -Options $options -Multiple -AllowEmpty -Hint 'Enter one or more option numbers (for example 1,3)'
                    if ($null -eq $servers) { $servers = @() }
                }
            }
            $selectedCoreRoleServers[$roleKey] = @($servers)
        }
    }

    $additionalDefinitions = @(
        @{ Role = 'LinuxSSH'; Label = 'Linux SSH access (SSSD GPO)'; Step = 'Domain 10/15' }
        @{ Role = 'Ping'; Label = 'Ping'; Step = 'Domain 10/15' }
        @{ Role = 'SNMP'; Label = 'SNMP'; Step = 'Domain 10/15' }
        @{ Role = 'ADCS'; Label = 'AD CS Certificate Authority'; Step = 'Domain 10/15' }
        @{ Role = 'XAMPP'; Label = 'XAMPP web ports'; Step = 'Domain 10/15' }
        @{ Role = 'MySQLMariaDB'; Label = 'MySQL/MariaDB ports'; Step = 'Domain 10/15' }
        @{ Role = 'SQLBrowser'; Label = 'SQL Browser'; Step = 'Domain 10/15' }
    )
    $selectedAdditionalRoleServers = @{}
    foreach ($definition in $additionalDefinitions) {
        if ($RoleServers.ContainsKey($definition.Role)) {
            $selectedAdditionalRoleServers[$definition.Role] = @($RoleServers[$definition.Role] | Where-Object { $_ })
        }
    }

    if ($gpoReady -and -not $NoPrompt -and (Read-YesNo -Message 'Link additional GPOs? (y/n): ') -eq 'y') {
        $promptDefinitions = @($additionalDefinitions | Where-Object { -not $RoleServers.ContainsKey($_.Role) })
        if ($promptDefinitions.Count -gt 0) {
            $optionNumber = 0
            $additionalOptions = @($promptDefinitions | ForEach-Object {
                $optionNumber++
                @{ Key = "$optionNumber"; Label = $_.Label; Value = $_.Role }
            })
            $additionalRoles = Read-Choice -Title 'Additional GPOs' `
                -Prompt 'Select additional GPOs to link' -Options $additionalOptions `
                -Multiple -AllowEmpty -Hint 'Enter one or more option numbers (for example 1,3)'

            foreach ($roleKey in @($additionalRoles)) {
                $definition = $promptDefinitions | Where-Object Role -eq $roleKey | Select-Object -First 1
                if (-not $definition) { continue }
                $isLinuxRole = $roleKey -eq 'LinuxSSH'
                $computers = @(Get-ADComputer -Filter * -Properties OperatingSystem, Enabled, PrimaryGroupID -ErrorAction Stop |
                    Where-Object {
                        if (-not $_.Enabled) { return $false }
                        $osName = [string]$_.OperatingSystem
                        if ($isLinuxRole) {
                            # Include unknown OS metadata so Linux computer objects without
                            # an OperatingSystem attribute remain selectable.
                            return ($osName -match 'Linux|Ubuntu|Red Hat|CentOS|Debian|SUSE|Rocky|AlmaLinux') -or
                                [string]::IsNullOrWhiteSpace($osName)
                        }
                        return $osName -match '^Windows (Server|10|11)\b'
                    } |
                    Sort-Object Name)

                if ($computers.Count -eq 0) {
                    Write-Status -Level Skip "No enabled computers found for $($definition.Label)"
                    continue
                }

                $optionNumber = 0
                $computerOptions = @($computers | ForEach-Object {
                    $optionNumber++
                    $osLabel = if ($_.OperatingSystem) { " - $($_.OperatingSystem)" } else { ' - OS not recorded' }
                    $dcMarker = if ($_.PrimaryGroupID -eq 516) { ' - domain controller' } else { '' }
                    @{ Key = "$optionNumber"; Label = "{0}{1}{2}" -f $_.Name, $osLabel, $dcMarker; Value = $_.Name }
                })
                $servers = Read-Choice -Title "$($definition.Label) servers" `
                    -Prompt "Select computers that need the $($definition.Label) GPO" `
                    -Options $computerOptions -Multiple -AllowEmpty `
                    -Hint 'Enter one or more option numbers (for example 1,3)'
                if (-not $servers -or @($servers).Count -eq 0) { continue }
                $selectedAdditionalRoleServers[$roleKey] = @($servers)
            }
        }
    }

    $hasSelectedAdditionalRole = @($selectedAdditionalRoleServers.Values | Where-Object { @($_).Count -gt 0 }).Count -gt 0
    if ($gpoReady -and ($hasSelectedAdditionalRole -or $FirewallPortRulesToAdd.Count -gt 0)) {
        try {
            Initialize-CcdcAdditionalGpoDraftEnvironment -BackupRoot $backupRoot | Out-Null
        } catch {
            Write-Status -Level Warning "Additional draft GPO package unavailable; skipping all GPO linking. $($_.Exception.Message)"
            $gpoReady = $false
        }
    }

    if ($gpoReady) {
    Write-Banner 'Link domain policies' -Style Inline -Log
    $script:NextStepLabel = 'Domain 4/15'
    Link-DcAllowAdGpo -BackupRoot $backupRoot

    $script:NextStepLabel = 'Domain 5/15'
    Link-DomainFirewallGpo -BackupRoot $backupRoot

    $script:NextStepLabel = 'Domain 6/15'
    Link-WebBrowsingGpo -BackupRoot $backupRoot -AllDomainComputers

    $script:NextStepLabel = 'Domain 7/15'
    Link-DomainGpoUpdateInterval -BackupRoot $backupRoot

    $script:NextStepLabel = 'Domain 8/15'
    Link-DomainGoodGpo -BackupRoot $backupRoot

    $script:NextStepLabel = 'Domain 9/15'
    Link-DomainAuditGpo -BackupRoot $backupRoot

    foreach ($definition in $roleDefinitions) {
        $roleKey = $definition.Role
        $servers = @($selectedCoreRoleServers[$roleKey])

        if ($servers.Count -gt 0) {
            $script:NextStepLabel = $definition.Step
            if ($roleKey -in @('Web', 'Mail')) {
                Link-ServerRoleGpo -Role $roleKey -ComputerName $servers -BackupRoot $backupRoot
            } else {
                Link-ServerServiceGpo -Role $roleKey -ComputerName $servers
            }
        } else {
            Write-Status -Level Skip "No $($definition.Label) servers selected; role GPO not linked" -LogMessage "No $($definition.Role) role servers selected"
        }
    }

    foreach ($definition in $additionalDefinitions) {
        $roleKey = $definition.Role
        if (-not $selectedAdditionalRoleServers.ContainsKey($roleKey)) { continue }
        $servers = @($selectedAdditionalRoleServers[$roleKey] | Where-Object { $_ })
        if ($servers.Count -eq 0) {
            Write-Status -Level Skip "No $($definition.Label) servers selected; role GPO not linked"
            continue
        }
        $script:NextStepLabel = $definition.Step
        if ($roleKey -eq 'LinuxSSH') {
            Write-Status -Level Info 'This GPO supplies the SSH logon right for SSSD. The Linux host must use SSSD AD GPO access control in enforcing mode for it to control SSH access.'
        }
        Link-ServerServiceGpo -Role $roleKey -ComputerName $servers
    }

    $script:NextStepLabel = 'Domain 11/15'
    foreach ($portRule in $FirewallPortRulesToAdd) {
        Add-DomainFirewallPortRule @portRule
    }
    foreach ($portRuleName in $FirewallPortRulesToRemove) {
        Remove-DomainFirewallPortRule -Name $portRuleName
    }
    if ($FirewallPortRulesToAdd.Count -eq 0 -and $FirewallPortRulesToRemove.Count -eq 0) {
        Write-Status -Level Skip 'No additional domain firewall port rules requested'
    }

    $script:NextStepLabel = 'Domain 12/15'
    if (-not $SkipSplunk -and -not $SplunkIP) {
        $SplunkIP = Read-HostAddress -Prompt 'Splunk server IP'
    }
    if ($SkipSplunkOutbound) {
        Write-Status -Level Skip 'Domain Splunk outbound firewall GPO skipped (-SkipSplunkOutbound)'
    } elseif ($SplunkIP) {
        Link-DomainSplunkOutboundGpo -BackupRoot $backupRoot -SplunkIP $SplunkIP
    } else {
        Write-Status -Level Skip 'No Splunk address supplied; Splunk outbound firewall GPO skipped'
    }

    Write-Banner 'Refresh Group Policy' -Style Inline -Log
    $script:NextStepLabel = 'Domain 13/15'
    Invoke-HardeningOperation -OperationName 'Refresh Group Policy' -ScriptBlock {
        try {
            Invoke-CcdcGpUpdate
            Write-Status -Level Success 'gpupdate /force completed successfully'
        } catch {
            Write-Status -Level Warning "gpupdate /force failed; continuing: $($_.Exception.Message)" -LogMessage "gpupdate /force failed: $($_.Exception.Message)"
            throw
        }
    }
    } else {
        Write-Status -Level Skip 'GPO linking and gpupdate skipped because the draft package was unavailable or invalid'
    }

    Write-Banner 'Final configuration' -Style Inline -Log
    if ($SkipSplunk) {
        Write-Status -Level Skip 'Splunk installation skipped (-SkipSplunk)'
    } else {
        if (-not $SplunkIP) { $SplunkIP = Read-HostAddress -Prompt 'Splunk server IP' }
        $script:NextStepLabel = 'Domain 14/15'
        Install-Splunk -IP $SplunkIP
    }

    if ($SkipPasswordChange) {
        Write-Status -Level Skip 'CCDC account creation skipped (-SkipPasswordChange)'
    } else {
        $script:NextStepLabel = 'Domain 15/15'
        Create-CCDCUsers -SaltPhrase $SaltPhrase
    }

    Write-Banner 'Domain Hardening Complete' -Style Inline -Color Green -Log
    Show-OperationSummary
    $newErrorCount = $global:Error.Count - $errorCountAtStart
    if ($newErrorCount -gt 0) {
        Write-Status -Level Warning "$newErrorCount error record(s) were written during this run" -LogMessage "Domain hardening recorded $newErrorCount error record(s)"
    }
    Write-Status "Log file location: $script:LogFile"
}

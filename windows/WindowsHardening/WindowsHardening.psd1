@{
    RootModule        = 'WindowsHardening.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a5b6951f-2e85-4915-bfd1-4fc3a779d13c'
    Author            = 'Aaron-M-Anderson, echo8358, deltabluejay, TheBushWookiee, zinkozapper, hyper-lang'
    CompanyName       = 'BYU CCDC'
    Description       = 'Windows hardening module for local systems and Active Directory domains, with user management, Group Policy deployment, firewall configuration, and service hardening.'

    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        # -- Public/ - entry points ------------------------------------------
        'Invoke-WindowsHardening'
        'Invoke-DomainHardening'
        'Invoke-HardeningMenu'

        # -- Public/Backups/ --------------------------------------------------
        'New-HardeningVssSnapshot'

        # -- Public/GPO/ -----------------------------------------------------
        'Backup-DomainGpos'
        'Link-DcAllowAdGpo'
        'Link-DomainFirewallGpo'
        'Link-DomainSplunkOutboundGpo'
        'Link-DomainGpoUpdateInterval'
        'Link-DomainGoodGpo'
        'Link-DomainAuditGpo'
        'Link-ServerRoleGpo'
        'Link-ServerWinRMGpo'
        'Link-ServerServiceGpo'
        'Link-SqlBrowserGpo'
        'Link-WebBrowsingGpo'
        'Add-DomainFirewallPortRule'
        'Remove-DomainFirewallPortRule'

        # -- Public/Users/ ---------------------------------------------------
        'Invoke-UserHardening'
        'Set-ZuluPassword'
        'Write-ZuluLog'
        'Set-UserPassword'
        'Set-AdministratorPassword'
        'Create-CCDCUsers'
        'New-ADUserAccount'
        'Remove-AdminUsers'
        'Remove-RDPUsers'
        'Add-RDPUsers'
        'Protect-Mimikatz'

        # -- Public/Network/ -------------------------------------------------
        'Invoke-NetworkHardening'
        'Set-FirewallConfiguration'
        'Mitigate-ZeroLogon'
        'Add-FirewallPort'
        'Get-FirewallPortOptions'
        'Remove-RemoteManagement'

        # -- Public/Services/ ------------------------------------------------
        'Invoke-ServiceHardening'
        'Disable-UnusedNetworkProtocols'
        'Mitigate-EternalBlue'
        'Set-RestrictedExecutionPolicy'

        # -- Public/TH-IR/ ----------------------------------------------------
        'Install-Splunk'
        'Enable-AdvancedAuditing'

        # -- Public/Patching/ ------------------------------------------------
        'Install-EternalBluePatch'

        # -- Public/Messages/ - logging & prompts ----------------------------
        'Start-HardeningLog'
        'Write-Status'
        'Set-OperationStatus'
        'Reset-OperationStatus'
        'Show-OperationSummary'
        'Read-YesNo'
        'Read-Choice'
        'Read-HostAddress'
        'Write-Banner'
        'Read-SecretInput'

        # -- Public/Helpers/ -------------------------------------------------
        'Initialize-System'
        'Initialize-Context'
        'Get-HardeningContext'
        'Test-Prerequisites'
        'Test-IsDomainController'
        'Get-OperatingSystemInfo'
        'Invoke-HardeningOperation'
        'Get-FileFromUrl'
        'Set-RegistryValue'
        'Show-Users'
        'New-Password'
        'ConvertTo-WordIndex'
        'Test-IsAdministrator'
        'ConvertTo-PortList'
        'Test-HostAddress'

        # -- Dev/ - experimental ---------------------------------------------
        'Backup-WindowsState'
        'Restore-WindowsState'
        'Get-LSARegistryValues'
        'Restore-LSAValues'
        'Restore-RegistrySecurityValues'
        'Install-NXLog'
        'Install-Fibratus'
    )

    AliasesToExport = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('Hardening', 'Security', 'Windows', 'Firewall', 'ActiveDirectory')
            ProjectUri = 'https://github.com/BYU-CCDC/public-ccdc-resources'
        }
    }
}

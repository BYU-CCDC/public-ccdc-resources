function Link-ServerServiceGpo {
    <#
    .SYNOPSIS
        Imports and links a service-role GPO to selected computer accounts.
    .DESCRIPTION
        Imports the role's GPO from the gpo-v1 draft package, applies only domain-specific
        access values, links it at the domain root, and filters it to the selected computers.
        MSSQL, SQL Browser, RDP, SNMP, and AD CS use service-scoped rules for all local ports and
        protocols when Windows Firewall can identify the service. IIS FTP uses TCP 21,
        its passive data range, and active-mode TCP 20 because the FTPSVC-scoped rules
        did not pass inbound traffic on Server 2022. IIS Web uses
        System/HTTP.sys-scoped TCP rules for 80/443 because W3SVC has SID type NONE.
        SSH uses executable-scoped any-port rules because the OpenSSH service SID is NONE;
        both the MSI and inbox executable paths are covered. SMB uses System/TCP 445 because
        Windows attributes its listener to System (PID 4), not LanmanServer. WinRM remains
        limited to TCP 5985/5986 because it listens through HTTP.sys. Ping is ICMP. XAMPP and
        MySQL/MariaDB retain conventional port rules because their service names and
        process/service installation modes vary. AD CS also needs the RPC endpoint mapper
        rule; optional Web Enrollment is hosted by IIS and is not enabled here.
        Domain Users are added to
        local groups for RDP, Windows SSH, and WinRM. SQLBrowser is a separate optional
        profile from the MSSQL engine.
        LinuxSSH is a separate logon-right policy for SSSD-managed Linux computers. SMB
        anonymous access is restricted, but share and NTFS ACLs remain administrator-owned.
        FTP anonymous authentication is left to local IIS configuration; authenticated FTP still
        requires site authorization, filesystem ACLs, and TLS configuration. AD CS web
        enrollment is optional and isn't enabled by this profile.
        SNMP must already be installed and configured. SQLBrowser is separate
        from MSSQLSERVER; named instances use different service names. XAMPP and
        MySQL/MariaDB roles only create firewall rules; they do not install or start software,
        or grant application/database access.
    .EXAMPLE
        Link-ServerServiceGpo -Role SSH -ComputerName LINUXGW01, FILE01
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateSet('Database', 'SQLBrowser', 'WinRM', 'SSH', 'LinuxSSH', 'RDP', 'FTP', 'SMB', 'Ping', 'SNMP', 'ADCS', 'XAMPP', 'MySQLMariaDB')][string]$Role,
        [Parameter(Mandatory=$true)][string[]]$ComputerName
    )

    if (-not $ComputerName -or $ComputerName.Count -eq 0) { return }
    $operationName = if ($Role -eq 'WinRM') { 'Link WinRM Management GPO' } else { "Link $Role Access GPO" }
    Invoke-HardeningOperation -OperationName $operationName -TargetComputerName $ComputerName -ScriptBlock {
        Add-CcdcServiceRoleGpo -Role $Role -ComputerName $ComputerName
        if ($Role -eq 'FTP') {
                Write-Status -Level Warning "IIS FTP passive data is configured for TCP 50000-50100. Confirm any external firewall/NAT forwards this range to the FTP server. For FileZilla or another FTP server, add its configured passive range: Add-DomainFirewallPortRule -Name <name> -ComputerName <server> -Port '<low>-<high>'" `
                -LogMessage 'FTP role: TCP 21 plus bounded passive TCP 50000-50100; IIS range and GPO firewall range are aligned.'
        }
    }
}

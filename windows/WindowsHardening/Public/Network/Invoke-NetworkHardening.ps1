function Invoke-NetworkHardening {
    <#
    .SYNOPSIS
        Orchestrates all network and remote-access hardening in a single call.

    .DESCRIPTION
        Runs the full network hardening sequence in the recommended order:

          1. Set-FirewallConfiguration  - enables all profiles, blocks inbound, allows only
                                         specified ports; optionally preserves TCP 5985/5986
                                         for WinRM management.
          2. Mitigate-ZeroLogon          - limits inbound TCP RPC allow rules to LocalSubnet.
          3. Remove-RemoteManagement    - stops and disables WinRM, Remote Registry, RDP,
                                         SSH (if present), and Telnet.

        The steps are deliberately ordered: configure the firewall, restrict RPC, then
        tear down remote-management services so there is no window where a service is
        stopped but its port remains open.

        When -PreserveManagementPort is set (typically when applying hardening over
        WinRM), Remove-RemoteManagement is called with -SkipWinRM
        so the active management session is not severed.

    .PARAMETER PreserveManagementPort
        Keep firewall allow-rules for WinRM (TCP 5985/5986) and skip the WinRM teardown
        in Remove-RemoteManagement. Pass this when running remotely over WinRM.

    .PARAMETER NonInteractive
        Passed to Set-FirewallConfiguration: never prompt. Without -FirewallPorts,
        a DC gets the common AD ports and any other machine gets Deny All only.

    .PARAMETER FirewallPorts
        Ports to allow, passed to Set-FirewallConfiguration.

    .PARAMETER Prompt
        Passed to Set-FirewallConfiguration: keep the default ports, then ask for extra
        ports to allow on top of them. Works with -NonInteractive.

    .PARAMETER AdditionalPorts
        Extra ports allowed on top of -FirewallPorts or the defaults, passed to
        Set-FirewallConfiguration.

    .PARAMETER SkipRemoteManagement
        Skip the Remove-RemoteManagement step entirely. Use when you want to apply
        firewall and RPC hardening but leave remote channels open.

    .PARAMETER SkipRDP
        When Remove-RemoteManagement runs, pass -SkipRDP so RDP is not disabled.
        Useful when the team still needs RDP access during the competition.

    .EXAMPLE
        Invoke-NetworkHardening
        # Full sequence: firewall, RPC mitigation, then remote-management teardown.

    .EXAMPLE
        Invoke-NetworkHardening -PreserveManagementPort
        # Firewall closes with WinRM 5985/5986 allowed; WinRM teardown skipped so remote
        # session survives.

    .EXAMPLE
        Invoke-NetworkHardening -SkipRemoteManagement
        # Firewall and RPC mitigation; remote channels left running.
    #>
    [CmdletBinding()]
    param(
        [switch]$PreserveManagementPort,

        [switch]$NonInteractive,

        [switch]$Prompt,

        [int[]]$FirewallPorts,

        [int[]]$AdditionalPorts,

        [switch]$SkipRemoteManagement,

        [Alias('srdp')]
        [switch]$SkipRDP
    )

    Write-Banner "Network & Remote-Access Hardening"

    # Step 1: Firewall
    $script:NextStepLabel = 'Network 1/3'
    Set-FirewallConfiguration -NonInteractive:$NonInteractive -Prompt:$Prompt -FirewallPorts $FirewallPorts -AdditionalPorts $AdditionalPorts -PreserveManagementPort:$PreserveManagementPort

    # Step 2: Restrict RPC after firewall configuration has enabled its AD rules.
    $script:NextStepLabel = 'Network 2/3'
    Mitigate-ZeroLogon

    # Step 3: Remote management teardown
    if (-not $SkipRemoteManagement) {
        $script:NextStepLabel = 'Network 3/3'
        if ($PreserveManagementPort) {
            # Running over WinRM - keep WinRM alive, still disable RDP unless caller opts out
            if ($SkipRDP) {
                Remove-RemoteManagement -SkipWinRM -SkipRDP
            } else {
                Remove-RemoteManagement -SkipWinRM
            }
        } else {
            if ($SkipRDP) {
                Remove-RemoteManagement -SkipRDP
            } else {
                Remove-RemoteManagement
            }
        }
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Network 3/3' "SKIPPED - remote management teardown (-SkipRemoteManagement)" -LogMessage "Invoke-NetworkHardening: Remove-RemoteManagement skipped"
    }

    Write-Host ""
    Write-Status -Tag Network "Done." -LogMessage "Invoke-NetworkHardening completed"
}

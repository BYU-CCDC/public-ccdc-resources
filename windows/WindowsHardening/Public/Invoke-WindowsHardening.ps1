function Invoke-WindowsHardening {
    <#
    .SYNOPSIS
        Runs the complete hardening sequence in the competition-approved order.
    .DESCRIPTION
        Starts a fresh log, shows the OS and AD status detected at module import,
        checks for administrator rights, then runs:

          1. Set-AdministratorPassword    - unless -SkipPasswordChange
          2. Remove-AdminUsers
          3. Set-ZuluPassword             - existing accounts, unless -SkipPasswordChange
          4. Ask whether WinRM is needed, then configure the firewall accordingly (unless -SkipFirewall)
          5. Mitigate-ZeroLogon (unless -SkipFirewall)
          6. Mitigate-EternalBlue
          7. Ask whether RDP is needed, then apply RDP group/service changes
          8. Protect-Mimikatz
          9. Remove-RemoteManagement
         10. Disable-UnusedNetworkProtocols
         11. Install-Splunk                - unless -SkipSplunk
         12. Create-CCDCUsers               - unless -SkipPasswordChange
         13. Set-RestrictedExecutionPolicy - machine-wide Restricted

        Each step is wrapped in Invoke-HardeningOperation, so one failure is counted and
        reported without stopping the rest. Ends with the operation summary.

        Prompts for passwords and values not passed: the Administrator password, Zulu salt
        phrase, Splunk server IP, whether WinRM and RDP are needed, and extra firewall ports.
        The WinRM choice precedes firewall configuration; firewall and SMB hardening precede
        the RDP choice. A skilled operator should account for possible session loss. To pick
        individual steps or sections instead, use
        Invoke-HardeningMenu.
    .PARAMETER SkipFirewall
        Leave the existing firewall configuration and rules unchanged. Skips firewall
        configuration, ZeroLogon firewall-rule changes, and firewall-rule removal during
        remote-management cleanup. Other hardening and service choices still run.
        -FirewallPorts and -AdditionalPorts are ignored.
    .PARAMETER SkipPasswordChange
        Skip the Administrator password change, Zulu rotation, and CCDC account creation. Alias: -sp.
    .PARAMETER SkipRDP
        Leave RDP enabled and skip the RDP group reset, without asking. Alias: -srdp.
    .PARAMETER DisableRDP
        Disable RDP and reset the RDP group, without asking. Alias: -drdp. With neither
        this nor -SkipRDP, the run asks whether RDP is needed after SMB hardening; with
        -NoPrompt (or in a session that cannot prompt) it disables RDP unless -SkipRDP is set.
    .PARAMETER SkipWinRM
        Leave WinRM enabled and keep TCP 5985/5986 allowed through the firewall, without
        asking. Alias: -swrm. -PreserveManagementPort has the same effect.
    .PARAMETER DisableWinRM
        Disable WinRM and do not add its standard firewall allow rules, without asking. Alias: -dwrm.
        With neither WinRM switch nor -PreserveManagementPort, the run asks whether WinRM
        is needed before configuring the firewall; with -NoPrompt it disables WinRM.
    .PARAMETER FirewallPorts
        Ports to allow ("80, 443", @("80","443"), or 80,443). If omitted, a domain
        controller gets the common AD ports and any other machine gets Deny All only. Alias: -f.
    .PARAMETER AdditionalPorts
        Extra ports to allow on top of -FirewallPorts or the defaults above - e.g. a database
        or web port the box needs. Same formats as -FirewallPorts. Alias: -ap.
    .PARAMETER NoPrompt
        Don't ask whether WinRM or RDP is needed (both are disabled unless their keep switch
        is given), or for extra firewall ports (only the defaults, -FirewallPorts, and
        -AdditionalPorts are used).
    .PARAMETER SaltPhrase
        Salt phrase for Zulu password generation. If omitted, Zulu prompts for it. Alias: -s.
    .PARAMETER LogPath
        Path for log files. Default: C:\Windows\Logs\Hardening.
    .PARAMETER PreserveManagementPort
        Keep WinRM reachable: firewall Allow rules for TCP 5985/5986 are kept and WinRM is not
        disabled. Use when applying hardening over WinRM so the session is not locked out.
    .PARAMETER SplunkIP
        Splunk server IP. If omitted (and -SkipSplunk is not set), prompts for it.
    .PARAMETER SkipSplunk
        Skip the Splunk installation step (no prompt).
    .EXAMPLE
        Invoke-WindowsHardening -SaltPhrase 'a long passphrase' -SkipSplunk -NoPrompt
        # Full run with no prompts.
    #>
    [CmdletBinding()]
    param(

        [Alias("sp")]
        [switch]$SkipPasswordChange,

        [Alias("srdp")]
        [switch]$SkipRDP,

        [Alias("drdp")]
        [switch]$DisableRDP,

        [Alias("swrm")]
        [switch]$SkipWinRM,

        [Alias("dwrm")]
        [switch]$DisableWinRM,

        [switch]$SkipFirewall,

        [Alias("f")]
        [string[]]$FirewallPorts,

        [Alias("ap")]
        [string[]]$AdditionalPorts,

        [switch]$NoPrompt,

        [Alias("s")]
        [string]$SaltPhrase,

        [string]$LogPath,

        [switch]$PreserveManagementPort,

        [string]$SplunkIP,

        [switch]$SkipSplunk
    )

    if ($SkipRDP -and $DisableRDP) {
        throw "-SkipRDP and -DisableRDP cannot be used together"
    }
    if (($SkipWinRM -and $DisableWinRM) -or ($DisableWinRM -and $PreserveManagementPort)) {
        throw "-SkipWinRM/-PreserveManagementPort and -DisableWinRM cannot be used together"
    }
    if ($PreserveManagementPort) { $SkipWinRM = $true }

    # -- FirewallPorts parsing ----------------------------------------------
    if ($SkipFirewall) {
        $ports = @()
        $extraPorts = @()
    } else {
        try {
            $ports = ConvertTo-PortList -Ports $FirewallPorts
            $extraPorts = ConvertTo-PortList -Ports $AdditionalPorts
        } catch {
            Write-Status -Level Error "Failed to parse FirewallPorts parameter: $($_.Exception.Message)"
            throw "Invalid FirewallPorts parameter: $($_.Exception.Message)"
        }
    }
    if ($ports.Count -gt 0) {
        Write-Status "Firewall ports provided via parameter: $($ports -join ', ')"
    }
    if ($extraPorts.Count -gt 0) {
        Write-Status "Additional firewall ports: $($extraPorts -join ', ')"
    }

    # Check -SplunkIP now, so a typo fails before hardening starts rather than at step 4.
    if ($SplunkIP -and -not (Test-HostAddress ($SplunkIP -replace ':\d+$', ''))) {
        throw "Invalid -SplunkIP '$SplunkIP': not an IP address or host name"
    }

    # $global:Error: inside a module, $Error is a separate module-scoped (empty) collection.
    $errorCountAtStart = $global:Error.Count

    # -- Banner --------------------------------------------------------------
    Write-Banner "Windows Hardening MODULE v1.0"

    # -- Initialize (OS detection, logging, context) -------------------------
    Initialize-System -Force -LogPath $LogPath

    $osInfo = $script:HardeningContext.OS
    if ($osInfo) {
        Write-Banner "Detected Operating System" -Color Yellow -Body @(
            "OS Version: $($osInfo.OSVersion)"
            "Build Number: $($osInfo.BuildNumber)"
            "Edition: $($osInfo.Edition)"
            "Is Server: $($osInfo.IsServer)"
            "Is Server Core: $($osInfo.IsServerCore)"
        )
    } else {
        Write-Host ""
        Write-Status -Level Error "Failed to detect operating system."
        if ((Read-YesNo -Message "The script may not function correctly. Continue anyway? (y/n) ") -ne 'y') {
            throw "OS detection failed. Script aborted by user."
        }
    }

    # -- AD status display (detected at module import) ------------------------
    if ($osInfo) {
        if ($osInfo.IsDomainJoined) {
            Write-Banner "Active Directory Status: DOMAIN JOINED$(if ($osInfo.IsDomainController) { ' (Domain Controller)' })" -Body "Domain: $($osInfo.Domain)"
        } else {
            Write-Banner "Active Directory Status: NOT DOMAIN JOINED" -Body "Workgroup: $($osInfo.Workgroup)" -Color Yellow
        }
        Write-Host ""
    }

    # -- Pre-flight checks ---------------------------------------------------
    try {
        Test-Prerequisites
    } catch {
        Write-Host ""
        Write-Status -Level Error "Pre-flight checks failed: $($_.Exception.Message)"
        throw "Pre-flight checks failed: $($_.Exception.Message)"
    }

    # -- Hardening sequence ---------------------------------------------------
    if ($SkipPasswordChange) {
        Write-Status "Administrator password change, password rotation, and CCDC account creation will be skipped (-sp)"
    }
    if ($SkipRDP) {
        Write-Status "RDP group reset and RDP disable will be skipped (RDP stays enabled)"
    }
    if ($SkipWinRM) {
        if ($SkipFirewall) {
            Write-Status "WinRM will be kept enabled; firewall rules will remain unchanged (-SkipFirewall)"
        } else {
            Write-Status "WinRM will be kept enabled and TCP 5985/5986 will be allowed"
        }
    }
    if ($SkipFirewall) {
        Write-Status -Level Skip "Firewall configuration and firewall rule changes will be skipped (-SkipFirewall)"
    }

    Write-Banner "Step 1/13: Change Administrator password" -Style Inline -Log
    if ($SkipPasswordChange) {
        Write-Status -Level Skip "Administrator password change skipped (-SkipPasswordChange)"
    } else {
        $script:NextStepLabel = 'Full Run 1/13'
        Set-AdministratorPassword -SaltPhrase $SaltPhrase
    }

    Write-Banner "Step 2/13: Remove unauthorized administrators" -Style Inline -Log
    $script:NextStepLabel = 'Full Run 2/13'
    Remove-AdminUsers

    Write-Banner "Step 3/13: Rotate existing user passwords" -Style Inline -Log
    if ($SkipPasswordChange) {
        Write-Status -Level Skip "Existing-user password rotation skipped (-SkipPasswordChange)"
    } else {
        $script:NextStepLabel = 'Full Run 3/13'
        Set-ZuluPassword -SaltPhrase $SaltPhrase
    }

    Write-Banner "Pre-hardening VSS snapshot" -Style Inline -Log
    $null = New-HardeningVssSnapshot

    # Decide before configuring the firewall so the WinRM allow rules match the service choice.
    if (-not $SkipWinRM -and -not $DisableWinRM) {
        if ($NoPrompt) {
            Write-Status "WinRM will be disabled (-NoPrompt; pass -SkipWinRM or -PreserveManagementPort to keep it)"
        } else {
            Write-Host ""
            Write-Status -Level Warning "Disabling WinRM can end a WinRM session to this machine." -NoLog
            $keepWinRMLabel = if ($SkipFirewall) { 'Yes - keep WinRM enabled' } else { 'Yes - keep WinRM enabled and allow TCP 5985/5986' }
            $disableWinRMLabel = if ($SkipFirewall) { 'No  - disable WinRM' } else { 'No  - disable WinRM without preserving its firewall ports' }
            try {
                $winrmChoice = Read-Choice -Prompt "Is WinRM needed on this machine?" -Default 'Y' -Options @(
                    @{ Key = 'Y'; Label = $keepWinRMLabel; Value = 'keep' }
                    @{ Key = 'N'; Label = $disableWinRMLabel; Value = 'disable' }
                )
                $SkipWinRM = $winrmChoice -eq 'keep'
            } catch {
                Write-Status -Level Warning "Cannot ask in this session; WinRM will be disabled (pass -SkipWinRM to keep it)" `
                    -LogMessage "WinRM prompt unavailable: $($_.Exception.Message)"
            }
            Write-Status "WinRM will be $(if ($SkipWinRM) { 'kept' } else { 'disabled' }) (answered at the prompt)" -LogOnly
        }
    }

    Write-Banner "Step 4/13: Configure firewall" -Style Inline -Log
    $script:NextStepLabel = 'Full Run 4/13'
    if ($SkipFirewall) {
        Write-Status -Level Skip "Firewall configuration skipped (-SkipFirewall)"
    } else {
        Set-FirewallConfiguration -NonInteractive -Prompt:(-not $NoPrompt) -FirewallPorts $ports -AdditionalPorts $extraPorts -PreserveManagementPort:$SkipWinRM
    }

    Write-Banner "Step 5/13: Mitigate ZeroLogon" -Style Inline -Log
    $script:NextStepLabel = 'Full Run 5/13'
    if ($SkipFirewall) {
        Write-Status -Level Skip "ZeroLogon firewall rule changes skipped (-SkipFirewall)"
    } else {
        Mitigate-ZeroLogon
    }

    Write-Banner "Step 6/13: Mitigate EternalBlue (SMBv1)" -Style Inline -Log
    $script:NextStepLabel = 'Full Run 6/13'
    Mitigate-EternalBlue

    # This decision follows firewall and SMB changes. A skilled operator should
    # account for any resulting loss of the current remote session.
    if (-not $SkipRDP -and -not $DisableRDP) {
        if ($NoPrompt) {
            Write-Status "RDP will be disabled (-NoPrompt; pass -SkipRDP to keep it)"
        } else {
            Write-Host ""
            Write-Status -Level Warning "Disabling RDP ends any RDP session to this machine, including yours." -NoLog
            try {
                $rdpChoice = Read-Choice -Prompt "Is RDP needed on this machine?" -Default 'Y' -Options @(
                    @{ Key = 'Y'; Label = 'Yes - keep RDP enabled and leave the group as is (same as -SkipRDP)'; Value = 'keep' }
                    @{ Key = 'N'; Label = 'No  - disable RDP and reset the Remote Desktop Users group'; Value = 'disable' }
                )
                $SkipRDP = $rdpChoice -eq 'keep'
            } catch {
                Write-Status -Level Warning "Cannot ask in this session; RDP will be disabled (pass -SkipRDP to keep it)" `
                    -LogMessage "RDP prompt unavailable: $($_.Exception.Message)"
            }
            Write-Status "RDP will be $(if ($SkipRDP) { 'kept' } else { 'disabled' }) (answered at the prompt)" -LogOnly
        }
    }

    Write-Banner "Step 7/13: Apply RDP user choice" -Style Inline -Log
    if ($SkipRDP) {
        Write-Status -Level Skip "RDP group reset skipped (-SkipRDP); RDP stays enabled"
    } else {
        $script:NextStepLabel = 'Full Run 7/13'
        Remove-RDPUsers
    }

    Write-Banner "Step 8/13: Protect credentials from Mimikatz" -Style Inline -Log
    $script:NextStepLabel = 'Full Run 8/13'
    Protect-Mimikatz

    Write-Banner "Step 9/13: Remove remote management services" -Style Inline -Log
    $script:NextStepLabel = 'Full Run 9/13'
    $remoteManagementArgs = @{}
    if ($SkipWinRM) { $remoteManagementArgs.SkipWinRM = $true }
    if ($SkipRDP) { $remoteManagementArgs.SkipRDP = $true }
    if ($SkipFirewall) { $remoteManagementArgs.SkipFirewallRules = $true }
    Remove-RemoteManagement @remoteManagementArgs

    Write-Banner "Step 10/13: Disable unused network protocols" -Style Inline -Log
    $script:NextStepLabel = 'Full Run 10/13'
    Disable-UnusedNetworkProtocols

    Write-Banner "Step 11/13: Configuring Splunk" -Style Inline -Log
    if ($SkipSplunk) {
        Write-Status -Level Skip "Splunk configuration skipped (-SkipSplunk)" -LogMessage "Splunk configuration skipped per -SkipSplunk"
    } else {
        $script:NextStepLabel = 'Full Run 11/13'
        if ([string]::IsNullOrEmpty($SplunkIP)) {
            $SplunkIP = Read-HostAddress -Prompt "Splunk server IP"
        }
        Install-Splunk -IP $SplunkIP
    }

    Write-Banner "Step 12/13: Creating CCDC competition accounts" -Style Inline -Log
    if (-not $SkipPasswordChange) {
        $script:NextStepLabel = 'Full Run 12/13'
        Create-CCDCUsers -SaltPhrase $SaltPhrase
    } else {
        Write-Status -Level Skip "CCDC account creation skipped (-SkipPasswordChange)"
    }

    Write-Banner "Step 13/13: Setting Execution Policy to Restricted" -Style Inline -Log
    $script:NextStepLabel = 'Full Run 13/13'
    Set-RestrictedExecutionPolicy

    Write-Host ""
    Write-Status -Level Warning "All sections applied. Next: enable Windows Defender, then run Windows Updates."

    # -- Final summary -------------------------------------------------------
    Write-Banner "Script Completed" -Style Inline -Color Green -Log
    Show-OperationSummary

    # $Error is newest-first, so this run's errors are the first (new count) entries
    $newErrorCount = $global:Error.Count - $errorCountAtStart
    if ($newErrorCount -gt 0) {
        try {
            $errorFile = "$env:USERPROFILE\Desktop\hard.txt"
            $global:Error[0..($newErrorCount - 1)] | Out-File $errorFile -Append -Encoding utf8
            Write-Status "Errors written to $errorFile" -LogOnly
        } catch {
            Write-Status -Level Warning "Could not write errors to file: $($_.Exception.Message)"
        }
    }

    Write-Status -LogOnly "=== Script Execution Completed ==="
    Write-Status "Log file location: $script:LogFile"

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 60) -ForegroundColor Cyan
    if ($script:OperationResults.Failed -eq 0 -and $script:OperationResults.Skipped -eq 0) {
        Write-Status -Level Success "Hardening completed successfully! All $($script:OperationResults.Total) operation(s) completed without errors." -LogMessage "=== Hardening completed successfully ==="
    } elseif ($script:OperationResults.Failed -eq 0) {
        Write-Status -Level Warning "Hardening completed with warnings! All operations completed, but $($script:OperationResults.Skipped) operation(s) were skipped (see details above)." -LogMessage "=== Hardening completed with warnings ==="
    } else {
        Write-Status -Level Error "Hardening completed with errors - review the summary above. Failed Operations: $($script:OperationResults.Failed)" -LogMessage "=== Hardening completed with errors ==="
    }
    Write-Host ("=" * 60) -ForegroundColor Cyan
}

#Requires -Version 5.1

<#
.SYNOPSIS
    Configures Windows Firewall with mandatory Deny All Inbound rule and optional port allowances.

.DESCRIPTION
    This function consolidates all firewall configuration logic. It always creates a high-priority
    "Deny All Inbound" rule for security. It then handles three scenarios:

    - -FirewallPorts given: allows exactly those ports (no prompts).
    - -NonInteractive without ports: Deny All only for Local; common AD/DC ports for AD.
    - Neither: prompts for ports and confirmation.

    -AdditionalPorts are added on top of whichever set was chosen.

    -Prompt picks the base set the same way -NonInteractive does (-FirewallPorts, else the
    AD ports on a DC), then asks for any additional ports to allow on top of it.

    Existing "Allow <Protocol> <Port>" rules from earlier runs are re-enabled instead of
    duplicated, and enabled Block rules that would override an Allow rule are reported.
    To open a port later without resetting the firewall, use Add-FirewallPort.

    Domain-vs-Local branching is driven by $script:HardeningContext.OS.IsDomainController.

.PARAMETER FirewallPorts
    Ports to allow. When given, no prompts are shown and no ports are added automatically.

.PARAMETER AdditionalPorts
    Extra ports to allow on top of -FirewallPorts, the DC defaults, or the ports chosen at
    the prompt - e.g. a database or web port the box is known to need.

.PARAMETER NonInteractive
    Never prompt (used by Invoke-WindowsHardening), unless -Prompt is also given.

.PARAMETER Prompt
    Keep the default ports (or -FirewallPorts), then ask for any additional ports to allow.
    Enter port numbers directly, separated by commas; Enter adds none.

.PARAMETER PreserveManagementPort
    When set, creates Allow rules for TCP 5986 (WinRM-HTTPS) and TCP 5985
    (WinRM-HTTP) after all existing rules are disabled, so a remote session
    applying this over WinRM does not lock itself out. The later port-rule loop
    skips both to avoid duplicates.
#>
function Set-FirewallConfiguration {
    [CmdletBinding()]
    param(
        [int[]]$FirewallPorts,

        [int[]]$AdditionalPorts,

        [switch]$NonInteractive,

        [switch]$Prompt,

        [switch]$PreserveManagementPort
    )

    Invoke-HardeningOperation -OperationName "Configure Firewall" -ScriptBlock {
        try {
            $portsToAllow = @()
            $isDC = $script:HardeningContext.OS.IsDomainController

            if ($isDC) {
                $commonADorDC = @(53, 139, 88, 67, 68, 135, 389, 445, 636, 3268, 3269, 464)
            }

            # Explicit ports: use exactly these
            if ($null -ne $FirewallPorts -and $FirewallPorts.Count -gt 0) {
                $portsToAllow = $FirewallPorts
                Write-Status "Using firewall ports from parameter: $($portsToAllow -join ', ')"
            }
            # Non-interactive without ports: AD ports on a DC, Deny All only on a local machine
            elseif ($NonInteractive -or $Prompt) {
                if ($isDC) {
                    $portsToAllow = $commonADorDC
                    Write-Status "Using common AD ports: $($portsToAllow -join ', ')"
                } else {
                    Write-Status "No ports specified - applying Deny All Inbound rule only"
                }
            }
            # Interactive: one multi-select prompt over the suggested ports; unlisted ports
            # can be typed too. On a DC, Enter keeps the AD ports; elsewhere Enter = none.
            else {
                $portOptions = @(Get-FirewallPortOptions -IsDC:$isDC)
                $defaultKeys = @($portOptions | Where-Object { $_.Default } | ForEach-Object { $_.Key })
                Write-Host "Suggested ports are common scored services and/or ports AD needs." -ForegroundColor DarkGray
                if (-not $isDC) {
                    Write-Host "AD ports are listed in case this box is joined to a domain later." -ForegroundColor DarkGray
                }

                $ready = $false
                while ($true) {
                    $desigPorts = Read-Choice -Title "Firewall Ports" -Prompt "Ports to allow" -Options $portOptions `
                        -Multiple -AllowCustom -AllowEmpty -AllowQuit -Default $defaultKeys `
                        -ValidateCustom { param($value) (ConvertTo-PortList -Ports $value)[0] }
                    if ($null -eq $desigPorts) { break }

                    Write-Banner "Designated Ports" -Style Inline
                    if ($desigPorts.Count -gt 0) {
                        Write-Host (($desigPorts | Sort-Object) -join ', ')
                    } else {
                        Write-Host "(none - Deny All Inbound only)"
                    }
                    if ((Read-YesNo -Message "Are these ports correct (y/n)? ") -eq 'y') {
                        $portsToAllow = $desigPorts
                        $ready = $true
                        break
                    }
                }

                if (-not $ready) {
                    # Invoke-HardeningOperation counts OperationCanceledException as a skip.
                    throw [System.OperationCanceledException]::new("Firewall configuration cancelled by user")
                }
            }

            # -Prompt: keep the base set, then ask for extra ports on top of it.
            $promptedPorts = @()
            if ($Prompt) {
                $alreadyAllowed = @(@($portsToAllow) + @($AdditionalPorts) | Where-Object { "$_" -ne '' } | ForEach-Object { [int]"$_" } | Sort-Object -Unique)
                if ($alreadyAllowed.Count -gt 0) {
                    Write-Status "Already allowed: $($alreadyAllowed -join ', ')"
                }
                try {
                    $promptedPorts = Read-Choice -Title "Additional Ports" -Prompt "Any additional ports to open" -Options @() `
                        -Multiple -AllowCustom -AllowEmpty `
                        -Hint "enter port numbers separated by commas" `
                        -ValidateCustom { param($value) (ConvertTo-PortList -Ports $value)[0] }
                } catch {
                    # No console (e.g. over WinRM): still apply the firewall, just without extras.
                    $promptedPorts = @()
                    Write-Status -Level Warning "Cannot ask for extra ports in this session; using the ports above only (pass -NoPrompt to skip the question)" `
                        -LogMessage "Extra-port prompt unavailable: $($_.Exception.Message)"
                }
            }

            # Add-on ports; also validates, de-duplicates, and drops blank prompt entries
            $extraPorts = @(@($AdditionalPorts) + @($promptedPorts) | Where-Object { $null -ne $_ })
            $portsToAllow = @((ConvertTo-PortList -Ports (@($portsToAllow) + $extraPorts | ForEach-Object { "$_" })) | Sort-Object -Unique)
            if ($extraPorts.Count -gt 0) {
                Write-Status "Additional ports: $($extraPorts -join ', ')" -LogMessage "Additional firewall ports: $($extraPorts -join ', ')"
            }

            # Back up the current policy. One file per run, so re-running never overwrites the
            # original pre-hardening backup. netsh reports failure only through its exit code.
            $FirewallBackupPath = Join-Path $script:HardeningContext.LogPath "fwback_$(Get-Date -Format 'yyyyMMdd_HHmmss').wfw"
            Write-Status "Backing up current Windows Firewall policy to $FirewallBackupPath"
            $netshOutput = netsh advfirewall export "$FirewallBackupPath" 2>&1
            if ($LASTEXITCODE -eq 0 -and (Test-Path $FirewallBackupPath)) {
                Write-Status -Level Success "Backup saved. To restore: netsh advfirewall import `"$FirewallBackupPath`""
            } else {
                Write-Status -Level Warning "Firewall backup failed (continuing): $(($netshOutput | Out-String).Trim())"
            }

            # Enable the firewall profiles and disable all pre-existing inbound and outbound rules
            Set-NetFirewallProfile -All -Enabled True

            # Disable ALL rules (including any pre-existing ones). This must run BEFORE the
            # management-port Allow rules are created below, otherwise it would disable them
            # and a remote WinRM session applying this would lock itself out.
            Get-NetFirewallRule | Disable-NetFirewallRule

            # Create a new firewall rule to block all inbound traffic and allow outbound traffic
            Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow

            # Keep WinRM (5985 HTTP, 5986 HTTPS) reachable when hardening over a remote session.
            if ($PreserveManagementPort) {
                $null = Set-FirewallAllowRule -Port 5986 -Protocol TCP
                Write-Status -Level Success "Added TCP inbound rules for port 5986 (WinRM-HTTPS, preserved management port)" -LogOnly
                $null = Set-FirewallAllowRule -Port 5985 -Protocol TCP
                Write-Status -Level Success "Added TCP inbound rules for port 5985 (WinRM-HTTP, preserved management port)" -LogOnly
            }

            # If ports are specified, create Allow rules for them (with higher priority than Deny All so they're evaluated first)
            if ($portsToAllow.Count -gt 0) {
                Write-Status "Creating Allow rules for specified ports..."
                foreach ($port in $portsToAllow) {
                    # Skip the preserved management ports - their Allow rules were already created above.
                    if ($PreserveManagementPort -and ($port -eq 5986 -or $port -eq 5985)) {
                        continue
                    }

                    $description = Get-FirewallPortDescription -Port $port

                    if ($isDC) {
                        # AD: create both TCP and UDP Allow rules
                        $null = Set-FirewallAllowRule -Port $port -Protocol TCP
                        $null = Set-FirewallAllowRule -Port $port -Protocol UDP
                        Write-Status -Level Success "Added inbound rules for port $port ($description)" -LogOnly
                    } else {
                        # Local: create TCP-only Allow rule
                        $null = Set-FirewallAllowRule -Port $port -Protocol TCP
                        Write-Status -Level Success "Added TCP inbound rules for port $port ($description)" -LogOnly
                    }
                }
                Write-Status -Level Success "Allow rules created for ports: $($portsToAllow -join ', ')" -LogMessage "Firewall configured with ports: $($portsToAllow -join ', ')"
            } else {
                if ($isDC) {
                    Write-Status "No ports specified - only AD rules applied" -LogMessage "Firewall configured with AD rules only (no other ports allowed)"
                } else {
                    Write-Status "No ports specified - only Deny All Inbound rule applied" -LogMessage "Firewall configured with Deny All Inbound rule only (no ports allowed)"
                }
            }

            # DC only: re-enable the built-in AD DS and DFS Replication inbound rules, limited to
            # the local subnet. These cover what the port list cannot: AD's dynamic RPC ports
            # (replication, Netlogon, SAM/LSA) and SYSVOL replication. Selected by rule group, not
            # by name wildcards: "*RPC*" also matched the Remote Service / Scheduled Task / Event
            # Log / WMI management rules, and "*445*" re-scoped this function's own Allow rules.
            if ($isDC) {
                $adRules = @(Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayGroup -in 'Active Directory Domain Services', 'DFS Replication' })
                if ($adRules.Count -gt 0) {
                    $adRules | Set-NetFirewallRule -RemoteAddress LocalSubnet -Enabled True
                    Write-Status -Level Success "Re-enabled $($adRules.Count) AD DS / DFS Replication rule(s) for the local subnet"
                } else {
                    Write-Status -Level Warning "No 'Active Directory Domain Services' firewall rules found; AD RPC traffic (replication, domain joins) may be blocked"
                }
            }

            Write-Status -Level Success "Firewall configured successfully" -LogMessage "Firewall configuration completed"
        } catch {
            if ($_.Exception -isnot [System.OperationCanceledException]) {
                Write-Status -Level Error "Firewall configuration failed: $($_.Exception.Message)"
            }
            throw
        }
    }
}

function Remove-RemoteManagement {
    <#
    .SYNOPSIS
        Disables remote management attack surface: WinRM, Remote Registry, RDP, and optional SSH.

    .DESCRIPTION
        Hardens the system by tearing down every common remote-management channel that
        attackers leverage for lateral movement and C2:

          1. WinRM             - Runs Disable-PSRemoting, removes all HTTP/HTTPS listeners,
                                 stops and disables the WinRM service, and removes WinRM
                                 firewall rules (5985/5986) unless -SkipFirewallRules.
          2. Remote Registry   - Stops and disables the RemoteRegistry service so attackers
                                 cannot read or write registry hives over the network.
          3. RDP               - Sets fDenyTSConnections=1 (disables RDP completely),
                                 enforces NLA (UserAuthentication=1), and removes the
                                 Remote Desktop firewall rule group unless -SkipFirewallRules.
          4. SSH (optional)    - If the OpenSSH Server service (sshd) is present, stops
                                 and disables it and removes the OpenSSH firewall rule unless
                                 -SkipFirewallRules.
          5. Telnet client     - Removes the Telnet-Client Windows feature if installed.

        All operations are wrapped in try/catch so a single failure does not abort
        the rest.  This function is safe to run on domain controllers and member
        servers; it does NOT touch AD or LDAP ports.

        Run AFTER Set-FirewallConfiguration, which blocks ports at the perimeter.
        This function kills the services so they cannot be re-exposed if firewall
        rules are tampered with.

    .PARAMETER SkipRDP
        Skip the RDP-disable step.  Use when RDP access must be preserved (e.g.
        for a jump-box role in competition).

    .PARAMETER SkipSSH
        Skip the SSH-disable step even if sshd is detected.

    .PARAMETER SkipWinRM
        Skip the WinRM-disable step.  Useful when running this function from a
        WinRM session you still need (run it last, or handle the disconnect).

    .PARAMETER SkipFirewallRules
        Leave firewall rules unchanged. Also skips Disable-PSRemoting because it can
        modify WinRM firewall exceptions; service and listener cleanup still runs.

    .EXAMPLE
        Remove-RemoteManagement
        # Disables WinRM, Remote Registry, RDP, and SSH (if present).

    .EXAMPLE
        Remove-RemoteManagement -SkipRDP
        # Disables everything except RDP (keeps remote desktop available).

    .EXAMPLE
        Remove-RemoteManagement -SkipWinRM
        # Disables RDP, Remote Registry, and SSH but leaves WinRM running.
        # Useful when hardening over a WinRM session.
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipRDP,
        [switch]$SkipSSH,
        [switch]$SkipWinRM,
        [switch]$SkipFirewallRules
    )

    Invoke-HardeningOperation -OperationName "Remove Remote Management" -ScriptBlock {

        # -- 1. WinRM ---------------------------------------------------------
        if (-not $SkipWinRM) {
            Write-Host ""
            Write-Status -Tag WinRM "Disabling Windows Remote Management..."

            if ($SkipFirewallRules) {
                Write-Status -Level Skip -Tag WinRM "Disable-PSRemoting skipped to preserve firewall rules"
            } else {
                try {
                    # Suppress the progress bar that Disable-PSRemoting writes
                    $oldPref = $ProgressPreference
                    $ProgressPreference = 'SilentlyContinue'
                    Disable-PSRemoting -Force -ErrorAction SilentlyContinue
                    $ProgressPreference = $oldPref
                    Write-Status -Level Success -Tag WinRM "PS remoting disabled" -LogMessage "Disabled PS remoting"
                } catch {
                    Write-Status -Level Warning -Tag WinRM "Disable-PSRemoting: $($_.Exception.Message)" -LogMessage "Disable-PSRemoting failed: $($_.Exception.Message)"
                }
            }

            # Remove all WinRM listeners
            try {
                $listeners = Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue
                if ($listeners) {
                    $listeners | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Status -Level Success -Tag WinRM "Removed all WinRM listeners"
                } else {
                    Write-Status -Level Warning -Tag WinRM "No WinRM listeners found"
                }
            } catch {
                Write-Status -Level Warning -Tag WinRM "Could not remove listeners: $($_.Exception.Message)" -LogMessage "Could not remove WinRM listeners: $($_.Exception.Message)"
            }

            # Stop and disable WinRM service
            try {
                $svc = Get-Service -Name WinRM -ErrorAction Ignore
                if ($svc) {
                    Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue
                    Set-Service  -Name WinRM -StartupType Disabled -ErrorAction Stop
                    Write-Status -Level Success -Tag WinRM "Service stopped and disabled" -LogMessage "WinRM service stopped and disabled"
                }
            } catch {
                Write-Status -Level Warning -Tag WinRM "Could not stop/disable WinRM service: $($_.Exception.Message)"
            }

            # Remove WinRM firewall rules (5985 HTTP, 5986 HTTPS)
            if ($SkipFirewallRules) {
                Write-Status -Level Skip -Tag WinRM "Firewall rules left unchanged (-SkipFirewallRules)"
            } else {
                try {
                    $winrmRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -match 'WinRM|Windows Remote Management' }
                    if ($winrmRules) {
                        $winrmRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                        Write-Status -Level Success -Tag WinRM "Firewall rules removed ($($winrmRules.Count) rule(s))" -LogMessage "Removed $($winrmRules.Count) WinRM firewall rule(s)"
                    } else {
                        Write-Status -Level Warning -Tag WinRM "No WinRM firewall rules found"
                    }
                } catch {
                    Write-Status -Level Warning -Tag WinRM "Could not remove firewall rules: $($_.Exception.Message)" -LogMessage "Could not remove WinRM firewall rules: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Status -Level Skip -Tag WinRM "SKIPPED (SkipWinRM specified)" -LogMessage "WinRM disable step skipped per -SkipWinRM"
        }

        # -- 2. Remote Registry -----------------------------------------------
        Write-Host ""
        Write-Status -Tag RemoteRegistry "Disabling Remote Registry service..."
        try {
            $svc = Get-Service -Name RemoteRegistry -ErrorAction Ignore
            if ($svc) {
                Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
                Set-Service  -Name RemoteRegistry -StartupType Disabled -ErrorAction Stop
                Write-Status -Level Success -Tag RemoteRegistry "Service stopped and disabled" -LogMessage "Remote Registry service stopped and disabled"
            } else {
                Write-Status -Tag RemoteRegistry "Service not found (may already be absent)" -LogMessage "RemoteRegistry service not found"
            }
        } catch {
            Write-Status -Level Warning -Tag RemoteRegistry "$($_.Exception.Message)" -LogMessage "Could not disable RemoteRegistry: $($_.Exception.Message)"
        }

        # -- 3. RDP -----------------------------------------------------------
        if (-not $SkipRDP) {
            Write-Host ""
            Write-Status -Tag RDP "Disabling Remote Desktop..."

            # Disable RDP via registry
            try {
                $rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
                Set-ItemProperty -Path $rdpKey -Name fDenyTSConnections -Value 1 -Type DWord -Force -ErrorAction Stop
                Write-Status -Level Success -Tag RDP "fDenyTSConnections set to 1 (RDP disabled)" -LogMessage "RDP disabled via registry (fDenyTSConnections=1)"
            } catch {
                Write-Status -Level Warning -Tag RDP "Could not set fDenyTSConnections: $($_.Exception.Message)" -LogMessage "Could not disable RDP via registry: $($_.Exception.Message)"
            }

            # Enforce NLA (Network Level Authentication) even if RDP is somehow re-enabled
            try {
                $nlaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
                Set-ItemProperty -Path $nlaKey -Name UserAuthentication -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                Write-Status -Level Success -Tag RDP "NLA enforced (UserAuthentication=1)" -LogMessage "NLA enforced on RDP-Tcp listener"
            } catch {
                Write-Status -Level Warning -Tag RDP "Could not enforce NLA: $($_.Exception.Message)"
            }

            # Remove RDP firewall rules
            if ($SkipFirewallRules) {
                Write-Status -Level Skip -Tag RDP "Firewall rules left unchanged (-SkipFirewallRules)"
            } else {
                try {
                    $rdpRules = Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction Ignore
                    if (-not $rdpRules) {
                        # Fallback: match by display name
                        $rdpRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
                            Where-Object { $_.DisplayName -match 'Remote Desktop' }
                    }
                    if ($rdpRules) {
                        $rdpRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                        Write-Status -Level Success -Tag RDP "Firewall rules removed ($($rdpRules.Count) rule(s))" -LogMessage "Removed $($rdpRules.Count) RDP firewall rule(s)"
                    } else {
                        Write-Status -Level Warning -Tag RDP "No RDP firewall rules found"
                    }
                } catch {
                    Write-Status -Level Warning -Tag RDP "Could not remove RDP firewall rules: $($_.Exception.Message)"
                }
            }

            # Stop TermService (Remote Desktop Services). Stop-Service would block until the
            # service stops, which takes ~10 minutes on Server 2022 while the RDP listener is
            # up. RDP is already denied above, so request the stop, wait briefly, and move on;
            # the Service Control Manager finishes the stop in the background.
            try {
                $svc = Get-Service -Name TermService -ErrorAction Ignore
                if ($svc -and $svc.Status -eq 'Running') {
                    $svc.Stop()
                    try {
                        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
                        Write-Status -Level Success -Tag RDP "TermService stopped"
                    } catch [System.ServiceProcess.TimeoutException] {
                        Write-Status -Level Warning -Tag RDP "TermService stop requested; still stopping after 30s (continuing)" -LogMessage "TermService still stopping after 30s; stop continues in the background"
                        if ($global:Error.Count -gt 0) { $global:Error.RemoveAt(0) }
                    }
                }
                # Note: TermService StartupType is left as-is (Manual) because changing
                # it to Disabled can break RDS licensing and other Windows subsystems.
            } catch {
                Write-Status -Level Warning -Tag RDP "Could not stop TermService: $($_.Exception.Message)"
            }
        } else {
            Write-Status -Level Skip -Tag RDP "SKIPPED (SkipRDP specified)" -LogMessage "RDP disable step skipped per -SkipRDP"
        }

        # -- 4. SSH (OpenSSH Server) -----------------------------------------
        if (-not $SkipSSH) {
            Write-Host ""
            Write-Status -Tag SSH "Checking for OpenSSH Server..."
            try {
                $svc = Get-Service -Name sshd -ErrorAction Ignore
                if ($svc) {
                    Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
                    Set-Service  -Name sshd -StartupType Disabled -ErrorAction Stop
                    Write-Status -Level Success -Tag SSH "OpenSSH Server stopped and disabled" -LogMessage "sshd service stopped and disabled"

                    if ($SkipFirewallRules) {
                        Write-Status -Level Skip -Tag SSH "Firewall rules left unchanged (-SkipFirewallRules)"
                    } else {
                        # Remove SSH firewall rule
                        $sshRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
                            Where-Object { $_.DisplayName -match 'SSH|OpenSSH' }
                        if ($sshRules) {
                            $sshRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                            Write-Status -Level Success -Tag SSH "Firewall rules removed ($($sshRules.Count) rule(s))" -LogMessage "Removed $($sshRules.Count) SSH firewall rule(s)"
                        }
                    }
                } else {
                    Write-Status -Tag SSH "OpenSSH Server not installed - skipping" -LogMessage "sshd service not found - SSH skip"
                }
            } catch {
                Write-Status -Level Warning -Tag SSH "$($_.Exception.Message)" -LogMessage "Could not disable sshd: $($_.Exception.Message)"
            }
        } else {
            Write-Status -Level Skip -Tag SSH "SKIPPED (SkipSSH specified)" -LogMessage "SSH disable step skipped per -SkipSSH"
        }

        # -- 5. Telnet Client ------------------------------------------------
        Write-Host ""
        Write-Status -Tag Telnet "Removing Telnet Client feature..."
        try {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue
            if ($feature -and $feature.State -eq 'Enabled') {
                Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart -ErrorAction Stop | Out-Null
                Write-Status -Level Success -Tag Telnet "Telnet Client removed" -LogMessage "Telnet Client feature removed"
            } else {
                Write-Status -Tag Telnet "Telnet Client not installed - skipping" -LogMessage "Telnet Client not installed"
            }
        } catch {
            Write-Status -Level Warning -Tag Telnet "$($_.Exception.Message)" -LogMessage "Could not remove Telnet Client: $($_.Exception.Message)"
        }

        Write-Host ""
        Write-Status -Level Success "Remote Management attack surface reduced." -LogMessage "Remove-RemoteManagement completed"
    }
}

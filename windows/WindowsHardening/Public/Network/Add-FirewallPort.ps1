#Requires -Version 5.1

# Add-FirewallPort.ps1 - Opens extra inbound ports on an already-hardened firewall,
# plus the shared rule helpers Set-FirewallConfiguration uses.

<#
.SYNOPSIS
    Returns a short description for a port from ports.json, or a fallback name.
#>
function Get-FirewallPortDescription {
    param([int]$Port)

    $portsData = $script:HardeningContext.Ports
    if ($null -ne $portsData -and $null -ne $portsData.ports -and $null -ne $portsData.ports."$Port") {
        return $portsData.ports."$Port".description
    }
    switch ($Port) {
        22   { "SSH" }
        53   { "DNS" }
        80   { "HTTP" }
        443  { "HTTPS" }
        3389 { "RDP" }
        5985 { "WinRM-HTTP" }
        5986 { "WinRM-HTTPS" }
        default { "Port-$Port" }
    }
}

<#
.SYNOPSIS
    Creates or re-enables the inbound "Allow <Protocol> <Port>" rule without duplicating it.
.DESCRIPTION
    If rules named "Allow <Protocol> <Port>" already exist (e.g. from an earlier run), the
    first is re-enabled and reset to Allow, and any extra copies are removed. Otherwise a new
    rule is created. Afterwards, warns about any enabled inbound Block rule covering the same
    port: in Windows Firewall a Block rule wins over an Allow rule, so the port stays closed.
    Returns 'Created' or 'Updated'.
#>
function Set-FirewallAllowRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [Parameter(Mandatory = $true)]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol
    )

    $displayName = "Allow $Protocol $Port"
    $existing = @(Get-NetFirewallRule -DisplayName $displayName -ErrorAction Ignore)

    if ($existing.Count -gt 0) {
        $existing[0] | Set-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop
        $existing[0] | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter -Protocol $Protocol -LocalPort $Port -ErrorAction Stop
        if ($existing.Count -gt 1) {
            $existing[1..($existing.Count - 1)] | Remove-NetFirewallRule -ErrorAction Stop
            Write-Status "Removed $($existing.Count - 1) duplicate '$displayName' rule(s)" -LogOnly
        }
        $status = 'Updated'
    } else {
        New-NetFirewallRule -DisplayName $displayName -Direction Inbound -LocalPort $Port -Action Allow -Protocol $Protocol -Enabled True -ErrorAction Stop | Out-Null
        $status = 'Created'
    }

    $blocking = @(
        Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True -ErrorAction Ignore |
            Where-Object {
                $filter = $_ | Get-NetFirewallPortFilter
                $protocolMatches = $filter.Protocol -eq 'Any' -or $filter.Protocol -eq $Protocol
                $portMatches = foreach ($localPort in @($filter.LocalPort)) {
                    if ($localPort -eq 'Any') { $true }
                    elseif ($localPort -match '^(\d+)-(\d+)$') { $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2] }
                    else { $localPort -eq "$Port" }
                }
                $protocolMatches -and ($portMatches -contains $true)
            }
    )
    foreach ($rule in $blocking) {
        $message = "Enabled Block rule '$($rule.DisplayName)' also matches $Protocol $Port and overrides the Allow rule"
        Write-Status -Level Warning "$message" -LogMessage $message
    }

    return $status
}

<#
.SYNOPSIS
    Opens additional inbound ports without resetting the rest of the firewall.

.DESCRIPTION
    Use this after Set-FirewallConfiguration / Invoke-WindowsHardening when a service turns
    out to need a port (a database, a web app on 8080, ...). Only the named ports are
    touched: existing "Allow <Protocol> <Port>" rules are re-enabled instead of duplicated,
    and enabled Block rules that would override the new rule are reported.

.PARAMETER Ports
    Ports to open ("1433, 8080", @("1433","8080"), or 1433,8080).

.PARAMETER Protocol
    TCP, UDP, or Both. Default matches Set-FirewallConfiguration: Both on a domain
    controller, TCP otherwise.

.EXAMPLE
    Add-FirewallPort -Ports 1433
    # Open SQL Server.

.EXAMPLE
    Add-FirewallPort -Ports "161" -Protocol UDP
    # Open SNMP.
#>
function Add-FirewallPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Ports,

        [ValidateSet('TCP', 'UDP', 'Both')]
        [string]$Protocol
    )

    $portList = ConvertTo-PortList -Ports $Ports
    if ($portList.Count -eq 0) {
        throw "No ports given"
    }

    Invoke-HardeningOperation -OperationName "Add Firewall Ports" -ScriptBlock {
        if (-not $Protocol) {
            $Protocol = if ($script:HardeningContext.OS.IsDomainController) { 'Both' } else { 'TCP' }
        }
        $protocols = if ($Protocol -eq 'Both') { @('TCP', 'UDP') } else { @($Protocol) }

        foreach ($port in ($portList | Sort-Object -Unique)) {
            $description = Get-FirewallPortDescription -Port $port
            foreach ($proto in $protocols) {
                $status = Set-FirewallAllowRule -Port $port -Protocol $proto
                Write-Status -Level Success -Tag ($status.ToUpper()) "Allow $proto $port ($description)" -LogMessage "$status inbound $proto rule for port $port ($description)"
            }
        }
    }
}

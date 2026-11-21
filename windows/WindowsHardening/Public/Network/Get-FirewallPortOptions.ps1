#Requires -Version 5.1

# Get-FirewallPortOptions.ps1 - The suggested firewall ports, as Read-Choice options.

function Get-FirewallPortOptions {
    <#
    .SYNOPSIS
        Returns the common scored-service and AD ports as Read-Choice options.
    .DESCRIPTION
        Each option's Key is the port number, so the user types ports directly. Labels
        show the description from ports.json and whether the port is a common scored
        service and/or needed for AD. On a domain controller the AD ports are marked
        Default = $true (the same set Set-FirewallConfiguration -NonInteractive allows).
    .PARAMETER IsDC
        Mark the AD ports as defaults.
    #>
    [CmdletBinding()]
    param(
        [switch]$IsDC
    )

    $scored = @(53, 3389, 80, 22)
    $adPorts = @(53, 139, 88, 67, 68, 135, 389, 445, 636, 3268, 3269, 464)
    $usual = @($scored + $adPorts) | Sort-Object -Unique

    foreach ($port in $usual) {
        $tags = @()
        if ($port -in $scored) { $tags += 'scored' }
        if ($port -in $adPorts) { $tags += 'AD' }
        @{
            Key     = "$port"
            Label   = "{0,-24} [{1}]" -f (Get-FirewallPortDescription -Port $port), ($tags -join ', ')
            Value   = $port
            Default = [bool]($IsDC -and $port -in $adPorts)
        }
    }
}

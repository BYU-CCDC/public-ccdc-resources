#Requires -Version 5.1

# Test-HostAddress.ps1 - True for an IPv4 address, an IPv6 address, or a host name.

function Test-HostAddress {
    <#
    .SYNOPSIS
        True when -Address is a dotted IPv4 address, an IPv6 address, or a DNS host name.
    .DESCRIPTION
        Stricter than [ipaddress]::TryParse, which accepts "10" (as 0.0.0.10) and other
        partial forms. A host name must contain a letter, so a partial address such as
        "10.0.0" is rejected instead of being treated as a name.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Address
    )

    $ip = $null
    if ($Address -match '^\d{1,3}(\.\d{1,3}){3}$') {
        return [ipaddress]::TryParse($Address, [ref]$ip)
    }
    if ($Address -match ':') {
        return [ipaddress]::TryParse($Address, [ref]$ip) -and $ip.AddressFamily -eq 'InterNetworkV6'
    }
    return ($Address -match '[A-Za-z]') -and
        ($Address -match '^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
}

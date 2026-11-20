#Requires -Version 5.1

# ConvertTo-PortList.ps1 - Parses -FirewallPorts input ("80, 443", @("80","443"), or 80,443)
# into validated integers. Throws on a non-numeric or out-of-range (1-65535) port.

function ConvertTo-PortList {
    [CmdletBinding()]
    param(
        [string[]]$Ports
    )

    $portStrings = @()
    foreach ($item in $Ports) {
        if (-not [string]::IsNullOrWhiteSpace($item)) {
            $portStrings += $item.Split(',') | ForEach-Object { $_.Trim() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        }
    }

    $result = @(
        foreach ($text in $portStrings) {
            $port = 0
            if (-not [int]::TryParse($text, [ref]$port)) {
                throw "Port '$text' is not a number"
            }
            if ($port -lt 1 -or $port -gt 65535) {
                throw "Port $port is out of valid range (1-65535)"
            }
            $port
        }
    )
    # Comma keeps a one-element array from being unrolled to a scalar.
    return ,$result
}

#Requires -Version 5.1

# Test-IsDomainController.ps1 - Raw DC probe (NTDS service present).

function Test-IsDomainController {
    <#
    .SYNOPSIS
        Raw DC probe (NTDS service present). Callers should read the cached
        (Get-OperatingSystemInfo).IsDomainController instead of calling this.
    #>
    [CmdletBinding()]
    param()
    try {
        $ntds = Get-Service -Name ntds -ErrorAction Ignore
        return $ntds -ne $null
    } catch {
        return $false
    }
}

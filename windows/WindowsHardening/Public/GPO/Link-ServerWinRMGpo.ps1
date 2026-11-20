function Link-ServerWinRMGpo {
    <#
    .SYNOPSIS
        Keeps WinRM firewall access available for selected server computer accounts.
    .DESCRIPTION
        Creates or updates a domain GPO with inbound TCP 5985/5986 access, scoped to the
        selected computers. The WinRM service itself is left in its current state.
        Same as Link-ServerServiceGpo -Role WinRM.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string[]]$ComputerName
    )

    Link-ServerServiceGpo -Role WinRM -ComputerName $ComputerName
}

function Link-SqlBrowserGpo {
    <#
    .SYNOPSIS
        Links the SQL Browser service firewall profile to selected domain computers.
    .DESCRIPTION
        Creates or updates a service-scoped SQLBrowser GPO. It is an optional profile and
        is not prompted for by Invoke-DomainHardening.
    .EXAMPLE
        Link-SqlBrowserGpo -ComputerName SQL01
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string[]]$ComputerName
    )

    Link-ServerServiceGpo -Role SQLBrowser -ComputerName $ComputerName
}

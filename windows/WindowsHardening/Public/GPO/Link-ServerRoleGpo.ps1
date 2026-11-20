function Link-ServerRoleGpo {
    <#
    .SYNOPSIS
        Imports and links the selected service-role GPO for the selected server computer accounts.
    .DESCRIPTION
        The role GPO is linked at the domain root with a computer-account security filter
        so only the named role servers receive it. The Web draft backup contains separate
        HTTP.sys-scoped TCP rules on 80/443 and automatic startup settings for IIS services.
        W3SVC has SID type NONE on supported builds, so Windows Firewall cannot match its
        traffic by service SID. Mail service and application access remain product-specific
        because Windows has no universal mail service identity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateSet('Web', 'Mail')][string]$Role,
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [Parameter(Mandatory=$true)][string]$BackupRoot
    )

    if (-not $ComputerName -or $ComputerName.Count -eq 0) { return }

    $gpoName = switch ($Role) {
        'Web'      { 'Web Servers Firewall Policy'; break }
        'Mail'     { 'Mail Servers Firewall Policy'; break }
    }

    Invoke-HardeningOperation -OperationName "Link $Role Server GPO" -TargetComputerName $ComputerName -ScriptBlock {
        Invoke-CcdcGpoLinkOperation -Name $gpoName -BackupRoot $BackupRoot `
            -Target (Get-CcdcDomainRootDn) -SecurityFilter $ComputerName
    }
}

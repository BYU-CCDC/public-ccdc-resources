function Link-DomainGpoUpdateInterval {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    Invoke-HardeningOperation -OperationName 'Link Domain GPO Update Interval' -ScriptBlock {
        Invoke-CcdcGpoLinkOperation -Name 'Domain GPO Update Interval' -BackupRoot $BackupRoot -Target (Get-CcdcDomainRootDn) -Enforced
    }
}

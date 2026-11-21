function Link-DomainGoodGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    Invoke-HardeningOperation -OperationName 'Link Domain Good-GPO' -ScriptBlock {
        $target = Get-CcdcDomainRootDn
        $commonName = 'CCDC v1 Domain Common Baseline'
        Import-CcdcGpo -Name $commonName -BackupRoot $BackupRoot | Out-Null
        Add-CcdcGpoLink -Name $commonName -Target $target -Enforced
        $defenderName = 'CCDC v1 Defender Baseline'
        Import-CcdcGpo -Name $defenderName -BackupRoot $BackupRoot | Out-Null
        Add-CcdcGpoLink -Name $defenderName -Target $target -Enforced
    }
}

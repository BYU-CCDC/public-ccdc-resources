function Link-DomainAuditGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    Invoke-HardeningOperation -OperationName 'Link Domain Audit Baseline GPO' -ScriptBlock {
        $gpoName = 'CCDC v1 Domain Audit'
        $gpo = Import-CcdcGpo -Name $gpoName -BackupRoot $BackupRoot
        # Register the draft's advanced audit CSV with the native Audit Configuration CSE.
        Set-CcdcGpoAdvancedAuditPolicy -GpoName $gpo.DisplayName
        Add-CcdcGpoLink -Name $gpo.DisplayName -Target (Get-CcdcDomainRootDn) -Enforced

        Write-Status -Level Success "Imported and linked '$gpoName' at the domain root" `
            -LogMessage "Imported and linked draft GPO '$gpoName' at the domain root"
    }
}

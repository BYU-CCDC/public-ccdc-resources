function Link-DcAllowAdGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    Invoke-HardeningOperation -OperationName 'Link Domain Controller Baseline' -ScriptBlock {
        $baselineName = 'CCDC Domain Controller Baseline'
        # Static LDAP settings, Kerberos rules, and DFSR rules are carried by the draft.
        $gpo = Import-CcdcGpo -Name 'DC Allow AD' -BackupRoot $BackupRoot -TargetName $baselineName
        # Enumerate every DC, link to each parent OU, and security-filter to the built-in
        # Domain Controllers group. This also protects non-DC computers if a DC shares an OU.
        $targets = Get-CcdcDomainControllersOu
        foreach ($target in $targets) {
            Add-CcdcGpoLink -Name $baselineName -Target $target `
                -SecurityFilterGroup @('Domain Controllers') -Enforced
        }

        # Retire links left by earlier runs of the separate firewall-only GPO after the
        # merged baseline is in place. The pre-hardening GPO backup preserves the old GPO.
        $legacyGpo = Get-GPO -Name 'DC Allow AD' -ErrorAction Ignore
        if ($legacyGpo) {
            foreach ($target in $targets) {
                $inheritance = Get-GPInheritance -Target $target -ErrorAction Stop
                if (@($inheritance.GpoLinks | Where-Object DisplayName -eq 'DC Allow AD').Count -gt 0) {
                    Remove-GPLink -Name 'DC Allow AD' -Target $target -Confirm:$false -ErrorAction Stop
                }
            }
            Remove-GPO -Name 'DC Allow AD' -Confirm:$false -ErrorAction Stop
        }
        Write-Status -Level Success "Linked '$baselineName' to $($targets.Count) DC OU(s), filtered to all Domain Controllers" `
            -LogMessage "Imported and linked merged DC baseline to: $($targets -join '; ')"
    }
}

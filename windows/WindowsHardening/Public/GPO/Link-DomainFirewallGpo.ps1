function Link-DomainFirewallGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    Invoke-HardeningOperation -OperationName 'Link Domain Firewall GPO' -ScriptBlock {
        $gpoName = 'Domain Allow AD + Core + Default Block'
        # Applies to every computer, DCs included; the combined DC baseline adds DC rules.
        # The explicit filter also undoes the Domain Computers-only filter of older runs.
        Invoke-CcdcGpoLinkOperation -Name $gpoName -BackupRoot $BackupRoot `
            -Target (Get-CcdcDomainRootDn) -SecurityFilterGroup @('Authenticated Users') -Enforced

        # The bundled baseline previously allowed general web egress to every computer.
        # Keep browsing opt-in through Link-WebBrowsingGpo instead.
        Remove-CcdcBroadWebEgress

    }
}

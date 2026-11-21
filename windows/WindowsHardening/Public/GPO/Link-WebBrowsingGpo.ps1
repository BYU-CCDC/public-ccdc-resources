function Link-WebBrowsingGpo {
    <#
    .SYNOPSIS
        Allows outbound HTTP and HTTPS from selected or all domain computers.
    .DESCRIPTION
        Imports the draft outbound-web policy backup and links it to selected computers
        or to all domain computers. DNS remains governed by the domain baseline.
    .PARAMETER ComputerName
        Domain computer accounts that need web browsing when -AllDomainComputers is not used.
    .PARAMETER AllDomainComputers
        Applies the GPO at the domain root to Domain Computers and Domain Controllers.
    .EXAMPLE
        Link-WebBrowsingGpo -BackupRoot C:\GPO-v1\expanded-draft-package\Backups -AllDomainComputers
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$BackupRoot,
        [string[]]$ComputerName = @(),
        [switch]$AllDomainComputers
    )

    if (-not $AllDomainComputers -and (-not $ComputerName -or $ComputerName.Count -eq 0)) {
        throw 'Supply -ComputerName or use -AllDomainComputers.'
    }

    $targetComputerNames = if ($AllDomainComputers) { @() } else { $ComputerName }
    Invoke-HardeningOperation -OperationName 'Link Web Browsing GPO' -TargetComputerName $targetComputerNames -ScriptBlock {
        foreach ($moduleName in @('ActiveDirectory', 'GroupPolicy', 'NetSecurity')) {
            if (-not (Get-Module -Name $moduleName)) { Import-Module $moduleName -ErrorAction Stop }
        }

        Remove-CcdcBroadWebEgress

        $gpoName = 'CCDC v1 Web Browsing Outbound'
        $gpo = Import-CcdcGpo -Name $gpoName -BackupRoot $BackupRoot
        if ($AllDomainComputers) {
            Add-CcdcGpoLink -Name $gpo.DisplayName -Target (Get-CcdcDomainRootDn) `
                -SecurityFilterGroup @('Domain Computers', 'Domain Controllers') -Enforced
            Write-Status -Level Success "Imported and linked '$($gpo.DisplayName)' for all domain computers and domain controllers" `
                -LogMessage "Imported '$gpoName' and linked it at the domain root for Domain Computers and Domain Controllers"
        } else {
            Add-CcdcGpoLink -Name $gpo.DisplayName -Target (Get-CcdcDomainRootDn) -SecurityFilter $ComputerName
            Write-Status -Level Success "Imported '$gpoName' and linked it for $($ComputerName -join ', ')" `
                -LogMessage "Imported '$gpoName' and linked to selected computers: $($ComputerName -join ', ')"
        }
    }
}

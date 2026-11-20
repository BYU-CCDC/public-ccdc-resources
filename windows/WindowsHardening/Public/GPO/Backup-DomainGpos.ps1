function Backup-DomainGpos {
    <#
    .SYNOPSIS
        Backs up all current domain GPOs and records where they are linked.
    .DESCRIPTION
        Creates a timestamped Group Policy backup before Invoke-DomainHardening
        changes or links GPOs. The GPO backup can be used with Restore-GPO. A JSON
        inventory records GPO links, order, enabled state, and enforcement for
        the domain root and every OU.
    .PARAMETER Path
        Parent directory for the timestamped backup folder. Defaults to the
        current hardening log directory.
    #>
    [CmdletBinding()]
    param(
        [string]$Path
    )

    if (-not (Get-Module -Name GroupPolicy)) {
        Import-Module GroupPolicy -ErrorAction Stop
    }
    if (-not (Get-Module -Name ActiveDirectory)) {
        Import-Module ActiveDirectory -ErrorAction Stop
    }

    if (-not $Path) {
        $Path = $script:HardeningContext.LogPath
    }
    if (-not $Path) {
        throw 'No GPO backup path was provided and the hardening log path is unavailable.'
    }

    $backupPath = Join-Path $Path "DomainGPOBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -Path $backupPath -ItemType Directory -Force -ErrorAction Stop | Out-Null

    Write-Status "Backing up all domain GPOs to $backupPath"
    $backedUpGpos = @(Backup-GPO -All -Path $backupPath `
        -Comment "Pre-hardening backup created by Invoke-DomainHardening on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')" `
        -ErrorAction Stop)
    if ($backedUpGpos.Count -eq 0) {
        Write-Status -Level Warning 'The domain contains no GPOs to back up' -LogMessage "No GPOs were returned by Backup-GPO; backup directory: $backupPath"
    } else {
        Write-Status -Level Success "Backed up $($backedUpGpos.Count) domain GPO(s) to $backupPath"
    }

    # Backup-GPO saves policy settings, but GPO link placement and link options
    # are domain/OU properties. Capture them separately to support rollback.
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $targets = @($domain.DistinguishedName)
        $targets += @(Get-ADOrganizationalUnit -Filter * -SearchBase $domain.DistinguishedName `
            -SearchScope Subtree -ErrorAction Stop | Select-Object -ExpandProperty DistinguishedName)

        $linkInventory = foreach ($target in $targets) {
            $inheritance = Get-GPInheritance -Target $target -ErrorAction Stop
            foreach ($link in @($inheritance.GpoLinks)) {
                [PSCustomObject]@{
                    Target          = $target
                    GpoId           = [string]$link.GpoId
                    DisplayName     = $link.DisplayName
                    Enabled         = $link.Enabled
                    Enforced        = $link.Enforced
                    Order           = $link.Order
                }
            }
        }
        $manifest = [PSCustomObject]@{
            Created       = (Get-Date).ToString('o')
            Domain        = $domain.DNSRoot
            BackupPath    = $backupPath
            GpoCount      = $backedUpGpos.Count
            GpoLinks      = @($linkInventory)
        }
        $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $backupPath 'DomainGpoLinks.json') `
            -Encoding UTF8 -ErrorAction Stop
        Write-Status -Level Success "Saved domain GPO link inventory to $(Join-Path $backupPath 'DomainGpoLinks.json')"
    } catch {
        Write-Status -Level Warning "Could not save the GPO link inventory (GPO contents are backed up): $($_.Exception.Message)" `
            -LogMessage "GPO link inventory failed for $backupPath : $($_.Exception.Message)"
    }

    return $backupPath
}

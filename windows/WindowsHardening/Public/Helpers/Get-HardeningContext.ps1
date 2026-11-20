#Requires -Version 5.1

# Get-HardeningContext.ps1 - Snapshot of the module's hardening context.

function Get-HardeningContext {
    <#
    .SYNOPSIS
        Returns a snapshot of the module's current hardening context (DC status, OS,
        log path, etc.; DC status is OS.IsDomainController) as populated by Initialize-System / Initialize-Context.
    #>
    [CmdletBinding()]
    param()
    [PSCustomObject]$script:HardeningContext.Clone()
}

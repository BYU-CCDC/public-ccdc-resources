function Add-DomainFirewallPortRule {
    <#
    .SYNOPSIS
        Adds or updates a named firewall allow rule in a computer-targeted domain GPO.
    .DESCRIPTION
        Imports a draft firewall-exception template as one GPO per rule name, links it
        at the domain root, and filters it to the specified computer accounts. Use this for ports that must survive the
        domain firewall policy's disabled local-policy merge.
    .PARAMETER Port
        Ports and ranges, for example 5432, '50000-50100', or 21, '50000-50100'.
        For inbound rules these are local ports; for outbound rules, remote ports.
    .EXAMPLE
        Add-DomainFirewallPortRule -Name 'FileZilla' -ComputerName FTP01 -Port 21, '50000-50100'
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 _.-]{0,39}$')][string]$Name,
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [Parameter(Mandatory=$true)][ValidateScript({ Test-CcdcPortSpec $_ })][string[]]$Port,
        [ValidateSet('TCP','UDP')][string]$Protocol = 'TCP',
        [ValidateSet('Inbound','Outbound')][string]$Direction = 'Inbound',
        [string[]]$RemoteAddress = @('Any')
    )

    if (-not $ComputerName -or @($ComputerName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
        throw 'Specify at least one computer account in -ComputerName.'
    }
    $gpoName = "CCDC Port Rule - $Name"
    $ruleName = 'CCDC-Port-' + ($Name -replace '[^A-Za-z0-9_.-]', '-')
    if ($PSCmdlet.ShouldProcess("$($ComputerName -join ', ') / $gpoName", "Add $Direction $Protocol port(s) $($Port -join ',')")) {
      Invoke-HardeningOperation -OperationName "Add Domain Firewall Port Rule '$Name'" -TargetComputerName $ComputerName -ScriptBlock {
        foreach ($moduleName in @('ActiveDirectory', 'GroupPolicy', 'NetSecurity')) {
            if (-not (Get-Module -Name $moduleName)) { Import-Module $moduleName -ErrorAction Stop }
        }
        $domain = Get-ADDomain -ErrorAction Stop
        $policyStore = "$($domain.DNSRoot)\$gpoName"
        $target = $domain.DistinguishedName
        if (-not $script:CcdcGpoActiveBackupRoot) { throw 'The draft GPO backup root is not initialized.' }
        $gpo = Import-CcdcGpo -Name 'CCDC v1 Custom Firewall Port Exception' `
            -BackupRoot $script:CcdcGpoActiveBackupRoot -TargetName $gpoName
        $existingRule = Get-NetFirewallRule -PolicyStore $policyStore -Name $ruleName -ErrorAction Ignore
        if ($existingRule) {
            Remove-NetFirewallRule -PolicyStore $policyStore -Name $ruleName -ErrorAction Stop
        }

        $ruleParams = @{
            PolicyStore = $policyStore
            Name = $ruleName
            DisplayName = $Name
            Description = "CCDC domain firewall exception; computer scope: $($ComputerName -join ', ')"
            Direction = $Direction
            Action = 'Allow'
            Protocol = $Protocol
            Profile = 'Domain'
            RemoteAddress = $RemoteAddress
            Enabled = 'True'
            ErrorAction = 'Stop'
        }
        if ($Direction -eq 'Inbound') {
            $ruleParams.LocalPort = @($Port | ForEach-Object { $_ -replace '\s', '' })
        } else {
            $ruleParams.RemotePort = @($Port | ForEach-Object { $_ -replace '\s', '' })
        }
        New-NetFirewallRule @ruleParams | Out-Null

        Add-CcdcGpoLink -Name $gpo.DisplayName -Target $target -SecurityFilter $ComputerName
        Write-Status -Level Success "Added '$Name' ($Direction $Protocol $($Port -join ',')) for $($ComputerName -join ', ')" `
            -LogMessage "Added domain firewall exception '$Name' in '$gpoName' for $($ComputerName -join ', ')"
      }
    }
}

function Remove-DomainFirewallPortRule {
    <#
    .SYNOPSIS
        Removes a named domain firewall port rule and its dedicated GPO link.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 _.-]{0,39}$')][string]$Name
    )

    $gpoName = "CCDC Port Rule - $Name"
    $ruleName = 'CCDC-Port-' + ($Name -replace '[^A-Za-z0-9_.-]', '-')
    foreach ($moduleName in @('ActiveDirectory', 'GroupPolicy')) {
        if (-not (Get-Module -Name $moduleName)) { Import-Module $moduleName -ErrorAction Stop }
    }
    $gpo = Get-GPO -Name $gpoName -ErrorAction Ignore
    if (-not $gpo) {
        Write-Status -Level Skip "No domain port rule named '$Name' exists" -LogMessage "No GPO '$gpoName' found to remove"
        return
    }

    if ($PSCmdlet.ShouldProcess($gpoName, "Remove port rule '$Name' and its domain link")) {
        Invoke-HardeningOperation -OperationName "Remove Domain Firewall Port Rule '$Name'" -ScriptBlock {
            if (-not (Get-Module -Name NetSecurity)) { Import-Module NetSecurity -ErrorAction Stop }
            $domain = Get-ADDomain -ErrorAction Stop
            $policyStore = "$($domain.DNSRoot)\$gpoName"
            Remove-NetFirewallRule -PolicyStore $policyStore -Name $ruleName -ErrorAction SilentlyContinue
            $inheritance = Get-GPInheritance -Target $domain.DistinguishedName -ErrorAction Stop
            if (@($inheritance.GpoLinks | Where-Object DisplayName -eq $gpoName).Count -gt 0) {
                Remove-GPLink -Name $gpoName -Target $domain.DistinguishedName -Confirm:$false -ErrorAction Stop | Out-Null
            }
            Remove-GPO -Name $gpoName -ErrorAction Stop
            Write-Status -Level Success "Removed domain firewall rule '$Name'" -LogMessage "Removed port rule GPO '$gpoName'"
        }
    }
}

function Test-CcdcPortSpec {
    # ValidateScript helper: accepts a port (N) or an inclusive range (N-M) within 1-65535.
    param([string]$Spec)

    $value = $Spec -replace '\s', ''
    if ($value -notmatch '^(\d{1,5})(?:-(\d{1,5}))?$') {
        throw "'$Spec' is not a port or range; use a number like 5432 or a range like 50000-50100."
    }
    $low = [int]$Matches[1]
    $high = if ($Matches[2]) { [int]$Matches[2] } else { $low }
    if ($low -lt 1 -or $high -gt 65535) { throw "'$Spec' is outside 1-65535." }
    if ($low -gt $high) { throw "'$Spec' has its low port above its high port." }
    $true
}

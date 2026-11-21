function Link-DomainSplunkOutboundGpo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$BackupRoot,
        [Parameter(Mandatory=$true)][string]$SplunkIP
    )

    $splunkRemoteAddresses = @(Resolve-CcdcFirewallRemoteAddress -HostNameOrAddress $SplunkIP)

    $draftName = 'CCDC v1 Splunk Outbound'
    $backupFolder = $null
    foreach ($folder in Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction Stop | Where-Object Name -like '{*') {
        $metadataPath = Join-Path $folder.FullName 'Backup.xml'
        if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) { continue }
        try { [xml]$metadata = Get-Content -LiteralPath $metadataPath -Raw -ErrorAction Stop } catch { continue }
        $metadataName = $metadata.SelectSingleNode("//*[local-name()='DisplayName']")
        if ($metadataName -and $metadataName.InnerText -eq $draftName) { $backupFolder = $folder; break }
    }
    if (-not $backupFolder) { throw "Draft package has no backup for GPO '$draftName'." }
    $reportPath = Join-Path $backupFolder.FullName 'gpreport.xml'
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        throw "Splunk draft backup '$draftName' is missing gpreport.xml; refusing to import or link it."
    }
    try { [xml]$backupReport = Get-Content -LiteralPath $reportPath -Raw -ErrorAction Stop }
    catch { throw "Splunk draft backup '$draftName' has an invalid gpreport.xml: $($_.Exception.Message)" }
    $draftRemotePorts = @($backupReport.SelectNodes(
        "//*[local-name()='OutboundFirewallRules'][*[local-name()='Protocol']='6']/*[local-name()='RPort']") |
        ForEach-Object { $_.InnerText } | Sort-Object -Unique)
    $expectedDraftPorts = @('9997', '8000')
    $missingDraftPorts = @($expectedDraftPorts | Where-Object { $_ -notin $draftRemotePorts })
    if ($missingDraftPorts.Count -gt 0) {
        throw "Splunk draft backup '$draftName' lacks outbound TCP rule(s) for port(s) $($missingDraftPorts -join ', '); refusing to import or link it."
    }

    Invoke-HardeningOperation -OperationName 'Link Domain Splunk Outbound GPO' -ScriptBlock {
        $stage = 'resolve domain root'
        try {
            $target = Get-CcdcDomainRootDn
            $gpoName = 'Domain Splomk'
            $domain = Get-ADDomain -ErrorAction Stop

            $stage = "import draft GPO '$gpoName'"
            $gpo = Import-CcdcGpo -Name $gpoName -BackupRoot $BackupRoot -Server $domain.PDCEmulator
            $policyStore = "$($domain.DNSRoot)\$gpoName"

            $stage = "read imported firewall rules from '$policyStore'"
            $firewallRegistryKey = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules'
            $policyValues = @(Get-GPRegistryValue -Name $gpoName -Key $firewallRegistryKey `
                -Server $domain.PDCEmulator -ErrorAction Stop)
            $rulesByPort = @{ '9997' = @(); '8000' = @() }
            foreach ($policyValue in $policyValues) {
                if ($policyValue.Type -ne 'String' -or -not $policyValue.HasValue) { continue }
                $ruleData = ([string]$policyValue.Value).TrimEnd([char]0)
                if ($ruleData -notmatch '(^|\|)Dir=Out(\||$)' -or
                    $ruleData -notmatch '(^|\|)Protocol=6(\||$)') { continue }
                foreach ($port in @('9997', '8000')) {
                    if ($ruleData -match ('(^|\|)RPort=' + [regex]::Escape($port) + '(\||$)')) {
                        $rulesByPort[$port] += [pscustomobject]@{
                            ValueName = $policyValue.ValueName
                            Data = $ruleData
                        }
                    }
                }
            }

            foreach ($port in @('9997', '8000')) {
                if ($rulesByPort[$port].Count -ne 1) {
                    throw "Imported Splunk GPO must contain exactly one outbound TCP rule for port $port; found $($rulesByPort[$port].Count)."
                }
            }

            $ipAddresses = @($splunkRemoteAddresses | ForEach-Object { [System.Net.IPAddress]::Parse($_) })
            $ipv4Addresses = @($ipAddresses | Where-Object AddressFamily -eq ([System.Net.Sockets.AddressFamily]::InterNetwork) | ForEach-Object ToString)
            $ipv6Addresses = @($ipAddresses | Where-Object AddressFamily -eq ([System.Net.Sockets.AddressFamily]::InterNetworkV6) | ForEach-Object ToString)
            # The firewall policy stores IPv4 and IPv6 remote scopes independently. Use
            # a loopback entry for an absent address family so it cannot
            # accidentally retain the draft's default Any scope.
            if ($ipv4Addresses.Count -eq 0) { $ipv4Addresses = @('127.0.0.1') }
            if ($ipv6Addresses.Count -eq 0) { $ipv6Addresses = @('::1') }
            $remoteAddressFields = @(
                ('RA4=' + ($ipv4Addresses -join ',')),
                ('RA6=' + ($ipv6Addresses -join ','))
            )

            foreach ($port in @('9997', '8000')) {
                $policyRule = $rulesByPort[$port][0]
                $stage = "scope imported TCP $port firewall rule '$($policyRule.ValueName)'"
                $ruleData = [regex]::Replace($policyRule.Data, '\|RA[46]=[^|]*', '')
                $nameFieldIndex = $ruleData.IndexOf('|Name=', [System.StringComparison]::Ordinal)
                if ($nameFieldIndex -lt 0) {
                    throw "Imported firewall rule '$($policyRule.ValueName)' has no Name field."
                }
                $scopedRuleData = $ruleData.Insert($nameFieldIndex, '|' + ($remoteAddressFields -join '|'))
                Set-GPRegistryValue -Name $gpoName -Key $firewallRegistryKey `
                    -ValueName $policyRule.ValueName -Type String -Value $scopedRuleData `
                    -Server $domain.PDCEmulator -ErrorAction Stop | Out-Null

                $stage = "verify imported TCP $port firewall rule '$($policyRule.ValueName)'"
                $verifiedValue = Get-GPRegistryValue -Name $gpoName -Key $firewallRegistryKey `
                    -ValueName $policyRule.ValueName -Server $domain.PDCEmulator -ErrorAction Stop
                $verifiedData = ([string]$verifiedValue.Value).TrimEnd([char]0)
                foreach ($field in $remoteAddressFields) {
                    if ($verifiedData -notmatch ('(^|\|)' + [regex]::Escape($field) + '(\||$)')) {
                        throw "Imported firewall rule '$($policyRule.ValueName)' did not retain runtime scope '$field'."
                    }
                }
                $policyRuleObject = Get-NetFirewallRule -PolicyStore $policyStore `
                    -Name $policyRule.ValueName -ErrorAction Stop
                $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $policyRuleObject `
                    -PolicyStore $policyStore -ErrorAction Stop
                $actualAddresses = @($addressFilter.RemoteAddress | ForEach-Object { [string]$_ } | Sort-Object -Unique)
                $expectedAddresses = @($splunkRemoteAddresses | Sort-Object -Unique)
                if (@(Compare-Object -ReferenceObject $expectedAddresses -DifferenceObject $actualAddresses).Count -gt 0) {
                    throw "Imported firewall rule '$($policyRule.ValueName)' has remote scope '$($actualAddresses -join ', ')'; expected '$($expectedAddresses -join ', ')'."
                }
            }

            $stage = "link and security-filter GPO '$gpoName'"
            Add-CcdcGpoLink -Name $gpo.DisplayName -Target $target `
                -SecurityFilterGroup @('Domain Computers', 'Domain Controllers') -Enforced
            Write-Status -Level Success "Scoped imported Splunk outbound TCP 9997 and 8000 to $($splunkRemoteAddresses -join ', ')" `
                -LogMessage "Splunk outbound GPO remote addresses: $($splunkRemoteAddresses -join ', ')"
        } catch {
            Write-Status -Level Error "Splunk GPO stage '$stage' failed" `
                -LogMessage "Splunk GPO stage '$stage' failed: $($_.Exception.Message)"
            throw
        }
    }
}

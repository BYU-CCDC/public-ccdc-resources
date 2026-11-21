#Requires -Version 5.1

function Mitigate-ZeroLogon {
    <#
    .SYNOPSIS
        Restricts inbound TCP RPC allow rules to the local subnet.

    .DESCRIPTION
        Finds inbound allow rules whose local port filter includes the RPC alias.
        Rules that also allow other local ports are split so those ports remain
        allowed with the original rule settings. The RPC rule is recreated for
        TCP with its remote address limited to LocalSubnet (IPv4 and IPv6).
    #>
    [CmdletBinding()]
    param()

    Invoke-HardeningOperation -OperationName "Mitigate ZeroLogon" -ScriptBlock {
        $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction Stop)
        $rpcRules = @(
            foreach ($rule in $rules) {
                $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
                $protocol = [string]$portFilter.Protocol
                $hasRpc = @($portFilter.LocalPort | Where-Object { [string]$_ -ieq 'RPC' }).Count -gt 0

                # The GPO rule uses TCP RPC. Include protocol Any since those rules
                # also permit TCP RPC and need the RPC portion narrowed to TCP.
                if ($hasRpc -and ($protocol -in @('6', 'TCP', 'Any', '-1', '256'))) {
                    [pscustomobject]@{
                        Rule        = $rule
                        PortFilter  = $portFilter
                        Protocol    = $protocol
                        LocalPorts  = @($portFilter.LocalPort | ForEach-Object { [string]$_ })
                    }
                }
            }
        )

        if ($rpcRules.Count -eq 0) {
            Write-Status -Level Success "No inbound allow rules for TCP RPC were found" -LogOnly
            return
        }

        foreach ($entry in $rpcRules) {
            $rule = $entry.Rule
            $portFilter = $entry.PortFilter
            $localPorts = @($entry.LocalPorts)
            $otherPorts = @($localPorts | Where-Object { $_ -ine 'RPC' })
            $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
            $applicationFilter = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
            $serviceFilter = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
            $interfaceFilter = $rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
            $securityFilter = $rule | Get-NetFirewallSecurityFilter -ErrorAction Stop

            $commonRuleParameters = @{
                Direction     = 'Inbound'
                Action        = 'Allow'
                Enabled       = $rule.Enabled
                Profile       = $rule.Profile
                LocalAddress  = @($addressFilter.LocalAddress)
                Program       = $applicationFilter.Program
                Service       = $serviceFilter.Service
                InterfaceType = @($interfaceFilter.InterfaceType)
                Description   = $rule.Description
                EdgeTraversalPolicy = $rule.EdgeTraversalPolicy
                LooseSourceMapping = $rule.LooseSourceMapping
                LocalOnlyMapping = $rule.LocalOnlyMapping
                Authentication = $securityFilter.Authentication
                Encryption = $securityFilter.Encryption
                OverrideBlockRules = $securityFilter.OverrideBlockRules
            }
            # The user/machine security filters are scalar SDDL strings. Wrapping
            # them in @() creates Object[], which Windows PowerShell 5.1 cannot bind.
            if ($securityFilter.LocalUser) {
                $commonRuleParameters['LocalUser'] = [string]$securityFilter.LocalUser
            }
            if ($securityFilter.RemoteUser) {
                $commonRuleParameters['RemoteUser'] = [string]$securityFilter.RemoteUser
            }
            if ($securityFilter.RemoteMachine) {
                $commonRuleParameters['RemoteMachine'] = [string]$securityFilter.RemoteMachine
            }

            # Preserve the non-RPC ports in their own rule before removing the
            # original. Keep its protocol and address filters, including narrower
            # remote-address restrictions that may already be in place.
            if ($otherPorts.Count -gt 0) {
                $residualParameters = $commonRuleParameters.Clone()
                $residualParameters['Name'] = 'ZeroLogon-Preserved-' + [guid]::NewGuid().ToString('N')
                $residualParameters['DisplayName'] = "$($rule.DisplayName) (non-RPC ports preserved)"
                $residualParameters['Group'] = 'WindowsHardening ZeroLogon Mitigation'
                $residualParameters['Protocol'] = $entry.Protocol
                $residualParameters['LocalPort'] = $otherPorts
                $residualParameters['RemotePort'] = @($portFilter.RemotePort)
                $residualParameters['RemoteAddress'] = @($addressFilter.RemoteAddress)
                $null = New-NetFirewallRule @residualParameters -ErrorAction Stop
            }

            $rpcParameters = $commonRuleParameters.Clone()
            $rpcParameters['Name'] = 'ZeroLogon-RPC-' + [guid]::NewGuid().ToString('N')
            $rpcParameters['DisplayName'] = "$($rule.DisplayName) (RPC local subnet only)"
            $rpcParameters['Group'] = 'WindowsHardening ZeroLogon Mitigation'
            $rpcParameters['Protocol'] = 'TCP'
            $rpcParameters['LocalPort'] = 'RPC'
            $rpcParameters['RemotePort'] = @($portFilter.RemotePort)
            $rpcParameters['RemoteAddress'] = 'LocalSubnet'
            $null = New-NetFirewallRule @rpcParameters -ErrorAction Stop

            $rule | Remove-NetFirewallRule -ErrorAction Stop
            Write-Status -Level Success "Restricted RPC allow rule '$($rule.DisplayName)' to the local subnet"
        }
    }
}

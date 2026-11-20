function Set-RestrictedExecutionPolicy {
    <#
    .SYNOPSIS
        Sets the machine-wide (LocalMachine) execution policy to Restricted.
    .DESCRIPTION
        LocalMachine scope persists after this session ends. A session started with
        -ExecutionPolicy Bypass keeps running under its Process-scope override, so the
        module can finish; new sessions get Restricted. Group Policy or a CurrentUser
        policy still take precedence over LocalMachine and are reported as warnings.
    #>
    [CmdletBinding()]
    param()

    Invoke-HardeningOperation -OperationName "Set Execution Policy" -ScriptBlock {
        try {
            Set-ExecutionPolicy Restricted -Scope LocalMachine -Force -ErrorAction Stop
        } catch {
            # The value is saved, but a more specific scope (e.g. -ExecutionPolicy Bypass on
            # this session) overrides it for now. Anything else is a real failure.
            if ($_.FullyQualifiedErrorId -notlike 'ExecutionPolicyOverride*') {
                Write-Status -Level Error "Failed to set Execution Policy: $($_.Exception.Message)"
                throw
            }
            # Expected; drop it from $Error so it is not reported as a failure in hard.txt.
            # Inside a module, $Error is module-scoped; the record lands in $global:Error.
            $global:Error.RemoveAt(0)
        }

        $machinePolicy = Get-ExecutionPolicy -Scope LocalMachine
        if ($machinePolicy -ne 'Restricted') {
            throw "LocalMachine execution policy is '$machinePolicy' after setting Restricted"
        }

        foreach ($scope in 'MachinePolicy', 'UserPolicy', 'CurrentUser') {
            $policy = Get-ExecutionPolicy -Scope $scope
            if ($policy -ne 'Undefined' -and $policy -ne 'Restricted') {
                $message = "Execution policy '$policy' at scope $scope overrides the LocalMachine Restricted setting"
                Write-Status -Level Warning "$message" -LogMessage $message
            }
        }

        Write-Status -Level Success "Execution Policy set to Restricted (LocalMachine)" -LogMessage "Set LocalMachine Execution Policy to Restricted"
    }
}

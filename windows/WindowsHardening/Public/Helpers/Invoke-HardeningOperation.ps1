#Requires -Version 5.1

# Invoke-HardeningOperation.ps1 - The runner every hardening step executes inside.

function Invoke-HardeningOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OperationName,

        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,

        [string[]]$OSCompatibility = @(),

        [string]$ProgressMessage = "",

        [string[]]$TargetComputerName = @()
    )

    # Step label (e.g. "Users 2/6") set by the calling orchestrator via
    # $script:NextStepLabel, for this operation only. Taken before Initialize-System,
    # whose own "Initialize Context" operation must not pick it up.
    $stepLabel = $script:NextStepLabel
    $script:NextStepLabel = $null

    Initialize-System

    $script:OperationResults.Total++
    $header = if ($stepLabel) { "[$stepLabel] $OperationName" } else { "[EXECUTING] $OperationName..." }

    # Check OS compatibility
    if ($OSCompatibility.Count -gt 0) {
        if ($script:HardeningContext.OS.OSFamily -notin $OSCompatibility) {
            $message = "Operation '$OperationName' is not compatible with $($script:HardeningContext.OS.OSVersion) (OS Family: $($script:HardeningContext.OS.OSFamily))"
            Write-Host "`n$header" -ForegroundColor Cyan
            Write-Status -Level Skip $message
            $script:OperationResults.Skipped++
            $script:OperationResults.Warnings += "[SKIPPED] $message"
            Set-OperationStatus $OperationName "Skipped - OS incompatible ($($script:HardeningContext.OS.OSFamily))"
            return
        }
    }

    try {
        Write-Host "`n$header" -ForegroundColor Cyan
        Write-Status -LogOnly "Starting operation: $OperationName$(if ($stepLabel) { " ($stepLabel)" })"
        if ($ProgressMessage) {
            Write-Status $ProgressMessage
        }
        if ($TargetComputerName.Count -gt 0) {
            Write-Status "Applying configuration for $($TargetComputerName -join ', ')..." -NoLog
        } elseif ($script:HardeningContext.OS) {
            Write-Status "Applying configuration for $($script:HardeningContext.OS.OSVersion)..." -NoLog
        }

        & $ScriptBlock

        Write-Status -Level Success "$OperationName completed successfully"
        $script:OperationResults.Successful++
        Set-OperationStatus $OperationName "Executed successfully"

    } catch [System.OperationCanceledException] {
        # A step throws OperationCanceledException when the user backs out of it (e.g. Q at
        # a prompt): that is a skip, not a failure.
        Write-Status -Level Skip "$OperationName : $($_.Exception.Message)"
        $script:OperationResults.Skipped++
        Set-OperationStatus $OperationName "Skipped - $($_.Exception.Message)"
    } catch {
        Write-Status -Level Error "$OperationName : $($_.Exception.Message)"
        Write-Status -Level Error -Tag 'ERROR DETAILS' "Exception Type: $($_.Exception.GetType().FullName)"
        if ($_.Exception.InnerException) {
            Write-Status -Level Error -Tag 'ERROR DETAILS' "Inner Exception: $($_.Exception.InnerException.Message)"
        }

        $script:OperationResults.Failed++
        Set-OperationStatus $OperationName "Failed with error: $($_.Exception.Message)"
    }
}

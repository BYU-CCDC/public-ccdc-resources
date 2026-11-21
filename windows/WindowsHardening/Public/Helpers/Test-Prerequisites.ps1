#Requires -Version 5.1

# Test-Prerequisites.ps1 - Pre-flight checks: administrator rights (required), OS and PowerShell version (warnings).

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Pre-flight checks. Throws if not running as Administrator (every hardening
        step needs it); OS and PowerShell version problems are warnings only.
    #>
    [CmdletBinding()]
    param()

    Write-Banner "Pre-flight Checks" -Style Inline -Log

    $allChecksPassed = $true

    # Check administrator privileges
    try {
        if (-not (Test-IsAdministrator)) {
            Write-Status -Level Error "Script must be run as Administrator" -LogMessage "Administrator privileges required"
            $allChecksPassed = $false
        } else {
            Write-Status -Level Success "Running with Administrator privileges" -LogMessage "Administrator privileges confirmed"
        }
    } catch {
        Write-Status -Level Error "Could not verify administrator privileges" -LogMessage "Could not verify administrator privileges: $($_.Exception.Message)"
        $allChecksPassed = $false
    }

    # Check OS compatibility
    try {
        if (-not $script:HardeningContext.OS) {
            Write-Status -Level Warning "OS not detected. OS-specific steps will be skipped." -LogMessage "OS not detected"
        } elseif ($script:HardeningContext.OS.OSVersion -eq "Unknown") {
            Write-Status -Level Warning "Unknown OS version detected. Some operations may not work correctly." -LogMessage "Unknown OS version detected"
        } else {
            Write-Status -Level Success "OS detected: $($script:HardeningContext.OS.OSVersion)"
        }
    } catch {
        Write-Status -Level Warning "OS detection failed" -LogMessage "OS detection failed: $($_.Exception.Message)"
    }

    # Check PowerShell version
    try {
        $psVersion = $PSVersionTable.PSVersion
        if ($psVersion.Major -lt 3) {
            Write-Status -Level Warning "PowerShell version $psVersion may not support all features" -LogMessage "PowerShell version $psVersion detected"
        } else {
            Write-Status -Level Success "PowerShell version: $psVersion"
        }
    } catch {
        Write-Status -Level Warning "Could not determine PowerShell version"
    }

    Write-Banner "Pre-flight Checks Complete" -Style Inline -Log

    if (-not $allChecksPassed) {
        throw "Must be run as Administrator (start PowerShell with 'Run as administrator')."
    }
}

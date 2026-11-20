#Requires -Version 5.1

# Initialize-System.ps1 - The module's single setup path: logging and context. Idempotent, so every
# hardening step can call it (via Invoke-HardeningOperation) when run on its own.

function Initialize-System {
    <#
    .SYNOPSIS
        Detects the OS, starts a log file, and initializes the hardening context.
    .DESCRIPTION
        Runs once per session. Later calls return immediately unless -Force is given.
    .PARAMETER Force
        Re-run initialization (new log file, fresh operation counters).
    .PARAMETER LogPath
        Log directory, passed to Start-HardeningLog. Default: C:\Windows\Logs\Hardening.
    #>
    [CmdletBinding()]
    param(
        [switch]$Force,

        [string]$LogPath
    )

    if ($script:HardeningContext.Initialized -and -not $Force) {
        return
    }

    Write-Host "`nInitializing system..." -ForegroundColor Cyan

    # Set before Initialize-Context runs: it executes inside Invoke-HardeningOperation,
    # which calls Initialize-System whenever this flag is unset.
    $script:HardeningContext.Initialized = $true

    try {
        try {
            $script:HardeningContext.OS = Get-OperatingSystemInfo
        } catch {
            $script:HardeningContext.OS = $null
            Write-Status -Level Warning "OS detection failed; OS-specific steps will be skipped: $($_.Exception.Message)"
        }

        # Before Start-HardeningLog, which writes it into the log header.
        try {
            $script:HardeningContext.CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        } catch {
            $script:HardeningContext.CurrentUser = $null
        }

        Start-HardeningLog -LogPath $LogPath
        Reset-OperationStatus
        Initialize-Context

        Write-Status -Level Success "Initialization complete"
    } catch {
        $script:HardeningContext.Initialized = $false
        Write-Status -Level Error "Initialization failed: $($_.Exception.Message)" -LogMessage "System initialization failed: $($_.Exception.Message)"
        throw "System initialization failed: $($_.Exception.Message)"
    }
}

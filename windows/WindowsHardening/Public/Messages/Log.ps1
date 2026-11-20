#Requires -Version 5.1

# Log.ps1 - Log file setup, Write-Log (internal; use Write-Status), and the execution summary.

function Start-HardeningLog {
    [CmdletBinding()]
    param(
        [string]$LogPath
    )

    if ([string]::IsNullOrEmpty($LogPath)) {
        $LogPath = $script:DefaultLogPath
    }
    $script:HardeningContext.LogPath = $LogPath

    try {
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
            Write-Verbose "Created log directory: $LogPath"
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logFileName = "Hardening_$timestamp.log"
        $script:LogFile = Join-Path $LogPath $logFileName

        $osInfo = $script:HardeningContext.OS
        $currentUser = if ($script:HardeningContext.ContainsKey('CurrentUser')) { $script:HardeningContext.CurrentUser } else { $null }

        $header = @"
========================================
Windows Hardening Script Execution Log
========================================
Start Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
OS Version: $($osInfo.OSVersion)
OS Build: $($osInfo.BuildNumber)
OS Edition: $($osInfo.Edition)
Is Server: $($osInfo.IsServer)
Is Server Core: $($osInfo.IsServerCore)
Current User: $currentUser
Script Version: 2.0
========================================

"@

        $header | Out-File -FilePath $script:LogFile -Encoding UTF8
        Write-Host "Log file created: $script:LogFile" -ForegroundColor Cyan

        $script:OperationResults = @{
            Total          = 0
            Successful     = 0
            Failed         = 0
            Skipped        = 0
            Warnings       = @()
        }

        $script:log = @{}

    } catch {
        Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
        $script:LogFile = $null
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Appends a timestamped line to the log file. Internal: call Write-Status instead,
        which also handles the screen (Write-Status -LogOnly for log-only details).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL", "SKIP")]
        [string]$Level,

        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message
    )

    if (-not $script:LogFile) {
        return
    }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try {
        "[$timestamp] [$Level] $Message" | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
    } catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }
}

function Set-OperationStatus {
    param(
        [string]$Key,
        [string]$Value
    )
    $script:log[$Key] = $Value
}

# Operations prelisted in the run summary before steps run. Standalone operations
# are added when invoked through Set-OperationStatus.
$script:TrackedOperations = @(
    "Initialize Context",
    "Link DC Allow AD GPO", "Link Domain Firewall GPO", "Link Domain GPO Update Interval",
    "Link Domain Good-GPO", "Link Splunk Server GPO", "Link Database Access GPO",
    "Link Web Server GPO", "Link Mail Server GPO", "Link WinRM Management GPO",
    "Link SSH Access GPO", "Link RDP Access GPO", "Link FTP Access GPO", "Link SMB Access GPO",
    "Refresh Group Policy",
    "Remove Admin Users", "Remove RDP Users", "Add RDP Users",
    "Change Administrator Password", "Zulu Passwords", "Add Competition Users", "Change Passwords", "Patch Mimikatz",
    "Configure Firewall", "Remove Remote Management",
    "Disable Unused Network Protocols", "Mitigate EternalBlue",
    "Enable Advanced Auditing", "Configure Splunk",
    "Set Execution Policy"
)

function Reset-OperationStatus {
    foreach ($func in $script:TrackedOperations) {
        Set-OperationStatus $func "Not executed"
    }
}

function Show-OperationSummary {
    Write-Banner "Script Execution Summary" -Width 60

    if ($script:HardeningContext.OS) {
        $osInfo = $script:HardeningContext.OS
        Write-Host "`nOperating System:" -ForegroundColor Yellow
        Write-Host "  Version: $($osInfo.OSVersion)" -ForegroundColor White
        Write-Host "  Build: $($osInfo.BuildNumber)" -ForegroundColor White
        Write-Host "  Edition: $($osInfo.Edition)" -ForegroundColor White
        Write-Host "  Is Server: $($osInfo.IsServer)" -ForegroundColor White
        Write-Status -LogOnly "OS: $($osInfo.OSVersion) (Build $($osInfo.BuildNumber))"
    }

    Write-Host "`nIndividual Operations:" -ForegroundColor Yellow
    foreach ($entry in $script:log.GetEnumerator()) {
        $status = $entry.Value
        # First match wins (break): failure and skip wording is checked before success
        # wording, since an error message can contain words like "completed".
        $color = switch -Wildcard ($status) {
            "Failed*"        { "Red"; break }
            "Skipped*"       { "Yellow"; break }
            "*successfully*" { "Green"; break }
            "*Enabled*"      { "Green"; break }
            "*Completed*"    { "Green"; break }
            "*Mitigated*"    { "Green"; break }
            "*Disabled*"     { "Red"; break }
            default          { "White" }
        }
        Write-Host "  $($entry.Key): " -NoNewline -ForegroundColor White
        Write-Host $status -ForegroundColor $color
        Write-Status -LogOnly "$($entry.Key): $status"
    }

    Write-Banner "Operation Statistics" -Width 60 -Color Cyan
    Write-Host "Total Operations Attempted: $($script:OperationResults.Total)" -ForegroundColor White
    Write-Host "  Successful Operations: $($script:OperationResults.Successful)" -ForegroundColor Green
    Write-Host "  Failed Operations: $($script:OperationResults.Failed)" -ForegroundColor Red
    Write-Host "  Skipped Operations: $($script:OperationResults.Skipped)" -ForegroundColor Yellow

    Write-Status -LogOnly "Total Operations: $($script:OperationResults.Total)"
    Write-Status -LogOnly "Successful: $($script:OperationResults.Successful)"
    Write-Status -LogOnly "Failed: $($script:OperationResults.Failed)"
    Write-Status -LogOnly "Skipped: $($script:OperationResults.Skipped)"

    if ($script:OperationResults.Skipped -gt 0) {
        Write-Host "`nSkipped Operations (with reasons):" -ForegroundColor Yellow
        $skippedOps = $script:log.GetEnumerator() | Where-Object { $_.Value -like "Skipped*" }
        foreach ($op in $skippedOps) {
            Write-Host "  - $($op.Key): $($op.Value)" -ForegroundColor Yellow
            Write-Status -Level Skip -LogOnly "$($op.Key) - $($op.Value)"
        }
    }

    if ($script:OperationResults.Warnings.Count -gt 0) {
        Write-Banner "Warnings" -Style Inline -Color Yellow
        foreach ($warning in $script:OperationResults.Warnings) {
            Write-Host "  - $warning" -ForegroundColor Yellow
            Write-Status -Level Warning -LogOnly "$warning"
        }
    }

    Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
}

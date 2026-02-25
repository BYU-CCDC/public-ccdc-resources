<#
.SYNOPSIS
    Comprehensive Windows Hardening Script with OS Detection and Enhanced Error Handling
    
.DESCRIPTION
    This script performs comprehensive Windows hardening operations with automatic OS detection,
    platform-specific configurations, robust error handling, and detailed logging.
    
    Supported Operating Systems:
    - Windows Server 2016
    - Windows Server 2019
    - Windows Server 2022
    - Windows 7
    - Windows 10
    - Windows 11
    
.PARAMETER LogPath
    Specifies the path for log files. Default: C:\Windows\Logs\Hardening
    
.PARAMETER FirewallPorts
    Specifies the ports to allow through the firewall during Quick Harden.
    Accepts a comma-separated string of port numbers (1-65535).
    Spaces after commas are automatically handled (e.g., "80,443,3389" or "80, 443, 3389").
    If provided, suppresses firewall-related prompts during script execution.
    Alias: -f
    
.PARAMETER SaltPhrase
    Optional salt phrase for password generation (e.g., "123-456-789").
    If not provided, a random salt phrase will be generated from the wordlist.
    When provided, this salt will be used for all password generation operations.
    Alias: -s

.PARAMETER SaltRandom
    Generate a random salt phrase to make hardening faster.
    Alias: -sr

.PARAMETER QuickHarden
    Switch to run the Quick Harden sequence. This will disable unnecessary services, configure the firewall, and change passwords.
    Alias: -q

.PARAMETER QuickHardenNoPassword
    Switch to run the Quick Harden sequence without password changes. This will disable unnecessary services, configure the firewall, but skip password changes.
    Alias: -qp

.EXAMPLE
    .\AD-Hardening-New.ps1
    Generates random salt phrase for password generation

.EXAMPLE
    .\AD-Hardening-New.ps1 -f 80,443,3389
    Configures firewall with specified ports

.EXAMPLE
    .\AD-Hardening-New.ps1 -q -f 80, 443
    Runs the Quick Harden sequence with specified firewall ports and changes passwords using the provided salt phrase
    
.EXAMPLE
    .\AD-Hardening-New.ps1 -qp -f 80, 443
    Runs the Quick Harden sequence with specified firewall ports but skips password changes

#>

[CmdletBinding()]
param(
    # Logging Configuration
    [Parameter(HelpMessage="Path for log files")]
    [string]$LogPath = "C:\Windows\Logs\Hardening",
    
    # Firewall Configuration
    [Parameter(HelpMessage="Ports to allow through firewall during Quick Harden. Accepts comma-separated port numbers (1-65535).")]
    [Alias("f")]
    [string[]]$FirewallPorts = $null,

    # Random Salt SaltRandom
    [Parameter(HelpMessage="Chooses a random salt phrase and prints it to the screen.")]
    [Alias("rs")]
    [switch]$SaltRandom = $false,

    # Quick Harden Configuration
    [Parameter(HelpMessage="Switch to run the Quick Harden sequence. This will disable unnecessary services, configure the firewall, and change passwords.")]
    [Alias("q")]
    [switch]$QuickHarden = $false,
    
    # Quick Harden Without Password Change
    [Parameter(HelpMessage="Switch to run the Quick Harden sequence without password changes. This will disable unnecessary services, configure the firewall, but skip password changes.")]
    [Alias("sp")]
    [switch]$SkipPasswordChange = $false,

    # Skip RDP harden
    [Parameter(HelpMessage="Switch to run the Quick Harden sequence without password changes. This will disable unnecessary services, configure the firewall, but skip password changes.")]
    [Alias("srdp")]
    [switch]$SkipRDP = $false


    
    # Future Parameters
    # Add new parameters here with proper categorization and documentation
)

# Parse FirewallPorts parameter if provided
# Handle comma-separated ports with optional spaces (e.g., "80,443,3389" or "80, 443, 3389")
# Note: Write-Log is not available here, so we only use Write-Host. Logging will happen later in Configure-Firewall.
$script:FirewallPortsArray = $null
$script:FirewallPortsProvided = $false

if ($null -ne $FirewallPorts -and $FirewallPorts.Count -gt 0) {
    try {
        # Handle array input - flatten and process each element
        $portStrings = @()
        foreach ($item in $FirewallPorts) {
            if (-not [string]::IsNullOrWhiteSpace($item)) {
                # If item contains commas, split it (handles cases like "80,443" as single string)
                $portStrings += $item.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            }
        }
        
        # Convert to integers and validate
        $script:FirewallPortsArray = $portStrings | 
            ForEach-Object { 
                $port = [int]$_
                if ($port -lt 1 -or $port -gt 65535) {
                    throw "Port $port is out of valid range (1-65535)"
                }
                $port
            }
        
        if ($script:FirewallPortsArray.Count -gt 0) {
            $script:FirewallPortsProvided = $true
            Write-Host "[INFO] Firewall ports provided via parameter: $($script:FirewallPortsArray -join ', ')" -ForegroundColor Cyan
            # Note: Write-Log will be called later in Configure-Firewall after logging is initialized
        }
    } catch {
        Write-Host "[ERROR] Failed to parse FirewallPorts parameter: $($_.Exception.Message)" -ForegroundColor Red
        # Note: Write-Log is not available here, logging will happen later if needed
        throw "Invalid FirewallPorts parameter: $($_.Exception.Message)"
    }
}

#region Script Configuration and Global Variables

$ErrorActionPreference = "Continue"
# TODO: Change this to the BYU-CCDC repo before pushing to production.
# Correct repo: https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/hardening
$ccdcRepoWindowsHardeningPath = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/hardening/"
$portsFile = "ports.json"
$usersFile = "users.txt"    
$advancedAuditingFile = "advancedAuditing.ps1"
$patchURLFile = "patchURLs.json"
$wordlistFileName = "wordlist.txt"
$passwordWordCount = 5 # Max of 8 words or stuff breaks.

# Global variables for tracking
$script:OperationResults = @{
    Total = 0
    Successful = 0
    Failed = 0
    Skipped = 0
    CriticalErrors = @()
    Warnings = @()
}

$script:LogFile = $null
$script:OSInfo = $null
$script:OSVersion = $null
$script:OSBuild = $null
$script:OSEdition = $null
$script:IsServer = $false
$script:IsServerCore = $false
$script:CurrentUser = $null
$script:UserArray = @()
$script:PortsObject = $null
$script:EternalBlueStatus = "Unknown"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Function names for tracking
$functionNames = @(
    "Initialize Context", "Change Passwords", 
    "Quick Harden", "Add Competition Users", "Remove RDP Users", "Add RDP Users", "Configure Firewall", 
    "Disable Unnecessary Services", "Enable Advanced Auditing", "Configure Splunk", 
    "EternalBlue Mitigated", "Upgrade SMB", "Patch Mimikatz", 
    "Set Execution Policy", "Remove Admins"
)

$script:log = @{}

#endregion

#region OS Detection Functions


function Get-OperatingSystemInfo {
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Detecting operating system..."
        
        # Use CIM for better compatibility, fallback to WMI if needed
        try {
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        } catch {
            Write-Warning "CIM query failed, falling back to WMI..."
            $osInfo = Get-WmiObject -Class Win32_OperatingSystem
        }
        
        $caption = $osInfo.Caption
        $version = $osInfo.Version
        $buildNumber = $osInfo.BuildNumber
        $productType = $osInfo.ProductType  # 1=Workstation, 2=Domain Controller, 3=Server
        
        # Determine OS edition
        $edition = $osInfo.OperatingSystemSKU
        $editionName = switch ($edition) {
            { $_ -in 4, 27, 28, 48, 49, 50, 161, 162 } { "Server Core" }
            { $_ -in 7, 8, 10, 48, 49, 50, 161, 162 } { "Server" }
            default { "Client" }
        }
        
        # Detect Server Core
        $isServerCore = $false
        if ($productType -in 2, 3) {
            try {
                $serverFeatures = Get-WindowsFeature
                if ($serverFeatures) {
                    $guiFeature = $serverFeatures | Where-Object { $_.Name -eq "Server-Gui-Mgmt-Infra" -or $_.Name -eq "Server-Gui-Shell" }
                    $isServerCore = ($guiFeature -and $guiFeature.InstallState -ne "Installed")
                }
            } catch {
                # If Get-WindowsFeature fails, check for Server Core indicators
                $isServerCore = ($caption -match "Server Core" -or $editionName -eq "Server Core")
            }
        }
        
        # Parse OS version
        $osVersion = "Unknown"
        $osFamily = "Unknown"
        
        if ($caption -match "Windows Server 2022") {
            $osVersion = "Windows Server 2022"
            $osFamily = "Server2022"
        } elseif ($caption -match "Windows Server 2019") {
            $osVersion = "Windows Server 2019"
            $osFamily = "Server2019"
        } elseif ($caption -match "Windows Server 2016") {
            $osVersion = "Windows Server 2016"
            $osFamily = "Server2016"
        } elseif ($caption -match "Windows 11") {
            $osVersion = "Windows 11"
            $osFamily = "Client11"
        } elseif ($caption -match "Windows 10") {
            $osVersion = "Windows 10"
            $osFamily = "Client10"
        } elseif ($caption -match "Windows 7") {
            $osVersion = "Windows 7"
            $osFamily = "Client7"
        } elseif ($caption -match "Windows Server 2012 R2") {
            $osVersion = "Windows Server 2012 R2"
            $osFamily = "Server2012R2"
        } elseif ($caption -match "Windows Server 2012") {
            $osVersion = "Windows Server 2012"
            $osFamily = "Server2012"
        } elseif ($caption -match "Windows Server 2008 R2") {
            $osVersion = "Windows Server 2008 R2"
            $osFamily = "Server2008R2"
        } elseif ($caption -match "Windows Server 2008") {
            $osVersion = "Windows Server 2008"
            $osFamily = "Server2008"
        } elseif ($caption -match "Windows 8") {
            $osVersion = "Windows 8"
            $osFamily = "Client8"
        } elseif ($caption -match "Windows Vista") {
            $osVersion = "Windows Vista"
            $osFamily = "ClientVista"
        } elseif ($caption -match "Windows XP") {
            $osVersion = "Windows XP"
            $osFamily = "ClientXP"
        }
        
        $result = [PSCustomObject]@{
            Caption = $caption
            Version = $version
            BuildNumber = $buildNumber
            OSVersion = $osVersion
            OSFamily = $osFamily
            Edition = $editionName
            IsServer = ($productType -in 2, 3)
            IsServerCore = $isServerCore
            ProductType = $productType
        }
        
        Write-Host "`n[INFO] OS Detection: $($result.OSVersion) (Build $($result.BuildNumber)) - $($result.Edition)" -ForegroundColor Cyan
        Write-Log -Level "INFO" -Message "OS Detection: $($result.OSVersion) (Build $($result.BuildNumber)) - $($result.Edition)"
        
        return $result
        
    } catch {
        Write-Error "Failed to detect operating system: $($_.Exception.Message)"
        throw
    }
}

#endregion

#region Logging Functions


function Initialize-Logging {
    [CmdletBinding()]
    param()
    
    try {
        # Create log directory if it doesn't exist
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
            Write-Verbose "Created log directory: $LogPath"
        }
        
        # Create timestamped log file
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logFileName = "Hardening_$timestamp.log"
        $script:LogFile = Join-Path $LogPath $logFileName
        
        # Write log header
        $header = @"
========================================
Windows Hardening Script Execution Log
========================================
Start Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
OS Version: $($script:OSInfo.OSVersion)
OS Build: $($script:OSInfo.BuildNumber)
OS Edition: $($script:OSInfo.Edition)
Is Server: $($script:OSInfo.IsServer)
Is Server Core: $($script:OSInfo.IsServerCore)
Current User: $($script:CurrentUser)
Script Version: 2.0
========================================

"@
        
        $header | Out-File -FilePath $script:LogFile -Encoding UTF8
        Write-Host "Log file created: $script:LogFile" -ForegroundColor Cyan
        
    } catch {
        Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
        $script:LogFile = $null
    }
}


function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL")]
        [string]$Level,
        
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [switch]$Console
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    if ($script:LogFile) {
        try {
            $logEntry | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
        } catch {
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
    
    # Write to console if requested
    if ($Console -or $Level -in "ERROR", "CRITICAL", "WARNING") {
        $color = switch ($Level) {
            "SUCCESS" { "Green" }
            "WARNING" { "Yellow" }
            "ERROR" { "Red" }
            "CRITICAL" { "Red" }
            default { "White" }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
}


function Update-Log {
    param(
        [string]$key,
        [string]$value
    )
    $script:log[$key] = $value
}


function Initialize-Log {
    foreach ($func in $functionNames) {
        Update-Log $func "Not executed"
    }
}

function Print-Log {
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "### Script Execution Summary ###" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Log -Level "INFO" -Message "=== Execution Summary ===" -Console
    
    # Display OS information
    if ($script:OSInfo) {
        Write-Host "`nOperating System:" -ForegroundColor Yellow
        Write-Host "  Version: $($script:OSInfo.OSVersion)" -ForegroundColor White
        Write-Host "  Build: $($script:OSInfo.BuildNumber)" -ForegroundColor White
        Write-Host "  Edition: $($script:OSInfo.Edition)" -ForegroundColor White
        Write-Host "  Is Server: $($script:OSInfo.IsServer)" -ForegroundColor White
        Write-Log -Level "INFO" -Message "OS: $($script:OSInfo.OSVersion) (Build $($script:OSInfo.BuildNumber))"
    }
    
    # Print individual operation results
    Write-Host "`nIndividual Operations:" -ForegroundColor Yellow
    foreach ($entry in $script:log.GetEnumerator()) {
        
        $status = $entry.Value
        
        $color = switch -Wildcard ($status) {
            "*successfully*" { "Green" }
            "*Enabled*" { "Green" }
            "*Completed*" { "Green" }
            "*Mitigated*" { "Green" }
            "*Failed*" { "Red" }
            "*Disabled*" { "Red" }
            "*Skipped*" { "Yellow" }
            default { "White" }
        }
        Write-Host "  $($entry.Key): " -NoNewline -ForegroundColor White
        Write-Host $status -ForegroundColor $color
        Write-Log -Level "INFO" -Message "$($entry.Key): $status"
    }
    
    # Print operation statistics
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "### Operation Statistics ###" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "Total Operations Attempted: $($script:OperationResults.Total)" -ForegroundColor White
    Write-Host "  Successful Operations: $($script:OperationResults.Successful)" -ForegroundColor Green
    Write-Host "  Failed Operations: $($script:OperationResults.Failed)" -ForegroundColor Red
    Write-Host "  Skipped Operations: $($script:OperationResults.Skipped)" -ForegroundColor Yellow
    
    Write-Log -Level "INFO" -Message "Total Operations: $($script:OperationResults.Total)" -Console
    Write-Log -Level "INFO" -Message "Successful: $($script:OperationResults.Successful)" -Console
    Write-Log -Level "INFO" -Message "Failed: $($script:OperationResults.Failed)" -Console
    Write-Log -Level "INFO" -Message "Skipped: $($script:OperationResults.Skipped)" -Console
    
    # Display skipped operations with reasons
    if ($script:OperationResults.Skipped -gt 0) {
        Write-Host "`nSkipped Operations (with reasons):" -ForegroundColor Yellow
        $skippedOps = $script:log.GetEnumerator() | Where-Object { $_.Value -like "*Skipped*" }
        foreach ($op in $skippedOps) {
            Write-Host "  - $($op.Key): $($op.Value)" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Skipped: $($op.Key) - $($op.Value)"
        }
    }
    
    if ($script:OperationResults.CriticalErrors.Count -gt 0) {
        Write-Host "`n" + ("=" * 60) -ForegroundColor Red
        Write-Host "### Critical Errors ###" -ForegroundColor Red
        Write-Host ("=" * 60) -ForegroundColor Red
        foreach ($_error in $script:OperationResults.CriticalErrors) {
            Write-Host "  - $_error" -ForegroundColor Red
            Write-Log -Level "CRITICAL" -Message "Critical Error: $_error" -Console
        }
    }
    
    if ($script:OperationResults.Warnings.Count -gt 0) {
        Write-Host "`n### Warnings ###" -ForegroundColor Yellow
        foreach ($warning in $script:OperationResults.Warnings) {
            Write-Host "  - $warning" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Warning: $warning" -Console
        }
    }
    
    Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
}

#endregion

#region Error Handling Functions

<#
.SYNOPSIS
    Executes a hardening operation with comprehensive error handling.
    
.DESCRIPTION
    Wraps hardening operations in try-catch blocks, tracks success/failure,
    and provides appropriate user feedback.
    
.PARAMETER OperationName
    Name of the operation being performed.
    
.PARAMETER ScriptBlock
    The script block to execute.
    
.PARAMETER IsCritical
    Whether this operation is critical (script will halt on failure).
    
.PARAMETER OSCompatibility
    Array of OS families this operation is compatible with. If empty, applies to all.
#>
function Invoke-HardeningOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OperationName,
        
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        
        [switch]$IsCritical,
        
        [string[]]$OSCompatibility = @(),
        
        [string]$ProgressMessage = ""
    )
    
    $script:OperationResults.Total++
    
    # Check OS compatibility
    if ($OSCompatibility.Count -gt 0) {
        if ($script:OSInfo.OSFamily -notin $OSCompatibility) {
            $message = "[SKIPPED] Operation '$OperationName' is not compatible with $($script:OSInfo.OSVersion) (OS Family: $($script:OSInfo.OSFamily))"
            Write-Host $message -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message $message -Console
            $script:OperationResults.Skipped++
            $script:OperationResults.Warnings += $message
            Update-Log $OperationName "Skipped - OS incompatible ($($script:OSInfo.OSFamily))"
            return
        }
    }
    
    try {
        Write-Host "`n[EXECUTING] $OperationName..." -ForegroundColor Cyan
        if ($ProgressMessage) {
            Write-Host "[INFO] $ProgressMessage" -ForegroundColor White
        }
        Write-Log -Level "INFO" -Message "Starting operation: $OperationName" -Console
        if ($script:OSInfo) {
            Write-Host "[INFO] Applying configuration for $($script:OSInfo.OSVersion)..." -ForegroundColor DarkGray
        }
        
        # Execute the script block
        & $ScriptBlock
        
        $message = "[SUCCESS] $OperationName completed successfully"
        Write-Host $message -ForegroundColor Green
        Write-Log -Level "SUCCESS" -Message $message -Console
        $script:OperationResults.Successful++
        Update-Log $OperationName "Executed successfully"
        
    } catch {
        $errorMessage = "[FAILED] $OperationName : $($_.Exception.Message)"
        Write-Host $errorMessage -ForegroundColor Red
        Write-Host "[ERROR DETAILS] Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor DarkRed
        if ($_.Exception.InnerException) {
            Write-Host "[ERROR DETAILS] Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor DarkRed
        }
        Write-Log -Level "ERROR" -Message $errorMessage -Console
        Write-Log -Level "ERROR" -Message "Exception Type: $($_.Exception.GetType().FullName)"
        if ($_.Exception.InnerException) {
            Write-Log -Level "ERROR" -Message "Inner Exception: $($_.Exception.InnerException.Message)"
        }
        
        $script:OperationResults.Failed++
        Update-Log $OperationName "Failed with error: $($_.Exception.Message)"
        
        if ($IsCritical) {
            $script:OperationResults.CriticalErrors += "$OperationName : $($_.Exception.Message)"
            Write-Host "`n[CRITICAL] Operation '$OperationName' failed. This is a critical operation." -ForegroundColor Red
            Write-Log -Level "CRITICAL" -Message "Critical operation failed: $OperationName" -Console
            
            $continue = Read-Host "Continue with remaining operations? (y/n)"
            if ($continue -ne "y" -and $continue -ne "Y") {
                throw "Script halted due to critical error in: $OperationName"
            }
        }
    }
}


function Set-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [object]$Value,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("String", "DWord", "QWord", "MultiString", "ExpandString", "Binary")]
        [string]$PropertyType,
        
        [string]$OperationName = "Registry Operation",
        
        [switch]$CreatePathIfMissing
    )
    
    try {
        # Validate prerequisite - check if registry path exists
        if (-not (Test-Path $Path)) {
            if ($CreatePathIfMissing) {
                Write-Host "[INFO] Creating registry path: $Path" -ForegroundColor Cyan
                New-Item -Path $Path -Force | Out-Null
                Write-Log -Level "SUCCESS" -Message "Created registry path: $Path"
            } else {
                $message = "Registry path not found and CreatePathIfMissing not specified: $Path"
                Write-Host "[SKIPPED] $message" -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "$OperationName - $message" -Console
                $script:OperationResults.Skipped++
                return $false
            }
        }
        
        # Check if property exists, if not create it
        $existingValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        
        if ($null -ne $existingValue -and $existingValue.PSObject.Properties[$Name]) {
            # Property exists, update it
            Set-ItemProperty -Path $Path -Name $Name -Value $Value | Out-Null
            Write-Host "[SUCCESS] Updated registry value: $Path\$Name = $Value" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Updated registry value: $Path\$Name = $Value"
        } else {
            # Property doesn't exist, create it
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
            Write-Host "[SUCCESS] Created and set registry value: $Path\$Name = $Value" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Created registry value: $Path\$Name = $Value"
        }
        
        return $true
        
    } catch {
        $errorMessage = "Failed to set registry value $Path\$Name : $($_.Exception.Message)"
        Write-Host "[ERROR] $errorMessage" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "$OperationName - $errorMessage" -Console
        throw
    }
}

#region Pre-flight Checks

function Test-Prerequisites {
    [CmdletBinding()]
    param()
    
    Write-Host "`n=== Pre-flight Checks ===" -ForegroundColor Cyan
    Write-Log -Level "INFO" -Message "=== Pre-flight Checks ===" -Console
    
    $allChecksPassed = $true
    
    # Check administrator privileges
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Host "[FAIL] Script must be run as Administrator" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Administrator privileges required" -Console
            $allChecksPassed = $false
        } else {
            Write-Host "[PASS] Running with Administrator privileges" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Administrator privileges confirmed"
        }
    } catch {
        Write-Host "[FAIL] Could not verify administrator privileges" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "Could not verify administrator privileges: $($_.Exception.Message)" -Console
        $allChecksPassed = $false
    }
    
    # Check OS compatibility
    try {
        if ($script:OSInfo.OSVersion -eq "Unknown") {
            Write-Host "[WARN] Unknown OS version detected. Some operations may not work correctly." -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Unknown OS version detected"
        } else {
            Write-Host "[PASS] OS detected: $($script:OSInfo.OSVersion)" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "OS detected: $($script:OSInfo.OSVersion)"
        }
    } catch {
        Write-Host "[FAIL] OS detection failed" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "OS detection failed: $($_.Exception.Message)" -Console
        $allChecksPassed = $false
    }
    
    # Check PowerShell version
    try {
        $psVersion = $PSVersionTable.PSVersion
        if ($psVersion.Major -lt 3) {
            Write-Host "[WARN] PowerShell version $psVersion may not support all features" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "PowerShell version $psVersion detected"
        } else {
            Write-Host "[PASS] PowerShell version: $psVersion" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "PowerShell version: $psVersion"
        }
    } catch {
        Write-Host "[WARN] Could not determine PowerShell version" -ForegroundColor Yellow
        Write-Log -Level "WARNING" -Message "Could not determine PowerShell version"
    }
    
    Write-Host "`n=== Pre-flight Checks Complete ===" -ForegroundColor Cyan
    Write-Log -Level "INFO" -Message "=== Pre-flight Checks Complete ===" -Console
    
    if (-not $allChecksPassed) {
        Write-Host "`n[WARNING] Some pre-flight checks failed. The script may not function correctly." -ForegroundColor Yellow
        $continue = Read-Host "Continue anyway? (y/n)"
        if ($continue -ne "y") {
            throw "Pre-flight checks failed. Script aborted by user."
        }
    }
    
    return $allChecksPassed
}

#endregion

#region Core Hardening Functions

function Initialize-Context {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Initialize Context" -ScriptBlock {
        # Download needed files
        $neededFiles = @($portsFile, $advancedAuditingFile, $patchURLFile, $wordlistFileName)
        foreach ($file in $neededFiles) {
            $filename = $(Split-Path -Path $file -Leaf)
            if (-not (Test-Path "$pwd\$filename")) {
                Write-Host "Downloading $filename..." -ForegroundColor Cyan
                try {
                    Invoke-WebRequest -Uri "$ccdcRepoWindowsHardeningPath/$file" -OutFile "$pwd\$filename"              
                    Write-Log -Level "SUCCESS" -Message "Downloaded $filename"
                } catch {
                    Write-Log -Level "WARNING" -Message "Failed to download $filename : $($_.Exception.Message)"
                    throw "Failed to download required file: $filename"
                }
            } else {
                Write-Verbose "File already exists: $filename"
            }
        }
        
        # Set global variables
        $script:CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        
        # Load userfile and portdata
        if (Test-Path ".\users.txt") {
            [string[]]$script:UserArray = Get-Content -Path ".\users.txt"
            Write-Log -Level "INFO" -Message "Loaded $($script:UserArray.Count) users from users.txt"
        } else {
            [string[]]$script:UserArray = @()
            Write-Log -Level "INFO" -Message "No users.txt found, using empty array"
        }
        
        if (Test-Path ".\ports.json") {
            $script:PortsObject = Get-Content -Path ".\ports.json" -Raw | ConvertFrom-Json
            Write-Log -Level "INFO" -Message "Loaded ports configuration from ports.json"
        } else {
            # Fallback port definitions
            $script:PortsObject = @{ ports = @{
                '53'   = @{ description = 'DNS' }
                '3389' = @{ description = 'RDP' }
                '80'   = @{ description = 'HTTP' }
                '445'  = @{ description = 'SMB' }
                '139'  = @{ description = 'NetBIOS Session' }
                '22'   = @{ description = 'SSH' }
                '88'   = @{ description = 'Kerberos' }
                '67'   = @{ description = 'DHCP Server' }
                '68'   = @{ description = 'DHCP Client' }
                '135'  = @{ description = 'RPC' }
                '389'  = @{ description = 'LDAP' }
                '636'  = @{ description = 'LDAPS' }
                '3268' = @{ description = 'Global Catalog' }
                '3269' = @{ description = 'Global Catalog SSL' }
                '464'  = @{ description = 'Kerberos Change/Set Password' }
            }
            }
            Write-Log -Level "WARNING" -Message "ports.json not found, using fallback port definitions"
        }
        
        Write-Host "Context initialized successfully" -ForegroundColor Green
    }
}

function Initialize-System {
    [CmdletBinding()]
    param()
    
    Write-Host "`nInitializing system..." -ForegroundColor Cyan
    
    try {
        # Initialize function execution log
        Initialize-Log
        Initialize-Logging
        # Initialize context (downloads files, sets variables)
        Initialize-Context
        
        Write-Host "Initialization complete" -ForegroundColor Green
    } catch {
        Write-Host "Initialization failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "System initialization failed: $($_.Exception.Message)" -Console
        throw "System initialization failed: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Generates a deterministic password based on secret and username using wordlist.
    
.DESCRIPTION
    Generates a passphrase by combining a secret and username (prompted from user),
    hashing them with MD5, and using the hash to select words from a wordlist.
    The result is a deterministic password that can be regenerated using the same inputs.
    The function downloads the wordlist if it doesn't exist locally.
#>

function new-Zulu-Integration {
    [CmdletBinding()]
    param(
        [Alias("h")][switch]$Help,
        [Alias("i")][switch]$Initial,
        [Alias("b")][string]$User,
        [Alias("U")][string]$UsersFile,
        [Alias("g")][switch]$GenerateOnly,
        [Alias("p")][string]$PCRFile,
        [Alias("s")][string]$Seed,

        [Parameter(Mandatory=$false, HelpMessage = "If we need to download the wordlist, this is the URL to get it from")]
        [Alias("url")]
        [string]$WordlistUrl = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/wordlist.txt"
    )
    process {
        # Script configuration
    $NumWords = 5
    $ExportUsersFile = "users_zulu.csv"
    $LogFile = "zulu.log"
    $WordlistFile = "wordlist.txt"
    $ExcludedUsers = @("Administrator", "ccdcuser1", "ccdcuser2", "ccdcuser3")

    function Write-Usage {
        Write-Host "Usage: .\Set-Passwords.ps1 [options]" -ForegroundColor Green
        Write-Host "Default behavior asks for a seed phrase and changes passwords for all auto-detected users minus excluded users."
        Write-Host "`nOptions:" -ForegroundColor Yellow
        @(
            "  -Help, -h          Show this help message",
            "  -Initial, -i       Perform initial setup (change Administrator password and create ccdcuser1/2)",
            "  -User, -u          Change password for a single user",
            "  -UsersFile, -U     Change passwords for newline-separated users in a file",
            "  -GenerateOnly, -g  Generate/print passwords only, do not change them",
            "  -PCRFile, -p       Output generated passwords as 'username,password' to a PCR (CSV) file",
            "  -Seed, -s          Seed phrase (non-interactive; skips prompt, for testing)",
            "  -url <url>         The url to the wordlist" 
            
        ) | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
    }

    function Get-SilentInput {
        param([string]$Prompt)
        Write-Host -NoNewline $Prompt
        $secure = Read-Host -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        $input = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        $input
    }

    function Get-FileFromUrl {
        param([string]$Url, [string]$OutputPath)
        try {
            Write-Host "Downloading from $Url..." -ForegroundColor Green
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
            $ProgressPreference = 'Continue'
            $true
        } catch {
            Write-Host "Failed to download file from $Url`nError: $($_.Exception.Message)" -ForegroundColor Red
            $false
        }
    }

    function Add-LogEntry {
        param([string]$Message)
        if (-not $GenerateOnly) { Add-Content -Path $LogFile -Value $Message }
    }

    function Test-Prerequisites {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Host "Please run script as Administrator." -ForegroundColor Red
            exit 1
        }
        if (-not (Test-Path $WordlistFile)) {
            Write-Host "Downloading wordlist file..." -ForegroundColor Green
            if (-not (Get-FileFromUrl -Url $WordlistUrl -OutputPath $WordlistFile)) { exit 1 }
        }
    }

    function Test-IsDomainController {
        try {
            $ntds = Get-Service -Name ntds -ErrorAction SilentlyContinue
            return $ntds -ne $null
        } catch {
            return $false
        }
    }


    function Set-UserPassword {
        param(
            [string]$Username,
            [string]$PasswordPrompt,
            [string]$Password,           # new optional parameter
            [switch]$AddToAdmins
        )

        if (-not $Password) {
            $Password = Get-SilentInput $PasswordPrompt
            $confirmPassword = Get-SilentInput "Confirm password: "
            if ($Password -ne $confirmPassword) {
                Write-Host "Passwords do not match." -ForegroundColor Red
                Set-UserPassword -Username $Username -PasswordPrompt $PasswordPrompt
            }
        }

        $securePassword = ConvertTo-SecureString -AsPlainText $Password -Force
        try{
            if ($IsDomainController) {
                Set-ADAccountPassword -Identity $Username -Reset -NewPassword $securePassword -ErrorAction Stop
                if ($AddToAdmins) { Add-ADGroupMember -Identity "Domain Admins" -Members $Username -ErrorAction SilentlyContinue }
            } else {
                Get-LocalUser -Name $Username | Set-LocalUser -Password $securePassword -ErrorAction Stop
                if ($AddToAdmins) { Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction SilentlyContinue }
            }
        }
        catch
        {
            Write-Host "Error setting password for ${Username}: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Please try a different password (likely complexity requirements)." -ForegroundColor Yellow
            
            Set-UserPassword -Username $Username -PasswordPrompt $PasswordPrompt -Password $null -AddToAdmins:$AddToAdmins
        }
    }

    function Initialize-Users {
        Write-Host "Changing Administrator password..." -ForegroundColor Green
        Set-UserPassword -Username "Administrator" -PasswordPrompt "Enter new password for Administrator: "
        
        Write-Host "`nCreating local ccdcuser1 and ccdcuser2..."

        @("ccdcuser1", "ccdcuser2") | ForEach-Object {
            if (-not (Get-LocalUser -Name $_ -ErrorAction SilentlyContinue)) {
                New-LocalUser -Name $_ -NoPassword
            }
        }
        Write-Host "`nSetting passwords for CCDC users..."
        Set-UserPassword -Username "ccdcuser1" -PasswordPrompt "Enter password for ccdcuser1: " -AddToAdmins
        Set-UserPassword -Username "ccdcuser2" -PasswordPrompt "Enter password for ccdcuser2: "
        
        #AD specific
        if ($IsDomainController) {
            New-ADUser -Name "ccdcuser3" -SamAccountName "ccdcuser3"
            @("ccdcuser3") | ForEach-Object {
                if (-not (Get-ADUser -Identity $_ -ErrorAction SilentlyContinue)) {
                    Write-Host "Domain user '$_' not found. Please create it before setting a password, or create it now using 'New-ADUser'." -ForegroundColor Yellow
                }
            }
            
            Write-Host "`nSetting passwords for CCDC domain admin..."
            foreach ($u in @("ccdcuser3")) {
                if (Get-ADUser -Identity $u -ErrorAction SilentlyContinue) {
                    Set-UserPassword -Username $u -PasswordPrompt "Enter password for ccdcuser3: " -AddToAdmins
                    Enable-ADAccount "ccdcuser3"
                }
            }
        }
    }

    function Scale-HashValue {
        param([Parameter(Mandatory=$true)][int]$HashValue, [Parameter(Mandatory=$true)][int]$WordlistCount)
        $TARGET_MAX = $wordlistData.Count - 1
        if ($TARGET_MAX -lt 0) { return 0 }
        return [int][Math]::Truncate(((($TARGET_MAX) * ($HashValue - 0x0000)) / (0xFFFF - 0x0000)))
    }

    function New-Password {
        param([string]$Username, [string]$SeedPhrase, [string[]]$WordlistData)
        
        $inputString = "$SeedPhrase$Username"
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $hashBytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($inputString))
        $hashString = [System.BitConverter]::ToString($hashBytes) -replace '-', ''
        
        $password = ""
        for ($i = 0; $i -lt ($NumWords * 4); $i += 4) {
            if ($i -ne 0) { $password += "-" }
            $hex = $hashString.Substring($i, 4)
            $dec = [Convert]::ToInt32($hex, 16)
            $index = Scale-HashValue -HashValue $dec -WordlistCount $WordlistData.Count
            $password += $WordlistData[$index]
        }
        $password + "1"
    }

    if ($Help) { Write-Usage; exit 0 }

    Write-Host "Starting Zulu Password Generator Script..." -ForegroundColor Green
    Add-LogEntry "Script started at $(Get-Date)"
    Write-Host "The default behavior is to change passwords for all users except: $($ExcludedUsers -join ', ')."

    Test-Prerequisites

    #Determine if this machine is a Domain Controller and set a flag for later use
    $IsDomainController = Test-IsDomainController
    if ($IsDomainController) {
        Write-Host "Domain Controller detected - AD password operations will be used." -ForegroundColor Green
    }

    if ($Initial) {
        Write-Host "Performing initial user setup..." -ForegroundColor Green
        Initialize-Users
    }

    Write-Host "`nPreparing to generate passwords..."

    $rawUsers = if ($User) { @($User) } 
                elseif ($UsersFile) { 
                    if (-not (Test-Path $UsersFile)) { Write-Host "Users file '$UsersFile' not found." -ForegroundColor Red; exit 1 }
                    Get-Content $UsersFile 
                }
                elseif ($IsDomainController) { 
                    Get-ADUser -Filter * | Where-Object { $_.Enabled } | Select-Object -ExpandProperty SamAccountName 
                }
                else { 
                    Get-LocalUser | Where-Object { $_.Enabled } | Select-Object -ExpandProperty Name 
                }

    $users = $rawUsers | Where-Object { $_ -notin $ExcludedUsers }

    if ($Seed) {
        if ($Seed.Length -lt 8) {
            Write-Host "Seed phrase must be at least 8 characters long." -ForegroundColor Red
            exit 1
        }
        $seedPhrase = $Seed
    } else {
        while ($true) {
            $seedPhrase = Get-SilentInput "Enter seed phrase: "
            $confirmSeedPhrase = Get-SilentInput "Confirm seed phrase: "
            
            if ($seedPhrase -ne $confirmSeedPhrase) {
                Write-Host "Seed phrases do not match. Please retry." -ForegroundColor Yellow
                continue
            }
            if ($seedPhrase.Length -lt 8) {
                Write-Host "Seed phrase must be at least 8 characters long. Please retry." -ForegroundColor Yellow
                continue
            }
            break
        }
    }

    $wordlistData = Get-Content $WordlistFile
    Write-Host "Generating passwords for $($users.Count) users..." -ForegroundColor Green

    if (-not $GenerateOnly) {
        Remove-Item $ExportUsersFile -ErrorAction SilentlyContinue
        New-Item -ItemType File -Path $ExportUsersFile -Force | Out-Null
    }

    foreach ($username in $users) {
        $password = New-Password -Username $username -SeedPhrase $seedPhrase -WordlistData $wordlistData
        
        if (-not $GenerateOnly) {
            Write-Host "Changing password for user $username..."
            try {
                Set-UserPassword -Username $username -Password $password
                if ($IsDomainController) {
                    Write-Host "Successfully changed AD password for ${username}." -ForegroundColor Green
                    Add-LogEntry "Successfully changed AD password for ${username}."
                } else {
                    Write-Host "Successfully changed password for ${username}." -ForegroundColor Green
                    Add-LogEntry "Successfully changed password for ${username}."
                }
                Add-Content -Path $ExportUsersFile -Value $username
            } catch {
                Write-Host "Failed to change password for ${username}. $($_.Exception.Message)" -ForegroundColor Red
                Add-LogEntry "Failed to change password for ${username}.: $($_.Exception.Message)"
            }
        } elseif (-not $PCRFile) {
            Write-Host "Generated password for user '${username}': ${password}"
        }
        
        if ($PCRFile) {
            Add-Content -Path $PCRFile -Value "${username},${password}"
        }
    }

    Write-Host "`nDone!" -ForegroundColor Green
    Write-Host "PLEASE REMEMBER TO CHANGE THE ADMINISTRATOR PASSWORD IF NOT DONE EARLIER." -ForegroundColor Yellow
    }
}



<#
.SYNOPSIS
    Removes users from Administrators group except specified ones.
#>

function Remove-Admin-Users {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Remove Admin Users" -ScriptBlock {
        Write-Host "Cleaning administrator groups on the domain (Domain Admins, Enterprise Admins, Administrators)..." -ForegroundColor Cyan
        Write-Host "Please go back and add users that need access per the competition scenario" -ForegroundColor Cyan
        
        # Define protected accounts that should NEVER be removed
        $ExclusionList = @("Administrator", "ccdcuser1")
        
        $adminGroupList = @("Domain Admins", "Enterprise Admins", "Administrators")
        foreach ($groupName in $adminGroupList) {
            try {
                # Get all members of the Administrators group
                $adminMembers = Get-ADGroupMember -Identity $GroupName -ErrorAction SilentlyContinue
                
                if ($null -eq $adminMembers -or $adminMembers.Count -eq 0) {
                    Write-Host "  [INFO] ${GroupName} group is empty (Unexpected)" -ForegroundColor Yellow
                    Write-Log -Level "INFO" -Message "${GroupName} group is already empty"
                } else {
                    $removedCount = 0
                    foreach ($member in $adminMembers) {
                        try {
                            # Extract username from "COMPUTER\Username" format
                            $username = $member.SAMAccountName

                            # Check if the user is in the exclusion list (Case-Insensitive)
                            if ($ExclusionList -contains $username) {
                                Write-Host "  [SKIP] Skipping ${username} (Protected Admin)" -ForegroundColor Magenta
                                Write-Log -Level "INFO" -Message "Skipped removal of ${username} from ${GroupName} group"
                                continue 
                            }

                            # Remove the member
                            Remove-ADGroupMember -Identity $GroupName -Members $username -Confirm:$false -ErrorAction Stop
                            
                            Write-Host "  [SUCCESS] Removed ${username} from ${GroupName}" -ForegroundColor Green
                            Write-Log -Level "SUCCESS" -Message "Removed ${username} from ${GroupName}"
                            $removedCount++
                        } catch {
                            $msg = $_.Exception.Message
                            Write-Host "  [WARNING] Could not remove $($member.Name): $msg" -ForegroundColor Yellow
                            Write-Log -Level "WARNING" -Message "Could not remove $($member.Name) from ${GroupName}: $msg"
                        }
                    }
                    Write-Host "  [INFO] Removed $removedCount unauthorized admin(s)" -ForegroundColor Cyan
                }
                
                Write-Host "Administrator group hardening complete" -ForegroundColor Green
                Write-Log -Level "SUCCESS" -Message "Administrators group reset completed"
            } catch {
                Write-Host "  [ERROR] Failed to harden Administrators: $($_.Exception.Message)" -ForegroundColor Red
                Write-Log -Level "ERROR" -Message "Failed to harden Administrators: $($_.Exception.Message)"
                throw
            }
        }
    }
}

<#
.SYNOPSIS
    Removes users from Remote Desktop Users group except specified ones.
#>
function Remove-RDP-Users {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Remove RDP Users" -ScriptBlock {
        Write-Host "Removing all users from Remote Desktop Users group..." -ForegroundColor Cyan
        $ExclusionList = @("ccdcuser1", "ccdcuser2")
        try {
            # Get all members of the Remote Desktop Users group
            $rdpGroupMembers = Get-ADGroupMember -Identity "Remote Desktop Users" -ErrorAction SilentlyContinue
            
            if ($null -eq $rdpGroupMembers -or $rdpGroupMembers.Count -eq 0) {
                Write-Host "  [INFO] Remote Desktop Users group is already empty" -ForegroundColor Yellow
                Write-Log -Level "INFO" -Message "Remote Desktop Users group is already empty"
            } else {
                $removedCount = 0
                foreach ($member in $rdpGroupMembers) {
                    try {
                        # Extract username from the member object (format: "DOMAIN\Username" or "COMPUTER\Username")
                        $username = $member.SAMAccountName
                        # Skip specified users
                        # Check if the user is in the exclusion list
                        if ($ExclusionList -contains $username) {
                            Write-Host "  [SKIP] Skipping $username (Protected Account)" -ForegroundColor Magenta
                            Write-Log -Level "INFO" -Message "Skipped removal of $username from RDP group"
                            continue # Jump to the next user in the loop
                        }


                        Remove-ADGroupMember -Identity "Remote Desktop Users" -Members $member -Confirm:$false -ErrorAction Stop
                        Write-Host "  [SUCCESS] Removed $username from Remote Desktop Users group" -ForegroundColor Green
                        Write-Log -Level "SUCCESS" -Message "Removed $username from Remote Desktop Users group"
                        $removedCount++
                    } catch {
                        Write-Host "  [WARNING] Could not remove $($member.SamAccountName) from Remote Desktop Users group: $($_.Exception.Message)" -ForegroundColor Yellow
                        Write-Log -Level "WARNING" -Message "Could not remove $($member.SamAccountName) from Remote Desktop Users group: $($_.Exception.Message)"
                    }
                }
                Write-Host "  [INFO] Removed $removedCount user(s) from Remote Desktop Users group" -ForegroundColor Cyan
            }
            
            Write-Host "RDP users removed successfully - Remote Desktop Users group has been reset" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "RDP users removal completed - Remote Desktop Users group reset"
        } catch {
            Write-Host "  [ERROR] Failed to remove RDP users: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Failed to remove RDP users: $($_.Exception.Message)"
            throw
        }
    }
}

<#
.SYNOPSIS
    Interactively adds users to the Remote Desktop Users group.
    
.DESCRIPTION
    Prompts the user for the number of users to add, then iteratively prompts for each username
    and adds them to the Remote Desktop Users group with error handling.
#>
function Add-RDP-Users {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Add RDP Users" -ScriptBlock {
        Write-Host "`n=== Add Users to Remote Desktop Users Group ===" -ForegroundColor Cyan
        
        # Prompt for the number of users to add
        $userCount = 0
        while ($true) {
            try {
                $userCountInput = Read-Host "Enter the number of users you wish to add to the Remote Desktop Users group"
                $userCount = [int]$userCountInput
                if ($userCount -gt 0) {
                    break
                } else {
                    Write-Host "  [ERROR] Please enter a positive number greater than 0." -ForegroundColor Red
                }
            } catch {
                Write-Host "  [ERROR] Invalid input. Please enter a valid number." -ForegroundColor Red
            }
        }
        
        Write-Host "`nYou will now be prompted to enter $userCount username(s)." -ForegroundColor Yellow
        Write-Host ""
        
        $successCount = 0
        $failedCount = 0
        
        # Loop to prompt for each username
        for ($i = 1; $i -le $userCount; $i++) {
            $username = Read-Host "Enter username #$i"
            
            # Skip empty usernames
            if ([string]::IsNullOrWhiteSpace($username)) {
                Write-Host "  [WARNING] Username #$i was empty, skipping..." -ForegroundColor Yellow
                $failedCount++
                continue
            }
            
            # Try to add the user to the Remote Desktop Users group
            try {
                Add-ADGroupMember -Identity "Remote Desktop Users" -Members $username -ErrorAction Stop
                Write-Host "  [SUCCESS] Added user '$username' to Remote Desktop Users group" -ForegroundColor Green
                Write-Log -Level "SUCCESS" -Message "Added user '$username' to Remote Desktop Users group"
                $successCount++
            } catch {
                $errorMessage = $_.Exception.Message
                Write-Host "  [ERROR] Could not add user '$username' to Remote Desktop Users group: $errorMessage" -ForegroundColor Red
                Write-Log -Level "ERROR" -Message "Could not add user '$username' to Remote Desktop Users group: $errorMessage"
                $failedCount++
                
                # Provide helpful error messages
                if ($errorMessage -like "*not found*" -or $errorMessage -like "*does not exist*") {
                    Write-Host "    [INFO] The user '$username' does not exist on the local system or domain." -ForegroundColor Yellow
                } elseif ($errorMessage -like "*already*" -or $errorMessage -like "*member*") {
                    Write-Host "    [INFO] The user '$username' is already a member of the Remote Desktop Users group." -ForegroundColor Yellow
                }
            }
        }
        
        # Summary
        Write-Host "`n=== Summary ===" -ForegroundColor Cyan
        Write-Host "  Successfully added: $successCount user(s)" -ForegroundColor Green
        if ($failedCount -gt 0) {
            Write-Host "  Failed to add: $failedCount user(s)" -ForegroundColor Red
        }
        Write-Host "`nRDP user addition process completed." -ForegroundColor Green
        Write-Log -Level "SUCCESS" -Message "Add RDP Users completed: $successCount succeeded, $failedCount failed"
    }
}

<#
.SYNOPSIS
    Prompts for yes or no response.
#>
function Prompt-Yes-No {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    
    try {
        do {
            $response = $(Write-Host $Message -ForegroundColor Yellow -NoNewline; Read-Host)
            if ($response -ieq 'y' -or $response -ieq 'n') {
                return $response
            } else {
                Write-Host "Please enter 'y' or 'n'." -ForegroundColor Yellow
            }
        } while ($true)
    } catch {
        Write-Log -Level "ERROR" -Message "Error in Prompt-Yes-No: $($_.Exception.Message)"
        return "n"
    }
}

<#
.SYNOPSIS
    Prints enabled and disabled users with their group memberships.
#>
function Print-Users {
    [CmdletBinding()]
    param()
    
    try {
        $output = @()
        
        Write-Host "`n==== Enabled Users ====" -ForegroundColor Green
        $enabledUsersOutput = "==== Enabled Users ===="
        $enabledUsers = Get-ADUser -Filter * | Where-Object { $_.Enabled -eq $true -and $_.ObjectClass -eq "User" } | ForEach-Object {
            Write-Host "User: $($_.Name)"
            $enabledUsersOutput += "`nUser: $($_.Name)"
            $user = $_
            
            $groups = Get-ADGroup -Filter * | Where-Object {
                $user.SID -in ($_ | Get-ADGroupMember | Select-Object -ExpandProperty "SID")
            } | Select-Object -ExpandProperty "Name"
            
            $groupString = "Groups: $($groups -join ', ')"
            Write-Host $groupString
            $enabledUsersOutput += "`n$groupString"
            [System.GC]::Collect()
        }
        $output += $enabledUsersOutput
        
        Write-Host "`n==== Disabled Users ====" -ForegroundColor Red
        $disabledUsersOutput = "==== Disabled Users ===="
        $disabledUsers = Get-ADUser -Filter * | Where-Object Enabled -eq $false | ForEach-Object {
            Write-Host "User: $($_.Name)"
            $disabledUsersOutput += "`nUser: $($_.Name)"
            
            $user = $_
            $groups = Get-ADGroup -Filter * | Where-Object {
                $user.SID -in ($_ | Get-ADGroupMember | Select-Object -ExpandProperty "SID")
            } | Select-Object -ExpandProperty "Name"
            
            $groupString = "Groups: $($groups -join ', ')"
            Write-Host $groupString
            $disabledUsersOutput += "`n$groupString"
            [System.GC]::Collect()
        }
        $output += $disabledUsersOutput
        
        return $output
    } catch {
        Write-Log -Level "ERROR" -Message "Error in Print-Users: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Gets a comma-separated list from user input.
#>
function Get-Comma-Separated-List {
    [CmdletBinding()]
    param(
        [string]$category,
        [string]$message
    )
    
    try {
        $userInput = $null
        if ($message -ne "") {
            $userInput = Read-Host $message
            return $userInput.Split(",") | ForEach-Object { $_.Trim() }
        } elseif ($category -ne "") {
            $userInput = Read-Host "List $category. Separate by commas if multiple. NO SPACES"
            return $userInput.Split(",") | ForEach-Object { $_.Trim() }
        }
    } catch {
        Write-Log -Level "ERROR" -Message "Error in Get-Comma-Separated-List: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Configures Windows Firewall with AD firewall rules rule and optional port allowances.
    
.DESCRIPTION
    This function consolidates all firewall configuration logic. It sets the default configuration to Deny Inbound and Allow Outbound.
     It then handles three scenarios:
    
    - Scenario A: Script called with -f parameter - uses script-level $script:FirewallPortsArray (suppresses prompts)
    - Scenario B: Called from Quick-Harden without -f parameter - only allow AD ports
    - Scenario C: Called manually/interactively - prompts user for ports and confirmation
    
.PARAMETER FirewallPorts
    Optional array of port numbers to allow (function parameter). If script was called with -f parameter,
    those ports take precedence and this parameter is ignored.
    
.PARAMETER FromQuickHarden
    Switch indicating this is called from Quick-Harden sequence. Prevents interactive prompts unless
    no -f parameter was provided at script launch.
#>
function Configure-Firewall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int[]]$FirewallPorts = $null,
        
        [Parameter(Mandatory=$false)]
        [switch]$FromQuickHarden = $false
    )
    
    Invoke-HardeningOperation -OperationName "Configure Firewall" -ScriptBlock {
        try {
            # Determine which scenario we're in and get ports
            $portsToAllow = @()
            $usualPorts = @(53, 3389, 80, 445, 139, 22, 88, 67, 68, 135, 139, 389, 636, 3268, 3269, 464) | Sort-Object
            $commonScored = @(53, 3389, 80, 22)
            $commonADorDC = @(53, 139, 88, 67, 68, 135, 139, 389, 445, 636, 3268, 3269, 464)
            
            # Scenario A: Script called with -f parameter (ports provided via script parameter)
            if ($script:FirewallPortsProvided) {
                $portsToAllow = $script:FirewallPortsArray
                Write-Host "  [INFO] Using firewall ports from script parameter: $($portsToAllow -join ', ')" -ForegroundColor Yellow
                Write-Log -Level "INFO" -Message "Using firewall ports from -f parameter: $($portsToAllow -join ', ')"
            }
            # Scenario B: Called from Quick-Harden without -f parameter (Allow AD ports)
            # Different from local hardening because domain controllers need to function.
            elseif ($FromQuickHarden) {
                # Allow ports from function parameter and ad ports
                $portsToAllow = $FirewallPorts + $commonADorDC
                Write-Host "  [INFO] Using firewall ports from function parameter and AD ports: $($portsToAllow -join ', ')" -ForegroundColor Yellow
            }
            # Scenario C: Interactive/manual call (not from Quick-Harden, no -f parameter)
            else {
                # Interactive prompt for ports
                $ready = $false
                :outer while ($true) {
                    $desigPorts = Get-Comma-Separated-List -message "List needed port numbers for firewall config. Separate by commas."
                    
                    Write-Host "All the following ports that we suggest are either common scored services, or usually needed for AD processes. We will say which is which. While this box isn't domain bound, AD ports have been left on the list in case this box gets bound later."
                    
                    foreach ($item in $usualPorts) {
                        if ($desigPorts -notcontains $item) {
                            if ($item -in $commonScored) {
                                Write-Host "`nCommon Scored Service" -ForegroundColor Green
                            }
                            if ($item -in $commonADorDC) {
                                if ($item -eq 445 -or $item -eq 53) {
                                    Write-Host "`nCommon Scored Service" -ForegroundColor Green -NoNewline
                                    Write-Host " and" -ForegroundColor Cyan -NoNewline
                                    Write-Host " Common port needed for DC/AD processes" -ForegroundColor Red
                                } else {
                                    Write-Host "`nCommon port needed for DC/AD processes" -ForegroundColor Red
                                }
                            }
                            $confirmation = $(Write-Host "Need " -NoNewline) + $(Write-Host "$item" -ForegroundColor Green -NoNewline) + $(Write-Host ", " -NoNewline) + $(Write-Host "$($script:PortsObject.ports.$item.description)? " -ForegroundColor Cyan -NoNewline) + $(Write-Host "(y/n)" -ForegroundColor Yellow; Read-Host)
                            
                            while($true) {
                                if ($confirmation.toLower() -eq "y") {
                                    $desigPorts = @($desigPorts) + $item
                                    break
                                }
                                if ($confirmation.toLower() -eq "n") {
                                    break
                                }
                            }
                        }
                    }
                    
                    Write-Host "`n==== Designated Ports ====" -ForegroundColor Cyan
                    Write-Host ($desigPorts -join "`n") | Sort-Object
                    
                    $confirmation = ""
                    while($true) {
                        $confirmation = Prompt-Yes-No -Message "Are these ports correct (y/n)?"
                        if ($confirmation.toLower() -eq "y") {
                            $portsToAllow = $desigPorts
                            $ready = $true
                            break outer
                        }
                        if ($confirmation.toLower() -eq "n") {
                            $ready = $false
                            break
                        }
                    }
                }
                
                if ($ready -eq $false) {
                    Write-Log -Level "INFO" -Message "Firewall configuration skipped by user"
                    throw "Operation skipped by user"
                }
            }

            #Backup current firewall config
            $FirewallBackupPath = ".\fwback.wfw"
            Write-Host "Backing up current Windows Firewall policy to $FirewallBackupPath" -ForegroundColor Yellow
            try {
                # The -PolicyStore parameter specifies the active, persistent store.
                netsh advfirewall export "$FirewallBackupPath" | Out-Null
                Write-Host "Backup successful. To restore, use: Import-NetFirewallPolicy -Path '$FirewallBackupPath'" -ForegroundColor Green
            } catch {
                Write-Host "Error during backup: $($_.Exception.Message). Continuing with rule modification." -ForegroundColor Red
            }


            #Enable the firewall profiles and disable all pre-existing inbound and outbound rules
            Set-NetFirewallProfile -All -Enabled True
            Get-NetFirewallRule | Disable-NetFirewallRule

            # Create a new firewall rule to block all inbound traffic and allow outbound traffic
            Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow
            
            # If ports are specified, create Allow rules for them (with higher priority than Deny All so they're evaluated first)
            if ($portsToAllow.Count -gt 0) {
                Write-Host "  [ACTION] Creating Allow rules for specified ports..." -ForegroundColor White
                foreach ($port in $portsToAllow) {
                    # Try to get description from PortsObject, fallback to switch
                    $description = ""
                    if ($null -ne $script:PortsObject -and $null -ne $script:PortsObject.ports -and $null -ne $script:PortsObject.ports.$port) {
                        $description = $script:PortsObject.ports.$port.description
                    } else {
                        $description = switch ($port) {
                            22 { "SSH" }
                            53 { "DNS" }
                            80 { "HTTP" }
                            443 { "HTTPS" }
                            3389 { "RDP" }
                            5985 { "WinRM-HTTP" }
                            5986 { "WinRM-HTTPS" }
                            default { "Port-$port" }
                        }
                    }
                    
                    # Inbound Allow rules (with higher priority/lower number than Deny All so they're evaluated first)
                    New-NetFirewallRule -DisplayName "Allow TCP $port" -Direction Inbound -LocalPort $port -Action Allow -Protocol TCP -Enabled True
                    New-NetFirewallRule -DisplayName "Allow UDP $port" -Direction Inbound -LocalPort $port -Action Allow -Protocol UDP -Enabled True
                    Write-Log -Level "SUCCESS" -Message "Added inbound rules for port $port ($description)"
                }
                Write-Host "  [SUCCESS] Allow rules created for ports: $($portsToAllow -join ', ')" -ForegroundColor Green
                Write-Log -Level "SUCCESS" -Message "Firewall configured with ports: $($portsToAllow -join ', ')"
            } else {
                Write-Host "  [INFO] No ports specified - only AD rules applied" -ForegroundColor Yellow
                Write-Log -Level "INFO" -Message "Firewall configured with AD rules only (no other ports allowed)"
            }

            # We need to enable these rules to allow the domain to work, but we should restrict them to our local subnet
            # This may cause problems at nats
            Get-NetFirewallRule | Where-Object { $_.Name -like "*RPC*" -or $_.DisplayName -like "*135*" } | Set-NetFirewallRule -RemoteAddress "LocalSubnet" -Enabled "True"
            Get-NetFirewallRule | Where-Object { $_.Name -like "*SMB*" -or $_.DisplayName -like "*139*" -or $_.DisplayName -like "*445*" } | Set-NetFirewallRule -RemoteAddress "LocalSubnet" -Enabled "True"
            
            Write-Host "Firewall configured successfully" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Firewall configuration completed"
        } catch {
            if ($_.Exception.Message -ne "Operation skipped by user") {
                Write-Host "Firewall configuration failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-Log -Level "ERROR" -Message "Firewall configuration failed: $($_.Exception.Message)"
            }
            throw
        }
    }
}

<#
.SYNOPSIS
    Disables unnecessary services and network features.
#>
function Disable-Unnecessary-Services {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Disable Unnecessary Services" -ScriptBlock {
        # Get all active network adapters
        $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        
        if ($activeAdapters) {
            # Loop through each active adapter and disable IPv6
            foreach ($adapter in $activeAdapters) {
                try {
                    Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6
                    Write-Log -Level "SUCCESS" -Message "Disabled IPv6 on adapter: $($adapter.Name)"
                } catch {
                    Write-Log -Level "WARNING" -Message "Could not disable IPv6 on adapter $($adapter.Name): $($_.Exception.Message)"
                }
            }
        }
        
        # Get all IP-enabled adapters and disable NetBIOS over TCP/IP
        try {
            $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
            
            foreach ($adapter in $adapters) {
                try {
                    # Disable NetBIOS over TCP/IP (NetbiosOptions = 2)
                    $adapter.SetTcpipNetbios(2) | Out-Null
                    Write-Log -Level "SUCCESS" -Message "Disabled NetBIOS over TCP/IP on adapter"
                } catch {
                    Write-Log -Level "WARNING" -Message "Could not disable NetBIOS: $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Log -Level "WARNING" -Message "Could not get network adapters: $($_.Exception.Message)"
        }
        
        Write-Host "Unnecessary services disabled successfully" -ForegroundColor Green
    }
}

<#
.SYNOPSIS
    Quick harden function that performs essential hardening steps.
#>
function Quick-Harden {
    [CmdletBinding()]
    param()
    
    $operationName = if ($SkipPasswordChange) { "Quick Harden (No Password Change)" } else { "Quick Harden" }
    $totalSteps = if ($SkipPasswordChange) { 7 } else { 8 }
    $currentStep = 1
    
    Invoke-HardeningOperation -OperationName $operationName -ScriptBlock {
        Write-Host "`n=== QUICK HARDENING STARTED ===" -ForegroundColor Green
        Write-Host "This will perform essential hardening steps automatically..." -ForegroundColor Yellow
        Write-Host "`n[WARNING] Quick Harden will run automatically without user prompts." -ForegroundColor Yellow
        Write-Host "EXCEPTIONS: User input will be required for:" -ForegroundColor Cyan
        Write-Host "  - Add Competition Users (usernames/passwords)" -ForegroundColor Cyan
        Write-Host "  - Configure Splunk (Splunk server IP and OS version)" -ForegroundColor Cyan
        if ($SkipPasswordChange) {
            Write-Host "`n[NOTE] Password change step will be skipped (using -qp parameter)" -ForegroundColor Yellow
        }
        Write-Host ""
        
        # Call initialization first
        Initialize-System
        
        # Step 1: Upgrade SMB
        Write-Host "`nStep 1/8: Upgrading SMB..." -ForegroundColor Cyan
        Upgrade-SMB



        
        # Step 2: Change Passwords (skip if requested)
        #if (-not $SkipPasswordChange -and $SaltRandom) {
        #    Write-Host "`nStep 2/8: Changing Passwords using a random Salt..." -ForegroundColor Cyan
        #    Change-Passwords -randomSalt   
        if (-not $SkipPasswordChange ) {
                Write-Host "Step 2/8: Creating competiton users and changing passwords..." -ForegroundColor Green
                New-Zulu-Integration -Initial
        } else {
            Write-Host "`n[SKIPPED] Step 2/8: Password change step skipped (using -qp parameter)" -ForegroundColor Yellow
            Write-Log -Level "INFO" -Message "Password change step skipped per -qp parameter"
        }
        
        Write-Host "`nStep 3/8: No step 3 for now..." -ForegroundColor Cyan

        # Step 4: Configure Firewall
        Write-Host "`nStep 4/8: Configuring Firewall..." -ForegroundColor Cyan
        Configure-Firewall -FromQuickHarden
        
        # Step 5: Disable unnecessary services
        Write-Host "`nStep 5/8: Disabling Unnecessary Services..." -ForegroundColor Cyan
        Disable-Unnecessary-Services
        
        # Step 5: Add Competition Users (USER INPUT REQUIRED)
        #Write-Host "`nStep 5/8: Adding Competition Users..." -ForegroundColor Cyan
        #Write-Host "  [NOTE] User input will be required for usernames/passwords" -ForegroundColor Yellow
        #Add-Competition-Users
        
        # Step 6: Remove non-administrator users from Remote Desktop Users group
        if (-not $skipRDP) {
            Write-Host "`nStep 6/8: Removing non-administrator users from Remote Desktop Users group..." -ForegroundColor Cyan
            Remove-RDP-Users
        } else {
            Write-Host "`n[SKIPPED] Step 6/8: Removing non-administrator users from Remote Desktop Users group skipped (using -sr parameter)" -ForegroundColor Yellow
            Write-Log -Level "INFO" -Message "Remove RDP users step skipped per -sr parameter"
        }
        
        # Step 7: Configure Splunk (USER INPUT REQUIRED)
        Write-Host "`nStep 7/8: Configuring Splunk..." -ForegroundColor Cyan
        Write-Host "  [NOTE] User input will be required for Splunk configuration" -ForegroundColor Yellow
        $SplunkIP = Read-Host "`nInput IP address of Splunk Server"
        Download-Install-Setup-Splunk -IP $SplunkIP
        
        # Step 8: Set Execution Policy to Restricted
        Write-Host "`nStep 8/8: Setting Execution Policy to Restricted..." -ForegroundColor Cyan
        try {
            Set-ExecutionPolicy Restricted -Scope Process -Force
            Write-Host "Execution Policy set to Restricted successfully" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Set Execution Policy to Restricted"
        } catch {
            Write-Host "Failed to set Execution Policy: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Failed to set Execution Policy: $($_.Exception.Message)"
            throw "Failed to set Execution Policy: $($_.Exception.Message)"
        }
        
        Write-Host "`n=== QUICK HARDENING COMPLETED ===" -ForegroundColor Green
        Write-Host "Essential hardening steps have been completed successfully!" -ForegroundColor Green
        Write-Host "Next Hardening Steps: Turn on Windows Defender! Then run Windows Updates! It might take a while." -ForegroundColor Yellow
    }
}

<#
.SYNOPSIS
    Downloads, installs, and configures Splunk.
#>
function Download-Install-Setup-Splunk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Version,
        
        [Parameter(Mandatory=$true)]
        [string]$IP
    )
    
    Invoke-HardeningOperation -OperationName "Configure Splunk" -ScriptBlock {
        $splunkBeta = $true
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $downloadURL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk/splunk.ps1"
            
            Invoke-WebRequest -Uri $downloadURL -OutFile ./splunk.ps1
            Write-Log -Level "SUCCESS" -Message "Downloaded Splunk installation script"
            
            $splunkServer = "$($IP):9997"
            
            # Install splunk using downloaded script
            & ./splunk.ps1 $Version $SplunkServer
            
            Write-Log -Level "SUCCESS" -Message "Splunk installation completed"
        } catch {
            Write-Log -Level "ERROR" -Message "Splunk installation failed: $($_.Exception.Message)"
            throw
        }
    }
}

<#
.SYNOPSIS
    Installs the EternalBlue patch for the detected OS version.
#>
function Install-EternalBluePatch {
    [CmdletBinding()]
    param()
    
    # EternalBlue patch is only for older OS versions
    $eternalBlueCompatible = @("Client7", "Client8", "Server2008", "Server2008R2", "Server2012", "Server2012R2")
    
    # Track status for executive report
    $script:EternalBlueStatus = "Unknown"
    
    Invoke-HardeningOperation -OperationName "EternalBlue Mitigated" -OSCompatibility $eternalBlueCompatible -ScriptBlock {
        if (-not (Test-Path "patchURLs.json")) {
            Write-Host "patchURLs.json not found. Please run Initialize Context first." -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "patchURLs.json not found"
            throw "Required file not found"
        }
        
        $patchURLs = Get-Content -Raw -Path "patchURLs.json" | ConvertFrom-Json
        
        # Determine patch URL based on OS version keywords
        $patchURL = switch -Regex ($script:OSInfo.OSVersion) {
            '(?i)Vista'  { $patchURLs.Vista; break }
            'Windows 7'  { $patchURLs.'Windows 7'; break }
            'Windows 8'  { $patchURLs.'Windows 8'; break }
            '2008 R2'    { $patchURLs.'2008 R2'; break }
            '2008'       { $patchURLs.'2008'; break }
            '2012 R2'    { $patchURLs.'2012 R2'; break }
            '2012'       { $patchURLs.'2012'; break }
            default { throw "Unsupported OS version for EternalBlue patch: $($script:OSInfo.OSVersion)" }
        }
        
        Write-Host "Patch URL: $patchURL" -ForegroundColor Cyan
        
        # Download the patch to a temporary location
        $path = "$env:TEMP\eternalblue_patch.msu"
        
        Write-Host "Downloading patch file to $path" -ForegroundColor Cyan
        try {
            $wc = New-Object net.webclient
            $wc.Downloadfile($patchURL, $path)
            Write-Log -Level "SUCCESS" -Message "Downloaded EternalBlue patch"
        } catch {
            Write-Log -Level "ERROR" -Message "Failed to download EternalBlue patch: $($_.Exception.Message)"
            throw
        }
        
        # Install the patch
        Write-Host "Installing patch..." -ForegroundColor Cyan
        try {
            $process = Start-Process -FilePath "wusa.exe" -ArgumentList "$path /quiet /norestart" -Wait -PassThru
            if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
                throw "Patch installation returned exit code: $($process.ExitCode)"
            }
            Write-Log -Level "SUCCESS" -Message "EternalBlue patch installed successfully"
            $script:EternalBlueStatus = "Mitigated"
        } catch {
            Write-Log -Level "ERROR" -Message "Failed to install EternalBlue patch: $($_.Exception.Message)"
            $script:EternalBlueStatus = "Failed - $($_.Exception.Message)"
            throw
        } finally {
            # Cleanup
            if (Test-Path $path) {
                Remove-Item -Path $path -Force            }
        }
        
        Write-Host "Patch for $($script:OSInfo.OSVersion) installed successfully!" -ForegroundColor Green
    }
}

<#
.SYNOPSIS
    Upgrades SMB by enabling SMBv2/v3 and disabling SMBv1.
#>
function Upgrade-SMB {
    [CmdletBinding()]
    param()
    
    # SMB configuration varies by OS version
    # Get-SmbServerConfiguration is available on Windows Server 2012+ and Windows 8+
    # Older OS versions may need different approaches
    $smbUpgradeCompatible = @("Client8", "Client10", "Client11", "Server2012", "Server2012R2", "Server2016", "Server2019", "Server2022")
    
    Invoke-HardeningOperation -OperationName "Upgrade SMB" -OSCompatibility $smbUpgradeCompatible -ProgressMessage "Enabling SMBv2/v3 and disabling SMBv1 for improved security" -ScriptBlock {
        # Check if SMB module is available (required for Get-SmbServerConfiguration)
        if (-not (Get-Module -ListAvailable -Name SmbShare)) {
            Write-Host "[WARNING] SMB module not available. Attempting to import..." -ForegroundColor Yellow
            try {
                Import-Module SmbShare
                Write-Log -Level "SUCCESS" -Message "Imported SMB module"
            } catch {
                Write-Host "[WARNING] Could not import SMB module. SMB configuration may not work correctly." -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "SMB module not available: $($_.Exception.Message)"
            }
        }
        
        try {
            # Detect the current SMB version
            Write-Host "[INFO] Detecting current SMB configuration..." -ForegroundColor Cyan
            $smbConfig = Get-SmbServerConfiguration
            $smbv1Enabled = $smbConfig.EnableSMB1Protocol
            $smbv2Enabled = $smbConfig.EnableSMB2Protocol
            # EnableSMB3Protocol property may not exist on all OS versions, use try-catch
            $smbv3Enabled = $null
            try {
                $smbv3Enabled = $smbConfig.EnableSMB3Protocol
            } catch {
                # Property doesn't exist on this OS version
                $smbv3Enabled = $null
            }
            $restart = $false
            
            Write-Host "[INFO] Current SMB Configuration:" -ForegroundColor Cyan
            Write-Host "  SMBv1: $(if ($smbv1Enabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($smbv1Enabled) { 'Red' } else { 'Green' })
            Write-Host "  SMBv2: $(if ($smbv2Enabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($smbv2Enabled) { 'Green' } else { 'Yellow' })
            if ($null -ne $smbv3Enabled) {
                Write-Host "  SMBv3: $(if ($smbv3Enabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($smbv3Enabled) { 'Green' } else { 'Yellow' })
            }
            
            # Enable SMBv2 (SMBv3 is enabled automatically if supported on Server 2012+ and Windows 8+)
            if ($smbv2Enabled -eq $false) {
                Write-Host "[ACTION] Enabling SMBv2..." -ForegroundColor Yellow
                try {
                    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
                    Write-Host "[SUCCESS] SMBv2 enabled" -ForegroundColor Green
                    Write-Log -Level "SUCCESS" -Message "Enabled SMBv2/SMBv3"
                    $restart = $true
                } catch {
                    Write-Host "[FAILED] SMB upgrade failed: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Log -Level "ERROR" -Message "SMB upgrade failed: $($_.Exception.Message)"
                    throw
                }
            } else {
                Write-Host "[INFO] SMBv2 already enabled" -ForegroundColor Green
                Write-Log -Level "INFO" -Message "SMBv2 already enabled"
            }
            
            # Disable SMBv1 (vulnerable protocol)
            if ($smbv1Enabled -eq $true) {
                Write-Host "[ACTION] Disabling SMBv1 (vulnerable protocol)..." -ForegroundColor Yellow
                try {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
                    Write-Host "[SUCCESS] SMBv1 disabled" -ForegroundColor Green
                    Write-Log -Level "SUCCESS" -Message "Disabled SMBv1"
                    $restart = $true
                } catch {
                    Write-Host "[FAILED] SMB upgrade failed: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Log -Level "ERROR" -Message "SMB upgrade failed: $($_.Exception.Message)"
                    throw
                }
            } else {
                Write-Host "[INFO] SMBv1 already disabled" -ForegroundColor Green
                Write-Log -Level "INFO" -Message "SMBv1 already disabled"
            }
            
            # Restart might be required after these changes
            if ($restart -eq $true) {
                Write-Host "[WARNING] System restart recommended for SMB changes to take full effect" -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "System restart may be required for SMB changes"
            } else {
                Write-Host "[SUCCESS] SMB configuration is already optimal" -ForegroundColor Green
            }
        } catch {
            Write-Host "[ERROR] SMB upgrade failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "SMB upgrade failed: $($_.Exception.Message)" -Console
            throw
        }
    }
}

<#
.SYNOPSIS
    Patches Mimikatz by disabling WDigest credential storage.
#>
function Patch-Mimikatz {
    [CmdletBinding()]
    param()
    
    # WDigest registry path is available on Windows 7 and later
    # On Windows Server 2008/2008 R2, the path might need to be created
    $mimikatzCompatible = @("Client7", "Client8", "Client10", "Client11", "Server2008", "Server2008R2", "Server2012", "Server2012R2", "Server2016", "Server2019", "Server2022")
    
    Invoke-HardeningOperation -OperationName "Patch Mimikatz" -OSCompatibility $mimikatzCompatible -ProgressMessage "Disabling WDigest credential storage to prevent Mimikatz credential extraction" -ScriptBlock {
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        
        # OS-specific note: WDigest exists on Windows 7+ and Windows Server 2008+
        Write-Host "[INFO] This patch disables WDigest credential storage (UseLogonCredential = 0)" -ForegroundColor Cyan
        Write-Host "[INFO] This prevents Mimikatz from extracting plaintext credentials from memory" -ForegroundColor Cyan
        
        # Use the helper function with CreatePathIfMissing since WDigest path might not exist on older OS versions
        Set-RegistryValue -Path $registryPath -Name "UseLogonCredential" -Value 0 -PropertyType "DWord" -OperationName "Patch Mimikatz" -CreatePathIfMissing
        
        Write-Host "Mimikatz (WDigest) patch applied successfully" -ForegroundColor Green
        Write-Host "[INFO] System restart recommended for changes to take full effect" -ForegroundColor Yellow
        Write-Log -Level "SUCCESS" -Message "Mimikatz patch (WDigest) applied - UseLogonCredential set to 0"
    }
}

<#
.SYNOPSIS
    Displays the main menu.
#>
function Show-Main-Menu {
    #Clear-Host This line clears the console. Makes the menu look cleaner.
    Write-Host "`n==== Local Windows Hardening Menu ====" -ForegroundColor Green
    Write-Host "Prerequisites:"
    Write-Host "  - (A) Initialize Context BEFORE running hardening tasks" -ForegroundColor Yellow
    Write-Host "  - Configure Splunk (8) works best after Initialize Context (A)" -ForegroundColor Yellow
    Write-Host "`nSelect an option by number (or Q to quit):" -ForegroundColor Cyan
    Write-Host "  0) Print Execution Summary"
    Write-Host "  A) Initialize Context (download files, set variables)"
    Write-Host "  1) Quick Harden (essential steps only)"
    Write-Host "  2) Change Passwords"
    Write-Host "  3) Add Competition Users (also resets all user passwords)"
    Write-Host "  4) Remove RDP Users (reset RDP access - removes all users except ours)"
    Write-Host "  5) Add RDP Users (interactively add users to RDP group)"
    Write-Host "  6) Configure Firewall"
    Write-Host "  7) Disable Unnecessary Services"
    Write-Host "  8) Enable Advanced Auditing + Firewall Logging"
    Write-Host "  9) Configure Splunk"
    Write-Host " 10) Install EternalBlue Patch"
    Write-Host " 11) Upgrade SMB (enable v2/3, disable v1)"
    Write-Host " 12) Patch Mimikatz (WDigest)"
    Write-Host " 13) Set Execution Policy to Restricted"
    Write-Host " 14) Remove Admin Users"
}


#endregion

#region Main Script Execution

# Display OS information at startup
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Windows Hardening Script v2.0" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

# Detect operating system
try {
    $script:OSInfo = Get-OperatingSystemInfo
    $script:OSVersion = $script:OSInfo.OSVersion
    $script:OSBuild = $script:OSInfo.BuildNumber
    $script:OSEdition = $script:OSInfo.Edition
    $script:IsServer = $script:OSInfo.IsServer
    $script:IsServerCore = $script:OSInfo.IsServerCore
    
    Write-Host "`nDetected Operating System:" -ForegroundColor Yellow
    Write-Host "  OS Version: $($script:OSInfo.OSVersion)" -ForegroundColor White
    Write-Host "  Build Number: $($script:OSInfo.BuildNumber)" -ForegroundColor White
    Write-Host "  Edition: $($script:OSInfo.Edition)" -ForegroundColor White
    Write-Host "  Is Server: $($script:OSInfo.IsServer)" -ForegroundColor White
    Write-Host "  Is Server Core: $($script:OSInfo.IsServerCore)" -ForegroundColor White
    Write-Host ""
} catch {
    Write-Host "`n[ERROR] Failed to detect operating system: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "The script may not function correctly. Continue anyway? (y/n)" -ForegroundColor Yellow
    $continue = Read-Host
    if ($continue -ne "y") {
        exit 1
    }
}

# Detect Active Directory domain join status
try {
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $isDomainJoined = $computerSystem.PartOfDomain
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    if ($isDomainJoined) {
        Write-Host "  Active Directory Status: DOMAIN JOINED" -ForegroundColor Green
        Write-Host "  Domain: $($computerSystem.Domain)" -ForegroundColor White
    } else {
        Write-Host "  Active Directory Status: NOT DOMAIN JOINED" -ForegroundColor Yellow
        Write-Host "  Workgroup: $($computerSystem.Workgroup)" -ForegroundColor White
    }
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
} catch {
    Write-Host "`n[WARNING] Failed to detect Active Directory status: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "Continuing with script execution..." -ForegroundColor Yellow
    Write-Host ""
}


# Perform pre-flight checks
try {
    Test-Prerequisites
} catch {
    Write-Host "`n[ERROR] Pre-flight checks failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log -Level "CRITICAL" -Message "Pre-flight checks failed: $($_.Exception.Message)" -Console
    exit 1
}

# Check if Quick Harden parameter was provided
if ($QuickHarden) {
    Quick-Harden
}

# Main execution loop
while ($true) {
    Show-Main-Menu
    $choice = Read-Host "Selection"
    if ($choice -match '^(?i)q$') { break }
    
    try {
        switch ($choice) {
            '0' { Print-Log }
            'A' { Initialize-System }
            '1' { Write-Host "`n***Quick Hardening (Essential Steps Only)...***" -ForegroundColor Magenta; Quick-Harden }
            '2' { Write-Host "`n***Changing Passwords...***" -ForegroundColor Magenta; New-Zulu-Integration}
            '3' { Write-Host "`n***Adding Competition Users and Change Admin Password...***" -ForegroundColor Magenta; New-Zulu-Integration -Initial }
            '4' { Write-Host "`n***Removing all users from RDP group (resetting RDP access)...***" -ForegroundColor Magenta; Remove-RDP-Users }
            '5' { Write-Host "`n***Adding users to RDP group (interactive)...***" -ForegroundColor Magenta; Add-RDP-Users }
            '6' { Write-Host "`n***Configuring firewall...***" -ForegroundColor Magenta; Configure-Firewall }
            '7' { Write-Host "`n***Disabling unnecessary services...***" -ForegroundColor Magenta; Disable-Unnecessary-Services }
            '8' { 
                Write-Host "`n***Enabling Advanced Auditing and Firewall logging...***" -ForegroundColor Magenta
                if (Test-Path ".\advancedAuditing.ps1") {
                    try {
                        & .\advancedAuditing.ps1
                        Update-Log "Enable Advanced Auditing" "Executed successfully"
                        Write-Log -Level "SUCCESS" -Message "Advanced auditing script executed"
                    } catch {
                        Update-Log "Enable Advanced Auditing" "Failed with error: $($_.Exception.Message)"
                        Write-Log -Level "ERROR" -Message "Advanced auditing script failed: $($_.Exception.Message)"
                    }
                } else {
                    Write-Host "advancedAuditing.ps1 not found, skipping..." -ForegroundColor Yellow
                    Update-Log "Enable Advanced Auditing" "Skipped - file not found"
                    Write-Log -Level "WARNING" -Message "advancedAuditing.ps1 not found"
                }
                Write-Host "Enabling Firewall logging successful and blocked connections" -ForegroundColor Green
                try {
                    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True
                    Write-Log -Level "SUCCESS" -Message "Enabled firewall logging"
                } catch {
                    Write-Log -Level "WARNING" -Message "Could not enable firewall logging: $($_.Exception.Message)"
                }
            }
            '9' {
                Write-Host "`n***Configuring Splunk...***" -ForegroundColor Magenta
                $SplunkIP = Read-Host "`nInput IP address of Splunk Server"
                $SplunkVersion = Read-Host "`nInput OS Version (7, 8, 10, 11, 2012, 2016, 2019, 2022): "
                Download-Install-Setup-Splunk -Version $SplunkVersion -IP $SplunkIP
            }
            '10' { Write-Host "`n***Installing EternalBlue Patch...***" -ForegroundColor Magenta; Install-EternalBluePatch }
            '11' { Write-Host "`n***Upgrading SMB...***" -ForegroundColor Magenta; Upgrade-SMB }
            '12' { Write-Host "`n***Patching Mimikatz (WDigest)...***" -ForegroundColor Magenta; Patch-Mimikatz }
            '13' { 
                Write-Host "`n***Setting Execution Policy back to Restricted...***" -ForegroundColor Magenta
                try {
                    Set-ExecutionPolicy Restricted -Scope Process -Force
                    Update-Log "Set Execution Policy" "Executed successfully"
                    Write-Log -Level "SUCCESS" -Message "Set execution policy to Restricted"
                } catch {
                    Update-Log "Set Execution Policy" "Failed with error: $($_.Exception.Message)"
                    Write-Log -Level "ERROR" -Message "Could not set execution policy: $($_.Exception.Message)"
                }
            }
            '14' { Write-Host "`n***Removing Admin Users...***" -ForegroundColor Magenta; Remove-Admin-Users }
            Default { Write-Host "Invalid selection." -ForegroundColor Yellow }
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..." -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "Menu operation error: $($_.Exception.Message)" -Console
    }
    
    Write-Host "`nPress Enter to return to menu..." -ForegroundColor DarkGray
    Read-Host | Out-Null
}

# Final summary
Write-Host "`n***Script Completed!!!***" -ForegroundColor Green
Print-Log

# Write errors to file if any
if ($Error.Count -gt 0) {
    try {
        $errorFile = "$env:USERPROFILE\Desktop\hard.txt"
        $Error | Out-File $errorFile -Append -Encoding utf8
        Write-Log -Level "INFO" -Message "Errors written to $errorFile"
    } catch {
        Write-Log -Level "WARNING" -Message "Could not write errors to file: $($_.Exception.Message)"
    }
}

# Final log entry
Write-Log -Level "INFO" -Message "=== Script Execution Completed ===" -Console
Write-Log -Level "INFO" -Message "Log file location: $script:LogFile" -Console

# Determine final status
Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
if ($script:OperationResults.Failed -eq 0 -and $script:OperationResults.CriticalErrors.Count -eq 0 -and $script:OperationResults.Skipped -eq 0) {
    Write-Host "[SUCCESS] Hardening completed successfully!" -ForegroundColor Green
    Write-Host "All $($script:OperationResults.Total) operation(s) completed without errors." -ForegroundColor Green
    Write-Log -Level "SUCCESS" -Message "=== Hardening completed successfully ===" -Console
} elseif ($script:OperationResults.Failed -eq 0 -and $script:OperationResults.CriticalErrors.Count -eq 0) {
    Write-Host "[SUCCESS] Hardening completed with warnings!" -ForegroundColor Green
    Write-Host "All operations completed, but $($script:OperationResults.Skipped) operation(s) were skipped (see details above)." -ForegroundColor Yellow
    Write-Log -Level "SUCCESS" -Message "=== Hardening completed with warnings ===" -Console
} else {
    Write-Host "[WARNING] Hardening completed with errors - review the summary above" -ForegroundColor Yellow
    Write-Host "Failed Operations: $($script:OperationResults.Failed)" -ForegroundColor Red
    Write-Host "Critical Errors: $($script:OperationResults.CriticalErrors.Count)" -ForegroundColor Red
    if ($script:OperationResults.CriticalErrors.Count -gt 0) {
        Write-Host "`nCritical errors occurred. Please review the errors above before considering the system hardened." -ForegroundColor Red
    }
    Write-Log -Level "ERROR" -Message "=== Hardening completed with errors ===" -Console
}
Write-Host ("=" * 60) -ForegroundColor Cyan

#endregion

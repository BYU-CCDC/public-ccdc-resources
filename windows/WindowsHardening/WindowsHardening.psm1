#Requires -Version 5.1

# WindowsHardening Module Loader
# Dot-sources Public/**/*.ps1 then Dev/*.ps1 (sorted alphabetically)
# Initializes $script:HardeningContext, then detects OS and DC status (see end of file)

# Bundled data files, including the gpo-v1 draft archive.
$script:DataPath = Join-Path $PSScriptRoot 'Data'
$script:DefaultLogPath = 'C:\Windows\Logs\Hardening'

# Initialize the HardeningContext placeholder
$script:HardeningContext = @{
    OS                 = $null
    LogPath            = $null
    CurrentUser        = $null
    Ports              = $null
    Initialized        = $false
}

# Shared state for logging and operation tracking
$script:LogFile = $null
$script:log = @{}
$script:OperationResults = @{
    Total          = 0
    Successful     = 0
    Failed         = 0
    Skipped        = 0
    Warnings       = @()
}

# Dot-source Public functions (recursing into subfolders).
$publicPath = Join-Path $PSScriptRoot 'Public'
if (Test-Path $publicPath) {
    Get-ChildItem -Path $publicPath -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName |
        ForEach-Object {
            . $_.FullName
        }
}

# Dot-source Dev (R&D) functions
$devPath = Join-Path $PSScriptRoot 'Dev'
if (Test-Path $devPath) {
    Get-ChildItem -Path $devPath -Filter '*.ps1' -ErrorAction SilentlyContinue |
        Sort-Object Name |
        ForEach-Object {
            . $_.FullName
        }
}

# Detect the OS and DC status once, at import, so orchestrators and standalone
# functions all read the same cached $script:HardeningContext.OS. Logging and
# data-file setup stay in Initialize-System, which runs on first use.
try {
    $null = Get-OperatingSystemInfo
} catch {
    Write-Warning "OS detection failed at import; OS-specific steps will be skipped: $($_.Exception.Message)"
}

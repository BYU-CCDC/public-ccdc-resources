<#
.SYNOPSIS
    Downloads and imports the WindowsHardening module ZIP from public-ccdc-resources.
.DESCRIPTION
    Downloads windows/WindowsHardening.zip, validates the archive contains the
    WindowsHardening module, and replaces only that module under -Destination.
    Requires an elevated Windows PowerShell 5.1 session. Unsigned scripts are
    allowed for this session only (Process scope).
.PARAMETER ModuleZipUri
    Direct URL to the module ZIP. Defaults to the public resource package.
.PARAMETER Destination
    Parent folder for the WindowsHardening module. Default is the all-users
    Windows PowerShell module directory under Program Files.
.EXAMPLE
    irm https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/loader.ps1 | iex
#>
[CmdletBinding()]
param(
    [string]$ModuleZipUri = 'https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/WindowsHardening.zip',
    [string]$Destination = (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
)

# Run in a child scope so helper variables do not leak into the caller when piped to iex.
& {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this loader from an elevated Windows PowerShell 5.1 session to install WindowsHardening for all users.'
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    try { Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop }
    catch { Write-Warning "Could not set Process execution policy: $($_.Exception.Message)" }

    $work = Join-Path ([IO.Path]::GetTempPath()) "CCDC-Win-Module-$([guid]::NewGuid().ToString('N'))"
    $zip = Join-Path $work 'WindowsHardening.zip'
    $stagedModule = Join-Path $work 'WindowsHardening'
    $moduleDestination = Join-Path $Destination 'WindowsHardening'
    $previousModule = Join-Path $Destination "WindowsHardening.previous-$([guid]::NewGuid().ToString('N'))"

    try {
        New-Item -ItemType Directory -Path $work -Force -ErrorAction Stop | Out-Null
        Write-Host "Downloading WindowsHardening from $ModuleZipUri" -ForegroundColor Cyan
        Invoke-WebRequest -Uri $ModuleZipUri -OutFile $zip -UserAgent 'WindowsHardening-loader' -UseBasicParsing -ErrorAction Stop
        if ((Get-Item -LiteralPath $zip -ErrorAction Stop).Length -eq 0) { throw 'The downloaded module ZIP is empty.' }

        Expand-Archive -LiteralPath $zip -DestinationPath $work -Force -ErrorAction Stop
        if (-not (Test-Path -LiteralPath (Join-Path $stagedModule 'WindowsHardening.psd1') -PathType Leaf)) {
            throw 'The archive must contain WindowsHardening/WindowsHardening.psd1 at its root.'
        }
        Test-ModuleManifest -Path (Join-Path $stagedModule 'WindowsHardening.psd1') -ErrorAction Stop | Out-Null

        New-Item -ItemType Directory -Path $Destination -Force -ErrorAction Stop | Out-Null
        if (Test-Path -LiteralPath $moduleDestination) {
            Move-Item -LiteralPath $moduleDestination -Destination $previousModule -ErrorAction Stop
        }
        try {
            Move-Item -LiteralPath $stagedModule -Destination $moduleDestination -ErrorAction Stop
        } catch {
            if (Test-Path -LiteralPath $previousModule) {
                Move-Item -LiteralPath $previousModule -Destination $moduleDestination -ErrorAction Stop
            }
            throw
        }

        try {
            if ($env:OS -eq 'Windows_NT') {
                Get-ChildItem -LiteralPath $moduleDestination -Recurse -File | Unblock-File
            }
            Import-Module (Join-Path $moduleDestination 'WindowsHardening.psd1') -Force -Global -ErrorAction Stop
        } catch {
            Remove-Module -Name WindowsHardening -Force -ErrorAction Ignore
            Remove-Item -LiteralPath $moduleDestination -Recurse -Force -ErrorAction Ignore
            if (Test-Path -LiteralPath $previousModule) {
                Move-Item -LiteralPath $previousModule -Destination $moduleDestination -ErrorAction Stop
            }
            throw
        }
        Remove-Item -LiteralPath $previousModule -Recurse -Force -ErrorAction Ignore
        $module = Get-Module WindowsHardening
        Write-Host "Loaded WindowsHardening $($module.Version) from $ModuleZipUri" -ForegroundColor Green
        Write-Host 'Run Invoke-WindowsHardening to start, or Get-Command -Module WindowsHardening to list commands.' -ForegroundColor Green
    } finally {
        Remove-Item -LiteralPath $zip -Force -ErrorAction Ignore
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction Ignore
    }
}

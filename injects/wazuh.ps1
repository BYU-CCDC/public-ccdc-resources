
# Wazuh Agent Installer for Windows
# Run this as Administrator

# --- Configuration ---
$wazuhManagerIp = "192.168.220.240"
$installerPath = "C:\Temp\wazuh-agent.msi"
# Using a specific recent version ensures stability. You can update this version number if needed.
$downloadUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.10.1-1.msi"

# 1. Check for Administrator Privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You do not have Administrator rights to run this script! Please re-run as Administrator."
    Break
}

# 2. Setup Workspace
# Create the Temp directory if it doesn't exist
if (-not (Test-Path C:\Temp)) {
    New-Item -Path C:\Temp -ItemType Directory | Out-Null
}

# 3. Download the Agent
Write-Host "--- Downloading Wazuh Agent..." -ForegroundColor Cyan
# Force TLS 1.2 for older Windows Servers (2012/2016)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath
}
catch {
    Write-Error "Failed to download agent. Check internet connection or DNS."
    Break
}

# 4. Install the Agent
Write-Host "--- Installing Wazuh Agent pointing to $wazuhManagerIp..." -ForegroundColor Cyan

# Arguments:
# /q = Quiet mode (no UI)
# /i = Install
# WAZUH_MANAGER = The IP of your Wazuh Manager
# WAZUH_REGISTRATION_SERVER = Use the same IP for registration
# WAZUH_AGENT_NAME = Defaults to computer name
$installArgs = "/i `"$installerPath`" /q WAZUH_MANAGER=`"$wazuhManagerIp`" WAZUH_REGISTRATION_SERVER=`"$wazuhManagerIp`" WAZUH_AGENT_NAME=`"$env:COMPUTERNAME`""

$process = Start-Process -FilePath msiexec.exe -ArgumentList $installArgs -Wait -PassThru

if ($process.ExitCode -eq 0) {
    Write-Host "--- Installation Successful! ---" -ForegroundColor Green
} else {
    Write-Error "Installation failed with exit code $($process.ExitCode)"
}

# 5. Start the Service
Write-Host "--- Starting Wazuh Service..." -ForegroundColor Cyan
Start-Service wazuhsvc
Get-Service wazuhsvc
Write-Host "Done."

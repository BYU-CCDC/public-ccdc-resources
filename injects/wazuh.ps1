# Wazuh Agent Installer for Windows (Version 4.7.5)
# Run this script as Administrator

# ---------------- CONFIGURATION ----------------
$wazuhVersion = "4.7.5"
$downloadUrl  = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$wazuhVersion-1.msi"
$tempFolder   = "C:\Temp"
$installerPath = "$tempFolder\wazuh-agent.msi"
$logPath      = "$tempFolder\wazuh-install.log"

# ---------------- INPUT ----------------
$wazuhManagerIp = Read-Host "Enter the Wazuh Manager IP Address"

if ([string]::IsNullOrWhiteSpace($wazuhManagerIp)) {
    Write-Error "No Wazuh Manager IP provided. Exiting."
    exit 1
}

# ---------------- ADMIN CHECK ----------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# ---------------- WORKSPACE ----------------
if (-not (Test-Path $tempFolder)) {
    New-Item -Path $tempFolder -ItemType Directory | Out-Null
}

# ---------------- DOWNLOAD ----------------
Write-Host "Downloading Wazuh Agent $wazuhVersion..." -ForegroundColor Cyan
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

try {
    # Using BITS for a more reliable download on Windows
    Start-BitsTransfer -Source $downloadUrl -Destination $installerPath -ErrorAction Stop
}
catch {
    Write-Host "BITS transfer failed, falling back to Invoke-WebRequest..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath -UseBasicParsing
    }
    catch {
        Write-Error "Failed to download Wazuh agent MSI."
        exit 1
    }
}

# ---------------- INSTALL & ENROLL ----------------
Write-Host "Installing and enrolling Wazuh Agent..." -ForegroundColor Cyan

$installArgs = "/i `"$installerPath`" /q /L*V `"$logPath`" WAZUH_MANAGER=`"$wazuhManagerIp`""

$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru

if ($process.ExitCode -ne 0) {
    Write-Error "MSI install failed (exit code $($process.ExitCode)). Check $logPath"
    exit 1
}

# ---------------- DYNAMIC PATH VERIFICATION ----------------
$agentPath = if (Test-Path "${env:ProgramFiles}\ossec-agent") {
    "${env:ProgramFiles}\ossec-agent"
} elseif (Test-Path "${env:ProgramFiles(x86)}\ossec-agent") {
    "${env:ProgramFiles(x86)}\ossec-agent"
}

if (-not $agentPath) {
    Write-Error "Wazuh installation directory not found."
    exit 1
}

# ---------------- VERIFY & START ----------------
Write-Host "Ensuring service is started..." -ForegroundColor Cyan
$serviceName = "WazuhSvc"

Start-Sleep -Seconds 2

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($service) {
    if ($service.Status -ne 'Running') {
        Start-Service -Name $serviceName
    }
    Write-Host "Wazuh Agent is installed and running." -ForegroundColor Green
} else {
    Write-Error "Wazuh service not found. Check logs at $logPath"
}

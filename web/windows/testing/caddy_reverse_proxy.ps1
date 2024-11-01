# Define variables
$caddyDownloadUrl = "https://github.com/caddyserver/caddy/releases/latest/download/caddy_windows_amd64.zip"
$caddyInstallDir = "C:\Caddy"
$caddyExePath = "$caddyInstallDir\caddy.exe"
$caddyfile = "$caddyInstallDir\Caddyfile"
$logFile = "$caddyInstallDir\caddy_setup_log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Step 1: Create the Caddy installation directory if it doesn’t exist
if (!(Test-Path -Path $caddyInstallDir)) {
    New-Item -Path $caddyInstallDir -ItemType Directory -Force | Out-Null
    Write-Output "$currentDateTime - Created Caddy installation directory at $caddyInstallDir" | Out-File -FilePath $logFile -Append
}

# Step 2: Download and install Caddy
$caddyZipPath = "$env:TEMP\caddy.zip"
if (!(Test-Path -Path $caddyExePath)) {
    Write-Output "$currentDateTime - Downloading Caddy..." | Out-File -FilePath $logFile -Append
    Invoke-WebRequest -Uri $caddyDownloadUrl -OutFile $caddyZipPath
    Write-Output "$currentDateTime - Caddy downloaded to $caddyZipPath" | Out-File -FilePath $logFile -Append

    # Extract Caddy executable
    Write-Output "$currentDateTime - Extracting Caddy executable..." | Out-File -FilePath $logFile -Append
    Expand-Archive -Path $caddyZipPath -DestinationPath $caddyInstallDir -Force
} else {
    Write-Output "$currentDateTime - Caddy is already installed at $caddyExePath" | Out-File -FilePath $logFile -Append
}

# Step 3: Prompt user for reverse proxy configuration
Write-Output "Enter the domain you want to use for the reverse proxy (e.g., example.com):"
$domain = Read-Host
Write-Output "Enter the backend server URL to proxy to (e.g., http://localhost:8080):"
$backend = Read-Host

# Step 4: Create the Caddyfile configuration
$caddyConfig = @"
# Caddy reverse proxy configuration
$domain {
    reverse_proxy $backend
}
"@
Set-Content -Path $caddyfile -Value $caddyConfig
Write-Output "$currentDateTime - Caddyfile created at $caddyfile" | Out-File -FilePath $logFile -Append

# Step 5: Set up Caddy as a Windows Service using NSSM (Non-Sucking Service Manager)
$nssmDownloadUrl = "https://nssm.cc/release/nssm-2.24.zip"
$nssmPath = "$env:TEMP\nssm.zip"
$nssmExtractDir = "$env:TEMP\nssm"
$nssmExe = "$nssmExtractDir\win64\nssm.exe"

if (!(Test-Path -Path $nssmExe)) {
    Write-Output "$currentDateTime - Downloading NSSM..." | Out-File -FilePath $logFile -Append
    Invoke-WebRequest -Uri $nssmDownloadUrl -OutFile $nssmPath
    Expand-Archive -Path $nssmPath -DestinationPath $nssmExtractDir -Force
}

Write-Output "$currentDateTime - Installing Caddy as a Windows service..." | Out-File -FilePath $logFile -Append
& $nssmExe install Caddy "$caddyExePath" "run" "--config" "$caddyfile"
& $nssmExe set Caddy AppDirectory $caddyInstallDir
& $nssmExe set Caddy Start SERVICE_AUTO_START

# Step 6: Start the Caddy service
Start-Service -Name "Caddy"
Write-Output "$currentDateTime - Caddy service started" | Out-File -FilePath $logFile -Append

Write-Output "$currentDateTime - Caddy reverse proxy setup completed. Check logs at $logFile" | Out-File -FilePath $logFile -Append

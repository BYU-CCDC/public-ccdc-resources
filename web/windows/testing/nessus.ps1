# Define variables
$nessusVersion = "10.5.0"  # Specify the desired Nessus Agent version
$nessusDownloadUrl = "https://www.tenable.com/downloads/api/v1/public/pages/nessus-agents/downloads/13801/download?i_agree_to_tenable_license_agreement=true"
$nessusInstallerPath = "$env:TEMP\NessusAgent-$nessusVersion.msi"
$serverHost = "your-nessus-manager-server.com"  # Replace with your Nessus Manager or Tenable.io server
$groupKey = "YOUR_GROUP_KEY"  # Replace with the appropriate group key from Tenable
$logFile = "C:\WebBackups\Nessus_Agent_Install_Log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Output "$currentDateTime - Starting Nessus Agent Installation..." | Out-File -FilePath $logFile -Append

# Step 1: Download the Nessus Agent MSI
if (!(Test-Path -Path $nessusInstallerPath)) {
    Write-Output "$currentDateTime - Downloading Nessus Agent..." | Out-File -FilePath $logFile -Append
    Invoke-WebRequest -Uri $nessusDownloadUrl -OutFile $nessusInstallerPath
    Write-Output "$currentDateTime - Nessus Agent downloaded to $nessusInstallerPath." | Out-File -FilePath $logFile -Append
} else {
    Write-Output "$currentDateTime - Nessus Agent installer already exists, skipping download." | Out-File -FilePath $logFile -Append
}

# Step 2: Install Nessus Agent
try {
    Write-Output "$currentDateTime - Installing Nessus Agent..." | Out-File -FilePath $logFile -Append
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$nessusInstallerPath`" /qn /norestart" -Wait -NoNewWindow
    Write-Output "$currentDateTime - Nessus Agent installation completed." | Out-File -FilePath $logFile -Append
} catch {
    Write-Output "$currentDateTime - Nessus Agent installation failed. Error: $_" | Out-File -FilePath $logFile -Append
    exit
}

# Step 3: Configure Nessus Agent to link with the Nessus Manager/Tenable.io server
Write-Output "$currentDateTime - Linking Nessus Agent to server $serverHost with group key..." | Out-File -FilePath $logFile -Append
$registerAgentCommand = "C:\Program Files\Tenable\Nessus Agent\nessuscli.exe" + `
                        " agent link --key=$groupKey --host=$serverHost --port=8834 --name=$(hostname)"

try {
    Invoke-Expression $registerAgentCommand
    Write-Output "$currentDateTime - Nessus Agent linked successfully." | Out-File -FilePath $logFile -Append
} catch {
    Write-Output "$currentDateTime - Failed to link Nessus Agent. Error: $_" | Out-File -FilePath $logFile -Append
    exit
}

# Step 4: Start Nessus Agent service
Write-Output "$currentDateTime - Starting Nessus Agent service..." | Out-File -FilePath $logFile -Append
Start-Service -Name "Tenable Nessus Agent"
Start-Sleep -Seconds 5  # Wait for the service to start

# Check if the service is running
$serviceStatus = Get-Service -Name "Tenable Nessus Agent"
if ($serviceStatus.Status -eq "Running") {
    Write-Output "$currentDateTime - Nessus Agent service started successfully." | Out-File -FilePath $logFile -Append
} else {
    Write-Output "$currentDateTime - Failed to start Nessus Agent service." | Out-File -FilePath $logFile -Append
    exit
}

Write-Output "$currentDateTime - Nessus Agent Installation and Configuration Completed Successfully." | Out-File -FilePath $logFile -Append
Write-Output "Nessus Agent is successfully installed, linked to the server, and running."

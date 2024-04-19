# Define base URL and local path for scripts and logs
$baseURL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/monitoring"
$scriptNames = @("checkProcessHollowing.ps1", "suspiciousServices.ps1")
$localScriptPath = ".\monitoringScripts"
$logDir = ".\monitoringLogs"

# Ensure the script and log directories exist
if (-not (Test-Path $localScriptPath)) {
    New-Item -Path $localScriptPath -ItemType Directory
}
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory
}

# Create a WebClient object
$wc = New-Object System.Net.WebClient

# Download scripts using WebClient
foreach ($scriptName in $scriptNames) {
    $url = $baseURL + $scriptName
    $destinationPath = Join-Path $localScriptPath $scriptName
    try {
        $wc.DownloadFile($url, $destinationPath)
        Write-Host "Downloaded '$scriptName' successfully."
    } catch {
        Write-Host "Failed to download '$scriptName': $_"
        continue
    }
}

# Dispose of the WebClient
$wc.Dispose()

# Create a Scheduled Task for each script
foreach ($scriptName in $scriptNames) {
    $taskName = "Monitor - " + $scriptName.Replace(".ps1", "")
    $scriptFullPath = Join-Path $localScriptPath $scriptName
    $logFullPath = Join-Path $logDir ($scriptName.Replace(".ps1", ".log"))

    # Task action to run PowerShell script and output to both console and log file
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptFullPath`" | Tee-Object -FilePath `"$logFullPath`""

    # Task trigger - every 5 minutes
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)

    # Task settings
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    # Register the task
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force
}

# Configure Splunk Universal Forwarder to ingest the log files
$splunkInputsConfPath = "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
$splunkConfEntry = @"
[monitor://$logDir\*.log]
disabled = false
index = windows
sourcetype = _json
"@
# Check if the inputs.conf file exists
if (Test-Path $splunkInputsConfPath) {
    # Read the current contents of inputs.conf
    $inputsContent = Get-Content -Path $splunkInputsConfPath -Raw
    
    # Check if our specific configuration already exists in inputs.conf
    if ($inputsContent -notmatch [regex]::Escape("[monitor://$logDir\*.log]")) {
        Write-Host "Appending new monitoring configuration to inputs.conf..."
        
        # Ensure two new lines precede the new configuration if the file isn't empty
        if ($inputsContent -ne "") {
            $splunkConfEntry = "`n`n" + $splunkConfEntry
        }
        
        # Append the new configuration to the file
        Add-Content -Path $splunkInputsConfPath -Value $splunkConfEntry
    } else {
        Write-Host "Monitoring configuration already exists in inputs.conf."
    }
} else {
    Write-Host "Creating new inputs.conf and adding monitoring configuration..."
    
    # Create the file and add the monitoring configuration
    New-Item -Path $splunkInputsConfPath -ItemType File -Force
    Add-Content -Path $splunkInputsConfPath -Value $splunkConfEntry
}

# Restart Splunk Universal Forwarder to apply changes
Write-Host "Restarting Splunk Universal Forwarder to apply changes..."
Stop-Service -Name SplunkForwarder
Start-Service -Name SplunkForwarder

Write-Host "Splunk Universal Forwarder configuration updated and service restarted."
Write-Host "Setup completed. Monitoring scripts are now scheduled and Splunk is configured to ingest logs."

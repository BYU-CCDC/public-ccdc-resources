# DLP ??
# Define variables
$wazuhAgentVersion = "4.4.0"  # Update to the desired Wazuh Agent version
$wazuhServerIP = "192.168.1.100"  # Replace with your Wazuh server IP or hostname
$installDir = "C:\Program Files (x86)\ossec-agent"
$wazuhDownloadUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$wazuhAgentVersion.msi"
$wazuhAgentInstaller = "$env:TEMP\wazuh-agent-$wazuhAgentVersion.msi"
$logFile = "C:\WebBackups\Wazuh_Agent_Install_Log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Output "$currentDateTime - Starting Wazuh Agent Installation..." | Out-File -FilePath $logFile -Append

# Function to download a file, compatible with older PowerShell versions
function Download-File {
    param (
        [string]$url,
        [string]$destinationPath
    )

    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($url, $destinationPath)
        Write-Output "$currentDateTime - Downloaded file from $url to $destinationPath" | Out-File -FilePath $logFile -Append
    } catch {
        Write-Error "Failed to download file from $url. Error: $_"
        Write-Output "$currentDateTime - Failed to download file from $url. Error: $_" | Out-File -FilePath $logFile -Append
        exit
    }
}

# Download Wazuh Agent MSI if it doesn't already exist
if (!(Test-Path -Path $wazuhAgentInstaller)) {
    Download-File -url $wazuhDownloadUrl -destinationPath $wazuhAgentInstaller
} else {
    Write-Output "$currentDateTime - Wazuh Agent installer already exists at $wazuhAgentInstaller, skipping download." | Out-File -FilePath $logFile -Append
}

# Install Wazuh Agent
try {
    Write-Output "$currentDateTime - Installing Wazuh Agent..." | Out-File -FilePath $logFile -Append
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$wazuhAgentInstaller`" /qn /norestart" -Wait -NoNewWindow
    Write-Output "$currentDateTime - Wazuh Agent installation completed." | Out-File -FilePath $logFile -Append
} catch {
    Write-Error "Failed to install Wazuh Agent. Error: $_"
    Write-Output "$currentDateTime - Failed to install Wazuh Agent. Error: $_" | Out-File -FilePath $logFile -Append
    exit
}

# Configure Wazuh Agent with the server IP
function Configure-WazuhAgent {
    $configFilePath = "$installDir\ossec.conf"
    
    if (Test-Path -Path $configFilePath) {
        # Load the XML configuration file
        [xml]$config = Get-Content -Path $configFilePath

        # Locate the <server> section and update the <address> with the Wazuh server IP
        $serverNode = $config.ossec_config.client.server
        if ($serverNode -ne $null) {
            $serverNode.address = $wazuhServerIP
            Write-Output "$currentDateTime - Configuring Wazuh Agent to connect to server at $wazuhServerIP" | Out-File -FilePath $logFile -Append
            
            # Save changes to the configuration file
            $config.Save($configFilePath)
            Write-Output "$currentDateTime - Wazuh Agent configuration file updated successfully." | Out-File -FilePath $logFile -Append
        } else {
            Write-Error "Server configuration section not found in ossec.conf."
            Write-Output "$currentDateTime - Error: Server configuration section not found in ossec.conf." | Out-File -FilePath $logFile -Append
            exit
        }
    } else {
        Write-Error "Configuration file not found: $configFilePath"
        Write-Output "$currentDateTime - Error: Configuration file not found: $configFilePath" | Out-File -FilePath $logFile -Append
        exit
    }
}

Configure-WazuhAgent

# Start and verify Wazuh Agent service
function Start-WazuhService {
    Write-Output "$currentDateTime - Starting Wazuh Agent service..." | Out-File -FilePath $logFile -Append
    Start-Service -Name "WazuhAgent"
    Start-Sleep -Seconds 5  # Wait for service to start

    # Check if the service is running
    $serviceStatus = Get-Service -Name "WazuhAgent"
    if ($serviceStatus.Status -eq "Running") {
        Write-Output "$currentDateTime - Wazuh Agent service started successfully." | Out-File -FilePath $logFile -Append
    } else {
        Write-Error "Failed to start Wazuh Agent service."
        Write-Output "$currentDateTime - Failed to start Wazuh Agent service." | Out-File -FilePath $logFile -Append
        exit
    }
}

Start-WazuhService

# Verify connectivity to the Wazuh server
function Verify-Connectivity {
    Write-Output "$currentDateTime - Verifying connectivity to Wazuh server..." | Out-File -FilePath $logFile -Append
    $ping = Test-Connection -ComputerName $wazuhServerIP -Count 2 -ErrorAction SilentlyContinue

    if ($ping) {
        Write-Output "$currentDateTime - Connectivity to Wazuh server $wazuhServerIP verified." | Out-File -FilePath $logFile -Append
    } else {
        Write-Error "Failed to connect to Wazuh server at $wazuhServerIP."
        Write-Output "$currentDateTime - Error: Failed to connect to Wazuh server at $wazuhServerIP." | Out-File -FilePath $logFile -Append
        exit
    }
}

Verify-Connectivity

Write-Output "$currentDateTime - Wazuh Agent Installation and Configuration Completed Successfully." | Out-File -FilePath $logFile -Append
Write-Output "Wazuh Agent is successfully installed and configured to communicate with the Wazuh server at $wazuhServerIP."

# Define variables
$ossecVersion = "3.6.0"  # Specify the version you want to install
$ossecDownloadUrl = "https://updates.atomicorp.com/channels/atomic/windows/OSSEC-Agent-$ossecVersion.msi"
$ossecInstallerPath = "$env:TEMP\OSSEC-Agent-$ossecVersion.msi"
$installDir = "C:\Program Files (x86)\OSSEC Agent"
$configFilePath = "$installDir\ossec.conf"
$serverIP = "192.168.1.100"  # Replace with your OSSEC server IP or hostname
$logFile = "C:\WebBackups\OSSEC_Agent_Install_Log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Logging function
function Write-Log {
    param (
        [string]$message
    )
    Write-Output "$currentDateTime - $message" | Out-File -FilePath $logFile -Append
}

Write-Log "Starting OSSEC Agent Installation..."

# Step 1: Download the OSSEC Agent MSI
if (!(Test-Path -Path $ossecInstallerPath)) {
    Write-Log "Downloading OSSEC Agent..."
    try {
        Invoke-WebRequest -Uri $ossecDownloadUrl -OutFile $ossecInstallerPath -ErrorAction Stop
        Write-Log "OSSEC Agent downloaded to $ossecInstallerPath."
    } catch {
        Write-Log "Failed to download OSSEC Agent. Error: $_"
        exit
    }
} else {
    Write-Log "OSSEC Agent installer already exists, skipping download."
}

# Step 2: Install OSSEC Agent
try {
    Write-Log "Installing OSSEC Agent..."
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$ossecInstallerPath`" /qn /norestart" -Wait -NoNewWindow
    Write-Log "OSSEC Agent installation completed."
} catch {
    Write-Log "OSSEC Agent installation failed. Error: $_"
    exit
}

# Step 3: Configure OSSEC Agent to connect to the server
function Set-OSSEC {
    if (Test-Path -Path $configFilePath) {
        # Load the ossec.conf file
        [xml]$config = Get-Content -Path $configFilePath

        # Check for and configure the server node
        $clientNode = $config.ossec_config.client
        $serverNode = $clientNode.server

        if ($serverNode) {
            # Modify existing server address
            $serverNode.address = $serverIP
            Write-Log "Updated OSSEC Agent to connect to server at $serverIP."
        } else {
            # Create a new server node if it doesn't exist
            $newServerNode = $config.CreateElement("server")
            $newAddressNode = $config.CreateElement("address")
            $newAddressNode.InnerText = $serverIP
            $newServerNode.AppendChild($newAddressNode) | Out-Null
            $clientNode.AppendChild($newServerNode) | Out-Null
            Write-Log "Added OSSEC server address to configuration."
        }

        # Save the updated configuration
        $config.Save($configFilePath)
        Write-Log "OSSEC Agent configuration file updated successfully."
    } else {
        Write-Log "Error: Configuration file not found at $configFilePath"
        exit
    }
}

Set-OSSEC

# Step 4: Start OSSEC Agent service
Write-Log "Starting OSSEC Agent service..."
try {
    Start-Service -Name "ossec_agent"
    Start-Sleep -Seconds 5  # Wait for the service to start

    # Check if the service is running
    $serviceStatus = Get-Service -Name "ossec_agent"
    if ($serviceStatus.Status -eq "Running") {
        Write-Log "OSSEC Agent service started successfully."
    } else {
        Write-Log "Failed to start OSSEC Agent service."
        exit
    }
} catch {
    Write-Log "Error starting OSSEC Agent service: $_"
    exit
}

Write-Log "OSSEC Agent Installation and Configuration Completed Successfully."
Write-Output "OSSEC Agent is successfully installed and running."

# Define variables
$velociraptorVersion = "0.6.8"  # Specify the desired Velociraptor version
$velociraptorDownloadUrl = "https://github.com/Velocidex/velociraptor/releases/download/v$velociraptorVersion/velociraptor-v$velociraptorVersion-windows-amd64.exe"
$velociraptorExePath = "$env:ProgramFiles\Velociraptor\velociraptor.exe"
$installDir = "$env:ProgramFiles\Velociraptor"
$configDir = "$installDir\config"
$configFilePath = "$configDir\client.config.yaml"
$serverAddress = "https://your-velociraptor-server-address:8000"  # Replace with your Velociraptor server URL
$logFile = "C:\WebBackups\Velociraptor_Install_Log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Output "$currentDateTime - Starting Velociraptor Installation..." | Out-File -FilePath $logFile -Append

# Step 1: Ensure the installation directory exists
if (!(Test-Path -Path $installDir)) {
    New-Item -Path $installDir -ItemType Directory -Force | Out-Null
    Write-Output "$currentDateTime - Created installation directory: $installDir" | Out-File -FilePath $logFile -Append
}

# Step 2: Download Velociraptor if it doesn't exist
if (!(Test-Path -Path $velociraptorExePath)) {
    Write-Output "$currentDateTime - Downloading Velociraptor..." | Out-File -FilePath $logFile -Append
    Invoke-WebRequest -Uri $velociraptorDownloadUrl -OutFile "$installDir\velociraptor.exe"
    Write-Output "$currentDateTime - Velociraptor downloaded to $velociraptorExePath." | Out-File -FilePath $logFile -Append
} else {
    Write-Output "$currentDateTime - Velociraptor executable already exists, skipping download." | Out-File -FilePath $logFile -Append
}

# Step 3: Create configuration directory
if (!(Test-Path -Path $configDir)) {
    New-Item -Path $configDir -ItemType Directory -Force | Out-Null
    Write-Output "$currentDateTime - Created configuration directory: $configDir" | Out-File -FilePath $logFile -Append
}

# Step 4: Generate client configuration file
Write-Output "$currentDateTime - Generating client configuration file..." | Out-File -FilePath $logFile -Append
$clientConfig = @"
Client:
  client_id: auto
  server: "$serverAddress"
  use_self_signed_ssl: true
  transport: "https"
Logging:
  verbosity: "info"
  log_file: "$installDir\velociraptor.log"
"@
Set-Content -Path $configFilePath -Value $clientConfig
Write-Output "$currentDateTime - Client configuration file created at $configFilePath." | Out-File -FilePath $logFile -Append

# Step 5: Register Velociraptor as a service
Write-Output "$currentDateTime - Registering Velociraptor as a service..." | Out-File -FilePath $logFile -Append
$serviceScript = "$velociraptorExePath --config $configFilePath service install"
Invoke-Expression $serviceScript

# Step 6: Start Velociraptor service
Write-Output "$currentDateTime - Starting Velociraptor service..." | Out-File -FilePath $logFile -Append
Start-Service -Name "Velociraptor"
Start-Sleep -Seconds 5  # Wait for the service to start

# Check if the service is running
$serviceStatus = Get-Service -Name "Velociraptor"
if ($serviceStatus.Status -eq "Running") {
    Write-Output "$currentDateTime - Velociraptor service started successfully." | Out-File -FilePath $logFile -Append
} else {
    Write-Output "$currentDateTime - Failed to start Velociraptor service." | Out-File -FilePath $logFile -Append
    exit
}

Write-Output "$currentDateTime - Velociraptor Agent Installation and Configuration Completed Successfully." | Out-File -FilePath $logFile -Append
Write-Output "Velociraptor Agent is successfully installed and running."

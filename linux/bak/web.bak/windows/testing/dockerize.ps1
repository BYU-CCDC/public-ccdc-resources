# Define directories and files
$projectDir = "C:\DockerizedServices"  # Directory for Docker configurations
$composeFile = "$projectDir\docker-compose.yml"
$serviceConfigsDir = "$projectDir\service_configs"
$logFile = "$projectDir\docker_setup_log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Function to check if a program is installed
function Is-Installed {
    param ($program)
    return Get-Command $program -ErrorAction SilentlyContinue
}

# Step 1: Check and Install Docker
if (!(Is-Installed "docker")) {
    Write-Output "$currentDateTime - Docker is not installed. Installing Docker Desktop..." | Out-File -FilePath $logFile -Append

    # Download Docker Desktop installer
    $dockerUrl = "https://desktop.docker.com/win/stable/Docker%20Desktop%20Installer.exe"
    $dockerInstaller = "$env:TEMP\DockerDesktopInstaller.exe"
    Invoke-WebRequest -Uri $dockerUrl -OutFile $dockerInstaller

    # Install Docker Desktop silently
    Start-Process -FilePath $dockerInstaller -ArgumentList "install", "--quiet" -Wait
    Write-Output "$currentDateTime - Docker Desktop installation completed." | Out-File -FilePath $logFile -Append

    # Restart Docker service to ensure it is running
    Start-Service -Name "com.docker.service"
} else {
    Write-Output "$currentDateTime - Docker is already installed." | Out-File -FilePath $logFile -Append
}

# Step 2: Verify Docker Compose
if (!(Is-Installed "docker-compose")) {
    Write-Output "$currentDateTime - Docker Compose not found. Please ensure Docker Desktop includes Compose or install separately." | Out-File -FilePath $logFile -Append
} else {
    Write-Output "$currentDateTime - Docker Compose is available." | Out-File -FilePath $logFile -Append
}

# Step 3: Create directories if they don’t exist
if (!(Test-Path -Path $projectDir)) {
    New-Item -Path $projectDir -ItemType Directory -Force | Out-Null
}
if (!(Test-Path -Path $serviceConfigsDir)) {
    New-Item -Path $serviceConfigsDir -ItemType Directory -Force | Out-Null
}

# Initialize Docker Compose file content
$composeContent = @"
version: '3.8'
services:
"@

# Define available services
$availableServices = @{
    "1" = "HTTP (Apache)";
    "2" = "FTP (vsftpd)";
    "3" = "RDP (xrdp)"
}

Write-Output "Select the services to set up:"
foreach ($key in $availableServices.Keys) {
    Write-Output "$key: $($availableServices[$key])"
}
Write-Output "Enter the numbers for the services you want to enable (e.g., '1 2' for HTTP and FTP):"
$userInput = Read-Host "Selected services"

# Process user input
foreach ($serviceOption in $userInput.Split(" ")) {
    switch ($serviceOption) {
        "1" {
            # HTTP Service (Apache)
            $httpPort = Read-Host "Enter the host port for HTTP (default 80)"
            if (-not $httpPort) { $httpPort = 80 }

            # Add HTTP service configuration to compose content
            $composeContent += @"
  http_service:
    image: httpd:latest
    container_name: http_service
    ports:
      - "$httpPort:80"
    volumes:
      - $serviceConfigsDir\httpd.conf:/usr/local/apache2/conf/httpd.conf
    restart: always
"@
        }
        "2" {
            # FTP Service (vsftpd)
            $ftpPort = Read-Host "Enter the host port for FTP (default 21)"
            if (-not $ftpPort) { $ftpPort = 21 }

            # Add FTP service configuration to compose content
            $composeContent += @"
  ftp_service:
    image: fauria/vsftpd
    container_name: ftp_service
    ports:
      - "$ftpPort:21"
      - "20:20"
    environment:
      - FTP_USER=user
      - FTP_PASS=pass
    volumes:
      - $serviceConfigsDir\vsftpd.conf:/etc/vsftpd/vsftpd.conf
    restart: always
"@
        }
        "3" {
            # RDP Service (xrdp)
            $rdpPort = Read-Host "Enter the host port for RDP (default 3389)"
            if (-not $rdpPort) { $rdpPort = 3389 }

            # Add RDP service configuration to compose content
            $composeContent += @"
  rdp_service:
    image: oznu/xrdp
    container_name: rdp_service
    ports:
      - "$rdpPort:3389"
    restart: always
"@
        }
        default {
            Write-Output "Invalid selection: $serviceOption"
        }
    }
}

# Save the Docker Compose file
Set-Content -Path $composeFile -Value $composeContent
Write-Output "$currentDateTime - Docker Compose file created at $composeFile" | Out-File -FilePath $logFile -Append

# Step 4: Copy current configurations from host into service_configs directory
Write-Output "$currentDateTime - Copying existing service configurations..." | Out-File -FilePath $logFile -Append
try {
    # Copy configuration files as needed
    if ($userInput -match "1") {
        Copy-Item -Path "C:\Path\To\Existing\httpd.conf" -Destination "$serviceConfigsDir\httpd.conf" -Force -ErrorAction Stop
    }
    if ($userInput -match "2") {
        Copy-Item -Path "C:\Path\To\Existing\vsftpd.conf" -Destination "$serviceConfigsDir\vsftpd.conf" -Force -ErrorAction Stop
    }
    Write-Output "$currentDateTime - Configuration files copied successfully." | Out-File -FilePath $logFile -Append
} catch {
    Write-Output "$currentDateTime - Error copying configuration files: $_" | Out-File -FilePath $logFile -Append
}

# Step 5: Set up Docker Compose to start services
Write-Output "$currentDateTime - Starting Docker containers using Docker Compose..." | Out-File -FilePath $logFile -Append
try {
    # Navigate to project directory
    Set-Location -Path $projectDir

    # Start services using Docker Compose
    docker-compose up -d
    Write-Output "$currentDateTime - Docker containers started successfully." | Out-File -FilePath $logFile -Append
} catch {
    Write-Output "$currentDateTime - Error starting Docker containers: $_" | Out-File -FilePath $logFile -Append
}

# Step 6: Monitor Docker containers and auto-recover
function Monitor-Containers {
    while ($true) {
        $containers = docker ps --filter "status=exited" --format "{{.Names}}"
        
        foreach ($container in $containers) {
            Write-Output "$currentDateTime - Restarting stopped container: $container" | Out-File -FilePath $logFile -Append
            docker start $container
        }

        Start-Sleep -Seconds 10  # Check every 10 seconds
    }
}

# Start monitoring in a background job
Start-Job -ScriptBlock { Monitor-Containers } | Out-Null
Write-Output "$currentDateTime - Started container monitoring background job." | Out-File -FilePath $logFile -Append

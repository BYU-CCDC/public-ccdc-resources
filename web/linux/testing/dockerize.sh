#!/bin/bash

# Define directories and files
projectDir="/DockerizedServices"  # Directory for Docker configurations
composeFile="$projectDir/docker-compose.yml"
serviceConfigsDir="$projectDir/service_configs"
logFile="$projectDir/docker_setup_log.txt"
currentDateTime=$(date '+%Y-%m-%d %H:%M:%S')

# Function to log messages
log() {
    echo "$currentDateTime - $1" | tee -a "$logFile"
}

# Function to check if a program is installed
is_installed() {
    command -v "$1" >/dev/null 2>&1
}

# Step 1: Check and Install Docker if not installed
if ! is_installed "docker"; then
    log "Docker is not installed. Installing Docker..."
    sudo apt update
    sudo apt install -y docker.io
    sudo systemctl enable --now docker
    log "Docker installation completed."
else
    log "Docker is already installed."
fi

# Step 2: Check Docker Compose
if ! is_installed "docker-compose"; then
    log "Docker Compose not found. Installing Docker Compose..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    log "Docker Compose installation completed."
else
    log "Docker Compose is available."
fi

# Step 3: Create directories if they don’t exist
mkdir -p "$projectDir" "$serviceConfigsDir"

# Initialize Docker Compose file content
composeContent="version: '3.8'\nservices:\n"

# Define available services
declare -A availableServices=(
    ["1"]="HTTP (Apache)"
    ["2"]="FTP (vsftpd)"
    ["3"]="RDP (xrdp)"
)

# Display available services and prompt for selection
log "Select the services to set up:"
for key in "${!availableServices[@]}"; do
    echo "$key: ${availableServices[$key]}"
done
read -p "Enter the numbers for the services you want to enable (e.g., '1 2' for HTTP and FTP): " userInput

# Process user input
for serviceOption in $userInput; do
    case "$serviceOption" in
        "1")  # HTTP Service (Apache)
            read -p "Enter the host port for HTTP (default 80): " httpPort
            httpPort="${httpPort:-80}"

            composeContent+="  http_service:\n    image: httpd:latest\n    container_name: http_service\n    ports:\n      - \"$httpPort:80\"\n    volumes:\n      - $serviceConfigsDir/httpd.conf:/usr/local/apache2/conf/httpd.conf\n    restart: always\n"
            ;;
        "2")  # FTP Service (vsftpd)
            read -p "Enter the host port for FTP (default 21): " ftpPort
            ftpPort="${ftpPort:-21}"

            composeContent+="  ftp_service:\n    image: fauria/vsftpd\n    container_name: ftp_service\n    ports:\n      - \"$ftpPort:21\"\n      - \"20:20\"\n    environment:\n      - FTP_USER=user\n      - FTP_PASS=pass\n    volumes:\n      - $serviceConfigsDir/vsftpd.conf:/etc/vsftpd/vsftpd.conf\n    restart: always\n"
            ;;
        "3")  # RDP Service (xrdp)
            read -p "Enter the host port for RDP (default 3389): " rdpPort
            rdpPort="${rdpPort:-3389}"

            composeContent+="  rdp_service:\n    image: oznu/xrdp\n    container_name: rdp_service\n    ports:\n      - \"$rdpPort:3389\"\n    restart: always\n"
            ;;
        *)
            log "Invalid selection: $serviceOption"
            ;;
    esac
done

# Save the Docker Compose file
echo -e "$composeContent" > "$composeFile"
log "Docker Compose file created at $composeFile."

# Step 4: Copy current configurations to service_configs directory
log "Copying existing service configurations..."
if [[ "$userInput" == *"1"* && -f "/path/to/existing/httpd.conf" ]]; then
    cp "/path/to/existing/httpd.conf" "$serviceConfigsDir/httpd.conf"
    log "Copied httpd.conf for HTTP service."
fi
if [[ "$userInput" == *"2"* && -f "/path/to/existing/vsftpd.conf" ]]; then
    cp "/path/to/existing/vsftpd.conf" "$serviceConfigsDir/vsftpd.conf"
    log "Copied vsftpd.conf for FTP service."
fi

# Step 5: Set up Docker Compose to start services
log "Starting Docker containers using Docker Compose..."
cd "$projectDir"
if docker-compose up -d; then
    log "Docker containers started successfully."
else
    log "Error starting Docker containers."
    exit 1
fi

# Step 6: Monitor Docker containers and auto-recover
log "Starting container monitoring..."

while true; do
    stoppedContainers=$(docker ps --filter "status=exited" --format "{{.Names}}")
    
    for container in $stoppedContainers; do
        log "Restarting stopped container: $container"
        docker start "$container"
    done

    sleep 10  # Check every 10 seconds
done &

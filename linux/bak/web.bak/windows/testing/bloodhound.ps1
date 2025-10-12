# BloodHound Automation Script
# This script automates downloading, installing, and setting up BloodHound with Neo4j

# Define variables
$neo4jDownloadUrl = "https://neo4j.com/artifact.php?name=neo4j-community-4.4.12-windows.zip"
$neo4jZipPath = "$env:TEMP\neo4j.zip"
$neo4jInstallDir = "$env:ProgramFiles\Neo4j"
$neo4jBinPath = "$neo4jInstallDir\neo4j-community-4.4.12\bin"
$bloodhoundUrl = "https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-win32-x64.zip"
$bloodhoundZipPath = "$env:TEMP\bloodhound.zip"
$bloodhoundInstallDir = "$env:ProgramFiles\BloodHound"
$sharpHoundUrl = "https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe"
$sharpHoundPath = "$bloodhoundInstallDir\SharpHound.exe"
$neo4jDefaultPassword = "bloodhound"  # Change as needed
$outputFile = "$env:TEMP\bloodhound_setup_log.txt"

# Function to invoke and expand ZIP files
function Invoke-ExpandZip {
    param (
        [string]$url,
        [string]$zipPath,
        [string]$destination
    )
    Write-Host "Downloading from $url..."
    Invoke-WebRequest -Uri $url -OutFile $zipPath -ErrorAction Stop
    Write-Host "Extracting to $destination..."
    Expand-Archive -Path $zipPath -DestinationPath $destination -Force
    Remove-Item -Path $zipPath -Force
}

# Function to install Neo4j
function Install-Neo4j {
    if (!(Test-Path -Path "$neo4jBinPath\neo4j.bat")) {
        Write-Host "Installing Neo4j..."
        Invoke-ExpandZip -url $neo4jDownloadUrl -zipPath $neo4jZipPath -destination $neo4jInstallDir
        Write-Host "Neo4j installed at $neo4jBinPath."
    } else {
        Write-Host "Neo4j is already installed."
    }
}

# Function to install BloodHound
function Install-BloodHound {
    if (!(Test-Path -Path "$bloodhoundInstallDir\BloodHound.exe")) {
        Write-Host "Installing BloodHound..."
        Invoke-ExpandZip -url $bloodhoundUrl -zipPath $bloodhoundZipPath -destination $bloodhoundInstallDir
        Write-Host "BloodHound installed at $bloodhoundInstallDir."
    } else {
        Write-Host "BloodHound is already installed."
    }
}

# Function to get SharpHound
function Get-SharpHound {
    if (!(Test-Path -Path $sharpHoundPath)) {
        Write-Host "Downloading SharpHound..."
        Invoke-WebRequest -Uri $sharpHoundUrl -OutFile $sharpHoundPath -ErrorAction Stop
        Write-Host "SharpHound downloaded to $sharpHoundPath."
    } else {
        Write-Host "SharpHound is already downloaded."
    }
}

# Function to set up Neo4j credentials
function Set-Neo4jCredentials {
    Write-Host "Configuring Neo4j credentials..."
    Start-Process -FilePath "$neo4jBinPath\neo4j.bat" -ArgumentList "install-service" -Wait
    Start-Service -Name "neo4j"
    Write-Host "Setting up Neo4j default user and password..."
    Start-Sleep -Seconds 10  # Wait for Neo4j to initialize

    # Change Neo4j password via REST API
    Invoke-RestMethod -Uri "http://localhost:7474/user/neo4j/password" -Method POST -Body @{password=$neo4jDefaultPassword} -Headers @{Authorization=("Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("neo4j:neo4j")))}
}

# Function to start BloodHound
function Start-BloodHound {
    Write-Host "Starting BloodHound..."
    Start-Process -FilePath "$bloodhoundInstallDir\BloodHound.exe"
    Write-Host "BloodHound started."
}

# Main Script Execution
Install-Neo4j
Install-BloodHound
Get-SharpHound
Set-Neo4jCredentials

# Start BloodHound
Start-BloodHound

Write-Host "BloodHound setup completed. You can start using SharpHound for data collection." | Out-File -FilePath $outputFile -Append

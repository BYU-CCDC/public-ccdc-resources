# Nuclei Automation Script in PowerShell
# This script automates downloading, installing (if needed), updating templates, and running Nuclei for vulnerability scanning.

# Define variables
$nucleiUrl = "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_Windows_amd64.zip"
$downloadPath = "$env:TEMP\nuclei.zip"
$installDir = "$env:ProgramFiles\nuclei"
$nucleiPath = "$installDir\nuclei.exe"
$templatesDir = "$env:USERPROFILE\nuclei-templates"
$outputFile = "$env:TEMP\nuclei_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Function to download and install Nuclei
function Install-Nuclei {
    if (!(Test-Path -Path $nucleiPath)) {
        Write-Host "Downloading Nuclei..."
        Invoke-WebRequest -Uri $nucleiUrl -OutFile $downloadPath -ErrorAction Stop

        # Extract the downloaded ZIP file
        Write-Host "Extracting Nuclei..."
        Expand-Archive -Path $downloadPath -DestinationPath $installDir -Force
        Remove-Item -Path $downloadPath -Force
        Write-Host "Nuclei installed successfully at $nucleiPath."
    } else {
        Write-Host "Nuclei is already installed at $nucleiPath."
    }
}

# Function to update Nuclei templates
function Update-NucleiTemplates {
    Write-Host "Updating Nuclei templates..."
    if (!(Test-Path -Path $templatesDir)) {
        mkdir $templatesDir | Out-Null
    }
    & $nucleiPath -update-templates -silent
    Write-Host "Templates updated successfully."
}

# Function to invoke a Nuclei scan
function Invoke-NucleiScan {
    param (
        [string]$target,
        [string]$templateType = "default"
    )

    Write-Host "Running Nuclei scan on $target with template type: $templateType..."

    # Set the template option based on the user's choice
    $templateOption = ""
    if ($templateType -ne "default") {
        $templateOption = "-t $templatesDir\$templateType"
    }

    # Execute the Nuclei scan
    & $nucleiPath -u $target $templateOption -o $outputFile -silent
    Write-Host "Scan completed. Results saved to $outputFile"
}

# Main script execution
Install-Nuclei
Update-NucleiTemplates

# Prompt user for target URL and template type
$target = Read-Host "Enter target URL or IP (e.g., https://example.com)"
$templateChoice = Read-Host "Enter template type (default, cves, misconfigurations, exposures):"

# Invoke the Nuclei scan based on user input
Invoke-NucleiScan -target $target -templateType $templateChoice

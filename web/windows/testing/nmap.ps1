# Define Variables
$networkRange = "192.168.1.0/24"  # Set your network range here
$outputDirectory = "$env:TEMP\Nmap_Scans"
$outputFile = "$outputDirectory\nmap_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$vulnerabilityScript = "--script vuln"  # Nmap script for basic vulnerability scan

# Ensure Output Directory Exists
if (!(Test-Path -Path $outputDirectory)) {
    New-Item -Path $outputDirectory -ItemType Directory | Out-Null
}

# Function to Test if Nmap is Installed
function Test-NmapInstallation {
    if (-not (Get-Command "nmap" -ErrorAction SilentlyContinue)) {
        Write-Host "Nmap is not installed or not in the system path. Please install Nmap before running this script."
        exit 1
    } else {
        Write-Host "Nmap is installed and ready for use."
    }
}

# Function to Start Nmap Port Scan
function Start-PortScan {
    param (
        [string]$range
    )
    Write-Host "Running Nmap port scan on $range..."
    $command = "nmap -p- -T4 -oN $outputFile $range"
    Invoke-Expression $command
    Write-Host "Port scan completed. Results saved to $outputFile"
}

# Function to Start Nmap Vulnerability Scan
function Start-VulnerabilityScan {
    param (
        [string]$range
    )
    Write-Host "Running Nmap vulnerability scan on $range..."
    $command = "nmap $vulnerabilityScript -T4 -oN $outputFile $range"
    Invoke-Expression $command
    Write-Host "Vulnerability scan completed. Results saved to $outputFile"
}

# Main Execution
Test-NmapInstallation

# Prompt User for Scan Type
$scanType = Read-Host "Select scan type: Enter '1' for Port Scan, '2' for Vulnerability Scan, '3' for Both"

switch ($scanType) {
    "1" {
        Start-PortScan -range $networkRange
    }
    "2" {
        Start-VulnerabilityScan -range $networkRange
    }
    "3" {
        Start-PortScan -range $networkRange
        Start-Sleep -Seconds 5
        Start-VulnerabilityScan -range $networkRange
    }
    default {
        Write-Host "Invalid selection. Please enter 1, 2, or 3."
        exit 1
    }
}

Write-Host "Scan completed. Results can be found in $outputDirectory"

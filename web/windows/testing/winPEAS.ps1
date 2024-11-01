# Define variables
$winPEASUrl = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe"
$winPEASPath = "$env:TEMP\winPEASany.exe"
$logFile = "$env:TEMP\winPEAS_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Function to Get winPEAS
function Get-winPEAS {
    if (!(Test-Path -Path $winPEASPath)) {
        Write-Host "Downloading winPEAS..."
        try {
            Invoke-WebRequest -Uri $winPEASUrl -OutFile $winPEASPath -ErrorAction Stop
            Write-Host "winPEAS downloaded successfully to $winPEASPath"
        } catch {
            Write-Host "Failed to download winPEAS. Please check your internet connection or the URL."
            exit 1
        }
    } else {
        Write-Host "winPEAS is already downloaded at $winPEASPath"
    }
}

# Function to Invoke winPEAS and capture output
function Invoke-winPEAS {
    Write-Host "Running winPEAS..."
    try {
        Start-Process -FilePath $winPEASPath -ArgumentList "/q" -NoNewWindow -RedirectStandardOutput $logFile -Wait
        Write-Host "winPEAS scan completed. Results saved to $logFile"
    } catch {
        Write-Host "Failed to run winPEAS. Please check if the file is downloaded correctly."
        exit 1
    }
}

# Main execution
Get-winPEAS
Invoke-winPEAS

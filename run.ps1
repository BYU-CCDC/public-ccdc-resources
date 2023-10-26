# Define the URL of the zip file
$zipFileUrl = "https://github.com/Aaron-M-Anderson/public-ccdc-resources/raw/main/windows.zip"

# Define where the zip file will be downloaded
$downloadPath = "C:\file.zip"

# Download the zip file using wget (Invoke-WebRequest in PowerShell)
Invoke-WebRequest -Uri $zipFileUrl -OutFile $downloadPath

# Unzip the downloaded file
$unzipDirectory = "C:\path\to\unzip\directory"
Expand-Archive -Path $downloadPath -DestinationPath $unzipDirectory

# Change directory into the unzip directory
Set-Location "$unzipDirectory\windows\hardening"

# Run the PowerShell script (assuming the script is named 'script.ps1' and is in the root of the unzipped directory)
.\Hardening-n-15min.ps1

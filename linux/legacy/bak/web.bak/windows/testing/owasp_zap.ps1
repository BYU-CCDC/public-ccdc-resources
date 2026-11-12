# OWASP ZAP version and download URL
$zapVersion = "2.13.0"  # Specify the version you want to install
$zapDownloadUrl = "https://github.com/zaproxy/zaproxy/releases/download/v$zapVersion/ZAP_$zapVersion_Windows.zip"
$installDir = "C:\Tools\OWASP_ZAP"  # Installation directory for OWASP ZAP
$zapExePath = "$installDir\ZAP.exe"
$shortcutPath = "$env:Public\Desktop\OWASP ZAP.lnk"  # Shortcut on the desktop

# Log file
$logFile = "C:\WebBackups\OWASP_ZAP_Install_Log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Output "$currentDateTime - Starting OWASP ZAP Installation..." | Out-File -FilePath $logFile -Append

# Check if PowerShell version is older and enable compatibility mode
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Output "$currentDateTime - PowerShell version is less than 3.0, compatibility mode enabled." | Out-File -FilePath $logFile -Append
}

# Ensure the installation directory exists
if (!(Test-Path -Path $installDir)) {
    New-Item -Path $installDir -ItemType Directory -Force | Out-Null
    Write-Output "$currentDateTime - Created installation directory: $installDir" | Out-File -FilePath $logFile -Append
}

# Function to download a file with compatibility for older PowerShell
function Download-File {
    param (
        [string]$url,
        [string]$destinationPath
    )

    try {
        # Use WebClient for compatibility with older PowerShell versions
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($url, $destinationPath)
        Write-Output "$currentDateTime - Downloaded file from $url to $destinationPath" | Out-File -FilePath $logFile -Append
    } catch {
        Write-Error "Failed to download file from $url. Error: $_"
        Write-Output "$currentDateTime - Failed to download file from $url. Error: $_" | Out-File -FilePath $logFile -Append
    }
}

# Download ZAP ZIP file
$zipFilePath = "$installDir\ZAP_$zapVersion.zip"
if (!(Test-Path -Path $zipFilePath)) {
    Download-File -url $zapDownloadUrl -destinationPath $zipFilePath
} else {
    Write-Output "$currentDateTime - OWASP ZAP ZIP file already exists at $zipFilePath, skipping download." | Out-File -FilePath $logFile -Append
}

# Function to extract ZIP files, compatible with older PowerShell
function Extract-ZipFile {
    param (
        [string]$zipPath,
        [string]$destination
    )

    if (!(Test-Path -Path $zipPath)) {
        Write-Error "ZIP file not found: $zipPath"
        Write-Output "$currentDateTime - ZIP file not found: $zipPath" | Out-File -FilePath $logFile -Append
        return
    }

    try {
        $shellApp = New-Object -ComObject Shell.Application
        $zip = $shellApp.NameSpace($zipPath)
        $destinationFolder = $shellApp.NameSpace($destination)
        $destinationFolder.CopyHere($zip.Items(), 16)  # 16 = No UI during extraction
        Write-Output "$currentDateTime - Extracted ZIP file to $destination" | Out-File -FilePath $logFile -Append
    } catch {
        Write-Error "Failed to extract ZIP file. Error: $_"
        Write-Output "$currentDateTime - Failed to extract ZIP file. Error: $_" | Out-File -FilePath $logFile -Append
    }
}

# Extract ZAP files
Extract-ZipFile -zipPath $zipFilePath -destination $installDir

# Check if ZAP.exe exists after extraction
if (!(Test-Path -Path $zapExePath)) {
    Write-Output "$currentDateTime - ZAP.exe not found after extraction. Installation failed." | Out-File -FilePath $logFile -Append
    exit
}

# Add ZAP to the PATH environment variable
function Add-ZapToPath {
    $path = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
    if ($path -notlike "*$installDir*") {
        [System.Environment]::SetEnvironmentVariable("Path", "$path;$installDir", [System.EnvironmentVariableTarget]::Machine)
        Write-Output "$currentDateTime - Added ZAP to system PATH." | Out-File -FilePath $logFile -Append
    } else {
        Write-Output "$currentDateTime - ZAP is already in the system PATH." | Out-File -FilePath $logFile -Append
    }
}

Add-ZapToPath

# Function to create a shortcut on the desktop
function Create-Shortcut {
    param (
        [string]$targetPath,
        [string]$shortcutPath,
        [string]$description = "OWASP ZAP - Zed Attack Proxy"
    )

    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $targetPath
        $shortcut.Description = $description
        $shortcut.Save()
        Write-Output "$currentDateTime - Created shortcut on desktop: $shortcutPath" | Out-File -FilePath $logFile -Append
    } catch {
        Write-Error "Failed to create shortcut. Error: $_"
        Write-Output "$currentDateTime - Failed to create shortcut. Error: $_" | Out-File -FilePath $logFile -Append
    }
}

# Create a desktop shortcut for OWASP ZAP
if (!(Test-Path -Path $shortcutPath)) {
    Create-Shortcut -targetPath $zapExePath -shortcutPath $shortcutPath
} else {
    Write-Output "$currentDateTime - OWASP ZAP shortcut already exists on desktop." | Out-File -FilePath $logFile -Append
}

Write-Output "$currentDateTime - OWASP ZAP Installation Completed." | Out-File -FilePath $logFile -Append
Write-Output "Installation complete. OWASP ZAP is ready to use."

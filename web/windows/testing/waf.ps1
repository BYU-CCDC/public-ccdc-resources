# Define variables
$modSecurityVersion = "2.9.3"  # Update to the version you want to install
$modSecurityDownloadUrl = "https://github.com/SpiderLabs/ModSecurity/releases/download/v$modSecurityVersion/modsecurity-iis_v$modSecurityVersion.zip"
$modSecurityZipPath = "$env:TEMP\modsecurity-iis_v$modSecurityVersion.zip"
$installDir = "C:\Program Files\ModSecurity IIS"
$rulesDir = "$installDir\conf"
$logFile = "C:\WebBackups\ModSecurity_Install_Log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Output "$currentDateTime - Starting ModSecurity Installation..." | Out-File -FilePath $logFile -Append

# Step 1: Ensure Visual C++ Redistributable is installed
$vcRedistInstalled = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Visual C++*Redistributable*" }
if (-not $vcRedistInstalled) {
    Write-Output "$currentDateTime - Visual C++ Redistributable is not installed. Downloading and installing..." | Out-File -FilePath $logFile -Append
    $vcRedistUrl = "https://aka.ms/vs/16/release/vc_redist.x64.exe"
    $vcRedistInstaller = "$env:TEMP\vc_redist.x64.exe"
    Invoke-WebRequest -Uri $vcRedistUrl -OutFile $vcRedistInstaller
    Start-Process -FilePath $vcRedistInstaller -ArgumentList "/install /quiet /norestart" -Wait
    Write-Output "$currentDateTime - Visual C++ Redistributable installed." | Out-File -FilePath $logFile -Append
} else {
    Write-Output "$currentDateTime - Visual C++ Redistributable is already installed." | Out-File -FilePath $logFile -Append
}

# Step 2: Download ModSecurity for IIS
if (!(Test-Path -Path $modSecurityZipPath)) {
    Write-Output "$currentDateTime - Downloading ModSecurity for IIS..." | Out-File -FilePath $logFile -Append
    Invoke-WebRequest -Uri $modSecurityDownloadUrl -OutFile $modSecurityZipPath
} else {
    Write-Output "$currentDateTime - ModSecurity ZIP file already exists at $modSecurityZipPath, skipping download." | Out-File -FilePath $logFile -Append
}

# Step 3: Extract ModSecurity to the installation directory
if (!(Test-Path -Path $installDir)) {
    New-Item -Path $installDir -ItemType Directory -Force | Out-Null
}

Write-Output "$currentDateTime - Extracting ModSecurity files..." | Out-File -FilePath $logFile -Append
$shell = New-Object -ComObject Shell.Application
$zip = $shell.NameSpace($modSecurityZipPath)
$destinationFolder = $shell.NameSpace($installDir)
$destinationFolder.CopyHere($zip.Items(), 16)  # 16 = No UI during extraction
Write-Output "$currentDateTime - ModSecurity files extracted to $installDir." | Out-File -FilePath $logFile -Append

# Step 4: Configure ModSecurity
Write-Output "$currentDateTime - Configuring ModSecurity..." | Out-File -FilePath $logFile -Append

# Update the main ModSecurity configuration file
$modSecurityConfigPath = "$installDir\modsecurity.conf"
$modSecurityRulesPath = "$rulesDir\owasp-modsecurity-crs-master\modsecurity_crs_10_setup.conf"

# Create rules directory if it doesn't exist
if (!(Test-Path -Path $rulesDir)) {
    New-Item -Path $rulesDir -ItemType Directory -Force | Out-Null
}

# Configure the main ModSecurity configuration file
if (Test-Path -Path $modSecurityConfigPath) {
    # Enable the OWASP CRS rules
    Add-Content -Path $modSecurityConfigPath -Value "Include $modSecurityRulesPath"
    Write-Output "$currentDateTime - Enabled OWASP Core Rule Set in ModSecurity config." | Out-File -FilePath $logFile -Append
} else {
    Write-Error "ModSecurity configuration file not found at $modSecurityConfigPath."
    Write-Output "$currentDateTime - Error: ModSecurity configuration file not found at $modSecurityConfigPath." | Out-File -FilePath $logFile -Append
    exit
}

# Step 5: Register ModSecurity as an IIS module
Write-Output "$currentDateTime - Registering ModSecurity as an IIS module..." | Out-File -FilePath $logFile -Append

Import-Module WebAdministration
$modSecurityDllPath = "$installDir\iis\ModSecurityIIS.dll"
if (Test-Path -Path $modSecurityDllPath) {
    New-WebGlobalModule -Name "ModSecurityIIS" -Image "$modSecurityDllPath"
    Write-Output "$currentDateTime - ModSecurity registered as an IIS module." | Out-File -FilePath $logFile -Append
} else {
    Write-Error "ModSecurity DLL not found at $modSecurityDllPath."
    Write-Output "$currentDateTime - Error: ModSecurity DLL not found at $modSecurityDllPath." | Out-File -FilePath $logFile -Append
    exit
}

# Step 6: Verify ModSecurity Installation
Write-Output "$currentDateTime - Verifying ModSecurity installation..." | Out-File -FilePath $logFile -Append
$modSecurityLogPath = "$installDir\logs\modsec_audit.log"
if (Test-Path -Path $modSecurityLogPath) {
    Write-Output "$currentDateTime - ModSecurity log file found, installation appears successful." | Out-File -FilePath $logFile -Append
} else {
    Write-Output "$currentDateTime - Warning: ModSecurity log file not found. Verify configuration." | Out-File -FilePath $logFile -Append
}

Write-Output "$currentDateTime - ModSecurity Installation and Configuration Completed." | Out-File -FilePath $logFile -Append
Write-Output "ModSecurity for IIS is successfully installed and configured."

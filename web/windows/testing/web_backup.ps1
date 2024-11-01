# Define backup directories
$backupRoot = "C:\WebBackups"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = Join-Path -Path $backupRoot -ChildPath $timestamp

# Ensure the backup directory exists
New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

# 1. SQL Server Backup
function Backup-SQLDatabase {
    param (
        [string]$serverInstance = "localhost",   # Adjust as needed
        [string[]]$databases = @("Database1", "Database2")  # List of databases to back up
    )

    # Directory to store SQL backups
    $sqlBackupDir = Join-Path -Path $backupDir -ChildPath "SQL"
    New-Item -Path $sqlBackupDir -ItemType Directory -Force | Out-Null

    foreach ($db in $databases) {
        $backupFile = Join-Path -Path $sqlBackupDir -ChildPath "$db.bak"
        $query = "BACKUP DATABASE [$db] TO DISK='$backupFile'"
        
        Invoke-Sqlcmd -ServerInstance $serverInstance -Query $query -ErrorAction Stop
        Write-Output "Backup of SQL Database '$db' completed."
    }
}

# 2. IIS Configuration Backup
function Backup-IISConfig {
    $iisBackupDir = Join-Path -Path $backupDir -ChildPath "IIS"
    New-Item -Path $iisBackupDir -ItemType Directory -Force | Out-Null
    
    # Export IIS configuration
    $iisBackupFile = Join-Path -Path $iisBackupDir -ChildPath "IIS_Config.xml"
    & "C:\Windows\System32\inetsrv\appcmd.exe" add backup "$timestamp" | Out-Null
    Write-Output "IIS configuration backup completed."
    
    # Export SSL certificates (assuming certs are stored in Cert:\LocalMachine\My)
    Export-PfxCertificate -Cert Cert:\LocalMachine\My -FilePath "$iisBackupDir\SSL_Certs.pfx" -Password (ConvertTo-SecureString -String "YourSecurePassword" -Force -AsPlainText)
    Write-Output "IIS SSL certificates backup completed."
}

# 3. Website Files Backup
function Backup-WebFiles {
    param (
        [string[]]$webDirectories = @("C:\inetpub\wwwroot", "C:\AdditionalWebDirectory")  # Adjust directories as needed
    )

    $webFilesBackupDir = Join-Path -Path $backupDir -ChildPath "WebFiles"
    New-Item -Path $webFilesBackupDir -ItemType Directory -Force | Out-Null

    foreach ($dir in $webDirectories) {
        $destination = Join-Path -Path $webFilesBackupDir -ChildPath (Split-Path -Path $dir -Leaf)
        Copy-Item -Path $dir -Destination $destination -Recurse -Force
        Write-Output "Backup of Web Files in '$dir' completed."
    }
}

# Run All Backup Functions
try {
    # SQL Backup
    Backup-SQLDatabase -serverInstance "localhost" -databases @("Database1", "Database2")  # Update database names

    # IIS Config Backup
    Backup-IISConfig

    # Web Files Backup
    Backup-WebFiles -webDirectories @("C:\inetpub\wwwroot")  # Update with additional directories as needed

    Write-Output "All backups completed successfully. Backup directory: $backupDir"
} catch {
    Write-Error "An error occurred during the backup process: $_"
}

# Once we get to a comfortable position, use this to check for changes, and considering the hashes don't match, restore to the previous? 
# Define directories and files
$monitorDirectory = "C:\Path\To\Monitor"  # Directory to monitor
$baselineFile = "C:\Path\To\Baseline\file_integrity_baseline.json"  # Baseline file to store checksums
$logFile = "C:\Path\To\Logs\file_integrity_log.txt"  # Log file for integrity changes
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Ensure baseline directory exists
$baselineDir = Split-Path -Path $baselineFile
if (!(Test-Path -Path $baselineDir)) {
    New-Item -Path $baselineDir -ItemType Directory -Force | Out-Null
}

# Function to calculate SHA-256 checksum of a file
function Get-FileHashSHA256 {
    param (
        [string]$filePath
    )
    try {
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256
        return $hash.Hash
    } catch {
        Write-Output "$currentDateTime - Error calculating hash for $filePath. Error: $_" | Out-File -FilePath $logFile -Append
        return $null
    }
}

# Function to save baseline checksums
function Save-Baseline {
    param (
        [string]$directory,
        [string]$baselinePath
    )
    
    $files = Get-ChildItem -Path $directory -File -Recurse
    $baselineData = @{}

    foreach ($file in $files) {
        $hash = Get-FileHashSHA256 -filePath $file.FullName
        if ($hash) {
            $baselineData[$file.FullName] = $hash
        }
    }

    # Save baseline data as JSON
    $baselineData | ConvertTo-Json | Set-Content -Path $baselinePath
    Write-Output "$currentDateTime - Baseline checksums saved to $baselinePath." | Out-File -FilePath $logFile -Append
}

# Function to monitor changes against baseline
function Monitor-Changes {
    param (
        [string]$directory,
        [string]$baselinePath,
        [string]$logPath
    )
    
    # Load baseline data
    if (!(Test-Path -Path $baselinePath)) {
        Write-Output "$currentDateTime - Baseline file not found. Generating a new baseline." | Out-File -FilePath $logPath -Append
        Save-Baseline -directory $directory -baselinePath $baselinePath
    }
    $baselineData = Get-Content -Path $baselinePath | ConvertFrom-Json
    $files = Get-ChildItem -Path $directory -File -Recurse

    foreach ($file in $files) {
        $currentHash = Get-FileHashSHA256 -filePath $file.FullName

        # Compare current hash with baseline
        if ($baselineData.ContainsKey($file.FullName)) {
            $baselineHash = $baselineData[$file.FullName]
            if ($currentHash -ne $baselineHash) {
                Write-Output "$currentDateTime - File modified: $($file.FullName)" | Out-File -FilePath $logPath -Append
                Write-Output "$currentDateTime - Old Hash: $baselineHash | New Hash: $currentHash" | Out-File -FilePath $logPath -Append
            }
        } else {
            # New file detected
            Write-Output "$currentDateTime - New file added: $($file.FullName)" | Out-File -FilePath $logPath -Append
        }
    }

    # Detect deleted files
    foreach ($baselineFile in $baselineData.Keys) {
        if (!(Test-Path -Path $baselineFile)) {
            Write-Output "$currentDateTime - File deleted: $baselineFile" | Out-File -FilePath $logPath -Append
        }
    }
}

# Check if baseline exists; if not, create it
if (!(Test-Path -Path $baselineFile)) {
    Write-Output "$currentDateTime - No baseline file found, creating a new baseline." | Out-File -FilePath $logFile -Append
    Save-Baseline -directory $monitorDirectory -baselinePath $baselineFile
} else {
    Write-Output "$currentDateTime - Baseline file found. Starting integrity check..." | Out-File -FilePath $logFile -Append
    Monitor-Changes -directory $monitorDirectory -baselinePath $baselineFile -logPath $logFile
}

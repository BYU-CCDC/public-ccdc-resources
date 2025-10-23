#Prob don't use, lol 
# Define directories and files
$monitorDirectory = "C:\DataToMonitor"  # Directory to monitor for sensitive data
$secureDirectory = "C:\SecureData"      # Directory to move sensitive files to
$logFile = "C:\DLP_Log.txt"             # Log file for tracking detections
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Create secure directory if it doesn’t exist
if (!(Test-Path -Path $secureDirectory)) {
    New-Item -Path $secureDirectory -ItemType Directory -Force | Out-Null
    Write-Output "$currentDateTime - Secure directory created at $secureDirectory" | Out-File -FilePath $logFile -Append
}

# Define sensitive data patterns (regex)
$sensitivePatterns = @{
    "CreditCard" = "\b(?:\d[ -]*?){13,16}\b"                  # Credit card number pattern
    "SSN" = "\b\d{3}-\d{2}-\d{4}\b"                           # Social Security Number pattern
    "Email" = "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"  # Email address pattern
}

# Function to check for sensitive data in a file
function Check-SensitiveData {
    param (
        [string]$filePath
    )

    # Read the file content
    $fileContent = Get-Content -Path $filePath -Raw
    $foundSensitiveData = $false

    # Search for each pattern in the file
    foreach ($patternName in $sensitivePatterns.Keys) {
        $pattern = $sensitivePatterns[$patternName]
        if ($fileContent -match $pattern) {
            Write-Output "$currentDateTime - Sensitive data detected ($patternName) in file: $filePath" | Out-File -FilePath $logFile -Append
            $foundSensitiveData = $true
        }
    }
    return $foundSensitiveData
}

# Function to secure files containing sensitive data
function Secure-File {
    param (
        [string]$filePath
    )

    try {
        # Move file to secure directory
        $destinationPath = Join-Path -Path $secureDirectory -ChildPath (Split-Path -Leaf $filePath)
        Move-Item -Path $filePath -Destination $destinationPath -Force
        Write-Output "$currentDateTime - File moved to secure location: $destinationPath" | Out-File -FilePath $logFile -Append
    } catch {
        Write-Output "$currentDateTime - Error moving file: $filePath. Error: $_" | Out-File -FilePath $logFile -Append
    }
}

# Function to monitor directory for sensitive data
function Monitor-Directory {
    param (
        [string]$directory
    )

    Write-Output "$currentDateTime - Starting DLP scan on directory: $directory" | Out-File -FilePath $logFile -Append

    # Monitor all files in directory
    $files = Get-ChildItem -Path $directory -File -Recurse
    foreach ($file in $files) {
        if (Check-SensitiveData -filePath $file.FullName) {
            Secure-File -filePath $file.FullName
        }
    }
    Write-Output "$currentDateTime - DLP scan completed." | Out-File -FilePath $logFile -Append
}

# Start monitoring the specified directory
Monitor-Directory -directory $monitorDirectory

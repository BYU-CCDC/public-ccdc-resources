# Define directories and encryption key
$scanDirectory = "C:\DataToScan"  # Directory containing files to scan
$backupDirectory = "C:\PII_Backup"  # Directory for storing backups
$encryptedDirectory = "C:\Encrypted_Files"  # Directory for storing encrypted files
$encryptionKey = "ComplexEncryptionKey123!"  # Symmetric key for encryption (modify as needed)
$logFile = "C:\WebBackups\PII_Audit_Log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Regex patterns for common PII data
$piiPatterns = @{
    "CreditCard" = "\b(?:\d[ -]*?){13,16}\b";  # Basic credit card pattern
    "PhoneNumber" = "\b\d{3}[-.\s]??\d{3}[-.\s]??\d{4}\b";  # North American phone numbers
    "SSN" = "\b\d{3}-\d{2}-\d{4}\b";  # Social Security Number pattern
    "Email" = "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b";  # Email addresses
    "FirstNameLastName" = "\b([A-Z][a-z]+)\s([A-Z][a-z]+)\b";  # First and last name (simple format)
    "Address" = "\b\d{1,5}\s\w+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd)\b"  # Basic address pattern
}

Write-Output "$currentDateTime - Starting PII Audit..." | Out-File -FilePath $logFile -Append

# Ensure backup and encrypted directories exist
if (!(Test-Path -Path $backupDirectory)) {
    New-Item -Path $backupDirectory -ItemType Directory -Force | Out-Null
}
if (!(Test-Path -Path $encryptedDirectory)) {
    New-Item -Path $encryptedDirectory -ItemType Directory -Force | Out-Null
}

# Function to encrypt a file with symmetric encryption
function Encrypt-File {
    param (
        [string]$filePath,
        [string]$outputPath
    )
    try {
        $plaintext = Get-Content -Path $filePath -Raw
        $encryptedData = ConvertTo-SecureString -String $plaintext -AsPlainText -Force | ConvertFrom-SecureString -Key ([Text.Encoding]::UTF8.GetBytes($encryptionKey))
        Set-Content -Path $outputPath -Value $encryptedData
        Write-Output "$currentDateTime - Encrypted file saved to $outputPath" | Out-File -FilePath $logFile -Append
    } catch {
        Write-Output "$currentDateTime - Encryption failed for $filePath. Error: $_" | Out-File -FilePath $logFile -Append
    }
}

# Function to obfuscate PII patterns in file content
function Obfuscate-PII {
    param (
        [string]$fileContent,
        [hashtable]$patterns
    )
    foreach ($patternName in $patterns.Keys) {
        $fileContent = $fileContent -replace $patterns[$patternName], "[REDACTED_$patternName]"
    }
    return $fileContent
}

# Function to scan for PII in files and handle audit, backup, encryption, and obfuscation
function Process-Files {
    param (
        [string]$directory,
        [hashtable]$patterns
    )
    
    $files = Get-ChildItem -Path $directory -Recurse -File
    foreach ($file in $files) {
        $content = Get-Content -Path $file.FullName -Raw
        $containsPII = $false

        foreach ($pattern in $patterns.Values) {
            if ($content -match $pattern) {
                $containsPII = $true
                break
            }
        }

        if ($containsPII) {
            Write-Output "$currentDateTime - PII found in file: $($file.FullName)" | Out-File -FilePath $logFile -Append

            # Backup file
            $backupPath = Join-Path -Path $backupDirectory -ChildPath $file.Name
            Copy-Item -Path $file.FullName -Destination $backupPath -Force
            Write-Output "$currentDateTime - Backup created for file: $($file.FullName)" | Out-File -FilePath $logFile -Append

            # Encrypt file
            $encryptedPath = Join-Path -Path $encryptedDirectory -ChildPath "$($file.BaseName)_encrypted.txt"
            Encrypt-File -filePath $file.FullName -outputPath $encryptedPath

            # Obfuscate PII in the file
            $obfuscatedContent = Obfuscate-PII -fileContent $content -patterns $patterns
            Set-Content -Path $file.FullName -Value $obfuscatedContent
            Write-Output "$currentDateTime - PII obfuscated in file: $($file.FullName)" | Out-File -FilePath $logFile -Append
        }
    }
}

# Run PII audit and processing on files in the specified directory
try {
    Process-Files -directory $scanDirectory -patterns $piiPatterns
    Write-Output "$currentDateTime - PII Audit completed successfully." | Out-File -FilePath $logFile -Append
} catch {
    Write-Output "$currentDateTime - An error occurred during PII processing: $_" | Out-File -FilePath $logFile -Append
}

# Function to check if the service's binary path is suspicious
function IsSuspiciousPath($path) {
    return ($path -like "C:\Users\*")
}
# Function to check if the service's binary is unsigned
function IsUnsigned($path) {
    try {
        $Signatures = Get-AuthenticodeSignature -FilePath $path
        return ($Signatures.Status -ne "Valid")
    }
    catch {
        return $true
    }
}
# Function to calculate the entropy of a string
function CalculateEntropy($input) {
    $inputChars = $input.ToCharArray()
    $charCount = $inputChars.Length
    $charFrequency = @{}
    foreach ($char in $inputChars) {
        $charFrequency[$char]++
    }
    [double]$entropy = 0
    foreach ($frequency in $charFrequency.Values) {
        $probability = $frequency / $charCount
        $entropy -= $probability * [Math]::Log($probability, 2)
    }
    return $entropy
}
# Function to check if the service has a high entropy name
function IsHighEntropyName($name) {
    $entropy = CalculateEntropy($name)
    return ($entropy -gt 3.5)
}
# Function to check if the service has a suspicious file extension
function HasSuspiciousExtension($path) {
    $suspiciousExtensions = @('.vbs', '.js', '.bat', '.cmd', '.scr')
    $extension = [IO.Path]::GetExtension($path)
    return ($suspiciousExtensions -contains $extension)
}
# Prompt the user to enable or disable checks more likely to result in false positives
$enableExtraChecks = Read-Host "Enable checks more likely to result in false positives? (yes/no)"
$extraChecks = $enableExtraChecks -eq "yes"
# Get all services on the local machine
$AllServices = Get-WmiObject -Class Win32_Service
# Create an empty array to store detected suspicious services
$DetectedServices = New-Object System.Collections.ArrayList
# Iterate through all services
foreach ($Service in $AllServices) {
    $BinaryPathName = $Service.PathName.Trim('"')
    # Check for suspicious characteristics
    $PathSuspicious = IsSuspiciousPath($BinaryPathName)
    $LocalSystemAccount = ($Service.StartName -eq "LocalSystem")
    $NoDescription = ([string]::IsNullOrEmpty($Service.Description))
    $Unsigned = IsUnsigned($BinaryPathName)
    $ShortName = $false
    $ShortDisplayName = $false
    $HighEntropyName = $false
    $HighEntropyDisplayName = $false
    $SuspiciousExtension = $false
    if ($extraChecks) {
        $ShortName = ($Service.Name.Length -le 5)
        $ShortDisplayName = ($Service.DisplayName.Length -le 5)
        $HighEntropyName = IsHighEntropyName($Service.Name)
        $HighEntropyDisplayName = IsHighEntropyName($Service.DisplayName)
        $SuspiciousExtension = HasSuspiciousExtension($BinaryPathName)
    }
    # If any of the suspicious characteristics are found, add the service to the list of detected services
    if ($PathSuspicious -or $LocalSystemAccount -or $NoDescription -or $Unsigned -or $ShortName -or $ShortDisplayName -or $HighEntropyName -or $HighEntropyDisplayName -or $SuspiciousExtension) {
        $DetectedServices.Add($Service) | Out-Null
    }
}
# Output the results
if ($DetectedServices.Count -gt 0) {
    Write-Host "Potentially Suspicious Services Detected"
    Write-Host "----------------------------------------"
    foreach ($Service in $DetectedServices) {
        Write-Host "Name: $($Service.Name) - Display Name: $($Service.DisplayName) - Status: $($Service.State) - StartName: $($Service.StartName) - Description: $($Service.Description) - Binary Path: $($Service.PathName.Trim('"'))"
        # Output verbose information about each suspicious characteristic
        if ($PathSuspicious) {
            Write-Host "`t- Running from a potentially suspicious path"
        }
        if ($LocalSystemAccount) {
            Write-Host "`t- Running with a LocalSystem account"
        }
        if ($NoDescription) {
            Write-Host "`t- No description provided"
        }
        if ($Unsigned) {
            Write-Host "`t- Unsigned executable"
        }
        if ($ShortName) {
            Write-Host "`t- Very short service name"
        }
        if ($ShortDisplayName) {
            Write-Host "`t- Very short display name"
        }
        if ($HighEntropyName) {
            Write-Host "`t- High entropy service name"
        }
        if ($HighEntropyDisplayName) {
            Write-Host "`t- High entropy display name"
        }
        if ($SuspiciousExtension) {
            Write-Host "`t- Suspicious file extension"
        }
        Write-Host ""
    }
} else {
    Write-Host "No potentially suspicious services detected."
}
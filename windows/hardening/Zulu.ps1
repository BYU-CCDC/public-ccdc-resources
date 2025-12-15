$NUM_WORDS = 5
$wordlistName = "wordlist.txt"
$ccdcRepoWindowsHardeningPath = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/hardening"
$wordlistPath = ".\$wordlistName"

# --- Wordlist Loading and Downloading ---
if (-not (Test-Path $wordlistPath)) {
    Write-Host "Downloading $wordlistName..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri "$ccdcRepoWindowsHardeningPath/$wordlistName" -OutFile $wordlistPath
        Write-Host "Downloaded $wordlistName successfully." -ForegroundColor Green
    } catch {
        Write-Error "Failed to download ${wordlistName}: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Host "File already exists: $wordlistName" -ForegroundColor Yellow
}

$wordlistData = (Get-Content -Path $wordlistPath -Raw) -split "`n" | Where-Object { $_ -ne "" }

if ($wordlistData.Count -eq 0) {
    Write-Error "The wordlist is empty after processing."
    exit 1
}

# --- Scale Function ---
function Scale-Value {
    param([Parameter(Mandatory=$true)][int]$x)
    $MIN = 0x0000
    $MAX = 0xFFFF
    $TARGET_MAX = $wordlistData.Count
    $TARGET_MIN = 0
    
    if ($TARGET_MAX -eq 0) { return 0 } 

    return [int](((($TARGET_MAX - $TARGET_MIN) * ($x - $MIN)) / ($MAX - $MIN)) + $TARGET_MIN)
}

# --- Main Logic ---

# 1. Get User Input
$user = Read-Host 'Enter a username:'
$secret = Read-Host 'Enter a salt you were given when you ran the script:'

# 2. Calculate MD5 Hash (Using System.Text.Encoding for brevity)
$inputString = "$secret$user"
$hash = [System.BitConverter]::ToString(([System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($inputString)))) -replace '-'

# 3. Determine Indices and Generate Passphrase
$passwordWords = @()
$indices = @()

for ($i = 0; $i -lt $hash.Length; $i += 4) {
    if ($i + 4 -le $hash.Length) {
        $hashSegment = $hash.Substring($i, 4)
        $intValue = [Convert]::ToInt32($hashSegment, 16)
        
        $index = Scale-Value -x $intValue
        $indices += $index
    }
}

for ($i = 0; $i -lt $NUM_WORDS; $i++) {
    if ($i -lt $indices.Count) {
        $passwordWords += $wordlistData[$indices[$i]]
    } else {
        Write-Warning "Not enough hash segments to generate $NUM_WORDS words."
        break
    }
}

# 4. Print Result
$password = $passwordWords -join '5-'
Write-Host ""
Write-Host "Generated Passphrase:" -ForegroundColor Green
Write-Host $password
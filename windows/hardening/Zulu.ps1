param (
    [Parameter(Mandatory=$false)]
    [Alias("f")]
    [string]$FilePath
)

$NUM_WORDS = 5
$wordlistName = "wordlist.txt"
$ccdcRepoWindowsHardeningPath = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/hardening"
$wordlistPath = ".\$wordlistName"
$ExcludedUsers = @("Guest", "DefaultAccount", "WDAGUtilityAccount", "ccdcuser1", "ccdcuser2", "Administrator")

# --- Wordlist Loading and Downloading ---
if (-not (Test-Path $wordlistPath)) {
    Write-Host "Downloading $wordlistName..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri "$ccdcRepoWindowsHardeningPath/$wordlistName" -OutFile $wordlistPath -ErrorAction Stop
        Write-Host "Downloaded $wordlistName successfully." -ForegroundColor Green
    } catch {
        Write-Error "Failed to download ${wordlistName}: $($_.Exception.Message)"
        exit 1
    }
}

$wordlistData = (Get-Content -Path $wordlistPath) | Where-Object { $_ -ne "" }

if ($wordlistData.Count -eq 0) {
    Write-Error "The wordlist is empty after processing."
    exit 1
}

# --- Scale Function ---
function Scale-Value {
    param([Parameter(Mandatory=$true)][int]$x)
    $MIN = 0x0000
    $MAX = 0xFFFF
    $TARGET_MAX = $wordlistData.Count - 1
    $TARGET_MIN = 0

    if ($TARGET_MAX -lt 0) { return 0 }

    # round down to nearest integer
    return [int][Math]::Truncate(((($TARGET_MAX - $TARGET_MIN) * ($x - $MIN)) / ($MAX - $MIN)) + $TARGET_MIN)
}

# --- Passphrase Generation Logic ---
function Get-Passphrase {
    param($user, $secret)

    $inputString = "$secret$user"
    $hash = [System.BitConverter]::ToString(([System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($inputString)))) -replace '-'

    $passwordWords = @()
    $indices = @()

    for ($i = 0; $i -lt $hash.Length; $i += 4) {
        if ($i + 4 -le $hash.Length) {
            $hashSegment = $hash.Substring($i, 4)
            $intValue = [Convert]::ToInt32($hashSegment, 16)
            $indices += Scale-Value -x $intValue
        }
    }

    for ($i = 0; $i -lt $NUM_WORDS; $i++) {
        if ($i -lt $indices.Count) {
            $passwordWords += $wordlistData[$indices[$i]]
        }
    }

    return ($passwordWords -join '-') + "1"
}

# --- Main Logic ---

if ($FilePath) {
    if (Test-Path $FilePath) {
        $usernames = Get-Content -Path $FilePath | Where-Object { $_ -match '\S' }
        $secret = Read-Host 'Enter the salt'
        $results = foreach ($u in $usernames) {
                $trimmedUser = $u.Trim()

                #Exclude machine accounts so we only grab local users
                if ($ExcludedUsers -contains $trimmedUser) {
                    Write-Host "Skipping excluded user: $trimmedUser" -ForegroundColor Yellow
                    continue # Skip to the next user in the loop
                }

                $pass = Get-Passphrase -user $trimmedUser -secret $secret
                Write-Host "Processing: $trimmedUser" -ForegroundColor Gray
                "$trimmedUser,$pass"
            }
            # 2. Write the entire collection to the file at once
        try {
            $ExportFilePath = ".\pcr.txt"
            $results | Out-File -FilePath $ExportFilePath -Encoding UTF8 -Force
            Write-Host "`n[SUCCESS] Exported $($results.Count) credential set(s) to: $ExportFilePath" -ForegroundColor Green
            } catch {
                Write-Host "[ERROR] Failed to export: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Error "File not found: $FilePath"
        }
} else {
    # Original Interactive Mode
    $user = Read-Host 'Enter a username'
    $secret = Read-Host 'Enter the salt'
    $password = Get-Passphrase -user $user -secret $secret

    Write-Host "`nGenerated Passphrase:" -ForegroundColor Green
    Write-Host $password
}

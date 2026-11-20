#Requires -Version 5.1

# New-Password.ps1 - Deterministic (Zulu) password generation.

function New-Password {
    <#
    .SYNOPSIS
        Generates a deterministic passphrase for a user given a seed phrase and wordlist.

    .DESCRIPTION
        Hashes (seed + username) with MD5, maps each 16-bit chunk to a wordlist index,
        and concatenates -NumWords words separated by dashes, with a trailing '1'.
        The result is always the same for the same inputs, making it reproducible
        across machines without storing passwords.

    .PARAMETER Username
        The username to generate a password for.

    .PARAMETER SeedPhrase
        The shared secret seed phrase (e.g. from -SaltPhrase).

    .PARAMETER WordlistData
        Array of words loaded from wordlist.txt.

    .EXAMPLE
        $words = Get-Content .\wordlist.txt
        New-Password -Username "jsmith" -SeedPhrase "competition2025" -WordlistData $words
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,

        [Parameter(Mandatory=$true)]
        [string]$SeedPhrase,

        [Parameter(Mandatory=$true)]
        [string[]]$WordlistData,

        # At most 8: each word uses 4 hex characters of the 32-character MD5 hash.
        [ValidateRange(1, 8)]
        [int]$NumWords = 5
    )

    $inputString = "$SeedPhrase$Username"
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $hashBytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($inputString))
    $hashString = [System.BitConverter]::ToString($hashBytes) -replace '-', ''

    $password = ""
    for ($i = 0; $i -lt ($NumWords * 4); $i += 4) {
        if ($i -ne 0) { $password += "-" }
        $hex = $hashString.Substring($i, 4)
        $dec = [Convert]::ToInt32($hex, 16)
        $index = ConvertTo-WordIndex -HashValue $dec -WordlistCount $WordlistData.Count
        $password += $WordlistData[$index]
    }
    $password + "1"
}

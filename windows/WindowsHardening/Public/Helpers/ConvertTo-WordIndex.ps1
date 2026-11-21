#Requires -Version 5.1

# ConvertTo-WordIndex.ps1 - Maps a hash fragment to a wordlist index (used by New-Password).

function ConvertTo-WordIndex {
    param(
        [Parameter(Mandatory=$true)]
        [int]$HashValue,

        [Parameter(Mandatory=$true)]
        [int]$WordlistCount
    )
    $TARGET_MAX = $WordlistCount - 1
    if ($TARGET_MAX -lt 0) { return 0 }
    return [int][Math]::Truncate(((($TARGET_MAX) * ($HashValue - 0x0000)) / (0xFFFF - 0x0000)))
}

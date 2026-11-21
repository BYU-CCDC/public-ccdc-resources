#Requires -Version 5.1

# Prompts.ps1 - Interactive prompts: yes/no, IP address or host name, hidden input.

function Read-YesNo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [switch]$Force
    )

    try {
        if ($Force) {
            return 'y'
        }

        do {
            Write-Host $Message -ForegroundColor Yellow -NoNewline
            $response = Read-Host
            if ($response -ieq 'y' -or $response -ieq 'n') {
                return $response
            } else {
                Write-Host "Please enter 'y' or 'n'." -ForegroundColor Yellow
            }
        } while ($true)
    } catch {
        Write-Status -Level Error "Error in Read-YesNo: $($_.Exception.Message)"
        return "n"
    }
}

function Read-HostAddress {
    <#
    .SYNOPSIS
        Prompts for an IP address or host name; asks again until Test-HostAddress accepts it.
    .EXAMPLE
        $ip = Read-HostAddress -Prompt "Splunk server IP"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Prompt
    )

    Read-Choice -Prompt $Prompt -AllowCustom -ValidateCustom {
        param($value)
        if (-not (Test-HostAddress $value)) { throw "not a valid IP address or host name" }
        $value
    }
}

function Read-SecretInput {
    param([string]$Prompt)
    Write-Host -NoNewline $Prompt

    # Read-Host masks input on both Windows PowerShell and Unix PowerShell.
    # SecureStringToBSTR returns a BSTR; PtrToStringAuto can read only one
    # character on some PowerShell 7 hosts, making every seed appear too short.
    $secure = Read-Host -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $input = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $input
}

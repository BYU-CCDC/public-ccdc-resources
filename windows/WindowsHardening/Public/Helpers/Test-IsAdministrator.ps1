#Requires -Version 5.1

# Test-IsAdministrator.ps1 - True when the current session is elevated.

function Test-IsAdministrator {
    [CmdletBinding()]
    param()
    $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

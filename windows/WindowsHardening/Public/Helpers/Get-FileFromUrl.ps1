#Requires -Version 5.1

# Get-FileFromUrl.ps1 - File download helper.

function Get-FileFromUrl {
    param(
        [string]$Url,
        [string]$OutputPath
    )
    try {
        Write-Status "Downloading $Url"
        $ProgressPreference = 'SilentlyContinue'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
        $ProgressPreference = 'Continue'
        $true
    } catch {
        Write-Status -Level Error "Failed to download $Url : $($_.Exception.Message)"
        $false
    }
}

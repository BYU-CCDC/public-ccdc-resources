function Install-Splunk {
    <#
    .SYNOPSIS
        Downloads and runs the CCDC splunk.ps1 to install a Universal Forwarder.
    .DESCRIPTION
        splunk.ps1 detects the Windows version itself and appends the forwarding port
        (9997) to the IP, so only the bare IP is passed. It prompts for the Splunk admin
        password.
    .PARAMETER IP
        Splunk indexer IP address (no port).
    .PARAMETER Version
        Override the detected Windows version. Short forms (10, 2019, 2012R2) or splunk.ps1's
        own names ("Windows Server 2019") are accepted.
    #>
    [CmdletBinding()]
    param(
        [string]$Version,

        [Parameter(Mandatory=$true)]
        [string]$IP
    )

    Invoke-HardeningOperation -OperationName "Configure Splunk" -ScriptBlock {
        $downloadURL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk/splunk.ps1"
        $splunkScript = Join-Path $env:TEMP 'splunk.ps1'

        # splunk.ps1 adds ":9997" itself; strip a port if one was given.
        $indexerIP = ($IP -replace ':\d+$', '').Trim()
        if (-not (Test-HostAddress $indexerIP)) {
            throw "Invalid -IP '$IP': not an IP address or host name"
        }

        $splunkArgs = @{ ip = $indexerIP }
        if ($Version) {
            $splunkArgs.WindowsVersion = switch -Regex ($Version.Trim()) {
                '^Windows '            { $Version.Trim(); break }
                '^(7|8|10|11)$'        { "Windows $Version"; break }
                '^(20\d\d)\s*R2$'     { "Windows Server $($Matches[1]) R2"; break }
                '^20\d\d$'             { "Windows Server $Version"; break }
                default { throw "Unrecognized -Version '$Version' (use e.g. 10, 2019, 2012R2)" }
            }
        }

        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $downloadURL -OutFile $splunkScript -UseBasicParsing -ErrorAction Stop
            Write-Status -Level Success "Downloaded Splunk installation script" -LogOnly

            # The upstream script maps Windows Server 2016 to $10_0_2_x64, but
            # never defines that variable. Supply its intended 10.0.2 x64 URL
            # in this scope so the child script can resolve it.
            Set-Variable -Name '10_0_2_x64' -Scope Local -Value 'https://download.splunk.com/products/universalforwarder/releases/10.0.2/windows/splunkforwarder-10.0.2-e2d18b4767e9-windows-x64.msi'

            Write-Status "Running splunk.ps1 (forwarding to ${indexerIP}:9997)$(if ($splunkArgs.WindowsVersion) { " for $($splunkArgs.WindowsVersion)" })"
            $global:LASTEXITCODE = 0
            & $splunkScript @splunkArgs
            if ($LASTEXITCODE -ne 0) {
                throw "splunk.ps1 failed with exit code $LASTEXITCODE"
            } else {
                Write-Status -Level Success "Splunk installation completed" -LogOnly
            }
        } catch {
            Write-Status -Level Error "Splunk installation failed: $($_.Exception.Message)"
            throw
        }
    }
}

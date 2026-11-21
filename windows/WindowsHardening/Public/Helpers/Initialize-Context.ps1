#Requires -Version 5.1

# Initialize-Context.ps1 - Hardening context: data files and port definitions.

# -- Module constants ---------------------------------------------------------

# No trailing slash: callers append "/<file>".
$script:CcdcRepoUrl = 'https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/hardening'
$script:RequiredFiles = @('ports.json', 'patchURLs.json', 'wordlist.txt')
$script:FallbackPorts = @{
    ports = @{
        '53'   = @{ description = 'DNS' }
        '3389' = @{ description = 'RDP' }
        '80'   = @{ description = 'HTTP' }
        '445'  = @{ description = 'SMB' }
        '139'  = @{ description = 'NetBIOS Session' }
        '22'   = @{ description = 'SSH' }
        '88'   = @{ description = 'Kerberos' }
        '67'   = @{ description = 'DHCP Server' }
        '68'   = @{ description = 'DHCP Client' }
        '135'  = @{ description = 'RPC' }
        '389'  = @{ description = 'LDAP' }
        '636'  = @{ description = 'LDAPS' }
        '3268' = @{ description = 'Global Catalog' }
        '3269' = @{ description = 'Global Catalog SSL' }
        '464'  = @{ description = 'Kerberos Change/Set Password' }
    }
}

function Initialize-Context {
    [CmdletBinding()]
    param()

    Invoke-HardeningOperation -OperationName "Initialize Context" -ScriptBlock {
        # Data files ship in the module's Data folder; download only if one is missing
        if (-not (Test-Path $script:DataPath)) {
            New-Item -Path $script:DataPath -ItemType Directory -Force | Out-Null
        }
        foreach ($file in $script:RequiredFiles) {
            $filename = $(Split-Path -Path $file -Leaf)
            $target = Join-Path $script:DataPath $filename
            if (-not (Test-Path $target)) {
                Write-Status "Downloading $filename (missing from Data\)"
                try {
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Invoke-WebRequest -Uri "$script:CcdcRepoUrl/$file" -OutFile $target
                    Write-Status -Level Success "Downloaded $filename" -LogOnly
                } catch {
                    # Non-fatal: each consumer checks for its own file (ports.json has a fallback).
                    Write-Status -Level Warning "Failed to download $filename : $($_.Exception.Message)"
                }
            } else {
                Write-Verbose "File already exists: $filename"
            }
        }

        # Load port data
        $portsFile = Join-Path $script:DataPath 'ports.json'
        if (Test-Path $portsFile) {
            $script:HardeningContext.Ports = Get-Content -Path $portsFile -Raw | ConvertFrom-Json
            Write-Status "Loaded ports configuration from ports.json" -LogOnly
        } else {
            $script:HardeningContext.Ports = $script:FallbackPorts
            Write-Status -Level Warning "ports.json not found, using fallback port definitions"
        }

    }
}

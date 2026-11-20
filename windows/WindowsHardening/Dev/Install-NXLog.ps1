#Requires -Version 5.1

function Install-NXLog {
    <#
    .SYNOPSIS
        Installs NXLog Community Edition and configures Windows Event Log forwarding to Graylog.
    .PARAMETER GraylogServer
        Graylog host name or IP address.
    .PARAMETER Port
        Graylog GELF input port. Defaults to 12201.
    .PARAMETER Transport
        GELF transport protocol. Defaults to UDP.
    .PARAMETER InstallerPath
        Optional local NXLog CE MSI. When omitted, the official NXLog CE MSI is downloaded.
    .PARAMETER InstallerUrl
        Optional direct MSI URL, useful when pinning an approved installer version. When
        omitted, the current Windows x64 MSI is resolved from NXLog's official download page.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$GraylogServer,

        [ValidateRange(1,65535)]
        [int]$Port = 12201,

        [ValidateSet('UDP','TCP')]
        [string]$Transport = 'UDP',

        [string]$InstallerPath,

        [string]$InstallerUrl
    )

    Invoke-HardeningOperation -OperationName 'Install NXLog' -ProgressMessage 'Installing and configuring NXLog for Graylog' -ScriptBlock {
        $server = $GraylogServer.Trim()
        if (-not (Test-HostAddress $server)) {
            throw "Invalid -GraylogServer '$GraylogServer': use an IP address or host name"
        }

        $msi = $InstallerPath
        if ($msi) {
            if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) {
                throw "NXLog installer not found: $msi"
            }
            $msi = (Resolve-Path -LiteralPath $msi).Path
        } else {
            $msi = Join-Path $env:TEMP 'nxlog-ce-installer.msi'
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                if ($InstallerUrl) {
                    Invoke-WebRequest -Uri $InstallerUrl -OutFile $msi -UseBasicParsing -ErrorAction Stop
                } else {
                    # NXLog requires selecting the MSI on its downloads page before it
                    # returns a short-lived download URL. Resolve the current x64 file ID
                    # rather than hardcoding a file ID that changes between releases.
                    $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
                    $page = Invoke-WebRequest -Uri 'https://nxlog.co/downloads/nxlog-ce' -UseBasicParsing -WebSession $webSession -ErrorAction Stop
                    $csrf = [Regex]::Match($page.Content, '<meta name="csrf-token" content="([^"]+)"').Groups[1].Value
                    $windowsLabelAt = $page.Content.IndexOf('Windows x86-64', [StringComparison]::OrdinalIgnoreCase)
                    $rowStart = if ($windowsLabelAt -ge 0) { $page.Content.LastIndexOf('<tr', $windowsLabelAt, [StringComparison]::OrdinalIgnoreCase) } else { -1 }
                    $rowEnd = if ($windowsLabelAt -ge 0) { $page.Content.IndexOf('</tr>', $windowsLabelAt, [StringComparison]::OrdinalIgnoreCase) } else { -1 }
                    $windowsRow = if ($rowStart -ge 0 -and $rowEnd -gt $rowStart) { $page.Content.Substring($rowStart, $rowEnd - $rowStart + 5) } else { '' }
                    $fileId = [Regex]::Match($windowsRow, '(?is)<input[^>]*value="(\d+)"').Groups[1].Value
                    if (-not $csrf -or -not $fileId) {
                        throw 'Could not find the Windows x86-64 NXLog CE MSI on the official download page.'
                    }
                    $headers = @{
                        Accept = 'application/json'
                        'X-Requested-With' = 'XMLHttpRequest'
                        'X-CSRF-Token' = $csrf
                    }
                    $body = @{ file_id = [int]$fileId } | ConvertTo-Json -Compress
                    $linkResponse = Invoke-WebRequest -Uri 'https://nxlog.co/downloads' -Method Post -Body $body `
                        -ContentType 'application/json' -Headers $headers -UseBasicParsing -WebSession $webSession -ErrorAction Stop
                    $downloadInfo = $linkResponse.Content | ConvertFrom-Json
                    if (-not $downloadInfo.success -or -not $downloadInfo.data.link) {
                        throw 'NXLog did not return a download link for its Windows MSI.'
                    }
                    Invoke-WebRequest -Uri $downloadInfo.data.link -OutFile $msi -UseBasicParsing -WebSession $webSession -ErrorAction Stop
                }
            } catch {
                throw "Could not download the NXLog MSI from NXLog. Supply -InstallerPath or a direct -InstallerUrl. $($_.Exception.Message)"
            }
            if (-not (Test-Path -LiteralPath $msi -PathType Leaf) -or (Get-Item -LiteralPath $msi).Length -lt 100000) {
                throw "The download did not produce an MSI. Supply -InstallerPath or a direct -InstallerUrl."
            }
            $stream = [IO.File]::OpenRead($msi)
            try {
                $signature = New-Object byte[] 8
                [void]$stream.Read($signature, 0, $signature.Length)
                if ([BitConverter]::ToString($signature) -ne 'D0-CF-11-E0-A1-B1-1A-E1') {
                    throw "The download is not an MSI file. Supply -InstallerPath or a direct -InstallerUrl."
                }
            } finally {
                $stream.Dispose()
            }
        }

        Write-Status "Installing NXLog from $msi"
        $msiLog = Join-Path $env:TEMP 'nxlog-install.log'
        $installerArgs = @('/i', "`"$msi`"", '/qn', '/norestart', '/l*v', "`"$msiLog`"")
        $install = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $installerArgs -Wait -PassThru
        if ($install.ExitCode -eq 1603) {
            Write-Status -Level Warning "NXLog returned MSI error 1603 on the first attempt; retrying once. See $msiLog for details."
            $install = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $installerArgs -Wait -PassThru
        }
        if ($install.ExitCode -notin @(0,3010,1641)) {
            throw "NXLog MSI installation failed with exit code $($install.ExitCode). See $msiLog for details."
        }

        $nxlogRoot = Join-Path $env:ProgramFiles 'nxlog'
        if (-not (Test-Path -LiteralPath $nxlogRoot) -and ${env:ProgramFiles(x86)}) {
            $nxlogRoot = Join-Path ${env:ProgramFiles(x86)} 'nxlog'
        }
        $configPath = Join-Path $nxlogRoot 'conf\nxlog.conf'
        if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
            throw "NXLog installed, but its configuration file was not found at '$configPath'"
        }

        $hostForConfig = $server
        if ($hostForConfig -match '[\s#]') { throw 'Graylog host names cannot contain spaces or # characters.' }
        $outputModule = if ($Transport -eq 'TCP') { 'om_tcp' } else { 'om_udp' }
        $outputType = if ($Transport -eq 'TCP') { 'GELF_TCP' } else { 'GELF_UDP' }
        $config = @"
## Windows Event Log forwarding to Graylog. Generated by Install-NXLog.
define ROOT $($nxlogRoot -replace '\\','/')
define CONFDIR %ROOT%/conf
define LOGDIR %ROOT%/data
LogFile %LOGDIR%/nxlog.log
LogLevel INFO

<Extension gelf>
    Module xm_gelf
</Extension>

<Input windows_events>
    Module im_msvistalog
</Input>

<Output graylog>
    Module $outputModule
    Host $hostForConfig
    Port $Port
    OutputType $outputType
</Output>

<Route windows_events_to_graylog>
    Path windows_events => graylog
</Route>
"@
        $backup = "$configPath.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        Copy-Item -LiteralPath $configPath -Destination $backup -Force
        Set-Content -LiteralPath $configPath -Value $config -Encoding ASCII

        $service = Get-Service -Name 'nxlog' -ErrorAction SilentlyContinue
        if (-not $service) { $service = Get-Service | Where-Object { $_.DisplayName -match '^NXLog' } | Select-Object -First 1 }
        if (-not $service) { throw 'NXLog was installed, but its Windows service could not be found.' }
        Set-Service -Name $service.Name -StartupType Automatic
        if ($service.Status -eq 'Running') { Restart-Service -Name $service.Name -Force -ErrorAction Stop }
        else { Start-Service -Name $service.Name -ErrorAction Stop }

        Write-Status -Level Success "NXLog is forwarding Windows Event Logs to ${server}:$Port over GELF/$Transport. Previous config: $backup"
    }
}

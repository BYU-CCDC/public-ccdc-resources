#Requires -Version 5.1

function Install-Fibratus {
    <#
    .SYNOPSIS
        Installs Fibratus and forwards its JSON event stream to Splunk UF, Splunk HEC, or NXLog.
    .PARAMETER ForwardingMode
        SplunkUniversalForwarder (default), Splunk (HEC), or NXLog.
    .PARAMETER SplunkHecUrl
        Splunk HEC raw endpoint URL, such as https://splunk.example:8088/services/collector/raw.
    .PARAMETER SplunkHecToken
        HEC token. This is written to the Fibratus config file; protect that file accordingly.
    .PARAMETER SplunkIndex
        Index configured for the Universal Forwarder monitor input. Defaults to security.
    .PARAMETER NXLogServer
        Graylog host name or IP address when ForwardingMode is NXLog.
    .PARAMETER NXLogPort
        Graylog GELF input port for NXLog mode. Defaults to 12201.
    .PARAMETER NXLogTransport
        GELF transport for NXLog mode. Defaults to UDP.
    .PARAMETER StreamPath
        Path to the JSON Lines event stream monitored by Splunk UF or NXLog.
    .PARAMETER FibratusVersion
        Optional Fibratus release tag to install (for example, v3.1.1). By default,
        Server 2016 and Server 2019 use v2.4.0 because the current v3.1.1 sensor panics
        while enriching process integrity on those OS versions; other versions use latest.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('SplunkUniversalForwarder','Splunk','NXLog')]
        [string]$ForwardingMode = 'SplunkUniversalForwarder',

        [string]$SplunkHecUrl,
        [string]$SplunkHecToken,
        [ValidatePattern('^[A-Za-z0-9_\-]+$')]
        [string]$SplunkIndex = 'security',

        [string]$NXLogServer,
        [ValidateRange(1,65535)]
        [int]$NXLogPort = 12201,
        [ValidateSet('UDP','TCP')]
        [string]$NXLogTransport = 'UDP',

        [string]$StreamPath = (Join-Path $env:ProgramFiles 'Fibratus\Logs\fibratus-stream.json'),

        [ValidatePattern('^v?\d+\.\d+\.\d+$')]
        [string]$FibratusVersion
    )

    Invoke-HardeningOperation -OperationName 'Install Fibratus' -ProgressMessage "Installing Fibratus ($ForwardingMode forwarding)" -ScriptBlock {
        if ($ForwardingMode -eq 'Splunk') {
            if (-not $SplunkHecUrl -or -not $SplunkHecToken) {
                throw "Splunk mode requires -SplunkHecUrl and -SplunkHecToken (use a Splunk HEC raw endpoint and token)."
            }
            $uri = $null
            if (-not [Uri]::TryCreate($SplunkHecUrl, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -notin @('https','http')) {
                throw "Invalid -SplunkHecUrl '$SplunkHecUrl': provide an absolute HTTP or HTTPS URL."
            }
            if ($uri.Scheme -ne 'https') { Write-Status -Level Warning 'Splunk HEC URL uses HTTP; the HEC token and events will not be encrypted in transit.' }
        }
        if ($ForwardingMode -eq 'NXLog') {
            if (-not $NXLogServer -or -not (Test-HostAddress $NXLogServer.Trim())) {
                throw 'NXLog mode requires a valid -NXLogServer host name or IP address.'
            }
            $NXLogServer = $NXLogServer.Trim()
        }

        $streamFullPath = [IO.Path]::GetFullPath($StreamPath)
        $streamDir = Split-Path -Parent $streamFullPath
        if (-not (Test-Path -LiteralPath $streamDir)) { New-Item -Path $streamDir -ItemType Directory -Force | Out-Null }
        $stderrPath = Join-Path $streamDir 'fibratus-errors.log'

        $bootstrapPath = Join-Path $env:TEMP 'install-fibratus.ps1'
        $osVersion = $script:HardeningContext.OS.OSVersion
        $selectedVersion = $FibratusVersion
        if (-not $selectedVersion -and $osVersion -match '^Windows Server (2016|2019)$') {
            $selectedVersion = 'v2.4.0'
            Write-Status -Level Warning "Using Fibratus $selectedVersion on $osVersion to avoid a process-integrity panic in v3.1.1. Pass -FibratusVersion to override."
        }
        if ($selectedVersion -and $selectedVersion -notmatch '^v') { $selectedVersion = "v$selectedVersion" }
        $installerStdout = Join-Path $env:TEMP 'install-fibratus.stdout.log'
        $installerStderr = Join-Path $env:TEMP 'install-fibratus.stderr.log'
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri 'https://install.fibratus.io' -OutFile $bootstrapPath -UseBasicParsing -ErrorAction Stop
            Write-Status 'Downloaded the official Fibratus installer'
            # The upstream bootstrap downloads the MSI in a background job when
            # attached to an interactive console. Start-Job launches a separate
            # PowerShell process, so the TLS 1.2 setting above is not inherited and
            # the asset download can fail on older Windows/.NET defaults. Redirect
            # its output so the bootstrap takes its synchronous download path.
            $powershellExe = Join-Path $PSHOME 'powershell.exe'
            Remove-Item -LiteralPath $installerStdout, $installerStderr -Force -ErrorAction SilentlyContinue

            $installerArguments = @(
                '-NoProfile',
                '-NonInteractive',
                '-ExecutionPolicy', 'Bypass',
                '-File', "`"$bootstrapPath`""
            )
            if ($selectedVersion) { $installerArguments += @('-Version', $selectedVersion) }
            $installerArguments += '-Force'

            $installerProcess = Start-Process -FilePath $powershellExe -ArgumentList $installerArguments `
                -RedirectStandardOutput $installerStdout -RedirectStandardError $installerStderr `
                -WindowStyle Hidden -Wait -PassThru

            foreach ($line in @(Get-Content -LiteralPath $installerStdout -ErrorAction SilentlyContinue)) {
                Write-Host $line
            }
            foreach ($line in @(Get-Content -LiteralPath $installerStderr -ErrorAction SilentlyContinue)) {
                Write-Host $line -ForegroundColor Red
            }
            if ($installerProcess.ExitCode -ne 0) {
                $details = @(
                    Get-Content -LiteralPath $installerStdout -Tail 8 -ErrorAction SilentlyContinue
                    Get-Content -LiteralPath $installerStderr -Tail 8 -ErrorAction SilentlyContinue
                ) -join ' '
                throw "Fibratus installer exited with code $($installerProcess.ExitCode). $details"
            }
        } catch {
            throw "Fibratus installation failed: $($_.Exception.Message)"
        } finally {
            Remove-Item -LiteralPath $installerStdout, $installerStderr -Force -ErrorAction SilentlyContinue
        }

        $fibratusExe = Join-Path $env:ProgramFiles 'Fibratus\Bin\fibratus.exe'
        if (-not (Test-Path -LiteralPath $fibratusExe -PathType Leaf)) {
            $found = Get-ChildItem -Path (Join-Path $env:ProgramFiles 'Fibratus') -Filter 'fibratus.exe' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) { $fibratusExe = $found.FullName }
        }
        if (-not (Test-Path -LiteralPath $fibratusExe -PathType Leaf)) { throw 'Fibratus installer completed, but fibratus.exe was not found under Program Files.' }

        $configDir = Join-Path $env:ProgramFiles 'Fibratus\Config'
        if (-not (Test-Path -LiteralPath $configDir)) { New-Item -Path $configDir -ItemType Directory -Force | Out-Null }
        $configPath = Join-Path $configDir 'fibratus.yml'
        if (Test-Path -LiteralPath $configPath) {
            $backup = "$configPath.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
            Copy-Item -LiteralPath $configPath -Destination $backup -Force
            Write-Status "Backed up the existing Fibratus configuration to $backup"
        }

        if ($ForwardingMode -eq 'Splunk') {
            $token = $SplunkHecToken.Replace('"','\"')
            $yaml = @"
forward: true
output:
  console:
    enabled: false
  http:
    enabled: true
    endpoints:
      - "$($SplunkHecUrl.Replace('"','\"'))"
    method: POST
    serializer: json
    headers:
      Authorization: "Splunk $token"
"@
        } else {
            # Splunk UF and NXLog both consume the JSON Lines file produced by stdout redirection.
            $yaml = @"
forward: true
output:
  console:
    enabled: true
    format: json
"@
        }
        Set-Content -LiteralPath $configPath -Value $yaml -Encoding UTF8
        if (-not (Test-Path -LiteralPath $streamFullPath)) { New-Item -Path $streamFullPath -ItemType File -Force | Out-Null }

        # Fibratus' MSI starts its own service. Use the same hidden `fibratus.exe run`
        # stdout-redirection pattern documented in the supplied screenshots so that
        # the stream file is available to the selected forwarder.
        $fibratusServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^Fibratus' -or $_.DisplayName -match '^Fibratus' }
        foreach ($svc in $fibratusServices) {
            if ($svc.Status -eq 'Running') { Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue }
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
        }
        $stopDeadline = (Get-Date).AddSeconds(45)
        do {
            $runningService = Get-Service -ErrorAction SilentlyContinue | Where-Object {
                ($_.Name -match '^Fibratus' -or $_.DisplayName -match '^Fibratus') -and $_.Status -eq 'Running'
            }
            $runningProcess = Get-Process -Name 'fibratus' -ErrorAction SilentlyContinue
            if (-not $runningService -and -not $runningProcess) { break }
            Start-Sleep -Seconds 2
        } while ((Get-Date) -lt $stopDeadline)
        if ($runningService -or $runningProcess) {
            throw 'The Fibratus service or process did not stop; refusing to launch a second instance.'
        }
        $escapedExe = $fibratusExe.Replace("'", "''")
        $escapedStream = $streamFullPath.Replace("'", "''")
        $escapedStderr = $stderrPath.Replace("'", "''")
        $taskCommand = "`$p=Start-Process -FilePath '$escapedExe' -ArgumentList 'run' -RedirectStandardOutput '$escapedStream' -RedirectStandardError '$escapedStderr' -WindowStyle Hidden -PassThru -Wait; if (`$p.ExitCode -ne 0) { exit `$p.ExitCode }"
        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"$taskCommand`"" -WorkingDirectory (Split-Path -Parent $fibratusExe)
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName 'Fibratus Event Stream' -Action $action -Trigger $trigger -Principal $principal -Description 'Runs Fibratus and writes its JSON event stream for the configured log forwarder.' -Force | Out-Null
        Start-ScheduledTask -TaskName 'Fibratus Event Stream'

        if ($ForwardingMode -eq 'SplunkUniversalForwarder') {
            $ufService = Get-Service -Name 'SplunkForwarder' -ErrorAction SilentlyContinue
            $splunkHomes = @((Join-Path $env:ProgramFiles 'SplunkUniversalForwarder'))
            if (${env:ProgramFiles(x86)}) {
                $splunkHomes += Join-Path ${env:ProgramFiles(x86)} 'SplunkUniversalForwarder'
            }
            $splunkHomes = $splunkHomes | Where-Object { Test-Path -LiteralPath $_ }
            $splunkHome = $splunkHomes | Select-Object -First 1
            if (-not $splunkHome -and $ufService) {
                try {
                    $ufBinary = (Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'").PathName
                    if ($ufBinary -match '^\s*"?(.+?SplunkUniversalForwarder)\\bin\\splunkd\.exe') { $splunkHome = $Matches[1] }
                } catch { }
            }
            if ($splunkHome) {
                $inputsDir = Join-Path $splunkHome 'etc\apps\CCDC_Fibratus\local'
                if (-not (Test-Path -LiteralPath $inputsDir)) { New-Item -Path $inputsDir -ItemType Directory -Force | Out-Null }
                $inputsPath = Join-Path $inputsDir 'inputs.conf'
                $monitorName = "monitor://$streamFullPath"
                $existingInputs = if (Test-Path -LiteralPath $inputsPath) { Get-Content -LiteralPath $inputsPath -Raw } else { '' }
                if ($existingInputs -notmatch ('(?im)^\[' + [Regex]::Escape($monitorName) + '\]$')) {
                    if (Test-Path -LiteralPath $inputsPath) {
                        $inputsBackup = "$inputsPath.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
                        Copy-Item -LiteralPath $inputsPath -Destination $inputsBackup -Force
                    }
                    $monitorConfig = @"
[$monitorName]
disabled = false
index = $SplunkIndex
sourcetype = _json
"@
                    Add-Content -LiteralPath $inputsPath -Value "`r`n$monitorConfig" -Encoding ASCII
                }
                if ($ufService) {
                    try {
                        if ($ufService.Status -eq 'Running') { Restart-Service -Name $ufService.Name -Force -ErrorAction Stop }
                        else { Start-Service -Name $ufService.Name -ErrorAction Stop }
                    } catch { Write-Status -Level Warning "The forwarder input was written, but SplunkForwarder could not be restarted: $($_.Exception.Message)" }
                } else {
                    Write-Status -Level Warning 'Universal Forwarder files were found, but its SplunkForwarder service was not found; restart the forwarder to load the new input.'
                }
                Write-Status -Level Success "Fibratus is writing JSON events to $streamFullPath; the Universal Forwarder input is configured in $inputsPath (index $SplunkIndex, sourcetype _json)."
            } else {
                Write-Status -Level Warning "Fibratus is writing JSON events to $streamFullPath, but Splunk Universal Forwarder was not found. Configure it to monitor this file with index $SplunkIndex and sourcetype _json."
            }
        } elseif ($ForwardingMode -eq 'Splunk') {
            Write-Status -Level Success "Fibratus HTTP output is configured for Splunk HEC at $SplunkHecUrl."
        } else {
            $nxlogRoot = Join-Path $env:ProgramFiles 'nxlog'
            if (-not (Test-Path -LiteralPath $nxlogRoot) -and ${env:ProgramFiles(x86)}) {
                $nxlogRoot = Join-Path ${env:ProgramFiles(x86)} 'nxlog'
            }
            $nxlogConf = Join-Path $nxlogRoot 'conf\nxlog.conf'
            if (-not (Test-Path -LiteralPath $nxlogConf)) { throw "NXLog mode requires NXLog to be installed; expected '$nxlogConf'." }
            $fragmentPath = Join-Path $nxlogRoot 'conf\fibratus.conf'
            $module = if ($NXLogTransport -eq 'TCP') { 'om_tcp' } else { 'om_udp' }
            $gelfType = if ($NXLogTransport -eq 'TCP') { 'GELF_TCP' } else { 'GELF_UDP' }
            $fileForNxlog = $streamFullPath.Replace('\','/')
            $fragment = @"
## Generated by Install-Fibratus. Ensure nxlog.conf includes this file.
<Extension fibratus_gelf>
    Module xm_gelf
</Extension>
<Input fibratus_stream>
    Module im_file
    File "$fileForNxlog"
</Input>
<Output fibratus_graylog>
    Module $module
    Host $NXLogServer
    Port $NXLogPort
    OutputType $gelfType
</Output>
<Route fibratus_to_graylog>
    Path fibratus_stream => fibratus_graylog
</Route>
"@
            Set-Content -LiteralPath $fragmentPath -Value $fragment -Encoding ASCII
            $mainConfig = Get-Content -LiteralPath $nxlogConf -Raw
            $includeLine = 'include %CONFDIR%/fibratus.conf'
            if ($mainConfig -notmatch '(?im)^\s*include\s+.*fibratus\.conf\s*$') {
                $nxlogBackup = "$nxlogConf.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
                Copy-Item -LiteralPath $nxlogConf -Destination $nxlogBackup -Force
                Add-Content -LiteralPath $nxlogConf -Value "`r`n$includeLine`r`n" -Encoding ASCII
            }
            $nxlogSvc = Get-Service -Name 'nxlog' -ErrorAction SilentlyContinue
            if (-not $nxlogSvc) { $nxlogSvc = Get-Service | Where-Object { $_.DisplayName -match '^NXLog' } | Select-Object -First 1 }
            if (-not $nxlogSvc) { throw 'NXLog config fragment was written, but the NXLog service was not found.' }
            if ($nxlogSvc.Status -eq 'Running') { Restart-Service -Name $nxlogSvc.Name -Force -ErrorAction Stop }
            else { Start-Service -Name $nxlogSvc.Name -ErrorAction Stop }
            Write-Status -Level Success "Fibratus JSON events at $streamFullPath are configured for NXLog -> ${NXLogServer}:$NXLogPort over GELF/$NXLogTransport."
        }

        # ETW initialization and the first emitted event can take several seconds on
        # Windows Server. Wait for a live process and, for file modes, actual file data.
        $streamReady = $ForwardingMode -eq 'Splunk'
        $processReady = $false
        for ($attempt = 0; $attempt -lt 12; $attempt++) {
            $processReady = [bool](Get-Process -Name 'fibratus' -ErrorAction SilentlyContinue)
            if ($ForwardingMode -ne 'Splunk' -and (Test-Path -LiteralPath $streamFullPath)) {
                $streamReady = (Get-Item -LiteralPath $streamFullPath).Length -gt 0
            }
            if ($processReady -and $streamReady) { break }

            if ($attempt -ge 1 -and -not $processReady) {
                $taskState = (Get-ScheduledTask -TaskName 'Fibratus Event Stream' -ErrorAction SilentlyContinue).State
                if ($taskState -ne 'Running') { break }
            }
            Start-Sleep -Seconds 5
        }

        if (-not $processReady) {
            $taskResult = (Get-ScheduledTaskInfo -TaskName 'Fibratus Event Stream' -ErrorAction SilentlyContinue).LastTaskResult
            $errorDetails = if (Test-Path -LiteralPath $stderrPath) {
                $lines = Get-Content -LiteralPath $stderrPath -ErrorAction SilentlyContinue
                (@($lines | Select-Object -First 2) + @($lines | Select-Object -Last 5)) -join ' '
            } else { 'No stderr file was written.' }
            throw "Fibratus exited during startup (task result: $taskResult). $errorDetails"
        }
        if (-not $streamReady) {
            $errorDetails = if (Test-Path -LiteralPath $stderrPath) {
                (Get-Content -LiteralPath $stderrPath -Tail 8 -ErrorAction SilentlyContinue) -join ' '
            } else { 'No stderr file was written.' }
            throw "Fibratus is running but has not written JSON events to '$streamFullPath'. $errorDetails"
        }
    }
}

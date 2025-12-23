$GITHUB_URL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main"
$OSSECDIR="C:\Program Files (x86)\ossec-agent"
$OSSEC_DOWNLOAD = "https://updates.atomicorp.com/channels/atomic/windows/ossec-agent-win32-3.8.0-35114.exe"

function print {
    param (
        [string]$msg
    )
    Write-Host "[*]" $msg
}

function error {
    param (
        [string]$msg
    )
    Write-Host "[X]" $msg
}

function download {
    param (
        [string]$url,
        [string]$path
    )
    print "Downloading $url to $path"
    
    # Remove the file if it exists
    if (Test-Path $path) {
        Remove-Item $path -Force
    }

    if ($LOCAL_INSTALL -and $url.StartsWith($GITHUB_URL)) {
        Copy-Item -Path $url -Destination $path -Force
    } else {
        $wc = New-Object net.webclient
        $wc.Downloadfile($url, $path) 2>$null

        if (-not $?) {
            error "Download failed; trying with wget"
            wget $url -OutFile $path
        }
    }
}

function install_ossec {
    # Install OSSEC
    download "$OSSEC_DOWNLOAD" "$pwd\ossec-agent.exe"
    Start-Process -FilePath ".\ossec-agent.exe" -Wait

    # Install configuration file
    Move-Item -Path "$OSSECDIR\ossec.conf" "$OSSECDIR\ossec.conf.bak" -Force 2>$null
    # download "$GITHUB_URL/ossec/windows/ossec-agent-local.conf" "$pwd\ossec-agent.conf"
    download "$GITHUB_URL/ossec/windows/ossec-agent.conf" "$pwd\ossec-agent.conf"

    (Get-Content ".\ossec-agent.conf") -replace "{SERVER_IP}", $ip | Set-Content ".\ossec-agent.conf"
    Move-Item -Path ".\ossec-agent.conf" -Destination "$OSSECDIR\ossec.conf" -Force

    # Register and start agent
    & "$OSSECDIR\ossec-agent.exe" install-service
    & "$OSSECDIR\agent-auth.exe" -m $ip -p 1515
    Move-Item "client.keys" "$OSSECDIR\client.keys" -Force
    print "OSSEC installed"
}

print "Installing OSSEC..."
print "You do not need to provide a key or server IP (just close the window when it asks for it)"
install_ossec
Start-Service OssecSvc
Get-Service OssecSvc
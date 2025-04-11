################## SCRIPT ARGUMENTS #################
param (
    [Parameter(Mandatory=$true)]
    [string]$version,

    [Parameter(Mandatory=$true)]
    [string]$ip,

    [Parameter(Mandatory=$true)]
    [ValidateSet("dc", "member")]
    [string]$type,

    [Parameter(Mandatory=$false)]
    [string]$url = "",

    [Parameter(Mandatory=$false)]
    [string]$local = "",

    [Parameter(Mandatory=$false)]
    [string]$run = "",

    [Parameter(Mandatory=$false)]
    [int]$arch = 64
    # pass 64 (bit) for x64, 32 (bit) for x86
)
#####################################################

################### DOWNLOAD URLS ###################
if ($run -ne "") {
    if (Get-Command $run -CommandType Function -ErrorAction SilentlyContinue) {
        & $run
        exit 0
    } else {
        Write-Host "Function '$run' not found."
    }
}

if ($url -ne "") {
    $GITHUB_URL = $url
} else {
    $GITHUB_URL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main"
}

if ($local -ne "") {
    $LOCAL_INSTALL = $true
    $GITHUB_URL = (Resolve-Path "$local").Path.TrimEnd('\')
} else {
    $LOCAL_INSTALL = $false
}

$SPLUNKDIR = ""
$9_2_5_x64 = "https://download.splunk.com/products/universalforwarder/releases/9.2.5/windows/splunkforwarder-9.2.5-7bfc9a4ed6ba-x64-release.msi"
$9_2_5_x86 = "https://download.splunk.com/products/universalforwarder/releases/9.2.5/windows/splunkforwarder-9.2.5-7bfc9a4ed6ba-x86-release.msi"
$9_1_6_x64 = "https://download.splunk.com/products/universalforwarder/releases/9.1.6/windows/splunkforwarder-9.1.6-a28f08fac354-x64-release.msi"
$9_1_6_x86 = "https://download.splunk.com/products/universalforwarder/releases/9.1.6/windows/splunkforwarder-9.1.6-a28f08fac354-x86-release.msi"
$7_3_9_x64 = "https://download.splunk.com/products/universalforwarder/releases/7.3.9/windows/splunkforwarder-7.3.9-39a78bf1bc5b-x64-release.msi"
$7_3_9_x86 = "https://download.splunk.com/products/universalforwarder/releases/7.3.9/windows/splunkforwarder-7.3.9-39a78bf1bc5b-x86-release.msi"
$newest_x64 = $9_2_5_x64
$newest_x86 = $9_2_5_x86

$OSSECDIR="C:\Program Files (x86)\ossec-agent"
$OSSEC_DOWNLOAD = "https://updates.atomicorp.com/channels/atomic/windows/ossec-agent-win32-3.8.0-35114.exe"
#####################################################

##################### FUNCTIONS #####################
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

function detect_version {
    if ($arch -eq 64) {
        switch ($version) {
            "7" { return $7_3_9_x64 } # technically this is not supported for 7
            "8" { return $7_3_9_x64 }
            "2012" { return $9_1_6_x64 }
            "2016" { return $9_2_4_x64 }
            {$_ -in "10", "11", "2019", "2022"} { return $newest_x64 }
            default { error "Invalid option"; exit 1 }
        }
    }
    elseif ($arch -eq 32) {
        switch ($version) {
            "7" { return = $7_3_9_x86 } # technically this is not supported for 7
            "8" { return = $7_3_9_x86 }
            "2012" { return = $9_1_6_x86 }
            "2016" { return = $9_2_4_x86 }
            {$_ -in "10", "11", "2019", "2022"} { return = $newest_x86 }
            default { error "Invalid option"; exit 1 }
        }
    } else {
        error "Invalid architecture"
        exit 1
    }
}

function install_splunk {
    print "Installing Splunk..."
    $msi = detect_version

    if (Test-Path "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe") {
        print "Splunk already installed"
        return
    }

    print "Downloading the Splunk installer"
    $installer_path = "$pwd\splunk.msi"
    download $msi $installer_path
    print "Download complete"
    print "Please enter a password for the new splunk user"
    print "WARNING: this needs to be at least 8 characters and match system password complexity requirements or else the install will fail"
    $securedValue = Read-Host -AsSecureString "Password"
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedValue)
    $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

    $securedValue = Read-Host -AsSecureString "Confirm password"
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedValue)
    $confirm_password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

    if ($password -ne $confirm_password) {
        error "Passwords do not match"
        exit 1
    }
    if ($password.Length -lt 8) {
        error "Password must be at least 8 characters"
        exit 1
    }

    print "The installation will now continue in the background. This may take a few minutes."
    # TODO: create splunk service user
    Start-Process msiexec.exe -ArgumentList "/i $installer_path SPLUNKUSERNAME=splunk SPLUNKPASSWORD=$password USE_LOCAL_SYSTEM=1 RECEIVING_INDEXER=`"$ip:9997`" AGREETOLICENSE=yes LAUNCHSPLUNK=1 SERVICESTARTTYPE=auto /L*v splunk_log.txt /quiet" -Wait -NoNewWindow

    if (Test-Path "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe") {
        print "Splunk installed successfully"
    } else {
        error "Splunk installation failed"
        exit 1
    }
}

function install_sysmon {
    print "Downloading Sysmon..."
    $sysmon_zip_path = "$pwd\Sysmon.zip"
    $sysmon_config_path = "$pwd\sysmonconfig-export.xml"
    $sysmon_extract_path = "$pwd\Sysmon"
    download "$GITHUB_URL/windows/hardening/sysmon/Sysmon.zip" "$sysmon_zip_path"
    download "$GITHUB_URL/windows/hardening/sysmon/sysmonconfig-export.xml" "$sysmon_config_path"

    print "Extracting Sysmon..."
    Expand-Archive -Path $sysmon_zip_path -DestinationPath "$sysmon_extract_path" -Force

    print "Installing Sysmon configuration..."
    Start-Process -FilePath "$sysmon_extract_path\Sysmon.exe" -ArgumentList "-accepteula -i $sysmon_config_path" -Wait -NoNewWindow
}

function install_custom_inputs {
    print "Installing custom inputs.conf..."
    print "This adds Windows Event Log monitors: System, Security, Application, PowerShell, Sysmon"
    download "$GITHUB_URL/splunk/windows/custom-inputs.conf" "$pwd\custom-inputs.conf"
    # TODO: change this for the indexer?
    # TODO: check that inputs doesn't already exist or add to it
    Move-Item -Path "$pwd\custom-inputs.conf" -Destination "$SPLUNKDIR\etc\apps\SplunkUniversalForwarder\local\inputs.conf" -Force
}

function add_monitor {
    param (
        [string]$source,
        [string]$index,
        [string]$sourcetype = "auto"
    )
    & "$SPLUNKDIR\bin\splunk.exe" add monitor $source -index $index -sourcetype $sourcetype
}

function install_windows_ta {
    print "Installing Splunk Add-on for Microsoft Windows..."
    download "$GITHUB_URL/splunk/windows/splunk-add-on-for-microsoft-windows_901.tgz" "$pwd\splunk-add-on-for-microsoft-windows_901.tgz"
    & "$SPLUNKDIR\bin\splunk.exe" install app "$pwd\splunk-add-on-for-microsoft-windows_901.tgz" -update 1

    print "Enabling inputs for the Windows TA..."
    New-Item -Path "$SPLUNKDIR\etc\apps\Splunk_TA_windows\local\" -ItemType Directory -Force
    download "$GITHUB_URL/splunk/windows/windows-ta-inputs.conf" "$pwd\windows-ta-inputs.conf"

    if ($type -eq "dc") {
        "`n[admon://default]`ndisabled=0`nmonitorSubtree=1" | Out-File -Append -Encoding ascii "$pwd\windows-ta-inputs.conf"
    }

    # TODO: change permissions
    # icacls "windows-ta-inputs.conf" /setowner "splunk"
    Move-Item -Path "$pwd\windows-ta-inputs.conf" -Destination "$SPLUNKDIR\etc\apps\Splunk_TA_windows\local\inputs.conf" -Force
}

function install_sysmon_ta {
    print "Installing Splunk Add-on for Sysmon..."
    download "$GITHUB_URL/splunk/windows/splunk-add-on-for-sysmon_402.tgz" "$pwd\splunk-add-on-for-sysmon_402.tgz"
    & "$SPLUNKDIR\bin\splunk.exe" install app "$pwd\splunk-add-on-for-sysmon_402.tgz" -update 1

    print "Enabling inputs for the Sysmon TA..."
    New-Item -Path "$SPLUNKDIR\etc\apps\Splunk_TA_microsoft_sysmon\local\" -ItemType Directory -Force
    download "$GITHUB_URL/splunk/windows/sysmon-ta-inputs.conf" "$pwd\sysmon-ta-inputs.conf"
    # TODO: change permissions
    # icacls "windows-ta-inputs.conf" /setowner "splunk"
    Move-Item -Path "$pwd\sysmon-ta-inputs.conf" -Destination "$SPLUNKDIR\etc\apps\Splunk_TA_microsoft_sysmon\local\inputs.conf" -Force
}

function install_add_ons {
    install_windows_ta
    install_sysmon_ta
}

function install_ossec {
    # Install OSSEC
    download "$OSSEC_DOWNLOAD" "$pwd\ossec-agent.exe"
    Start-Process -FilePath ".\ossec-agent.exe" -Wait

    # Install configuration file
    Move-Item -Path "$OSSECDIR\ossec.conf" "$OSSECDIR\ossec.conf.bak" -Force 2>$null
    # download "$GITHUB_URL/splunk/windows/ossec-agent-local.conf" "$pwd\ossec-agent.conf"
    download "$GITHUB_URL/splunk/windows/ossec-agent.conf" "$pwd\ossec-agent.conf"

    (Get-Content ".\ossec-agent.conf") -replace "{SERVER_IP}", $ip | Set-Content ".\ossec-agent.conf"
    Move-Item -Path ".\ossec-agent.conf" -Destination "$OSSECDIR\ossec.conf" -Force

    # Register and start agent
    & "$OSSECDIR\ossec-agent.exe" install-service
    & "$OSSECDIR\agent-auth.exe" -m $ip -p 1515
    Move-Item "client.keys" "$OSSECDIR\client.keys" -Force
    print "OSSEC installed"
}
#####################################################

######################## MAIN #######################
print "Start of script"
print "Please run this in an Administrator prompt. 3 seconds to CTRL + C if this is not the case..."
Start-Sleep -Seconds 3

# Set TLS 1.2 for compatibility with older systems
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($ip -eq "indexer" -or $ip -eq "i") {
    $SPLUNKDIR = "C:\Program Files\Splunk"  # TODO: check this path
    # TODO: implement indexer installation
    error "Indexer installation not implemented yet"
} else {
    $SPLUNKDIR = "C:\Program Files\SplunkUniversalForwarder"
    # $ip = $ip + ":9997"

    # Check that the IP is valid
    $regex = '\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b'
    if (-not ($ip -match $regex)) {
        Write-Output "Invalid IP"
        exit 1
    }
}

install_splunk
install_sysmon

if ($version -eq "7" -or $version -eq "8") {
    # Add-on isn't supported on these versions of Splunk
    install_custom_inputs

    print "Adding firewall logs..."
    netsh advfirewall set allprofiles logging allowedconnections enable
    netsh advfirewall set allprofiles logging droppedconnections enable
    add_monitor "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" "windows"
} else {
    install_add_ons
}

print "Adding web logs..."
add_monitor "C:\inetpub\logs\LogFiles\" "web"

print "Installing OSSEC..."
print "You do not need to provide a key or server IP (just close the window when it asks for it)"
install_ossec
Start-Service OssecSvc
Get-Service OssecSvc

print "End of script"
#####################################################
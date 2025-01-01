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
    [int]$arch = 64
    # pass 64 (bit) for x64, 32 (bit) for x86
)
#####################################################

################### DOWNLOAD URLS ###################
if ($url -ne "") {
    $GITHUB_URL = $url
} else {
    $GITHUB_URL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main"
}
$SPLUNKDIR = ""
$9_2_4_x64 = "https://download.splunk.com/products/universalforwarder/releases/9.2.4/windows/splunkforwarder-9.2.4-c103a21bb11d-x64-release.msi"
$9_2_4_x86 = "https://download.splunk.com/products/universalforwarder/releases/9.2.4/windows/splunkforwarder-9.2.4-c103a21bb11d-x86-release.msi"
$9_1_6_x64 = "https://download.splunk.com/products/universalforwarder/releases/9.1.6/windows/splunkforwarder-9.1.6-a28f08fac354-x64-release.msi"
$9_1_6_x86 = "https://download.splunk.com/products/universalforwarder/releases/9.1.6/windows/splunkforwarder-9.1.6-a28f08fac354-x86-release.msi"
$7_3_9_x64 = "https://download.splunk.com/products/universalforwarder/releases/7.3.9/windows/splunkforwarder-7.3.9-39a78bf1bc5b-x64-release.msi"
$7_3_9_x86 = "https://download.splunk.com/products/universalforwarder/releases/7.3.9/windows/splunkforwarder-7.3.9-39a78bf1bc5b-x86-release.msi"
$newest_x64 = $9_2_4_x64
$newest_x86 = $9_2_4_x86
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
    
    # Remove the file if it exists
    if (Test-Path $path) {
        Remove-Item $path -Force
    }

    $wc = New-Object net.webclient
    $wc.Downloadfile($url, $path)
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

    $path = $(Get-Location).path + "\splunk.msi"
    print "Downloading the Splunk installer to $path"
    download $msi $path
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
    Start-Process msiexec.exe -ArgumentList "/i $path SPLUNKUSERNAME=splunk SPLUNKPASSWORD=$password USE_LOCAL_SYSTEM=1 RECEIVING_INDEXER=$ip AGREETOLICENSE=yes LAUNCHSPLUNK=1 SERVICESTARTTYPE=auto /L*v splunk_log.txt /quiet" -Wait -NoNewWindow

    if (Test-Path "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe") {
        print "Splunk installed successfully"
    } else {
        error "Splunk installation failed"
        exit 1
    }
}

function install_sysmon {
    print "Downloading Sysmon..."
    $sysmon_zip_path = $(Get-Location).path + "\Sysmon.zip"
    download "$GITHUB_URL/windows/hardening/sysmon/Sysmon.zip" $sysmon_zip_path
    $sysmon_config_path = $(Get-Location).path + "\sysmonconfig-export.xml"
    download "$GITHUB_URL/windows/hardening/sysmon/sysmonconfig-export.xml" $sysmon_config_path

    print "Extracting Sysmon..."
    $sysmon_extract_path = $(Get-Location).path + "\Sysmon"
    Expand-Archive -Path $sysmon_zip_path -DestinationPath $sysmon_extract_path -Force

    print "Installing Sysmon configuration..."
    Start-Process -FilePath "$sysmon_extract_path\Sysmon.exe" -ArgumentList "-accepteula -i $sysmon_config_path" -Wait -NoNewWindow
}

function install_custom_inputs {
    print "Installing custom inputs.conf..."
    print "This adds Windows Event Log monitors: System, Security, Application, PowerShell, Sysmon"
    $path = $(Get-Location).path + "\custom-inputs.conf"
    download "$GITHUB_URL/splunk/windows/custom-inputs.conf" $path
    # TODO: change this for the indexer?
    # TODO: check that inputs doesn't already exist or add to it
    Move-Item -Path $path -Destination "$SPLUNKDIR\etc\apps\SplunkUniversalForwarder\local\inputs.conf" -Force
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
    $path = $(Get-Location).path + "\splunk-add-on-for-microsoft-windows_901.tgz"
    download "$GITHUB_URL/splunk/windows/splunk-add-on-for-microsoft-windows_901.tgz" $path
    & "$SPLUNKDIR\bin\splunk.exe" install app $path

    print "Enabling inputs for the Windows TA..."
    New-Item -Path "$SPLUNKDIR\etc\apps\Splunk_TA_windows\local\" -ItemType Directory -Force
    $path = $(Get-Location).path + "\windows-ta-inputs.conf"
    download "$GITHUB_URL/splunk/windows/windows-ta-inputs.conf" $path

    if ($type -eq "dc") {
        "`n[admon://default]`ndisabled=0`nmonitorSubtree=1" | Out-File -Append -Encoding ascii $path
    }

    # TODO: change permissions
    # icacls "windows-ta-inputs.conf" /setowner "splunk"
    Move-Item -Path $path -Destination "$SPLUNKDIR\etc\apps\Splunk_TA_windows\local\inputs.conf" -Force
}

function install_sysmon_ta {
    print "Installing Splunk Add-on for Sysmon..."
    $path = $(Get-Location).path + "\splunk-add-on-for-sysmon_402.tgz"
    download "$GITHUB_URL/splunk/windows/splunk-add-on-for-sysmon_402.tgz" $path
    & "$SPLUNKDIR\bin\splunk.exe" install app $path

    print "Enabling inputs for the Sysmon TA..."
    New-Item -Path "$SPLUNKDIR\etc\apps\Splunk_TA_microsoft_sysmon\local\" -ItemType Directory -Force
    $path = $(Get-Location).path + "\sysmon-ta-inputs.conf"
    download "$GITHUB_URL/splunk/windows/sysmon-ta-inputs.conf" $path
    # TODO: change permissions
    # icacls "windows-ta-inputs.conf" /setowner "splunk"
    Move-Item -Path $path -Destination "$SPLUNKDIR\etc\apps\Splunk_TA_microsoft_sysmon\local\inputs.conf" -Force
}

function install_add_ons {
    install_windows_ta
    install_sysmon_ta
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
    $ip = $ip + ":9997"

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

print "End of script"
#####################################################
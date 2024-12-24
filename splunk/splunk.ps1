param (
    [Parameter(Mandatory=$true)]
    [string]$version,
    [Parameter(Mandatory=$true)]
    [string]$ip,
    [int]$arch = 64
)

################### DOWNLOAD URLS ###################
$GITHUB_URL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main"
$SPLUNKDIR = ""
$9_2_3_x64 = "https://download.splunk.com/products/universalforwarder/releases/9.2.3/windows/splunkforwarder-9.2.3-282efff6aa8b-x64-release.msi"
$9_2_3_x86 = "https://download.splunk.com/products/universalforwarder/releases/9.2.3/windows/splunkforwarder-9.2.3-282efff6aa8b-x86-release.msi"
$9_1_6_x64 = "https://download.splunk.com/products/universalforwarder/releases/9.1.6/windows/splunkforwarder-9.1.6-a28f08fac354-x64-release.msi"
$9_1_6_x86 = "https://download.splunk.com/products/universalforwarder/releases/9.1.6/windows/splunkforwarder-9.1.6-a28f08fac354-x86-release.msi"
$7_3_9_x64 = ""
$7_3_9_x86 = ""
$newest_x64 = $9_2_3_x64
$newest_x86 = $9_2_3_x86
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

function detect_version {
    if ($arch -eq 64) {
        switch ($version) {
            "7" { return $7_3_9_x64 } # technically this is not supported for 7
            "8" { return $7_3_9_x64 }
            "2012" { return $9_1_6_x64 }
            "2016" { return $9_2_3_x64 }
            {$_ -in "10", "11", "2019", "2022"} { return $newest_x64 }
            default { error "Invalid option"; exit 1 }
        }
    }
    else {
        switch ($version) {
            "7" { return = $7_3_9_x86 } # technically this is not supported for 7
            "8" { return = $7_3_9_x86 }
            "2012" { return = $9_1_6_x86 }
            "2016" { return = $9_2_3_x86 }
            {$_ -in "10", "11", "2019", "2022"} { return = $newest_x86 }
            default { error "Invalid option"; exit 1 }
        }
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
    $wc = New-Object net.webclient
    $wc.Downloadfile($msi, $path)
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
    Start-Process msiexec.exe -ArgumentList "/i $path SPLUNKUSERNAME=splunk SPLUNKPASSWORD=$password USE_LOCAL_SYSTEM=1 RECEIVING_INDEXER=$ip AGREETOLICENSE=yes LAUNCHSPLUNK=1 SERVICESTARTTYPE=auto /L*v splunk_log.txt /quiet" -Wait -NoNewWindow

    if (Test-Path "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe") {
        print "Splunk installed successfully"
    } else {
        error "Splunk installation failed"
        exit 1
    }
}

function install_custom_inputs {
    print "Installing custom inputs.conf..."
    print "This adds Windows Event Log monitors: System, Security, Application, PowerShell, Sysmon"
    $wc = New-Object net.webclient
    $path = $(Get-Location).path + "\inputs.conf"
    $wc.Downloadfile("$GITHUB_URL/splunk/windows/inputs.conf", $path)
    # TODO: change this for the indexer?
    # TODO: check that inputs doesn't already exist or add to it
    Move-Item -Path $path -Destination "$SPLUNKDIR\etc\apps\SplunkUniversalForwarder\local\inputs.conf" -Force
}

function add_monitor {
    param (
        [string]$source
        [string]$index
        [string]$sourcetype = "auto"
    )
    & "$SPLUNKDIR\bin\splunk.exe" add monitor $source -index $index -sourcetype $sourcetype
}
#####################################################

print "Start of script"
print "Please run this in an Administrator prompt. 3 seconds to CTRL + C if this is not the case..."
Start-Sleep -Seconds 3

# Set TLS 1.2 for compatibility with older systems
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($ip -e "indexer" -or $ip -e "i") {
    $SPLUNKDIR = "C:\Program Files\Splunk"  # TODO: check this path
    # TODO: implement indexer installation
    error "Indexer installation not implemented yet"
} else {
    $SPLUNKDIR = "C:\Program Files\SplunkUniversalForwarder"
    $ip = $ip + ":9997"

    # Check that the IP is valid
    $regex = '^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'
    if (-not ($ip -match $regex)) {
        Write-Output "Invalid IP"
        exit 1
    }
}

install_splunk
install_custom_inputs

print "Adding firewall logs..."
netsh advfirewall set allprofiles logging allowedconnections enable
netsh advfirewall set allprofiles logging droppedconnections enable
add_monitor "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" "windows"

print "Adding web logs..."
add_monitor "C:\inetpub\logs\LogFiles\" "web"

print "End of script"
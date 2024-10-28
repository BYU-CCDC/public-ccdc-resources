param (
    [Parameter(Mandatory=$true)]
    [string]$version,
    [Parameter(Mandatory=$true)]
    [string]$ip,
    [int]$arch = 64
)

################### DOWNLOAD URLS ###################
# $GITHUB_URL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main"
$GITHUB_URL = "https://raw.githubusercontent.com/deltabluejay/public-ccdc-resources/main"
$SPLUNKDIR = "C:\Program Files\SplunkUniversalForwarder"
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
#####################################################

print "Start of script"
print "Please run this in an Adminstrator prompt. 3 seconds to CTRL + C if this is not the csae..."
# Start-Sleep -Seconds 3

# Set TLS 1.2 for compatability with older systems
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$msi = ""
if ($arch -eq 64) {
    switch ($version) {
        "7" {
            $msi = $7_3_9_x64 # technically this is not supported for 7 
        }
        "8" { $msi = $7_3_9_x64 }
        "2012" { $msi = $9_1_6_x64 }
        "2016" { $msi = $9_2_3_x64 }
        {$_ -in "10", "11", "2019", "2022"} { $msi = $newest_x64 }
        default { "Invalid option" }
    }
}
else {
    switch ($version) {
        "7" {
            $msi = $7_3_9_x86 # technically this is not supported for 7 
        }
        "8" { $msi = $7_3_9_x86 }
        "2012" { $msi = $9_1_6_x86 }
        "2016" { $msi = $9_2_3_x86 }
        {$_ -in "10", "11", "2019", "2022"} { $msi = $newest_x86 }
        default { "Invalid option" }
    }
}

if ($ip -ne "indexer") {
    # TODO: check that the IP is valid
    $ip = $ip + ":9997"
} else {
    error "Indexer installation not implemented yet"
    # TODO: implement indexer installation
}

if (-not (Test-Path "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe")) {
    print "Installing Splunk..."
    $path = $(Get-Location).path + "\splunk.msi"
    # print "Downloading the Splunk installer to $path"
    # $wc = New-Object net.webclient
    # $wc.Downloadfile($msi, $path)
    # print "Download complete"
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
} else {
    print "Splunk already installed"
}

# TODO: change this for the indexer
# Get-Service SplunkForwarder
# & "$SPLUNKDIR\bin\splunk.exe" status

# & "$SPLUNKDIR\bin\splunk.exe"
print "Installing custom inputs.conf..."
$wc = New-Object net.webclient
$wc.Downloadfile("$GITHUB_URL/splunk/windows/inputs.conf", ".\inputs.conf")
Move-Item -Path ".\inputs.conf" -Destination "$SPLUNKDIR\etc\apps\SplunkUniversalForwarder\local\inputs.conf" -Force

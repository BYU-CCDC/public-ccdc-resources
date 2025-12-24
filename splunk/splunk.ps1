# Copyright (C) 2025 deltabluejay
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

################## SCRIPT ARGUMENTS #################
param (
    # Install Splunk indexer instead of forwarder
    [switch]$indexer,

    # Windows version to target (optional; auto-detected if not provided)
    [Parameter(Mandatory=$false)]
    [string]$WindowsVersion,

    # IP address of Splunk indexer to forward to
    [Parameter(Mandatory=$false)]
    [string]$ip,

    # GitHub URL to download resources from
    [Parameter(Mandatory=$false)]
    [string]$GithubUrl = "",

    # Path to local copy of repository
    [Parameter(Mandatory=$false)]
    [string]$local = "",

    # Function to run directly
    [Parameter(Mandatory=$false)]
    [string]$run = "",

    # Architecture: 64 or 32 bit
    [Parameter(Mandatory=$false)]
    [ValidateSet(32, 64)]
    [int]$arch = 64,

    # Help
    [Parameter(Mandatory=$false)]
    [switch]$h,

    # Reset Splunk admin password (not implemented yet)
    [Parameter(Mandatory=$false)]
    [switch]$ResetPassword
)
#####################################################

###################### GLOBALS ######################
$SPLUNK_USERNAME = "splunk"
$INDEXES = @("system", "web", "network", "windows", "misc", "snoopy", "ossec")
$SPLUNKDIR = "C:\Program Files\SplunkUniversalForwarder"
$SPLUNK_SERVICE = "SplunkForwarder"
$GITHUB_URL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main"
$InformationPreference = "Continue"
#####################################################

################### DOWNLOAD URLS ###################
$indexer_10_0_2_x64 = "https://download.splunk.com/products/splunk/releases/10.0.2/windows/splunk-10.0.2-e2d18b4767e9-windows-x64.msi"
$indexer_9_2_11_x64 = "https://download.splunk.com/products/splunk/releases/9.2.11/windows/splunk-9.2.11-45e7d4c09780-x64-release.msi"
$latest_indexer_x64 = $indexer_10_0_2_x64

$10_0_2_x64 = "https://download.splunk.com/products/universalforwarder/releases/10.0.2/windows/splunkforwarder-10.0.2-e2d18b4767e9-windows-x64.msi"
$9_2_11_x64 = "https://download.splunk.com/products/universalforwarder/releases/9.2.11/windows/splunkforwarder-9.2.11-45e7d4c09780-x64-release.msi"
$9_2_11_x86 = "https://download.splunk.com/products/universalforwarder/releases/9.2.11/windows/splunkforwarder-9.2.11-45e7d4c09780-x86-release.msi"
$9_1_6_x64 = "https://download.splunk.com/products/universalforwarder/releases/9.1.6/windows/splunkforwarder-9.1.6-a28f08fac354-x64-release.msi"
$9_1_6_x86 = "https://download.splunk.com/products/universalforwarder/releases/9.1.6/windows/splunkforwarder-9.1.6-a28f08fac354-x86-release.msi"
$7_3_9_x64 = "https://download.splunk.com/products/universalforwarder/releases/7.3.9/windows/splunkforwarder-7.3.9-39a78bf1bc5b-x64-release.msi"
$7_3_9_x86 = "https://download.splunk.com/products/universalforwarder/releases/7.3.9/windows/splunkforwarder-7.3.9-39a78bf1bc5b-x86-release.msi"
$newest_x64 = $10_0_2_x64
$newest_x86 = $9_2_11_x86
#####################################################

##################### FUNCTIONS #####################
function verbose {
    param (
        [string]$msg
    )
    Write-Verbose $msg
}

function debug {
    param (
        [string]$msg
    )
    Write-Debug $msg
}

function info {
    param (
        [string]$msg
    )
    $old = [Console]::ForegroundColor
    [Console]::ForegroundColor = 'green'
    Write-Information $msg
    [Console]::ForegroundColor = $old
}

function warning {
    param (
        [string]$msg
    )
    Write-Warning $msg
}

function error {
    param (
        [string]$msg
    )
    $old = [Console]::ForegroundColor
    [Console]::ForegroundColor = 'Red'
    [Console]::Error.WriteLine("ERROR: " + $msg)
    [Console]::ForegroundColor = $old
}

function print_usage {
    Write-Host "Usage:" -ForegroundColor Green
    Write-Host "  .\splunk.ps1 -ip <INDEXER IP> [flags]" -ForegroundColor Cyan
    Write-Host "  .\splunk.ps1 -indexer [flags]" -ForegroundColor Cyan
    Write-Host "  .\splunk.ps1 -ResetPassword" -ForegroundColor Cyan
    Write-Host
    Write-Host "Flags:" -ForegroundColor Green
    Write-Host "  -h                 Show this help message" -ForegroundColor Yellow
    Write-Host "  -WindowsVersion    Specify Windows version (auto-detected if not provided)" -ForegroundColor Yellow
    Write-Host "  -arch              Specify architecture (32 or 64; default: 64)" -ForegroundColor Yellow
    Write-Host "  -GithubUrl         Specify custom GitHub URL to download resources from" -ForegroundColor Yellow
    Write-Host "  -local             Specify local path to repository for offline installation" -ForegroundColor Yellow
    Write-Host "  -run               Run a specific function and exit" -ForegroundColor Yellow
    Write-Host "  -ResetPassword     Reset the Splunk admin password" -ForegroundColor Yellow
    Write-Host

    exit 0
}

function reset_password {
    info "Enter a new password for the $SPLUNK_USERNAME user."
    $password = get_password
    Set-Content -Path "$SPLUNKDIR\etc\system\local\user-seed.conf" -Value "[user_info]
    USERNAME = $SPLUNK_USERNAME
    PASSWORD = $password"
    Remove-Item "$SPLUNKDIR\etc\passwd" -Force -ErrorAction SilentlyContinue
    info "Restarting Splunk service to apply new password..."
    Restart-Service -Name $SPLUNK_SERVICE
    exit 0
}

function download {
    param (
        [string]$url,
        [string]$path
    )
    verbose "Downloading $url to $path"
    
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
    # Detect the Windows version if not provided
    if ($script:WindowsVersion -eq "") {
        try {
            verbose "Detecting operating system..."
            
            # Use CIM for better compatibility, fallback to WMI if needed
            try {
                $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
                $role = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
            } catch {
                Write-Warning "CIM query failed, falling back to WMI..."
                $osInfo = Get-WmiObject -Class Win32_OperatingSystem
                $role = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
            }
            switch -Regex ($osInfo.Caption) {
                "Windows XP" { $script:WindowsVersion = "Windows XP"; break }
                "Windows Vista" { $script:WindowsVersion = "Windows Vista"; break }
                "Windows Server 2008" { $script:WindowsVersion = "Windows Server 2008"; break }
                "Windows Server 2008 R2" { $script:WindowsVersion = "Windows Server 2008 R2"; break }
                "Windows 7" { $script:WindowsVersion = "Windows 7"; break }
                "Windows 8" { $script:WindowsVersion = "Windows 8"; break }
                "Windows Server 2012" { $script:WindowsVersion = "Windows Server 2012"; break }
                "Windows Server 2012 R2" { $script:WindowsVersion = "Windows Server 2012 R2"; break }
                "Windows Server 2016" { $script:WindowsVersion = "Windows Server 2016"; break }
                "Windows 10" { $script:WindowsVersion = "Windows 10"; break }
                "Windows 11" { $script:WindowsVersion = "Windows 11"; break }
                "Windows Server 2019" { $script:WindowsVersion = "Windows Server 2019"; break }
                "Windows Server 2022" { $script:WindowsVersion = "Windows Server 2022"; break }
                "Windows Server 2025" { $script:WindowsVersion = "Windows Server 2025"; break }
                default {
                    warning "Detected unrecognized OS version: $($osInfo.Caption)"
                    select_version
                }
            }
            info "Detected Windows version: $script:WindowsVersion"
        } catch {
            error "Failed to detect Windows version: $($_.Exception.Message)"
            exit 1
        }
    } else {
        info "Using provided Windows version: $script:WindowsVersion"
    }

    # Get whether the system is a DC or member server
    if (($role -eq 5) -or ($role -eq 4 )) {
        $script:type = "dc"
    } else {
        $script:type = "member"
    }

    # Return the appropriate Splunk download URL
    if ($indexer) {
        if ($arch -eq 64) {
            $version_map = @{
                "Windows XP" = $null
                "Windows Vista" = $null
                "Windows Server 2008" = $null
                "Windows Server 2008 R2" = $null # good luck
                "Windows 7" = $null
                "Windows 8" = $null
                "Windows Server 2012" = $null
                "Windows Server 2012 R2" = $null
                "Windows Server 2016" = $latest_indexer_x64   # technically not supported
                "Windows 10" = $latest_indexer_x64            # technically not supported
                "Windows 11" = $latest_indexer_x64            # technically not supported
                "Windows Server 2019" = $latest_indexer_x64
                "Windows Server 2022" = $latest_indexer_x64
                "Windows Server 2025" = $latest_indexer_x64
            }
            
        } else {
            error "Indexer installation not supported on 32-bit systems"
            exit 1
        }
    } else {
        if ($arch -eq 64) {
            $version_map = @{
                "Windows XP" = $null
                "Windows Vista" = $null
                "Windows Server 2008" = $null
                "Windows Server 2008 R2" = $null # good luck
                "Windows 7" = $7_3_9_x64 # technically this is not supported for 7
                "Windows 8" = $7_3_9_x64
                "Windows Server 2012" = $9_1_6_x64
                "Windows Server 2012 R2" = $9_1_6_x64
                "Windows Server 2016" = $10_0_2_x64
                "Windows 10" = $newest_x64
                "Windows 11" = $newest_x64
                "Windows Server 2019" = $newest_x64
                "Windows Server 2022" = $newest_x64
                "Windows Server 2025" = $newest_x64
            }
        } else {
            $version_map = @{
                "Windows XP" = $null
                "Windows Vista" = $null
                "Windows Server 2008" = $null
                "Windows Server 2008 R2" = $null # good luck
                "Windows 7" = $7_3_9_x86 # technically this is not supported for 7
                "Windows 8" = $7_3_9_x86
                "Windows Server 2012" = $9_1_6_x86
                "Windows Server 2012 R2" = $9_1_6_x86
                "Windows Server 2016" = $10_0_2_x86
                "Windows 10" = $newest_x86
                "Windows 11" = $newest_x86
                "Windows Server 2019" = $newest_x86
                "Windows Server 2022" = $newest_x86
                "Windows Server 2025" = $newest_x86
            }
        }
    }

    try {
        return $version_map[$script:WindowsVersion]
    } catch {
        error "Unknown operating system: $script:WindowsVersion"
        exit 1
    }
}

function select_version {
    info "Please select your Windows version:"
    $versions = @(
        "Windows 7",
        "Windows 8",
        "Windows Server 2012",
        "Windows Server 2012 R2",
        "Windows Server 2016",
        "Windows 10",
        "Windows 11",
        "Windows Server 2019",
        "Windows Server 2022",
        "Windows Server 2025"
    )

    for ($i = 0; $i -lt $versions.Count; $i++) {
        Write-Host "[$i] $($versions[$i])"
    }

    while ($true) {
        $selection = Read-Host "Enter the number corresponding to your Windows version"
        if ($selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -lt $versions.Count) {
            $script:WindowsVersion = $versions[$selection]
            break
        } else {
            error "Invalid selection. Please try again."
        }
    }
}

function get_password {
    while ($true) {
        $securedValue = Read-Host -AsSecureString "Password"
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedValue)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

        $securedValue = Read-Host -AsSecureString "Confirm password"
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedValue)
        $confirm_password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

        if ($password -ne $confirm_password) {
            error "Passwords do not match"
        }
        elseif ($password.Length -lt 8) {
            error "Password must be at least 8 characters"
        } else {
            return $password
        }
    }
}

function handle_args {
    debug "Handling script arguments..."

    # Help
    if ($h) {
        print_usage
        exit 0
    }

    # Run a specific function and exit
    if ($run -ne "") {
        if (Get-Command $run -CommandType Function -ErrorAction SilentlyContinue) {
            & $run
            exit 0
        } else {
            error "Function '$run' not found."
            exit 1
        }
    }
    
    # Check if we are installing an indexer
    if ($indexer) {
        $script:SPLUNKDIR = "C:\Program Files\Splunk"  # TODO: check this path
        $script:SPLUNK_SERVICE = "Splunkd"
    } else {
        if ($ip -eq "" -and -not $ResetPassword) {
            error "Please provide the IP address of the Splunk indexer to forward to using the -ip parameter."
            exit 1
        }
    }

    # Reset splunk password
    if ($ResetPassword) {
        reset_password
        exit 0
    }

    if ($GithubUrl -ne "") {
        debug "Using custom GitHub URL: $GithubUrl"
        # TODO: trim trailing slash
        $script:GITHUB_URL = $GithubUrl
    }

    if ($local -ne "") {
        $script:LOCAL_INSTALL = $true
        $script:GITHUB_URL = (Resolve-Path "$local").Path.TrimEnd('\')
    } else {
        $script:LOCAL_INSTALL = $false
    }

    # Set global WindowsVersion variable if provided
    if ($PSBoundParameters.ContainsKey('WindowsVersion')) {
        $script:WindowsVersion = $WindowsVersion
    }
}

function install_splunk {
    if ($indexer) {
        info "Installing Splunk Indexer..."
    } else {
        info "Installing Splunk Universal Forwarder..."
    }
    $msi = detect_version

    if (Test-Path "$SPLUNKDIR\bin\splunk.exe") {
        info "Splunk already installed"
        return
    }

    if ($msi -eq $null) {
        error "Unsupported operating system for this script; please install Splunk manually"
        exit 1
    }

    info "Downloading the Splunk installer..."
    $installer_path = "$pwd\splunk.msi"
    download $msi $installer_path

    info "Please enter a password for the $SPLUNK_USERNAME user."
    warning "This needs to be at least 8 characters and match system password complexity requirements or else the install will fail!"
    $script:SPLUNK_PASSWORD = get_password

    info "The installation will now continue in the background. This may take a few minutes."
    # TODO: create splunk service user
    debug "Installer path: $installer_path"
    if ($indexer) {
        Start-Process msiexec.exe -ArgumentList "/i $installer_path SPLUNKUSERNAME=$SPLUNK_USERNAME SPLUNKPASSWORD=$script:SPLUNK_PASSWORD USE_LOCAL_SYSTEM=1 AGREETOLICENSE=yes LAUNCHSPLUNK=1 SERVICESTARTTYPE=auto /L*v splunk_log.txt /quiet" -Wait -NoNewWindow
    } else {
        Start-Process msiexec.exe -ArgumentList "/i $installer_path SPLUNKUSERNAME=$SPLUNK_USERNAME SPLUNKPASSWORD=$script:SPLUNK_PASSWORD USE_LOCAL_SYSTEM=1 RECEIVING_INDEXER=`"$($ip):9997`" AGREETOLICENSE=yes LAUNCHSPLUNK=1 SERVICESTARTTYPE=auto /L*v splunk_log.txt /quiet" -Wait -NoNewWindow
    }

    debug "Testing path at $SPLUNKDIR\bin\splunk.exe"
    if (Test-Path "$SPLUNKDIR\bin\splunk.exe") {
        info "Splunk installed successfully"
    } else {
        error "Splunk installation failed"
        exit 1
    }
}

function install_sysmon {
    info "Installing Sysmon..."
    info "Downloading Sysmon..."
    $sysmon_zip_path = "$pwd\Sysmon.zip"
    $sysmon_config_path = "$pwd\sysmon-config-windows.xml"
    $sysmon_extract_path = "$pwd\Sysmon"
    download "https://download.sysinternals.com/files/Sysmon.zip" "$sysmon_zip_path"
    download "$GITHUB_URL/log/sysmon/windows/sysmon-config-windows.xml" "$sysmon_config_path"

    info "Extracting Sysmon..."
    Expand-Archive -Path $sysmon_zip_path -DestinationPath "$sysmon_extract_path" -Force

    info "Installing Sysmon configuration..."
    Start-Process -FilePath "$sysmon_extract_path\Sysmon.exe" -ArgumentList "-accepteula -i $sysmon_config_path" -Wait -NoNewWindow
}

function enable_auditing {
    info "Downloading and running advanced auditing script..."
    download "$GITHUB_URL/windows/hardening/advancedAuditing.ps1" "$pwd\advancedAuditing.ps1"
    & "$pwd\advancedAuditing.ps1"

    add_monitor "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" "windows" # firewall logs
    add_monitor "C:\inetpub\logs\LogFiles\" "windows" # web and FTP logs
}

function install_manual_inputs {
    info "Installing manual inputs.conf..."
    info "This adds Windows Event Log monitors: System, Security, Application, PowerShell, Sysmon"
    download "$GITHUB_URL/splunk/windows/custom-inputs.conf" "$pwd\custom-inputs.conf"
    Move-Item -Path "$pwd\custom-inputs.conf" -Destination "$SPLUNKDIR\etc\apps\SplunkUniversalForwarder\local\inputs.conf" -Force
    # change ownership?
}

function add_monitor {
    param (
        [string]$source,
        [string]$index,
        [string]$sourcetype = "auto"
    )
    if (-not (Test-Path $source)) {
        warning "Source path $source does not exist; skipping monitor addition"
        return
    }
    & "$SPLUNKDIR\bin\splunk.exe" add monitor $source -index $index -sourcetype $sourcetype
}

function install_app {
    param (
        [string]$name,
        [string]$filename,
        [string]$url
    )
    info "Installing $name..."
    download $url "$pwd\$filename"
    & "$SPLUNKDIR\bin\splunk.exe" install app "$pwd\$filename" -update 1

    $app_folder = [System.IO.Path]::GetFileNameWithoutExtension($filename)
    $app_path = Join-Path $SPLUNKDIR "etc\apps\$app_folder"
    icacls $app_path /grant "SYSTEM:F" /T /C > $null 2>&1
}
#####################################################

######################## MAIN #######################
# Check for administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    error "Please run this script in an Administrator prompt."
    exit 1
}

# Set TLS 1.2 for compatibility with older systems
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

handle_args
install_splunk
Write-Host

& "$SPLUNKDIR\bin\splunk.exe" login -auth "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}"

install_sysmon
Write-Host

if ($script:WindowsVersion -eq "Windows 7" -or $script:WindowsVersion -eq "Windows 8") {
    # Add-ons aren't supported on old versions of Splunk
    install_manual_inputs
} else {
    if ($indexer) {
        # Add listening port
        info "Enabling Splunk to listen on port 9997 for forwarder data..."
        & "$SPLUNKDIR\bin\splunk.exe" enable listen 9997

        # Open firewall ports
        info "Adding Splunk firewall rules..."
        netsh advfirewall firewall add rule name="Splunk TCP Receive" dir=in action=allow protocol=TCP localport=9997
        netsh advfirewall firewall add rule name="Splunk HTTP Web" dir=in action=allow protocol=TCP localport=8000

        # Add indexes
        foreach ($index in $INDEXES) {
            verbose "Creating index: $index"
            & "$SPLUNKDIR\bin\splunk.exe" add index $index
        }

        # Give splunk user can_delete role
        info "Granting splunk user 'can_delete' role..."
        & "$SPLUNKDIR\bin\splunk.exe" edit user $SPLUNK_USERNAME -role admin -role can_delete
        
        # Enable HTTPS
        info "Enabling HTTPS for Splunk Web interface..."
        # New-Item -ItemType Directory -Path "$SPLUNKDIR\etc\auth\splunkweb" -Force
        # icacls "$SPLUNKDIR\etc\auth\splunkweb" /setowner $SPLUNK_USERNAME /T /C
        & "$SPLUNKDIR\bin\splunk.exe" createssl web-cert
        & "$SPLUNKDIR\bin\splunk.exe" enable web-ssl

        # Install indexer-specific apps
        install_app "CCDC App" "ccdc_app.spl" "$GITHUB_URL/splunk/ccdc-app.spl"
        install_app "Audit Parser" "TA-LinuxAuditDecoder.spl" "$GITHUB_URL/splunk/TA-LinuxAuditDecoder.spl"

        download "https://github.com/PaloAltoNetworks/Splunk-Apps/archive/refs/tags/v8.1.3.zip" "$pwd\palo.zip"
        Expand-Archive -Path "$pwd\palo.zip" -DestinationPath "$pwd\palo-apps" -Force

        # Palo Alto Apps
        Move-Item -Path "$pwd\palo-apps\Splunk-Apps-8.1.3\Splunk_TA_paloalto\" -Destination "$SPLUNKDIR\etc\apps\Splunk_TA_paloalto\" -Force
        icacls "$SPLUNKDIR\etc\apps\Splunk_TA_paloalto" /grant "SYSTEM:F" /T /C > $null 2>&1

        Move-Item -Path "$pwd\palo-apps\Splunk-Apps-8.1.3\SplunkforPaloAltoNetworks" -Destination "$SPLUNKDIR\etc\apps\SplunkforPaloAltoNetworks" -Force
        icacls "$SPLUNKDIR\etc\apps\SplunkforPaloAltoNetworks" /grant "SYSTEM:F" /T /C > $null 2>&1
    }

    # Install Splunk Add-ons
    install_app "Splunk Add-on for Microsoft Windows" "Splunk_TA_windows.spl" "$GITHUB_URL/splunk/windows/Splunk_TA_windows.spl"
    install_app "Splunk Add-on for Sysmon" "Splunk_TA_microsoft_sysmon.spl" "$GITHUB_URL/splunk/windows/Splunk_TA_microsoft_sysmon.spl"
}

enable_auditing
Write-Host

# Set Splunk service to start automatically
Set-Service -Name $SPLUNK_SERVICE -StartupType Automatic

info "Restarting Splunk service..."
Restart-Service $SPLUNK_SERVICE
#####################################################
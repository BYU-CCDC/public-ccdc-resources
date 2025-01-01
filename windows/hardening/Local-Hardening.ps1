#Start-Transcript "$env:Temp"

$ccdcRepoWindowsHardeningPath = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/hardening"
$portsFile = "ports.json"
$usersFile = "users.txt"
$advancedAuditingFile = "advancedAuditing.ps1"
$patchURLFile = "patchURLs.json"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$neededFiles = @($portsFile, $advancedAuditingFile, $patchURLFile)
foreach ($file in $neededFiles) {
    $filename = $(Split-Path -Path $file -Leaf)
    try {
        if (-not (Test-Path "$pwd\$filename")) {
            Invoke-WebRequest -Uri "$ccdcRepoWindowsHardeningPath/$file" -OutFile "$pwd\$filename"
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Write-Host "Download $file from $ccdcRepoWindowsHardeningPath"
        exit
    }
}

function GetCompetitionUsers {
    try {
        # Prompt the user for the first username
        $user1 = Read-Host "Please enter the first username"

        # Prompt the user for the second username
        $user2 = Read-Host "Please enter the second username"

        # Combine the usernames with a newline between them
        $content = "$user1`n$user2"

        # Write the usernames to users.txt in the current directory
        Set-Content -Path ".\users.txt" -Value $content

        # Notify the user that the file has been created
        Write-Host "The file users.txt has been created with the provided usernames." -ForegroundColor Green
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}
Write-Host "Getting Competition Users" -ForegroundColor Magenta
GetCompetitionUsers
$usersFile = "users.txt"

# Get OS version and current user
$OSVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Load userfile and portdata
[string[]]$UserArray = Get-Content -Path ".\users.txt"
$PortsObject = Get-Content -Path ".\ports.json" -Raw | ConvertFrom-Json
#
# Generate a random password with a mix of characters
function GeneratePassword {
    try {
        #define parameters
        $PasswordLength = 10

        #ASCII Character set for Password
        $CharacterSet = @{
                Uppercase   = (97..122) | Get-Random -Count 10 | % {[char]$_}
                Lowercase   = (65..90)  | Get-Random -Count 10 | % {[char]$_}
                Numeric     = (48..57)  | Get-Random -Count 10 | % {[char]$_}
                SpecialChar = (33..47)+(58..64)+(91..96)+(123..126) | Get-Random -Count 10 | % {[char]$_}
        }

        #Frame Random Password from given character set
        $StringSet = $CharacterSet.Uppercase + $CharacterSet.Lowercase + $CharacterSet.Numeric + $CharacterSet.SpecialChar

        $password = -join(Get-Random -Count $PasswordLength -InputObject $StringSet)
        return $password
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

# Disable all AD users except the current one
function Disable-AllUsers {
    try {
    $currentSamAccountName = $CurrentUser.Split('\')[-1]

    Get-LocalUser | Where-Object SamAccountName -ne $currentSamAccountName |
    ForEach-Object { $_ | Disable-LocalUser }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

function Disable-Users {
    try {
        $confirmation = Prompt-Yes-No -Message "Mass disable users (y/n)?"
            if ($confirmation.toLower() -eq "y") {
                Disable-AllUsers
                Write-Host "All users disabled but your own" -ForegroundColor Red
            } else {
                Write-Host "Skipping..." -ForegroundColor Red
            }
    } catch {
        Write-Host $_.Exception.Message
        Write-Host "Error disabling users. Revisit later." -ForegroundColor Yellow
    }
}



# Prompt user to set a password for an AD user
function Get-Set-Password {
    param($user)

    try {
        $pw = Read-Host -AsSecureString -Prompt "New password for '$user'?"
        $conf = Read-Host -AsSecureString -Prompt "Confirm password"
        # Convert SecureString to plain text
        $pwPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
        $confPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($conf))

        if ($pwPlainText -eq $confPlainText -and $pwPlainText -ne "") {
            Get-LocalUser -Name $user | Set-LocalUser -Password (ConvertTo-SecureString -AsPlainText $pwPlainText -Force) 
            Write-Host "Success!!`n"

            # Clear the plaintext passwords from memory
            $pwPlainText = $null
            $confPlainText = $null

            # Optionally, force a garbage collection to reclaim memory (though this is not immediate)
            [System.GC]::Collect()
            $pw.Dispose()
            $conf.Dispose()
            break
        } else {
            Write-Host "Either the passwords didn't match, or you typed nothing" -ForegroundColor Yellow
        }
    } catch {
        Write-Host $_.Exception.Message "`n"
        Write-Host "There was an error with your password submission. Try again...`n" -ForegroundColor Yellow
    }
}

# Add competition-specific users with certain privileges
function Add-Competition-Users {
    try {
        foreach ($user in $UserArray) {
            $splat = @{
                Name = $user
                Password = (ConvertTo-SecureString -String (GeneratePassword) -AsPlainText -Force)
            }
            New-LocalUser @splat

            if ($UserArray.indexOf($user) -eq 0) {
                Add-LocalGroupMember -Group "Administrators" -Member $user
                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $user

                while ($true) {
                    Get-Set-Password -user $user
                }
            }

            if ($UserArray.indexOf($user) -eq 1) {
                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $user

                while ($true) {
                    Get-Set-Password -user $user
                }
            }
        }
        $userInfos = Print-Users

        $confirmation = Prompt-Yes-No -Message "Any users you'd like to enable (y/n)?"
        if ($confirmation.ToLower() -eq "y") {
            $enableUsers = Get-Comma-Separated-List -category "users"

            $enableUsers | ForEach-Object {
                Enable-LocalUser -Name $_
                $userInfos = Print-Users
            }

        } else {
            Write-Host "Skipping...`n"
        }

        $confirmation = Prompt-Yes-No -Message "Any users you'd like to disable (y/n)?"
        if ($confirmation.ToLower() -eq "y") {
            $disableUsers = Get-Comma-Separated-List -category "users"

            $disableUsers | ForEach-Object {
                Disable-LocalUser -Name $_
                $userInfos = Print-Users
            }

        } else {
            Write-Host "Skipping...`n"
        }
		$userOutput = Print-Users
		if ($userOutput -ne $null) {
			$outputText = $userOutput -join "`n`n"
			$outputText | Out-File -FilePath "UserPerms.txt" -Encoding UTF8
			Write-Host "`nUser permissions have been exported to .\UserPerms.txt" -ForegroundColor Green
		}
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

# Remove users from "Remote Desktop Users" group excluding specified ones
function Remove-RDP-Users {
    try {
        Get-LocalUser -Name * |
        Where-Object {$_.name -ne $UserArray[0] -and $_.name -ne $UserArray[1]} |
        ForEach-Object {
            Remove-LocalGroupMember -Name "Remote Desktop Users" -Member $_ -Confirm:$false
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

# Prompt for a yes or no response
function Prompt-Yes-No {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    try {
        do {
            $response = $(Write-Host $Message -ForegroundColor Yellow -NoNewline; Read-Host)
            if ($response -ieq 'y' -or $response -ieq 'n') {
                return $response
            } else {
                Write-Host "Please enter 'y' or 'n'." -ForegroundColor Yellow
            }
        } while ($true)
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

# Print enabled and disabled users with their group memberships
function Print-Users {
    try {
        $output = @()

        Write-Host "`n==== Enabled Users ====" -ForegroundColor Green
        $enabledUsersOutput = "==== Enabled Users ===="
        $enabledUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true } | ForEach-Object {
            Write-Host "User: $($_.Name)"
	    $enabledUsersOutput += "`nUser: $($_.Name)"
	    $user = $_

	    $groupString = "Groups: $(Get-LocalGroup | Where-Object {  $user.SID -in ($_ | Get-LocalGroupMember | Select-Object -ExpandProperty "SID") } | Select-Object -ExpandProperty "Name")"
	    Write-Host $groupString
	    $enabledUsersOutput += "`n$groupString"
            [System.GC]::Collect()
            $_.Name, $groups -join "`n"
        }
        $output += $enabledUsersOutput

	Write-Host "`n==== Disabled Users ====" -ForegroundColor Red
        $disabledUsersOutput = "==== Disabled Users ===="
        $disabledUsers = Get-LocalUser | Where-Object Enabled -eq $false | ForEach-Object {
            Write-Host "User: $($_.Name)"
	    $disabledUsersOutput += "`nUser: $($_.Name)"

	    $user = $_
	    $groupString = "Groups: $(Get-LocalGroup | Where-Object {  $user.SID -in ($_ | Get-LocalGroupMember | Select-Object -ExpandProperty "SID") } | Select-Object -ExpandProperty "Name")"
	    Write-Host $groupString
	    $disabledUsersOutput += "`n$groupString"
            [System.GC]::Collect()
            $_.Name, $groups -join "`n"
        }
        $output += $disabledUsersOutput

        return $output

    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        return $null
    }
}

# Get a user inputted comma-separated list
function Get-Comma-Separated-List {
    param ([string]$category, [string]$message)

    try {
    $userInput = $null
    if ($message -ne "") {
        $userInput = Read-Host $message
        return $userInput.Split(",") | ForEach-Object { $_.Trim() }

    } elseif ($category -ne "") {
        $userInput = Read-Host "List $category. Separate by commas if multiple. NO SPACES"
        return $userInput.Split(",") | ForEach-Object { $_.Trim() }
    }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

function Configure-Firewall {
    $ready = $false
    try {
        :outer while ($true) {
            $desigPorts = Get-Comma-Separated-List -message "List needed port numbers for firewall config. Separate by commas."
            $usualPorts = @(53, 3389, 80, 445, 139, 22, 88, 67, 68, 135, 139, 389, 636, 3268, 3269, 464) | Sort-Object
            $commonScored = @(53, 3389, 80, 22)
            $commonADorDC = @(139, 88, 67, 68, 135, 139, 389, 445, 636, 3268, 3269, 464)
            Write-Host "All the following ports that we suggest are either common scored services, or usually needed for AD processes. We will say which is which. While this box isn't domain bound, AD ports have been left on the list in case this box gets bound later."
            foreach ($item in $usualPorts) {
                if ($desigPorts -notcontains $item) {
                    if ($item -in $commonScored) {
                        Write-Host "`nCommon Scored Service" -ForegroundColor Green
                    }
                    if ($item -in $commonADorDC) {
						if ($item -eq 445) {
							Write-Host "`nCommon Scored Service" -ForegroundColor Green -NoNewline
							Write-Host " and" -ForegroundColor Cyan -NoNewline
							Write-Host " Common port needed for CD/AD processes" -ForegroundColor Red
						}
						else {
							Write-Host "`nCommon port needed for DC/AD processes" -ForegroundColor Red
						}
                    }
                    $confirmation = $(Write-Host "Need " -NoNewline) + $(Write-Host "$item" -ForegroundColor Green -NoNewline) + $(Write-Host ", " -NoNewline) + $(Write-Host "$($PortsObject.ports.$item.description)? " -ForegroundColor Cyan -NoNewline) + $(Write-Host "(y/n)" -ForegroundColor Yellow; Read-Host)

                    while($true) {
                        if ($confirmation.toLower() -eq "y") {
                            $desigPorts = @($desigPorts) + $item
                            break
                        }
                        if ($confirmation.toLower() -eq "n") {
                            break
                        }
                    }
                }
            }

            Write-Host "`n==== Designated Ports ====" -ForegroundColor Cyan
            Write-Host ($desigPorts -join "`n") | Sort-Object

            $confirmation = ""
            while($true) {
                $confirmation = Prompt-Yes-No -Message "Are these ports correct (y/n)?"
                if ($confirmation.toLower() -eq "y") {
                    $ready = $true
                    break outer
                }
                if ($confirmation.toLower() -eq "n") {
                    $ready = $false
                    break
                }
            }
        }
        if ($ready -eq $true) {

            # Disable the firewall profiles temporarily
            netsh advfirewall set allprofiles state off

            # Disable all pre-existing inbound and outbound rules
            netsh advfirewall firewall set rule all dir=in new enable=no
            netsh advfirewall firewall set rule all dir=out new enable=no

            # # Delete all pre-existing inbound and outbound rules
            # netsh advfirewall firewall delete rule name=all dir=in
            # netsh advfirewall firewall delete rule name=all dir=out

            # Iterate through each port in the PortsObject and create the appropriate rules
            foreach ($port in $desigPorts) {
                $description = $PortsObject.ports.$port.description

                # Inbound rules
                netsh advfirewall firewall add rule name="TCP Inbound $description" dir=in action=allow protocol=TCP localport=$port
                netsh advfirewall firewall add rule name="UDP Inbound $description" dir=in action=allow protocol=UDP localport=$port

                # Outbound rules
                netsh advfirewall firewall add rule name="TCP Outbound $description" dir=out action=allow protocol=TCP localport=$port
                netsh advfirewall firewall add rule name="UDP Outbound $description" dir=out action=allow protocol=UDP localport=$port
            }

            # Re-enable the firewall profiles
            netsh advfirewall set allprofiles state on
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

function Disable-Unnecessary-Services {
    try {
        # Get all active network adapters
        $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

        # Loop through each active adapter and disable IPv6 and File and Printer Sharing
        foreach ($adapter in $activeAdapters) {
            # Disable IPv6 on the adapter
            Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6

            # # Disable File and Printer Sharing for Microsoft Networks
            # Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_server
        }

        # Get all IP-enabled adapters and disable NetBIOS over TCP/IP
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
        foreach ($adapter in $adapters) {
            # Disable NetBIOS over TCP/IP (NetbiosOptions = 2)
            $adapter.SetTcpipNetbios(2)
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}
function Download-Install-Setup-Splunk {
    param([string]$Version, [string]$IP)

    $splunkBeta = $true #((Prompt-Yes-No -Message "Install Splunk from deltabluejay repo? (y/n)").toLower() -eq 'y')
    #Write-Host $splunkBeta
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if ($splunkBeta) {
            #$downloadURL = "https://raw.githubusercontent.com/deltabluejay/public-ccdc-resources/refs/heads/dev/splunk/splunk.ps1"
            $downloadURL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk/splunk.ps1"
        }
        if (-not $splunkBeta) {
            $downloadURL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk/splunk.ps1"
        }

        Invoke-WebRequest -Uri $downloadURL -OutFile ./splunk.ps1

        $splunkServer = "$($IP):9997" # Replace with your Splunk server IP and receiving port

        # Install splunk using downloaded script
        if ((Get-ChildItem ./splunk.ps1).Length -lt 6000) {
            ./splunk.ps1 $Version $SplunkServer
        } else {
            ./splunk.ps1 $Version $SplunkServer "member"
        }

    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Configure Splunk" "Failed with error: $($_.Exception.Message)"
    }
}

function Install-EternalBluePatch {
    try {
        $patchURLs = Get-Content -Raw -Path "patchURLs.json" | ConvertFrom-Json
        # Determine patch URL based on OS version keywords
        $patchURL = switch -Regex ($osVersion) {
            '(?i)Vista'  { $patchURLs.Vista; break }
            'Windows 7'  { $patchURLs.'Windows 7'; break }
            'Windows 8'  { $patchURLs.'Windows 8'; break }
            '2008 R2'    { $patchURLs.'2008 R2'; break }
            '2008'       { $patchURLs.'2008'; break }
            '2012 R2'    { $patchURLs.'2012 R2'; break }
            '2012'       { $patchURLs.'2012'; break }
            default { throw "Unsupported OS version: $osVersion" }
        }
		Write-Host $patchURL

        # Download the patch to a temporary location
        $path = "$env:TEMP\eternalblue_patch.msu"

        Write-Host "Grabbing the patch file. Downloading it to $path" -ForegroundColor Cyan
        $wc = New-Object net.webclient
        $wc.Downloadfile($patchURL, $path)

        # Install the patch
        Start-Process -Wait -FilePath "wusa.exe" -ArgumentList "$path /quiet /norestart"

        # Cleanup
        Remove-Item -Path $path -Force

        Write-Host "Patch for $OSVersion installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

function Upgrade-SMB {
    try {
        # Step 1: Detect the current SMB version
        $smbv1Enabled = (Get-SmbServerConfiguration).EnableSMB1Protocol
        $smbv2Enabled = (Get-SmbServerConfiguration).EnableSMB2Protocol
        $restart = $false

        # Step 2: Decide on the upgrade path based on the detected version

        # Enable SMBv2 (assuming that by enabling SMBv2, SMBv3 will also be enabled if supported)
        if ($smbv2Enabled -eq $false) {
            Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
            Write-Host "Upgraded to SMBv2/SMBv3." -ForegroundColor Green
            $restart = $true
        } elseif ($smbv2Enabled -eq $true) {
            Write-Host "SMBv2 detected. No upgrade required if SMBv3 is supported alongside." -ForegroundColor Cyan
        }

        if ($smbv1Enabled -eq $true) {
            Write-Host "SMBv1 detected. disabling..." -ForegroundColor Yellow

            # Disable SMBv1
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
            $restart = $true
        }

        # Restart might be required after these changes
        if ($restart -eq $true) {
            Write-Host "Please consider restarting the machine for changes to take effect." -ForegroundColor Red
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

function Patch-Mimikatz {
    try {
        # Define the registry key path
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"

        # Check if the registry key exists
        if (Test-Path $registryPath) {
            # Check if the UseLogonCredential value exists
            $useLogonCredentialExists = Get-ItemProperty -Path $registryPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue

            if ($useLogonCredentialExists -eq $null) {
                # Create the UseLogonCredential value and set it to 0
                New-ItemProperty -Path $registryPath -Name "UseLogonCredential" -Value 0 -PropertyType DWord | Out-Null
            } else {
                # Set the UseLogonCredential value to 0
                Set-ItemProperty -Path $registryPath -Name "UseLogonCredential" -Value 0 -Type DWord
            }
        } else {
            Write-Host "Registry key path not found: $registryPath"
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

function Run-Windows-Updates {
    try{

        # Clear Windows Update cache
	Write-Host "Clearing Cache"
        Stop-Service -Name wuauserv
        Remove-Item -Path C:\Windows\SoftwareDistribution\* -Recurse -Force

        Start-Service -Name wuauserv

        # Check for disk space
        $diskSpace = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -ExpandProperty FreeSpace
        if ($diskSpace -lt 1073741824) { # 1 GB in bytes
            Write-Host "Insufficient disk space available on the system drive. Please free up disk space and try again."
            exit
        }

        # Check Windows Update logs for errors
        $updateLogPath = "C:\Windows\WindowsUpdate.log"
        if (Test-Path $updateLogPath) {
            $updateLogContent = Get-Content -Path $updateLogPath -Tail 50 # Read last 50 lines of the log
            if ($updateLogContent -match "error") {
                Write-Host "Error detected in Windows Update log. Please review the log for more details: $updateLogPath"
                exit
            }
        }

        # Check if updates are available
        $wuSession = New-Object -ComObject Microsoft.Update.Session
        $wuSearcher = $wuSession.CreateUpdateSearcher()
        $updates = $wuSearcher.Search("IsInstalled=0")

        # Install available updates
        if ($updates.Updates.Count -gt 0) {
            $totalUpdates = $updates.Updates.Count
            $updateCounter = 0

            # Initialize progress bar
            Write-Progress -Activity "Installing updates" -Status "0% Complete" -PercentComplete 0

            $updates.Updates | ForEach-Object {
                $updateCounter++
                $percentComplete = ($updateCounter / $totalUpdates) * 100
                Write-Progress -Activity "Installing updates" -Status "$percentComplete% Complete" -PercentComplete $percentComplete

                # Install update
                $installResult = $wuSession.CreateUpdateInstaller().Install($_)
                if ($installResult.ResultCode -ne 2) {
                    Write-Host "Failed to install update $($_.Title). Result code: $($installResult.ResultCode)"
                }
            }
            Write-Host "Updates successfully installed."
        } else {
            Write-Host "No updates available."
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}




function Run-StanfordHarden {
# Taken from Stanford Repo. Edited by BYU
# SCHOOL: DSU

# Start the Windows Firewall service
	Invoke-Expression "net start mpssvc"

# Set multicastbroadcastresponse to disable for all profiles
	Invoke-Expression "netsh advfirewall firewall set multicastbroadcastresponse disable"
	Invoke-Expression "netsh advfirewall firewall set multicastbroadcastresponse mode=disable profile=all"

# Set logging settings for Domain, Private, and Public profiles
	Invoke-Expression "netsh advfirewall set Domainprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log"
	Invoke-Expression "netsh advfirewall set Domainprofile logging maxfilesize 20000"
	Invoke-Expression "netsh advfirewall set Privateprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log"
	Invoke-Expression "netsh advfirewall set Privateprofile logging maxfilesize 20000"
	Invoke-Expression "netsh advfirewall set Publicprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log"
	Invoke-Expression "netsh advfirewall set Publicprofile logging maxfilesize 20000"
	Invoke-Expression "netsh advfirewall set Publicprofile logging droppedconnections enable"
	Invoke-Expression "netsh advfirewall set Publicprofile logging allowedconnections enable"
	Invoke-Expression "netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log"
	Invoke-Expression "netsh advfirewall set currentprofile logging maxfilesize 4096"
	Invoke-Expression "netsh advfirewall set currentprofile logging droppedconnections enable"
	Invoke-Expression "netsh advfirewall set currentprofile logging allowedconnections enable"

# Start Defender Service
	Start-Service -Name WinDefend

# Set Defender Policies
	$defenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
	$defenderScanPath = "$defenderPath\Scan"
	$defenderRealTimeProtectionPath = "$defenderPath\Real-Time Protection"
	$defenderReportingPath = "$defenderPath\Reporting"
	$defenderSpynetPath = "$defenderPath\Spynet"
	$defenderFeaturesPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"

# Create or set registry values for Defender policies
	New-ItemProperty -Path $defenderPath -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force
	New-ItemProperty -Path $defenderPath -Name "DisableAntiVirus" -Value 0 -PropertyType DWORD -Force
	New-ItemProperty -Path $defenderPath -Name "ServiceKeepAlive" -Value 1 -PropertyType DWORD -Force
	New-ItemProperty -Path $defenderScanPath -Name "DisableHeuristics" -Value 0 -PropertyType DWORD -Force
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value 3 -PropertyType DWORD -Force
	New-ItemProperty -Path $defenderRealTimeProtectionPath -Name "DisableRealtimeMonitoring" -Value 0 -PropertyType DWORD -Force
	New-ItemProperty -Path $defenderScanPath -Name "CheckForSignaturesBeforeRunningScan" -Value 1 -PropertyType DWORD -Force
	New-ItemProperty -Path $defenderRealTimeProtectionPath -Name "DisableBehaviorMonitoring" -Value 1 -PropertyType DWORD -Force
	New-ItemProperty -Path $defenderReportingPath -Name "DisableGenericRePorts" -Value 1 -PropertyType DWORD -Force
	New-ItemProperty -Path $defenderSpynetPath -Name "LocalSettingOverrideSpynetReporting" -Value 0 -PropertyType DWORD -Force
	New-ItemProperty -Path $defenderSpynetPath -Name "SubmitSamplesConsent" -Value 2 -PropertyType DWORD -Force
	New-ItemProperty -Path $defenderSpynetPath -Name "DisableBlockAtFirstSeen" -Value 1 -PropertyType DWORD -Force
	New-ItemProperty -Path $defenderSpynetPath -Name "SpynetReporting" -Value 0 -PropertyType DWORD -Force
	Write-Host "If the next command errors, it means tamper protection is already enabled:"
	New-ItemProperty -Path $defenderFeaturesPath -Name "TamperProtection" -Value 5 -PropertyType DWORD -Force

# Start Windows Update Service and set startup type to automatic
	Set-Service -Name wuauserv -StartupType Automatic
	Start-Service -Name wuauserv

# Windows Update registry keys
	$windowsUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
	$windowsUpdateAUPath = "$windowsUpdatePath\AU"
	$windowsUpdateAutoUpdatePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"

	#New-ItemProperty -Path $windowsUpdateAUPath -Name "AutoInstallMinorUpdates" -Value 1 -PropertyType DWORD -Force
	#New-ItemProperty -Path $windowsUpdateAUPath -Name "NoAutoUpdate" -Value 0 -PropertyType DWORD -Force
	#New-ItemProperty -Path $windowsUpdateAUPath -Name "AUOptions" -Value 4 -PropertyType DWORD -Force
	#New-ItemProperty -Path $windowsUpdateAutoUpdatePath -Name "AUOptions" -Value 4 -PropertyType DWORD -Force
	#New-ItemProperty -Path $windowsUpdatePath -Name "ElevateNonAdmins" -Value 0 -PropertyType DWORD -Force
	#New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWindowsUpdate" -Value 0 -PropertyType DWORD -Force
	#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWindowsUpdate" -Value 0 -PropertyType DWORD -Force
	#New-ItemProperty -Path "HKLM:\SYSTEM\Internet Communication Management\Internet Communication" -Name "DisableWindowsUpdateAccess" -Value 0 -PropertyType DWORD -Force
	#New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Value 0 -PropertyType DWORD -Force
	#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Value 0 -PropertyType DWORD -Force
	#New-ItemProperty -Path $windowsUpdateAutoUpdatePath -Name "IncludeRecommendedUpdates" -Value 1 -PropertyType DWORD -Force
	#New-ItemProperty -Path $windowsUpdateAutoUpdatePath -Name "ScheduledInstallTime" -Value 22 -PropertyType DWORD -Force
	#New-ItemProperty -Path $windowsUpdatePath -Name "DeferFeatureUpdates" -Value 0 -PropertyType DWORD -Force
	#New-ItemProperty -Path $windowsUpdatePath -Name "DeferQualityUpdates" -Value 0 -PropertyType DWORD -Force

# Delete netlogon fullsecurechannelprotection then add a new key with it enabled
	Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Force
	New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Value 1 -PropertyType DWORD -Force

# Disable the print spooler and make it never start
	Get-Service -Name Spooler | Stop-Service -Force
	Set-Service -Name Spooler -StartupType Disabled -Status Stopped

# DISM commands to disable insecure and unnecessary features
# These commands are called within CMD from PowerShell
	Invoke-Expression 'cmd /c "dism /online /disable-feature /featurename:TFTP /NoRestart"'
	Invoke-Expression 'cmd /c "dism /online /disable-feature /featurename:TelnetClient /NoRestart"'
	Invoke-Expression 'cmd /c "dism /online /disable-feature /featurename:TelnetServer /NoRestart"'
	Invoke-Expression 'cmd /c "dism /online /disable-feature /featurename:SMB1Protocol /NoRestart"'

# Disables editing registry remotely
	Get-Service -Name RemoteRegistry | Stop-Service -Force
	Set-Service -Name RemoteRegistry -StartupType Disabled -Status Stopped -Confirm:$false

# Remove sticky keys
	reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /f
	Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\sethc.exe" -NoNewWindow -Wait
	Start-Process icacls.exe -ArgumentList "C:\Windows\System32\sethc.exe /grant administrators:F" -NoNewWindow -Wait
	Remove-Item -Path "C:\Windows\System32\sethc.exe" -Force

# Delete utility manager (backdoor)
	Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\Utilman.exe" -NoNewWindow -Wait
	Start-Process icacls.exe -ArgumentList "C:\Windows\System32\Utilman.exe /grant administrators:F" -NoNewWindow -Wait
	Remove-Item -Path "C:\Windows\System32\Utilman.exe" -Force

# Delete on-screen keyboard (backdoor)
	Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\osk.exe" -NoNewWindow -Wait
	Start-Process icacls.exe -ArgumentList "C:\Windows\System32\osk.exe /grant administrators:F" -NoNewWindow -Wait
	Remove-Item -Path "C:\Windows\System32\osk.exe" -Force

# Delete narrator (backdoor)
	Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\Narrator.exe" -NoNewWindow -Wait
	Start-Process icacls.exe -ArgumentList "C:\Windows\System32\Narrator.exe /grant administrators:F" -NoNewWindow -Wait
	Remove-Item -Path "C:\Windows\System32\Narrator.exe" -Force

# Delete magnify (backdoor)
	Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\Magnify.exe" -NoNewWindow -Wait
	Start-Process icacls.exe -ArgumentList "C:\Windows\System32\Magnify.exe /grant administrators:F" -NoNewWindow -Wait
	Remove-Item -Path "C:\Windows\System32\Magnify.exe" -Force

#Delete ScheduledTasks
	Get-ScheduledTask | Unregister-ScheduledTask -Confirm:$false

#Disable Guest user
	net user Guest /active:no

#Make sure DEP is allowed (Triple Negative)
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f

#Only privileged groups can add or delete printer drivers
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

#Don't execute autorun commands
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f


#Don't allow empty password login
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

#Only local sessions can control the CD/Floppy
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f

# Enable logging for EVERYTHING
	auditpol /set /category:* /success:enable /failure:enable

# Set specific subcategory policies
	$auditCategories = @(
	    "Security State Change", "Security System Extension", "System Integrity", "IPsec Driver", "Other System Events",
	    "Logon", "Logoff", "Account Lockout", "IPsec Main Mode", "IPsec Quick Mode", "IPsec Extended Mode", "Special Logon",
	    "Other Logon/Logoff Events", "Network Policy Server", "User / Device Claims", "Group Membership", "File System",
	    "Registry", "Kernel Object", "SAM", "Certification Services", "Application Generated", "Handle Manipulation",
	    "File Share", "Filtering Platform Packet Drop", "Filtering Platform Connection", "Other Object Access Events",
	    "Detailed File Share", "Removable Storage", "Central Policy Staging", "Sensitive Privilege Use",
	    "Non Sensitive Privilege Use", "Other Privilege Use Events", "Process Creation", "Process Termination", "DPAPI Activity",
	    "RPC Events", "Plug and Play Events", "Token Right Adjusted Events", "Audit Policy Change",
	    "Authentication Policy Change", "Authorization Policy Change", "MPSSVC Rule-Level Policy Change",
	    "Filtering Platform Policy Change", "Other Policy Change Events", "User Account Management", "Computer Account Management",
	    "Security Group Management", "Distribution Group Management", "Application Group Management",
	    "Other Account Management Events", "Directory Service Access", "Directory Service Changes",
	    "Directory Service Replication", "Detailed Directory Service Replication", "Credential Validation",
	    "Kerberos Service Ticket Operations", "Other Account Logon Events", "Kerberos Authentication Service"
	)

	foreach ($category in $auditCategories) {
	    auditpol /set /subcategory:"$category" /success:enable /failure:enable
	}

#Flush DNS Lookup Cache
	ipconfig /flushdns

#Enable UAC popups if software trys to make changes
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

#Require admin authentication for operations that requires elevation of privileges
	reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorAdmin /T REG_DWORD /D 1 /F
#Does not allow user to run elevates privileges
	reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorUser /T REG_DWORD /D 0 /F
#Built-in administrator account is placed into Admin Approval Mode, admin approval is required for administrative tasks
	reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V FilterAdministratorToken /T REG_DWORD /D 1 /F

#Disable Multiple Avenues for Backdoors
	reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
	reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f
	reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f

#Don't allow Windows Search and Cortana to search cloud sources (OneDrive, SharePoint, etc.)
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f
#Disable Cortana
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
#Disable Cortana when locked
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
#Disable location permissions for windows search
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f

#start-process powershell.exe -argument '-nologo -noprofile -executionpolicy bypass -command [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Set-MpPreference -ThreatIDDefaultAction_Ids "2147597781" -ThreatIDDefaultAction_Actions "6"; Invoke-WebRequest -Uri https://github.com/ION28/BLUESPAWN/releases/download/v0.5.1-alpha/BLUESPAWN-client-x64.exe -OutFile BLUESPAWN-client-x64.exe; & .\BLUESPAWN-client-x64.exe --monitor -a Normal --log=console,xml'


#start-process powershell.exe -argument '-nologo -noprofile -executionpolicy bypass -command [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri https://download.comodo.com/cce/download/setups/cce_public_x64.zip?track=5890 -OutFile cce_public_x64.zip; Expand-Archive cce_public_x64.zip; .\cce_public_x64\cce_2.5.242177.201_x64\cce_x64\cce.exe -u; read-host "CCE Continue When Updated"; .\cce_public_x64\cce_2.5.242177.201_x64\cce_x64\cce.exe -s \"m;f;r\" -d "c"; read-host "CCE Finished"'

	sc.exe config trustedinstaller start= auto
	DISM /Online /Cleanup-Image /RestoreHealth
	sfc /scannow


# Remove sticky keys
	if (Test-Path "C:\Windows\System32\setch.exe") {
		Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\sethc.exe" -NoNewWindow -Wait
		Start-Process icacls.exe -ArgumentList "C:\Windows\System32\sethc.exe /grant administrators:F" -NoNewWindow -Wait
		Remove-Item -Path "C:\Windows\System32\sethc.exe" -Force
	}

# Delete utility manager (backdoor)
	if (Test-Path "C:\Windows\System32\Utilman.exe") {
		Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\Utilman.exe" -NoNewWindow -Wait
		Start-Process icacls.exe -ArgumentList "C:\Windows\System32\Utilman.exe /grant administrators:F" -NoNewWindow -Wait
		Remove-Item -Path "C:\Windows\System32\Utilman.exe" -Force
	}

# Delete on-screen keyboard (backdoor)
	if (Test-Path "C:\Windows\System32\osk.exe") {
		Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\osk.exe" -NoNewWindow -Wait
		Start-Process icacls.exe -ArgumentList "C:\Windows\System32\osk.exe /grant administrators:F" -NoNewWindow -Wait
		Remove-Item -Path "C:\Windows\System32\osk.exe" -Force
	}

# Delete narrator (backdoor)
	if (Test-Path "C:\Windows\System32\Narrator.exe") {
		Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\Narrator.exe" -NoNewWindow -Wait
		Start-Process icacls.exe -ArgumentList "C:\Windows\System32\Narrator.exe /grant administrators:F" -NoNewWindow -Wait
		Remove-Item -Path "C:\Windows\System32\Narrator.exe" -Force
	}

# Delete magnify (backdoor)
	if (Test-Path "C:\Windows\System32\Magnify.exe") {
		Start-Process takeown.exe -ArgumentList "/f C:\Windows\System32\Magnify.exe" -NoNewWindow -Wait
		Start-Process icacls.exe -ArgumentList "C:\Windows\System32\Magnify.exe /grant administrators:F" -NoNewWindow -Wait
		Remove-Item -Path "C:\Windows\System32\Magnify.exe" -Force
	}

# SCHOOL: CPP

	$Error.Clear()
	$ErrorActionPreference = "Continue"


	Write-Output "#########################"
	Write-Output "#                       #"
	Write-Output "#         Hard          #"
	Write-Output "#                       #"
	Write-Output "#########################"


	Write-Output "#########################"
	Write-Output "#    Hostname/Domain    #"
	Write-Output "#########################"
	Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select-Object Name, Domain
	Write-Output "#########################"
	Write-Output "#          IP           #"
	Write-Output "#########################"
	Get-WmiObject Win32_NetworkAdapterConfiguration | ? {$_.IpAddress -ne $null} | % {$_.ServiceName + "`n" + $_.IPAddress + "`n"}

	$DC = $false
	if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
	    $DC = $true
	    Import-Module ActiveDirectory
	}

# Disable storage of the LM hash for passwords less than 15 characters
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f | Out-Null
# https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/enable-ntlm-2-authentication
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
# Disable storage of plaintext creds in WDigest
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
# Enable remote UAC for Local accounts
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f | Out-Null
# Enable LSASS Protection
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
# Enable LSASSS process auditing
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null
	Write-Output "$Env:ComputerName [INFO] PTH Mitigation complete"
######### Defender #########

	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 2 /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 3 /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 0 /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v MpCloudBlockLevel /t REG_DWORD /d 6 /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 0 /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d 0 /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v "ForceDefenderPassiveMode" /t REG_DWORD /d 0 /f | Out-Null
	Write-Output "$Env:ComputerName [INFO] Set Defender options" 

	try {
	    # Block Office applications from injecting code into other processes
	    Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Block Office applications from creating executable content
	    Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Block all Office applications from creating child processes
	    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Block JavaScript or VBScript from launching downloaded executable content
	    Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Block execution of potentially obfuscated scripts
	    Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Block executable content from email client and webmail
	    Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Block Win32 API calls from Office macro
	    Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Block process creations originating from PSExec and WMI commands
	    Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Block untrusted and unsigned processes that run from USB
	    Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Use advanced protection against ransomware
	    Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
	    Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
	    Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Block Office communication application from creating child processes
	    Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Block Adobe Reader from creating child processes
	    Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    # Block persistence through WMI event subscription
	    Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled | Out-Null
	    Write-Output "$Env:ComputerName [INFO] Defender Attack Surface Reduction rules enabled" 
	    ForEach ($ExcludedASR in (Get-MpPreference).AttackSurfaceReductionOnlyExclusions) {
		Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $ExcludedASR | Out-Null
	    }
	}
	catch {
	    Write-Output "$Env:ComputerName [INFO] Old defender version detected, skipping ASR rules" 
	}
	ForEach ($ExcludedExt in (Get-MpPreference).ExclusionExtension) {
	    Remove-MpPreference -ExclusionExtension $ExcludedExt | Out-Null
	}
	ForEach ($ExcludedIp in (Get-MpPreference).ExclusionIpAddress) {
	    Remove-MpPreference -ExclusionIpAddress $ExcludedIp | Out-Null
	}
	ForEach ($ExcludedDir in (Get-MpPreference).ExclusionPath) {
	    Remove-MpPreference -ExclusionPath $ExcludedDir | Out-Null
	}
	ForEach ($ExcludedProc in (Get-MpPreference).ExclusionProcess) {
	    Remove-MpPreference -ExclusionProcess $ExcludedProc | Out-Null
	}
	Write-Output "$Env:ComputerName [INFO] Defender exclusions removed" 

	Write-Host "If the next command errors, it means tamper protection is already enabled:"
	reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 5 /f | Out-Null

######### Service Lockdown #########
# RDP NLA
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP" /v UserAuthentication /t REG_DWORD /d 1 /f | Out-Null
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f | Out-Null
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f | Out-Null

	if ($DC) {
	    # Add-ADGroupMember -Identity "Protected Users" -Members "Domain Users"
	    # CVE-2020-1472 (Zerologon)
	    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
	    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "vulnerablechannelallowlist" -Force | Out-Null
	    # CVE-2021-42278 & CVE-2021-42287 (noPac)
	    Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota"="0"} | Out-Null
	}


	net stop spooler | Out-Null
	sc.exe config spooler start=disabled | Out-Null
	Write-Output "$Env:ComputerName [INFO] Services locked down" 

# CVE-2021-34527 (PrintNightmare)
	reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f | Out-Null
	reg delete "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /f | Out-Null
	reg delete "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v UpdatePromptSettings /f | Out-Null
	reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f | Out-Null
# Network security: LDAP client signing requirements
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f | Out-Null
# Domain Controller: LDAP Server signing requirements
	#reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f | Out-Null
# Disable BITS transfers
	reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 0 /f | Out-Null
	reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 1 /f | Out-Null
	Write-Output "$Env:ComputerName [INFO] BITS locked down"
# UAC
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f | Out-Null
	Write-Output "$Env:ComputerName [INFO] UAC enabled"

}



#Start of script
Disable-Users


$confirmation = Prompt-Yes-No -Message "Enter the 'Add Competition Users' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Adding Competition Users...***" -ForegroundColor Magenta
    Add-Competition-Users
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


$confirmation = Prompt-Yes-No -Message "Enter the 'Remove users from RDP group except $($UserArray[0]) and $($UserArray[1])' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Removing every user from RDP group except $($UserArray[0]) and $($UserArray[1])...***" -ForegroundColor Magenta
    Remove-RDP-Users
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


$confirmation = Prompt-Yes-No -Message "Enter the 'Configure Firewall' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Configuring firewall***" -ForegroundColor Magenta
    Configure-Firewall
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


$confirmation = Prompt-Yes-No -Message "Enter the 'Disable unnecessary services (NetBIOS over TCP/IP, IPv6, closed port services)' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Disabling unnecessary services***" -ForegroundColor Magenta
    Disable-Unnecessary-Services
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


Write-Host "`n***Enabling advanced auditing***" -ForegroundColor Magenta
.\advancedAuditing.ps1
Write-Host "Enabling Firewall logging successful and blocked connections" -ForegroundColor Green
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True


$confirmation = Prompt-Yes-No -Message "Enter the 'Configure Splunk' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Configuring Splunk***" -ForegroundColor Magenta
    $SplunkIP = Read-Host "`nInput IP address of Splunk Server"
    $SplunkVersion = Read-Host "`nInput OS Version (7, 8, 10, 11, 2012, 2016, 2019, 2022): "
    Download-Install-Setup-Splunk -Version $SplunkVersion -IP $SplunkIP
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


Write-Host "`n***Installing EternalBlue Patch***" -ForegroundColor Magenta
Install-EternalBluePatch


Write-Host "`n***Upgrading SMB***" -ForegroundColor Magenta
Upgrade-SMB


Write-Host "`n***Patching Mimikatz***" -ForegroundColor Magenta
Patch-Mimikatz


$confirmation = Prompt-Yes-No -Message "Enter the 'Run Windows Updates' function? (y/n) This might take a while"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Running Windows Updater***" -ForegroundColor Magenta
    Run-Windows-Updates
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


$confirmation = Prompt-Yes-No -Message "Enter the 'Stanford Harden' function? (y/n) This might take a while"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Running Stanford Harden***" -ForegroundColor Magenta
    Run-StanfordHarden
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}

Write-Host "***Setting Execution Policy back to Restricted***" -ForegroundColor Red
Set-ExecutionPolicy Restricted

$Error | Out-File $env:USERPROFILE\Desktop\hard.txt -Append -Encoding utf8
#Stop-Transcript

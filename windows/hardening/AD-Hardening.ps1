Import-Module ActiveDirectory
Import-Module GroupPolicy

$ProgressPreference = 'SilentlyContinue'

$ccdcRepoWindowsHardeningPath = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/hardening"
$portsFile = "ports.json"
$advancedAuditingFile = "advancedAuditing.ps1"
$patchURLFile = "patchURLs.json"
$groupManagementFile = "groupManagement.ps1"
$mainFunctionsFile = "mainFunctionsList.txt"
$splunkFile = "../../splunk/splunk.ps1"
$localHardeningFile = "Local-Hardening.ps1"
$wwHardeningFile = "ww-hardening.ps1"

# Backup existing firewall rules
netsh advfirewall export ./firewallbackup.wfw

# Backup AD DNS Zones
dnscmd localhost /zoneexport $env:USERDNSDOMAIN backup\$env:USERDNSDOMAIN
dnscmd localhost /zoneexport _msdcs.$env:USERDNSDOMAIN backup\_msdcs.$env:USERDNSDOMAIN

# Export group memberships before editing stuff
mkdir ~/groups
get-adgroup -filter * | foreach-object { $_ | get-adgroupmember | export-csv -Path "~/groups/$($_.name).txt" }

# Block SMB initially, we'll turn it back on in the firewall section
# Inbound rules
netsh advfirewall firewall add rule name="TCP Inbound SMB" dir=in action=block protocol=TCP localport=139
netsh advfirewall firewall add rule name="UDP Inbound SMB" dir=in action=block protocol=UDP localport=139
# Outbound rules
netsh advfirewall firewall add rule name="TCP Outbound SMB" dir=out action=block protocol=TCP localport=139
netsh advfirewall firewall add rule name="UDP Outbound SMB" dir=out action=block protocol=UDP localport=139

# Inbound rules
netsh advfirewall firewall add rule name="TCP Inbound SMB" dir=in action=block protocol=TCP localport=445
netsh advfirewall firewall add rule name="UDP Inbound SMB" dir=in action=block protocol=UDP localport=445
# Outbound rules
netsh advfirewall firewall add rule name="TCP Outbound SMB" dir=out action=block protocol=TCP localport=445
netsh advfirewall firewall add rule name="UDP Outbound SMB" dir=out action=block protocol=UDP localport=445

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$neededFiles = @($portsFile, $advancedAuditingFile, $patchURLFile, $groupManagementFile, $mainFunctionsFile, $splunkFile, $localHardeningFile, $wwHardeningFile)
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

Write-Host "All necessary files have been downloaded." -ForegroundColor Green

# Copy local hardening script to sysvol so local hardening can start ASAP without pulling down the script on each machine
$domainDN = (Get-ADDomain).DistinguishedName
cp "./$localHardeningFile" "\\$domainDN\sysvol\$domainDN\$localHardeningFile"
cp "./$wwHardeningFile" "\\$domainDN\sysvol\$domainDN\$wwHardeningFile"

function GetCompetitionUsers {
    try {
        # Prompt the user for the first username
        $user1 = Read-Host "Please enter the first username"

        # Prompt the user for the second username
        $user2 = Read-Host "Please enter the second username"

        # Prompt the user for the third username
        $user3 = Read-Host "Please enter the third username"

        # Combine the usernames with a newline between them
        $content = "$user1`n$user2`n$user3"

        # Write the usernames to users.txt in the current directory
        Set-Content -Path ".\users.txt" -Value $content

        # Notify the user that the file has been created
        Write-Host "The file users.txt has been created with the provided usernames." -ForegroundColor Green
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

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

# Check if the function list file exists
if (Test-Path $mainFunctionsFile) {
    # Read the function names from the file
    $functionNames = Get-Content -Path $mainFunctionsFile
} else {
    Write-Host "Function list file does not exist: $mainFunctionsFile" -ForegroundColor Red
    exit
}

# Initialize log hash table
$log = @{}

# Function to update log
function Update-Log {
    param([string]$key, [string]$value)
    $log[$key] = $value
}

# Initialize function log based on the loaded list
function Initialize-Log {
    foreach ($func in $functionNames) {
        Update-Log $func "Not executed"
    }
}

# Function to print log
function Print-Log {
    Write-Host "`n### Script Execution Summary ###`n" -ForegroundColor Green
    foreach ($entry in $log.GetEnumerator()) {
        Write-Host "$($entry.Key): $($entry.Value)"
    }
}

# Disable all AD users except the current one
function Mass-Disable {
    Write-Host "Disabling all users except $CurrentUser..."
    try {
        $currentSamAccountName = $CurrentUser.Split('\')[-1]
        Get-ADUser -Filter {SamAccountName -ne $currentSamAccountName} |
        ForEach-Object { Disable-ADAccount -Identity $_ }
        Update-Log "Disable Users" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Disable Users" "Failed with error: $($_.Exception.Message)"
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
            Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString -AsPlainText $pwPlainText -Force) -Reset
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

function Change-Current-User-Password {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($currentUser.AuthenticationType -ne "Local") {
        Write-Host "User is a domain user."
        while ($true) {
            Get-Set-Password -User $env:username
        }
    } else {
        Write-Host "User is a local user."
        while ($true) {
            try {
                $pw = Read-Host -AsSecureString -Prompt "New password for $($env:Username):"
                $conf = Read-Host -AsSecureString -Prompt "Confirm password for $($env:Username):"

                # Convert SecureString to plain text
                $pwPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
                $confPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($conf))
                if ($pwPlainText -eq $confPlainText -and $pwPlainText -ne "") {
                    Get-LocalUser -Name $env:Username | Set-LocalUser -Password $password
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

    }
}

# Add competition-specific users with certain privileges
function Add-Competition-Users {
    $protectedUsers = Get-ADGroup -Filter 'Name -like "Protected Users"'
    if (!$protectedUsers) {
        Write-Host "Creating Protected Users group without protections. Your admin users may be vulnerable!"
        New-ADGroup -Name "Protected Users" -GroupScope Global
    }
    try {
        foreach ($user in $UserArray) {
            $splat = @{
                Name = $user
                AccountPassword = (ConvertTo-SecureString -String (GeneratePassword) -AsPlainText -Force)
                Enabled = $true
            }
            New-ADUser @splat

            if ($UserArray.indexOf($user) -eq 0) {
                Add-ADGroupMember -Identity "Administrators" -Members $user
                Add-ADGroupMember -Identity "Schema Admins" -Members $user
                Add-ADGroupMember -Identity "Enterprise Admins" -Members $user
                Add-ADGroupMember -Identity "Domain Admins" -Members $user
                Add-ADGroupMember -Identity "Remote Desktop Users" -Members $user
                Add-ADGroupMember -Identity "Group Policy Creator Owners" -Members $user

                # Can cause problems if domain functional level isn't above Windows Server 2008 R2
                Add-ADGroupMember -Identity "Protected Users" -Members $user

                while ($true) {
                    Get-Set-Password -user $user
                }
            }

            if ($UserArray.indexOf($user) -eq 1) {
                Add-ADGroupMember -Identity "Remote Desktop Users" -Members $user

                # not added to protected users to allow rdp from non-bound computers (like your laptop)

                while ($true) {
                    Get-Set-Password -user $user
                }
            }

            if ($UserArray.indexOf($user) -eq 2) {
                New-ADGroup -Name "Workstation Admins" -GroupScope Global
                Add-ADGroupMember -Identity "Workstation Admins" -Members $user

                # Can cause problems if domain functional level isn't above Windows Server 2008 R2
                Add-ADGroupMember -Identity "Protected Users" -Members $user

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
                Enable-ADAccount $_
                $userInfos = Print-Users
            }

        } else {
            Write-Host "Skipping...`n"
        }

        $confirmation = Prompt-Yes-No -Message "Any users you'd like to disable (y/n)?"
        if ($confirmation.ToLower() -eq "y") {
            $disableUsers = Get-Comma-Separated-List -category "users"

            $disableUsers | ForEach-Object {
                Disable-ADAccount $_
                $userInfos = Print-Users
            }

        } else {
            Write-Host "Skipping...`n"
        }
		$userOutput = Print-Users
		if ($userOutput -ne $null) {
			$outputText = $userOutput -join "`n`n"
			$outputText | Out-File -FilePath ".\UserPerms.txt" -Encoding UTF8
			Write-Host "`nUser permissions have been exported to .\UserPerms.txt" -ForegroundColor Green
		}
        Update-Log "Add Competition Users" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Add Competition Users" "Failed with error: $($_.Exception.Message)"
    }
}

# Remove users from "Remote Desktop Users" group excluding specified ones
function Remove-RDP-Users {
    try {
        Get-AdUser -Filter * |
        Where-Object {$_.name -ne $UserArray[0] -and $_.name -ne $UserArray[1]} |
        ForEach-Object {
            Remove-ADGroupMember -identity "Remote Desktop Users" -members $_ -Confirm:$false
        }
        Update-Log "Harden RDP" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Harden RDP" "Failed with error: $($_.Exception.Message)"
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
        $enabledUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties Name | ForEach-Object {
            $userOutput = $_.Name
            $groups = Get-ADPrincipalGroupMembership $_ | Select-Object -ExpandProperty Name
            $groups | ForEach-Object {
                $userOutput += "`n   - $_"
            }
            Write-Host $userOutput -ForegroundColor Cyan
            [System.GC]::Collect()
            $enabledUsersOutput += "`n$userOutput"
            $_.Name, $groups -join "`n"
        }
        $output += $enabledUsersOutput

        Write-Host "`n==== Disabled Users ====" -ForegroundColor Red
        $disabledUsersOutput = "==== Disabled Users ===="
        $disabledUsers = Get-ADUser -Filter {Enabled -eq $false} -Properties Name | ForEach-Object {
            $userOutput = $_.Name
            $groups = Get-ADPrincipalGroupMembership $_ | Select-Object -ExpandProperty Name
            $groups | ForEach-Object {
                $userOutput += "`n   - $_"
            }
            Write-Host $userOutput -ForegroundColor Cyan
            [System.GC]::Collect()
            $disabledUsersOutput += "`n$userOutput"
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
            Write-Host "All the following ports that we suggest are either common scored services, or usually needed for AD processes. We will say which is which"
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
        Update-Log "Configure Firewall" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Configure Firewall" "Failed with error: $($_.Exception.Message)"
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
        Update-Log "Disable Unnecessary Services" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Disable Unnecessary Services" "Failed with error: $($_.Exception.Message)"
    }
}

function Handle-First-Policy-in-GPO {
    try {
    # Install RSAT features
    #Install-WindowsFeature -Name RSAT -IncludeAllSubFeature

    # Define GPO and settings
    $gpoName = $GPOName

    $report = Get-GPOReport -Name $gpoName -ReportType xml

    # Check if there are any settings in the report
    if ($report -like "*Enabled=True*") {
        Write-Host "$gpoName has settings defined." -ForegroundColor Green
    } else {
        Write-Host "$gpoName does not have any settings defined.`n" -ForegroundColor Red
        Write-Host "Press Enter ONLY after doing the following:" -ForegroundColor Yellow
        Read-Host @"
1. Win + R
2. Type gpmc.msc
3. Find Good-GPO
4. Right click and select Edit
5. Navigate to Computer > Policies > Windows Settings > Security Settings > User Rights Assignment
6. Double-click "Generate Security Audits"
7. Check the box
8. Click on the "Add User or Group..." button
9. Type Administrators
10. Apply
"@
    }

    # Get the GPO's GUID
    $gpo = Get-GPO -Name $gpoName
    $gpoId = $gpo.Id

    # Construct full path
    $fullPath = "\\$($env:USERDNSDOMAIN)\sysvol\$($env:USERDNSDOMAIN)\Policies\{$gpoId}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

    # Backup the file
    Copy-Item -Path $fullPath -Destination "${fullPath}.backup"

   # Read the content of the file
    $lines = Get-Content $fullPath

    # Define the permission setting
    $permission = "SeRemoteInteractiveLogonRight = Domain Admins,*S-1-5-32-555"

    # Check if the section exists
    if ($lines -contains "[Privilege Rights]") {
        # Get the index of the section
        $index = $lines.IndexOf("[Privilege Rights]") + 1

        # Insert the permission setting after the section
        $lines = $lines[0..$index] + $permission + $lines[($index + 1)..$lines.Length]
    } else {
        # If the section doesn't exist, append the section and the permission at the end
        $lines += "[Privilege Rights]", $permission
    }

    # Write the content back to the file
    $lines | Set-Content -Path $fullPath
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

function Global-Gpupdate {
    try {
        # Invoke gpupdate on each computer
        Invoke-Command -ComputerName $ADcomputers -ScriptBlock {
            gpupdate /force
        } -AsJob  # Executes as background jobs to avoid waiting for each to finish
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

function Create-Good-GPO {
    try {
        Write-Host "Creating GPO named '$GPOName'..." -ForegroundColor Green
        $newGPO = New-GPO -Name $GPOName

        Write-Host "Fetching distinguished name of the domain..." -ForegroundColor Green
        $domainDN = (Get-ADDomain).DistinguishedName

        Write-Host "Linking GPO to the domain..." -ForegroundColor Green
        New-GPLink -Name $GPOName -Target $domainDN
		Write-Host "GPO linked successfully!" -ForegroundColor Green

        Write-Host "Setting permissions for GPO..." -ForegroundColor Green
        # Get the SID of the current user
        $userSID = (New-Object System.Security.Principal.NTAccount($CurrentUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        # Set permissions for the creating user (full control)
		try {
			Set-GPPermissions -Name $GPOName -TargetName $CurrentUser -TargetType User -PermissionLevel GpoEdit
			Write-Host "Permissions set successfully." -ForegroundColor Green
		} catch {
			Write-Host "Error setting permissions -- $_" -ForegroundColor Yellow
		}
		Write-Host "Go configure the GPO, specifically to deny the 'Apply Group Policy' for current user, before continuing" -ForegroundColor Black -BackgroundColor Yellow
		Read-Host " "
		Set-GPLink -Name $GPOName -Target $domainDN -Enforced Yes
		Write-Host "GPO fully and successfully configured and enforced!" -ForegroundColor Green
        Update-Log "Create Good GPO" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Create Good GPO" "Failed with error: $($_.Exception.Message)"
    }
}

function Configure-Secure-GPO {
    try {
        Handle-First-Policy-in-GPO

        # Define configurations
        $configurations = @{
            "Prevent Windows from Storing LAN Manager Hash" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "NoLMHash"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Disable Forced System Restarts" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
                "ValueName" = "NoAutoRebootWithLoggedOnUsers"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Disable Guest Account" = @{
                "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                "ValueName" = "AllowGuest"
                "Value" = 0
                "Type" = "DWORD"
            }
            "Disable Anonymous SID Enumeration" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "RestrictAnonymousSAM"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Enable Event Logs" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\Eventlog\Application"
                "ValueName" = "AutoBackupLogFiles"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Disable Anonymous Account in Everyone Group" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "EveryoneIncludesAnonymous"
                "Value" = 0
                "Type" = "DWORD"
            }
            "Enable User Account Control" = @{
                "Key" = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                "ValueName" = "EnableLUA"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Disable WDigest UseLogonCredential" = @{
                "Key" = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest"
                "ValueName" = "UseLogonCredential"
                "Value" = 0
                "Type" = "DWORD"
            }
            "Disable WDigest Negotiation" = @{
                "Key" = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest"
                "ValueName" = "Negotiate"
                "Value" = 0
                "Type" = "DWORD"
            }
            "Enable LSASS protection" = @{
                "Key" = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA"
                "ValueName" = "RunAsPPL"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Disable Restricted Admin" = @{
                "Key" = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA"
                "ValueName" = "DisableRestrictedAdmin"
                "Value" = 1
                "Type" = "DWORD"
            }
# # Configure Windows Defender Antivirus settings via Group Policy to enable real-time monitoring
            "Configure DisableAutoExclusions" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions"
                "ValueName" = "DisableAutoExclusions"
                "Value" = 0
                "Type" = "DWORD"
            }

            "Configure MpCloudBlockLevel" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine"
                "ValueName" = "MpCloudBlockLevel"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisableDatagramProcessing" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\NIS"
                "ValueName" = "DisableDatagramProcessing"
                "Value" = 1
                "Type" = "DWORD"
            }
 
            "Configure DisableProtocolRecognition" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\NIS"
                "ValueName" = "DisableProtocolRecognition"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisableSignatureRetirement" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS"
                "ValueName" = "DisableSignatureRetirement"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure LocalSettingOverridePurgeItemsAfterDelay" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Quarantine"
                "ValueName" = "LocalSettingOverridePurgeItemsAfterDelay"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisableRealtimeMonitoring" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "DisableRealtimeMonitoring"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisableBehaviorMonitoring" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "DisableBehaviorMonitoring"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisableIOAVProtection" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "DisableIOAVProtection"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisableOnAccessProtection" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "DisableOnAccessProtection"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisableRawWriteNotification" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "DisableRawWriteNotification"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisableScanOnRealtimeEnable" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "DisableScanOnRealtimeEnable"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisableScriptScanning" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "DisableScriptScanning"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure LocalSettingOverrideDisableBehaviorMonitoring" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "LocalSettingOverrideDisableBehaviorMonitoring"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure LocalSettingOverrideDisableIOAVProtection" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "LocalSettingOverrideDisableIOAVProtection"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure LocalSettingOverrideDisableOnAccessProtection" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "LocalSettingOverrideDisableOnAccessProtection"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure LocalSettingOverrideDisableRealtimeMonitoring" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "LocalSettingOverrideDisableRealtimeMonitoring"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure LocalSettingOverrideRealtimeScanDirection" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "LocalSettingOverrideRealtimeScanDirection"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure RealtimeScanDirection" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "RealtimeScanDirection"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisableHeuristics" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Scan"
                "ValueName" = "DisableHeuristics"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisablePackedExeScanning" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Scan"
                "ValueName" = "DisablePackedExeScanning"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisableRemovableDriveScanning" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Scan"
                "ValueName" = "DisableRemovableDriveScanning"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure ScanParameters" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Scan"
                "ValueName" = "ScanParameters"
                "Value" = 1
                "Type" = "DWORD"
            }
 
            "Configure QuickScanInterval" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Scan"
                "ValueName" = "QuickScanInterval"
                "Value" = 2
                "Type" = "DWORD"
            }
 
            "Configure MeteredConnectionUpdates" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                "ValueName" = "MeteredConnectionUpdates"
                "Value" = 1
                "Type" = "DWORD"
            }
 
            "Configure DisableScanOnUpdate" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                "ValueName" = "DisableScanOnUpdate"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisableScheduledSignatureUpdateOnBattery" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                "ValueName" = "DisableScheduledSignatureUpdateOnBattery"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure DisableUpdateOnStartupWithoutEngine" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                "ValueName" = "DisableUpdateOnStartupWithoutEngine"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure ForceUpdateFromMU" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                "ValueName" = "ForceUpdateFromMU"
                "Value" = 1
                "Type" = "DWORD"
            }
 
            "Configure RealtimeSignatureDelivery" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                "ValueName" = "RealtimeSignatureDelivery"
                "Value" = 1
                "Type" = "DWORD"
            }
 
            "Configure SignatureDisableNotification" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                "ValueName" = "SignatureDisableNotification"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure UpdateOnStartUp" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates"
                "ValueName" = "UpdateOnStartUp"
                "Value" = 1
                "Type" = "DWORD"
            }
 
            "Configure DisableBlockAtFirstSeen" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet"
                "ValueName" = "DisableBlockAtFirstSeen"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure SpynetReporting" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet"
                "ValueName" = "SpynetReporting"
                "Value" = 1
                "Type" = "DWORD"
            }
 
            "Configure LocalSettingOverrideSpynetReporting" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet"
                "ValueName" = "LocalSettingOverrideSpynetReporting"
                "Value" = 0
                "Type" = "DWORD"
            }
 
            "Configure EnableControlledFolderAccess" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"
                "ValueName" = "EnableControlledFolderAccess"
                "Value" = 1
                "Type" = "DWORD"
            }

            "Configure AllowNetworkProtectionOnWinServer" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
                "ValueName" = "AllowNetworkProtectionOnWinServer"
                "Value" = 1
                "Type" = "DWORD"
            }
 
            "Configure EnableNetworkProtection" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
                "ValueName" = "EnableNetworkProtection"
                "Value" = 2
                "Type" = "DWORD"
            }
        #other best practice keys
            "Configure SecurityLevel" = @{
                "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
                "ValueName" = "SecurityLevel"
                "Type" = "DWORD"
                "Value" = 0
            }
            "Configure SetCommand" = @{
                "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
                "ValueName" = "SetCommand"
                "Type" = "DWORD"
                "Value" = 0
            }
            "Configure AllocateCDRoms" = @{
                "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                "ValueName" = "AllocateCDRoms"
                "Type" = "String"
                "Value" = "1"
            }
            "Configure AllocateFloppies" = @{
                "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                "ValueName" = "AllocateFloppies"
                "Type" = "String"
                "Value" = "1"
            }
            "Configure CachedLogonsCount" = @{
                "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                "ValueName" = "CachedLogonsCount"
                "Type" = "String"
                "Value" = "0"
            }
            "Configure ForceUnlockLogon" = @{
                "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                "ValueName" = "ForceUnlockLogon"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure ConsentPromptBehaviorAdmin" = @{
                "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                "ValueName" = "ConsentPromptBehaviorAdmin"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure ConsentPromptBehaviorUser" = @{
                "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                "ValueName" = "ConsentPromptBehaviorUser"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure DisableCAD" = @{
                "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                "ValueName" = "DisableCAD"
                "Type" = "DWORD"
                "Value" = 0
            }
            "Configure EnableLUA" = @{
                "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                "ValueName" = "EnableLUA"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure FilterAdministratorToken" = @{
                "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                "ValueName" = "FilterAdministratorToken"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure NoConnectedUser" = @{
                "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                "ValueName" = "NoConnectedUser"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure PromptOnSecureDesktop" = @{
                "Key" = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                "ValueName" = "PromptOnSecureDesktop"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure ForceKeyProtection" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Cryptography"
                "ValueName" = "ForceKeyProtection"
                "Type" = "DWORD"
                "Value" = 2
            }
            "Configure AuthenticodeEnabled" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
                "ValueName" = "AuthenticodeEnabled"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure AuditBaseObjects" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "AuditBaseObjects"
                "Type" = "DWORD"
                "Value" = 0
            }
            "Configure DisableDomainCreds" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "DisableDomainCreds"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure EveryoneIncludesAnonymous" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "EveryoneIncludesAnonymous"
                "Type" = "DWORD"
                "Value" = 0
            }
            "Configure Enabled" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"
                "ValueName" = "Enabled"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure FullPrivilegeAuditing" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "FullPrivilegeAuditing"
                "Type" = "Binary"
                "Value" = 0
            }
            "Configure LimitBlankPasswordUse" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "LimitBlankPasswordUse"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure NTLMMinClientSec" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0"
                "ValueName" = "NTLMMinClientSec"
                "Type" = "DWORD"
                "Value" = 537395200
            }
            "Configure NTLMMinServerSec" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0"
                "ValueName" = "NTLMMinServerSec"
                "Type" = "DWORD"
                "Value" = 537395200
            }
            "Configure NoLMHash" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "NoLMHash"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure RestrictAnonymous" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "RestrictAnonymous"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure RestrictAnonymousSAM" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "RestrictAnonymousSAM"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure RestrictRemoteSAM" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "RestrictRemoteSAM"
                "Type" = "String"
                "Value" = "O:BAG:BAD:(A;;RC;;;BA)"
            }
            "Configure SCENoApplyLegacyAuditPolicy" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "SCENoApplyLegacyAuditPolicy"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure SubmitControl" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "SubmitControl"
                "Type" = "DWORD"
                "Value" = 0
            }
            "Configure AddPrinterDrivers" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
                "ValueName" = "AddPrinterDrivers"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure Winreg Exact Paths" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"
                "ValueName" = "Machine"
                "Type" = "MultiString"
                "Value" =  ""
            }
            "Configure Winreg Allowed Paths" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths"
                "ValueName" = "Machine"
                "Type" = "MultiString"
                "Value" = ""
            }
            "Configure ProtectionMode" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Session Manager"
                "ValueName" = "ProtectionMode"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure EnableSecuritySignature" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters"
                "ValueName" = "EnableSecuritySignature"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure RequireSecuritySignature" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters"
                "ValueName" = "RequireSecuritySignature"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure RestrictNullSessAccess" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters"
                "ValueName" = "RestrictNullSessAccess"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure EnablePlainTextPassword" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
                "ValueName" = "EnablePlainTextPassword"
                "Type" = "DWORD"
                "Value" = 0
            }
            "Configure EnableSecuritySignature Workstation" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
                "ValueName" = "EnableSecuritySignature"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure RequireSecuritySignature Workstation" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
                "ValueName" = "RequireSecuritySignature"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure LDAPClientIntegrity" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\LDAP"
                "ValueName" = "LDAPClientIntegrity"
                "Type" = "DWORD"
                "Value" = 2
            }
            "Configure DisablePasswordChange" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters"
                "ValueName" = "DisablePasswordChange"
                "Type" = "DWORD"
                "Value" = 0
            }
            "Configure RefusePasswordChange" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters"
                "ValueName" = "RefusePasswordChange"
                "Type" = "DWORD"
                "Value" = 0
            }
            "Configure RequireSignOrSeal" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters"
                "ValueName" = "RequireSignOrSeal"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure RequireStrongKey" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters"
                "ValueName" = "RequireStrongKey"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure SealSecureChannel" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters"
                "ValueName" = "SealSecureChannel"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure SignSecureChannel" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters"
                "ValueName" = "SignSecureChannel"
                "Type" = "DWORD"
                "Value" = 1
            }
            "Configure LdapEnforceChannelBinding" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\NTDS\Parameters"
                "ValueName" = "LdapEnforceChannelBinding"
                "Type" = "DWORD"
                "Value" = 2
            }
            "Configure LDAPServerIntegrity" = @{
                "Key" = "HKLM\System\CurrentControlSet\Services\NTDS\Parameters"
                "ValueName" = "LDAPServerIntegrity"
                "Type" = "DWORD"
                "Value" = 1 #doesn't enforce ldaps (ldap over tls), but prevents breaking the scoring engine if it is scoring normal ldap
            }

        }



        $successfulConfigurations = 0
        $failedConfigurations = @()

        # Loop through configurations
        foreach ($configName in $configurations.Keys) {
            $config = $configurations[$configName]
            $keyPath = $config["Key"]

            # Check if key path exists
            #if (-not (Test-Path "Registry::$keyPath")) {
            #    $failedConfigurations += $configName
            #    continue
            #}

            # Set GPO registry value
            Set-GPRegistryValue -Name $GPOName -Key $config["Key"] -ValueName $config["ValueName"] -Value $config["Value"] -Type $config["Type"]
            $successfulConfigurations++
        }

        Write-Host "$successfulConfigurations configurations successfully applied." -ForegroundColor Green

        if ($failedConfigurations.Count -gt 0) {
            Write-Host "`nConfigurations that couldn't be applied due to missing registry key paths:" -ForegroundColor Red
            $failedConfigurations
        } else {
            Write-Host "All configurations applied successfully." -ForegroundColor Green
        }

		#Write-Host "Applying gpupdate across all machines on the domain" -ForegroundColor Magenta
        #Global-Gpupdate
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

function Import-GPOs {
    Expand-Archive -Path ./gpos.zip

    $gpos = Get-ChildItem ./gpos

    $gpos | % {
        $xml = New-Object xml
        $xml.Load((Convert-Path ./gpos/$($_.name)/bkupInfo.xml))
        $gpoName = $xml.BackupInst.GPODisplayName."#cdata-section"

        New-GPO -Name $gpoName

        Import-GPO -path "$pwd/gpos" -BackupId $_.name -targetName $gpoName

        if (($gpoName.StartsWith("Domain")) -and ($gpoName -notlike "*Block*")) {
            New-GPLink -Name $gpoName -Target (Get-ADDomain -Current LocalComputer).DistinguishedName
        } 
        elseif ($gpoName.StartsWith("Web Servers")) {
            New-GPLink -Name $gpoName -Target "OU=Web Servers,$((Get-ADDomain -Current LocalComputer).DistinguishedName)"
        }
        elseif ($gpoName.StartsWith("Workstations")) {
            New-GPLink -Name $gpoName -Target "OU=Workstations,$((Get-ADDomain -Current LocalComputer).DistinguishedName)"
        }
        elseif ($gpoName.StartsWith("Databases")) {
            New-GPLink -Name $gpoName -Target "OU=Databases,$((Get-ADDomain -Current LocalComputer).DistinguishedName)"
        }
        elseif ($gpoName.StartsWith("DC")) {
            New-GPLink -Name $gpoName -Target "OU=Domain Controllers,$((Get-ADDomain -Current LocalComputer).DistinguishedName)"
        }
        elseif ($gpoName.StartsWith("Mail Servers")) {
            New-GPLink -Name $gpoName -Target "OU=Mail Servers,$((Get-ADDomain -Current LocalComputer).DistinguishedName)"
        }

    }

    #try two ways to force gpupdates
    Global-Gpupdate
    Get-ADComputer -Filter * | Invoke-GPUpdate

    $confirmation = Prompt-Yes-No -Message "Apply Default Block gpo? This shouldn't break AD... (y/n)"
    if ($confirmation.toLower() -eq "y") {
        New-GPLink -Name "Domain Allow AD + Core + Default Block" -Target "$((Get-ADDomain -Current LocalComputer).DistinguishedName)"
    } else {
        Write-Host "Skipping..." -ForegroundColor Red
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
            ./splunk.ps1 $Version $SplunkServer "dc" -local "../.."
        }

    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Configure Splunk" "Failed with error: $($_.Exception.Message)"
    }
}

function Install-EternalBluePatch {
    try {
        $patchURLsFromJSON = Get-Content -Raw -Path $patchURLFile | ConvertFrom-Json
        # Determine patch URL based on OS version keywords
        $patchURL = switch -Regex ($osVersion) {
            '(?i)Vista'  { $patchURLsFromJSON.Vista; break }
            'Windows 7'  { $patchURLsFromJSON.'Windows 7'; break }
            'Windows 8'  { $patchURLsFromJSON.'Windows 8'; break }
            '2008 R2'    { $patchURLsFromJSON.'2008 R2'; break }
            '2008'       { $patchURLsFromJSON.'2008'; break }
            '2012 R2'    { $patchURLsFromJSON.'2012 R2'; break }
            '2012'       { $patchURLsFromJSON.'2012'; break }
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
        Update-Log "Install EternalBlue Patch" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Install EternalBlue Patch" "Failed with error: $($_.Exception.Message)"
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
        Update-Log "Upgrade SMB" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Upgrade SMB" "Failed with error: $($_.Exception.Message)"
    }
}

function Patch-DCSync-Vuln {
    try {
        # Get all permissions in the domain, filtered to the two critical replication permissions represented by their GUIDs
        Import-Module ActiveDirectory
        $AllReplACLs = (Get-Acl -Path "AD:\$((Get-ADDomain).DistinguishedName)").Access | Where-Object { $_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -or $_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' }

        # Filter this list to RIDs above 1000 which will exclude well-known Administrator groups
		Write-Host "Users with Replicate ACLs" -ForegroundColor Yellow
        foreach ($ACL in $AllReplACLs) {
            $user = New-Object System.Security.Principal.NTAccount($ACL.IdentityReference)
            Write-Host "User:" $user # Print the user
            $SID = $user.Translate([System.Security.Principal.SecurityIdentifier])
            $RID = $SID.ToString().Split("-")[7]
            if([int]$RID -gt 1000) {
                Write-Host "Permission to Sync AD granted to:" $ACL.IdentityReference
            }
        }
        Update-Log "Patch DCSync" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Patch DCSync" "Failed with error: $($_.Exception.Message)"
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
        Update-Log "Patch Mimikatz" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Patch Mimikatz" "Failed with error: $($_.Exception.Message)"
    }
}

function Run-Windows-Updates {
    try {
        # Restart Windows Update service
        Restart-Service -Name wuauserv

        # Clear Windows Update cache
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
        Update-Log "Run Windows Updates" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Run Windows Updates" "Failed with error: $($_.Exception.Message)"
    }
}

function Harden-IIS {
    try {
        C:\windows\system32\inetsrv\appcmd.exe set config /section:directoryBrowse /enabled:false
        C:\windows\system32\inetsrv\appcmd.exe set config -section:anonymousAuthentication /username:"" --password
        C:\windows\system32\inetsrv\appcmd.exe set config /commit:WEBROOT /section:sessionState /cookieless:UseCookies /cookieName:ASP.NET_SessionID /timeout:20 
        C:\windows\system32\inetsrv\appcmd.exe set config /commit:WEBROOT /section:machineKey /validation:SHA1
        C:\windows\system32\inetsrv\appcmd.exe set config /section:requestfiltering /requestLimits.maxAllowedContentLength:300000
        C:\windows\system32\inetsrv\appcmd.exe set config /section:requestfiltering /requestLimits.maxURL:4096
        C:\windows\system32\inetsrv\appcmd.exe set config /section:requestfiltering /requestLimits.maxQueryString:2048
        C:\windows\system32\inetsrv\appcmd.exe set config /section:requestfiltering /allowHighBitCharacters:false
        C:\windows\system32\inetsrv\appcmd.exe set config /section:requestfiltering /allowDoubleEscaping:false
        C:\windows\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+verbs.[verb='TRACE',allowed='false']
        C:\windows\system32\inetsrv\appcmd.exe set config /section:requestfiltering /fileExtensions.allowunlisted:false
        C:\windows\system32\inetsrv\appcmd.exe set config /section:handlers /accessPolicy:Read
        C:\windows\system32\inetsrv\appcmd.exe set config -section:system.webServer/security/isapiCgiRestriction /notListedIsapisAllowed:false
        C:\windows\system32\inetsrv\appcmd.exe set config -section:system.webServer/security/isapiCgiRestriction /notListedCgisAllowed:false
        Update-Log "Harden IIS" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Harden IIS" "Failed with error: $($_.Exception.Message)"
    }
}

function Enable-UAC {
    try {
        $registryPath = "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $propertyName = "ConsentPromptBehaviorAdmin"
        $newValue = 1 # This means that every time administrator actions are wanted, a password is required

        if (Test-Path $registryPath) {
            Set-ItemProperty -Path $registryPath -Name $propertyName -Value $newValue
            Write-Host "Registry key updated successfully."
        } else {
            Write-Host "Registry key does not exist."
        }
        Update-Log "Enable UAC" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Enable UAC" "Failed with error: $($_.Exception.Message)"
    }
}

function Group-Management {
    try {
        & ".\$groupManagementFile"
        Update-Log "Group Management" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Group Management" "Failed with error: $($_.Exception.Message)"
    }
}

function Enable-Auditing {
    try {
        Write-Host "`n***Enabling advanced auditing...***" -ForegroundColor Magenta
        & ".\$advancedAuditingFile"
        Write-Host "Enabling Firewall logging successful and blocked connections..." -ForegroundColor Green
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True
        Update-Log "Enable Auditing" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Enable Auditing" "Failed with error: $($_.Exception.Message)"
    }
}

function Configure-Sysmon-Connect-Splunk {
    try {
        # Define base URL and local directory for the Sysmon files
        $sysmonPath = "$ccdcRepoWindowsHardeningPath/sysmon"
        $localSysmonDir = ".\sysmon"

        # Ensure the Sysmon directory exists
        if (-not (Test-Path $localSysmonDir)) {
            New-Item -Path $localSysmonDir -ItemType Directory
        }

        # File names to be downloaded
        $sysmonZip = "Sysmon.zip"
        $configXml = "sysmonconfig-export.xml"

        # Full paths for the files to be saved
        $sysmonZipPath = Join-Path $localSysmonDir $sysmonZip
        $configXmlPath = Join-Path $localSysmonDir $configXml

        # Download Sysmon and the configuration file using Invoke-WebRequest
        Write-Host "Downloading Sysmon..."
        Invoke-WebRequest -Uri "$sysmonPath/$sysmonZip" -OutFile $sysmonZipPath

        Write-Host "Downloading Sysmon configuration..."
        Invoke-WebRequest -Uri "$sysmonPath/$configXml" -OutFile $configXmlPath

        # Unzip Sysmon
        Write-Host "Extracting Sysmon..."
        $sysmonExtractPath = Join-Path $localSysmonDir "extracted"
        Expand-Archive -Path $sysmonZipPath -DestinationPath $sysmonExtractPath -Force

        # Install Sysmon with the configuration file
        Write-Host "Installing Sysmon with configuration..."
        Start-Process -FilePath "$sysmonExtractPath\Sysmon.exe" -ArgumentList "-accepteula -i $configXmlPath" -Wait -NoNewWindow

        # Define the Splunk Universal Forwarder inputs.conf path
        $splunkInputsConfPath = "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"

        # Ensure the directory for inputs.conf exists
        if (-not (Test-Path (Split-Path -Path $splunkInputsConfPath -Parent))) {
            New-Item -Path (Split-Path -Path $splunkInputsConfPath -Parent) -ItemType Directory -Force
        }

        # Define the new Splunk input configuration for Sysmon
        $sysmonInputsConf = @"
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
index = windows
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon
renderXml=false
"@

        # Check if the specific Sysmon configuration already exists in inputs.conf
        if (Test-Path $splunkInputsConfPath) {
            $inputsContent = Get-Content -Path $splunkInputsConfPath -Raw
            if ($inputsContent -notmatch 'WinEventLog://Microsoft-Windows-Sysmon/Operational') {
                Write-Host "Appending new Sysmon configuration to inputs.conf..."
                if ($inputsContent -ne "") {
                    # Ensure two new lines precede the new configuration if the file isn't empty
                    $sysmonInputsConf = "`n`n" + $sysmonInputsConf
                }
                Add-Content -Path $splunkInputsConfPath -Value $sysmonInputsConf
            } else {
                Write-Host "Sysmon configuration already exists in inputs.conf."
            }
        } else {
            Write-Host "Creating new inputs.conf and adding Sysmon configuration..."
            Add-Content -Path $splunkInputsConfPath -Value $sysmonInputsConf
        }

        # Restart Splunk Universal Forwarder to apply changes
        Write-Host "Restarting Splunk Universal Forwarder to apply changes..."
        Stop-Service -Name SplunkForwarder
        Start-Service -Name SplunkForwarder

        Write-Host "Sysmon installation and Splunk configuration complete." -ForegroundColor Green
        Update-Log "Configure Sysmon and Connect to Splunk" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Configure Sysmon and Connect to Splunk" "Failed with error: $($_.Exception.Message)"
    }
}

function Create-OUs {
    New-ADOrganizationalUnit -Name "Workstations" -ErrorAction SilentlyContinue
    New-ADOrganizationalUnit -Name "Web Servers" -ErrorAction SilentlyContinue
    New-ADOrganizationalUnit -Name "Mail Servers" -ErrorAction SilentlyContinue
    New-ADOrganizationalUnit -Name "Databases" -ErrorAction SilentlyContinue
} 

function Change-DA-Passwords {
    while ($true) {
        try {
            $pw = Read-Host -AsSecureString -Prompt "New password for Domain Admins:"
            $conf = Read-Host -AsSecureString -Prompt "Confirm password for Domain Admins:"

            # Convert SecureString to plain text
            $pwPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
            $confPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($conf))
            if ($pwPlainText -eq $confPlainText -and $pwPlainText -ne "") {
                #Get-ADGroup -Filter 'name -like "Domain Admins"' | Get-ADGroupMember | Where-Object objectClass -eq User | Set-ADAccountPassword -Reset -NewPassword $pw
                Get-ADGroup -Filter 'name -like "Domain Admins"' | Get-ADGroupMember | Where-Object objectClass -eq User | Foreach-object {
                    $stringAsStream = [System.IO.MemoryStream]::new()
                    $writer = [System.IO.StreamWriter]::new($stringAsStream)
                    $writer.write("$pwPlainText$($_.name)")
                    $writer.Flush()
                    $stringAsStream.Position = 0
                    $newpw = (Get-FileHash -Algorithm SHA256 -InputStream $stringAsStream).hash
                    $_ | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText -String ($newpw.Substring(0,12) + "!") -Force)
                }
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
}
function Change-User-Passwords {
    while ($true) {
        try {
            $pw = Read-Host -AsSecureString -Prompt "New password for non-Domain Admins:"
            $conf = Read-Host -AsSecureString -Prompt "Confirm password for non-Domain Admins:"

            # Convert SecureString to plain text
            $pwPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
            $confPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($conf))
            if ($pwPlainText -eq $confPlainText -and $pwPlainText -ne "") {
                #Get-ADGroup -Filter 'name -notlike "Domain Admins"' | Get-ADGroupMember | Where-Object objectClass -eq User | Set-ADAccountPassword -Reset -NewPassword $pw
                Get-ADGroup -Filter 'name -notlike "Domain Admins"' | Get-ADGroupMember | Where-Object objectClass -eq User | Foreach-object {
                    #$newpw = Get-FileHash -Algorithm SHA256 -InputStream [Text.Encoding]::Utf8.GetBytes("$pwPlainText$($_.name)") 
                    $stringAsStream = [System.IO.MemoryStream]::new()
                    $writer = [System.IO.StreamWriter]::new($stringAsStream)
                    $writer.write("$pwPlainText$($_.name)")
                    $writer.Flush()
                    $stringAsStream.Position = 0
                    $newpw = (Get-FileHash -Algorithm SHA256 -InputStream $stringAsStream).hash
                    $_ | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText -String ($newpw.Substring(0,12) + "!") -Force)
                }
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
}

function Enable-Disable-RDP {
    
    $confirmation = Prompt-Yes-No -Message "Should RDP be enabled?"
    if ($confirmation.toLower() -eq "y") {
        Write-Host "Enabling RDP"
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

        $confirmation = Prompt-Yes-No -Message "Will you be RDP-ing from computers not on the domain? (y/n)"
        if ($confirmation.toLower() -eq "y") { $nlaValue = 0 } else { $nlaValue = 1 }

        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value $nlaValue

    } else {
        Write-Host "Disabling RDP"
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
    }

}

function Identify-and-Fix-ASREP-Roastable-Accounts{
    $roastableAccounts = Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth
    Write-Host "ASREP Roastable Accounts:"
    $roastableAccounts

    $confirmation = Prompt-Yes-No -Message "Should we fix ASREP roastable accounts?(y/n)"
    if ($confirmation.toLower() -eq "y") {
        Write-Host "Fixing ASREP roastable accounts"
        
        foreach ($account in $roastableAccounts) {
            # Define the username of the user
            $UserName = $account.Name
            $User = Get-ADUser -Identity $UserName -ErrorAction Stop
            $updatedValue = $User.userAccountControl -band -4194305
            Set-ADUser -Identity $User -Replace @{userAccountControl=$updatedValue}  

            Write-Output "ASREP roastable account fixed for user: $UserName"
        }
    } else {
        Write-Host "Skipping..." -ForegroundColor Red
    }
}

function Identify-and-Fix-Kerberoastable-Accounts{   

    #Identify Kerberoastable Accounts
    $kerberoastableAccounts = Get-ADUser -Filter {ServicePrincipalName -ne "$null" -and msDS-SupportedEncryptionTypes -ne 24} -Property servicePrincipalName, msDS-SupportedEncryptionTypes | Select-Object Name
    Write-Host "Kerberoastable Accounts:"
    Write-Host $kerberoastableAccounts | Format-Table -Property Name, servicePrincipalName, msDS-SupportedEncryptionTypes -AutoSize
    
    $confirmation = Prompt-Yes-No -Message "Should we fix kerberoastable accounts? (y/n)"
    if ($confirmation.toLower() -eq "y") {
        Write-Host "Fixing kerberoastable accounts"
        
        foreach ($account in $kerberoastableAccounts) {
            # Define the username of the user
            $UserName = $account.Name
            $User = Get-ADUser -Identity $UserName -ErrorAction Stop

            # Set the msDS-SupportedEncryptionTypes to enforce AES128 and AES256 (Value: 24)
            Set-ADUser -Identity $User -Replace @{"msDS-SupportedEncryptionTypes"=24}

            Write-Output "AES128 and AES256 encryption enforced for user: $UserName"
            $updatedValue = $User.userAccountControl -band -4194305
            Set-ADUser -Identity $User -Replace @{userAccountControl=$updatedValue}   
            
            # Reset the password twice to flush insecure passwords from the domain controller cache
            Write-Host "Reset the password to flush insecure passwords from the domain controller cache" -ForegroundColor Yellow
            for($i=0; $i -lt 2; $i++){
            Get-Set-Password -user $User
            }
            Get-Set-Password -user $User
        }
    } else {
        Write-Host "Skipping..." -ForegroundColor Red
    }
}
###################################### MAIN ######################################


Initialize-Log

# Change current user's password
$confirmation = Prompt-Yes-No -Message "Change current user password? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Changing current user password***" -ForegroundColor Magenta
    Change-Current-User-Password
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}

Write-Host "Getting Competition Users" -ForegroundColor Magenta
GetCompetitionUsers
$usersFile = "users.txt"

# Get OS version and current user
$OSVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Load userfile and portdata
[string[]]$UserArray = Get-Content -Path ".\$usersFile"
$PortsObject = Get-Content -Path ".\$portsFile" -Raw | ConvertFrom-Json

# Get all computer names in the domain
$ADcomputers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

# Set GPO Name
$GPOName = "Good-GPO"


# Upgrade SMB
$confirmation = Prompt-Yes-No -Message "Upgrade SMB? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Upgrading SMB...***" -ForegroundColor Magenta
    Upgrade-SMB
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


# Group-Management
$confirmation = Prompt-Yes-No -Message "Do Group Management? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Doing Group Management...***" -ForegroundColor Magenta
    Group-Management
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}

# Change DA Passwords
$confirmation = Prompt-Yes-No -Message "Change DA passwords? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Change-DA-Passwords
    Write-Host "All DA passwords changed" -ForegroundColor Red
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}

# Change normal User Passwords
$confirmation = Prompt-Yes-No -Message "Change non-DA passwords? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Change-User-Passwords
    Write-Host "All non-DA passwords changed" -ForegroundColor Red
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}

# Mass Disable Users
$confirmation = Prompt-Yes-No -Message "Disable every user but your own? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Mass-Disable
    Write-Host "All users disabled but your own" -ForegroundColor Red
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


# Add Competition Users
$confirmation = Prompt-Yes-No -Message "Enter the 'Add Competition Users' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Adding Competition Users...***" -ForegroundColor Magenta
    Add-Competition-Users
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


# Harden RDP
$confirmation = Prompt-Yes-No -Message "Enter the 'Remove users from RDP group except $($UserArray[0]) and $($UserArray[1])' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Removing every user from RDP group except $($UserArray[0]) and $($UserArray[1])...***" -ForegroundColor Magenta
    Remove-RDP-Users
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}

# Enable RDP
#$confirmation = Prompt-Yes-No -Message "Enter the 'Enable RDP' function? (y/n)"
#if ($confirmation.toLower() -eq "y") {
#    Write-Host "`n***Enabling RDP...***" -ForegroundColor Magenta
#    Enable-Disable-RDP
#} else {
#    Write-Host "Skipping..." -ForegroundColor Red
#}


# Configure Firewall
$confirmation = Prompt-Yes-No -Message "Enter the 'Configure Firewall' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Configuring firewall...***" -ForegroundColor Magenta
    Configure-Firewall
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


# Disable Unnecessary Services
$confirmation = Prompt-Yes-No -Message "Enter the 'Disable unnecessary services (NetBIOS over TCP/IP, IPv6, closed port services)' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Disabling unnecessary services...***" -ForegroundColor Magenta
    Disable-Unnecessary-Services
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


# These steps are redundant now. The Good-GPO that got made is now part of gpos.zip
# Create Blank GPO
#$confirmation = Prompt-Yes-No -Message "Enter the 'Create Blank GPO with Correct Permissions' function? (y/n)"
#if ($confirmation.toLower() -eq "y") {
#    Write-Host "`n***Creating Blank GPO and applying to Root of domain...***" -ForegroundColor Magenta
#	Create-Good-GPO
#} else {
#    Write-Host "Skipping..." -ForegroundColor Red
#}


#$confirmation = Prompt-Yes-No -Message "Enter the 'Configure Secure GPO' function? (y/n)"
#if ($confirmation.toLower() -eq "y") {
#    Write-Host "`n***Configuring Secure GPO***" -ForegroundColor Magenta
#    Configure-Secure-GPO
#} else {
#    Write-Host "Skipping..." -ForegroundColor Red
#}

# Create Workstations OU (gives you something to do while splunk is installing)
$confirmation = Prompt-Yes-No -Message "Create OUs? (y/n)"
if ($confirmation.toLower() -eq "y") {
    try {
        Write-Host "***Creating OUs***" -ForegroundColor Magenta
        Create-OUs
        Update-Log "Create OUs" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Create OUs" "Failed with error: $($_.Exception.Message)"
    }
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}

$confirmation = Prompt-Yes-No -Message "Enter the 'Import GPOs' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Import GPOs***" -ForegroundColor Magenta
    Import-GPOs
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


# Configure Auditing
$confirmation = Prompt-Yes-No -Message "Enable Advanced Auditing and Firewall Logging? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Enable-Auditing
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


Write-Host "It is adviseable to configure other desired gpo attributes while the next steps are running."
Write-Host @"
Consider, after starting the splunk install:
    -Removing the debug process permission
    -Adding the audit directory access configuration
    -Preventing Domain Admins from logging into workstations
    -Adding Workstation Admins to workstation Administrators groups
    -Moving workstations into the Workstations OU
    -Applying group policy changes
Remember to check back periodically to type in credentials as needed
"@

# Configure Splunk
$confirmation = Prompt-Yes-No -Message "Enter the 'Configure Splunk' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Configuring Splunk...***" -ForegroundColor Magenta
    $SplunkIP = Read-Host "`nInput IP address of Splunk Server"
    $SplunkVersion = Read-Host "`nInput OS Version (7, 8, 10, 11, 2012, 2016, 2019, 2022): "
    Download-Install-Setup-Splunk -Version $SplunkVersion -IP $SplunkIP
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}

# Configure Sysmon and Connect to Splunk
$confirmation = Prompt-Yes-No -Message "Enter the 'Configure Sysmon and Connect to Splunk' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Configuring Sysmon and Connecting to Splunk...***" -ForegroundColor Magenta
    Configure-Sysmon-Connect-Splunk
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


# Harden IIS
$confirmation = Prompt-Yes-No -Message "Enter the 'Harden IIS' function? THIS ONLY WORKS WITH IIS 7.0 AND OLDER (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Hardening IIS...***" -ForegroundColor Magenta
    Harden-IIS
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


# Enable UAC With Password
$confirmation = Prompt-Yes-No -Message "Enable UAC with Password? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Enabling UAC with the key set to 1, always prompting password...***" -ForegroundColor Magenta
    Enable-UAC
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


# Install EternalBlue Patch
$confirmation = Prompt-Yes-No -Message "Install EternalBlue Patch? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Installing EternalBlue Patch...***" -ForegroundColor Magenta
    Install-EternalBluePatch
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


# Patch DCSync Vulnerability
$confirmation = Prompt-Yes-No -Message "Patch DCSync? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Patching DCSync...***" -ForegroundColor Magenta
    Patch-DCSync-Vuln
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


# Patch Mimikatz
$confirmation = Prompt-Yes-No -Message "Patch Mimikatz? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Patching Mimikatz...***" -ForegroundColor Magenta
    Patch-Mimikatz
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}

## Identify and Fix ASREP Roastable Accounts
$confirmation = Prompt-Yes-No -Message "Identify and Fix ASREP Roastable Accounts? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Identifying and Fixing ASREP Roastable Accounts...***" -ForegroundColor Magenta
    Identify-and-Fix-ASREP-Roastable-Accounts
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}

## Identify and Fix Kerberoastable Accounts
$confirmation = Prompt-Yes-No -Message "Identify and Fix Kerberoastable Accounts? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Identifying and Fixing Kerberoastable Accounts...***" -ForegroundColor Magenta
    Identify-and-Fix-Kerberoastable-Accounts
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}

# Run Windows Updates
$confirmation = Prompt-Yes-No -Message "Enter the 'Run Windows Updates' function? THIS WILL TAKE A WHILE... (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Running Windows Updater...***" -ForegroundColor Magenta
    Run-Windows-Updates
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


#Set Execution Policy back to Restricted
$confirmation = Prompt-Yes-No -Message "Set Execution Policy back to Restricted? (y/n)"
if ($confirmation.toLower() -eq "y") {
    try {
        Write-Host "`n***Setting Execution Policy back to Restricted...***" -ForegroundColor Magenta
        Set-ExecutionPolicy Restricted
        Update-Log "Set Execution Policy" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Set Execution Policy" "Failed with error: $($_.Exception.Message)"
    }
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}




Write-Host "`n***Script Completed!!!***" -ForegroundColor Green
Print-Log


###################################### MAIN ######################################
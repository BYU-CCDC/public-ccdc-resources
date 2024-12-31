Import-Module ActiveDirectory
Import-Module GroupPolicy

$ProgressPreference = 'SilentlyContinue'

$ccdcRepoWindowsHardeningPath = "https://tinyurl.com/byunccdc/windows/hardening"
$portsFile = "ports.json"
$advancedAuditingFile = "advancedAuditing.ps1"
$patchURLFile = "patchURLs.json"
$groupManagementFile = "groupManagement.ps1"
$mainFunctionsFile = "mainFunctionsList.txt"
$splunkFile = "../../splunk/splunk.ps1"

# Backup existing firewall rules
netsh advfirewall export ./firewallbackup.wfw

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
$neededFiles = @($portsFile, $advancedAuditingFile, $patchURLFile, $groupManagementFile, $mainFunctionsFile, $splunkFile)
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
Write-Host "Getting Competition Users" -ForegroundColor Magenta

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

                # Can cause problems if domain functional level isn't above Windows Server 2008 R2
                Add-ADGroupMember -Identity "Protected Users" -Members $user

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
                "Type" = "WORD"
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

        }



        $successfulConfigurations = 0
        $failedConfigurations = @()

        # Loop through configurations
        foreach ($configName in $configurations.Keys) {
            $config = $configurations[$configName]
            $keyPath = $config["Key"]

            # Check if key path exists
            if (-not (Test-Path "Registry::$keyPath")) {
                $failedConfigurations += $configName
                continue
            }

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

		Write-Host "Applying gpupdate across all machines on the domain" -ForegroundColor Magenta
        Global-Gpupdate
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

function Download-Install-Setup-Splunk {
    param([string]$Version)
    param([string]$IP)
    try {
        if (-not (Test-Path -Path ./splunk.ps1)) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $downloadURL = "https://tinyurl.com/byunccdc/splunk/splunk.ps1"

            Invoke-WebRequest -Uri $downloadURL -OutFile ./splunk.ps1
        }

        $splunkServer = "$($IP):9997" # Replace with your Splunk server IP and receiving port

        # Install splunk using downloaded script
        ./splunk.ps1 $Version $SplunkServer

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

function Create-Workstations-OU {
    New-ADOrganizationalUnit -Name "Workstations"
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


# Create Blank GPO
$confirmation = Prompt-Yes-No -Message "Enter the 'Create Blank GPO with Correct Permissions' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Creating Blank GPO and applying to Root of domain...***" -ForegroundColor Magenta
	Create-Good-GPO
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


$confirmation = Prompt-Yes-No -Message "Enter the 'Configure Secure GPO' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Configuring Secure GPO***" -ForegroundColor Magenta
    Configure-Secure-GPO
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

# Create Workstations OU (gives you something to do while splunk is installing)
$confirmation = Prompt-Yes-No -Message "Create Workstations OU? (y/n)"
if ($confirmation.toLower() -eq "y") {
    try {
        Write-Host "***Creating Workstations OU***" -ForegroundColor Magenta
        Create-Workstations-OU
        Update-Log "Create Workstations OU" "Executed successfully"
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Update-Log "Create Workstations OU" "Failed with error: $($_.Exception.Message)"
    }
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}

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

$gpo = @"
"PK\u0003\u0004\u0014\u0000\u0000\u0000\b\u0000ïTpYcÎÀU\u0005\u0000\u0000W\u0019\u0000\u00001\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/Backup.xmlÍYmoH\u0010þ^©ÿaÏR¥»Jkï\u0002æ¥ÝÃŒž95vT»ížª0¬\u0013.E°NbEùï·±\u0001»\rÉµ#+aÙg\u001eÙÁ\u003ey\u0017,Á\r\u0013œ\u0016n£\u0016 ¡K=?ŒìµVl\u0001ÕÖûþÉ\u001f\u0010\u0002FëØ¿ŒbàO÷/pæ»1Mèq{\u001cÑØa\u003c@\u001b\u0000}¹\u0004W\u0002bøxm\u0000aÿd\u0018ÓUtNŸ»\u001e8îõ*žW$ `~\u001dœÛ®/€ë§\u0016¶H¯µ Z:Ž\u0000§\u001d\u0026ïžk¯uÅXô®Ó¹œœm\u0007\u0005«¶KN\tÞ\u0019Ç\u0011Éi\u0026\u001bø³ ý×¯\u0000ÿ+ç3ÿK\\Ö?\u0010w\u0015ûl]J6)géLè*vyBvL\u0003S7\u003e¶ž³ïq]/\fSê\u0017\u0013a\u0017\n\u0018J\u0018aE¥®\u0000\u0005\tk$ªj\u0017ªrW\u00145û ôí[ÿ€\u0027N ».]lä\u0004d\u0017L÷\u0002?ô\u0013Æ\u0019Ç4w¯yN¹º;ÿÏü6en¹yDØàt\u003c1iàøa5òÙx:6ÆÎ3ï\u0003~f\u001c\u0005QWIÆ\u0019Žæ÷ù|ô\u0003öïA3ßüöü\u0016±öžÀVÈH\u001cÅ~B@Æ6i\"rè§Uî,3ÎÇ#÷^./ ¹ðžä9ÿær\u000ft~tZWxDçNœØþ;ì*éTz)ïŸdB\u0018ãý;»Õîå®!\u0019¥BÉºPR±\u0005µ©AEF²lÛ²­+ÚC¶r\nËÉý,³CAÌ$\u001bû\u0011£q\u001fa\u0010@\u0012ÐÜìà±\u000fJ§Ù1æ\u0007\u003cV²w\u0001\u0012 \u0016§xï\u0000\u0001u\u0001\u0016\u001ep\\@\u003c0\u0017Áb\u0001\u003c\f0\u0006s\t`/up\u0010p5 «`¡\u0001QË°%øn¡yÝ(d¬xÀôtQ¬Û=Å%£(¥|9XH@õ@×\u0005¢\u00034\u0004d%ý€¹äÎB)°YKTJ~ÑZüR%_á\u0005òú-k)õµòÒ€\u0012\u001fÝk­jy\u0012¶V\u0027\u0005¶ã!,\u0016ª\u0016§1V,î\u001aCéù;1ýÏEëjo\u001aRêA\u003eŒäOoÙc\u001ce³ÌÎ5*¶æt\"øÏd£U0\u0027qÝóÃã^ù!ù\u0001LÒT€n\u001aýaÏÕºc$LíÃï\u0018^Ü]QQ-Ý²*Ú\u0010cSºªé\u0010!\u0003Iö``Øºðpo\"amE¢\u0014Þôt\u000b\u000etU*`Ñ\u0015\u0019ÛøáÛÅœ*(Š5\u000bÊiÈ\u003cd\u0015Ñ\u0014ÍVEýá^E¢%\u001dÁ\u0001_!õBPGü\u001fB:24dw\u0015iÀ[h)«:ÿT©ª÷ï¯g§Œó·S4ü\u0003Í\u001cäf}ØÜ\u0006Ë6áS³×jŠL\u003eW§EÖ@¯õ\\ŠSÖº\u0018h·kÙ|M7\fî:œÖ\u001b^IßÏtãÃw{r®O?ŒÅ\bí.[¥ÀºÐ#^ÍŸàÔ\u001aOÃÿHÃQ»Œ³ÌurC³-KÔ\u0027É¬Ù\u00166ÛHÐGêfc{¯ï^|5ÊaP§\u0026Æ\u0013€)Tá»ûìmûí\nRp(§S)Žm\u0011\u001c\u001e=R\u001e¬z1\u0016=íùÅž}}Ýú¡Go\u0013\u0010²\u0019\u000fky\u003e\r#6å/m?\\Œè})jîid?\u0011ëÆY®øk¯œ\nÝŒ\u000bÁŸ8KßãW®Ñžì\u001bSøå5ôHýØK)\u001b\u0026T\u0005Þw%C0¡.`\u0004»\u0026âuÅ\u0012V÷êçsx\u001dÒÛ\u0010lãñ¢tL?þiåèQÄ©\u0014_\f\u001cAuì\u0013jp?+ N¿ùãÒ  !k»\u0001»;ô÷\t5H¿\u0002ê4¿ùÛ¯±\"õ\u001a\u0006yï\u0010ÏIzöuóìŠÇÿ\u001e±§HQ\u0006ÿOUxŽêT\t\u003eS¥m\u0027š5ÉÞ=£aVž4Ð ðzº³ÉÕqÕÂcÊ»Fª¹\u0000;às`NÌVÑq\tQæô\u0014\u001d6žÚëØnÂ©7_÷¿~U±Ôèÿ\u0007PK\u0003\u0004\u0014\u0000\u0000\u0000\b\u0000ïTpY§rÖ\u0019K\u0001\u0000\u0000\u003e\u0002\u0000\u00003\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/bkupInfo.xmluRMo@\u0014Œ7éhœ/\u001fËº,, ÄŠUô`\u003c¬\bíŠÀ#°ÆÆÿ^Ô\bÔ€·}3óf\u0026ëú\"þÚÓ¢V\u000fßyVÔOO¥Ê®ï÷{-q\u00055€J!×£\nvå\u00022\u0019\u001fôh1I%¢Ö_E!Ó€V\u0003Ïm\u0016ÑNn=÷q\u0015|ÉW?t\u0018\u0019\"!\u0019\"ÂÌ1rüÐA65(LèÛÎqœö\\œå6C\b¹E\u0027\u0018ªRêã\nŸbÚñæ²iba-FTl\u0012DRf£MBm$RLRj\u001bÂaéñ¯ØÍý\u0000\nUA%U\u0027û\u003e¡åxþ\u0016E/Ï$iÿ;ë³/=/etJØÀ\u0004\u00262éÒd#Ë\u0019aç,ÐÇNÃ^ Z\u003eåŸ\fFhS%æÈÁlØôÉiÐÔÈžÅ/NŽ\u0000ò\u003c)TÇ?oÚ×MY8ÌDßU\u0004°EÍ²ÍÒ\u0007éÝñîï~\u0001PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u00004\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u00008\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000@\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000M\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/Applications/PK\u0003\u0004\u0014\u0000\u0000\u0000\b\u0000TpYm\u0001¶@,\u0001\u0000\u0000*\u0002\u0000\u0000L\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/comment.cmtx±NÃ0\u0010w$ÞÁò©q\n\u000bªv\u0000\"T*`5Îµµ\u0014ÏiÊ³1ðHŒ\u0002®TÄèóßÿßÝÏ×wŸ8íÁ¶X$Ó4K\u0018 ²¥Æm4~3¹I\u0016óËŒ¶V·Ö\u0018@O,t!Í\u000eT\u0016|ç}=\u0013¢mÛŽœN­Û«,·åÃ³Úü$Öÿ\u0027\u001aÉKTÀœ©xHÅ\u0019Åÿ\u003eiWà\u0011Ôhå,ÙO5âÞÙŠ~ÉE\u001fý\u000e6\u001aµ\u000f\fâa.ÆúÉ\u001e¥\u0001ª¥\u0002ÕPo(ìÕ.4\u001c\n\u0014üp\u0010\u0015|y2|\rŸj,mKÁ\u0001°\u0004Çç¹ÎFüé«~£«,Í\u001aL]I\u000f¡ÿüÕQFúÜ\u0001ÙÆ\u0005\u00183\u001aWðÑh\u0007åjŽž\u0001LÞ,kù^\u001dÁç¯\u000e|B\u001d¯-Æçÿ\u0002PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000J\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/microsoft/PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000U\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/microsoft/windows nt/PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000]\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/PK\u0003\u0004\u0014\u0000\u0000\u0000\b\u0000œSpYŽ0{Q\u0004\u0000\u0000ì\u001a\u0000\u0000h\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.infÍXKoÚ@\u0010s¥þ\u0007+ê±€iÕS\u000e4*/\u003c\u000e¡\u0007\r±b\u001eÅ\u003cÂoûÍÌ®±\r\u0004Bí\u0004!\u0019ïî\u003cŸyììxÿþ¹§\u001bêOm\u001aK\u001eý¢ô!5wBs\u003cCY¹§[Œ0ò±Ú7ô\u003cêbÔ¢1M°Ê\u003c\u0007ôô.ñ,Ð\u0005Õ0\u003e\u0010ê+¬OÁaeÐÝŠ\u00102\u003cê\u0003®6~¬94zª\u0018Í0ïbÝ\u0017L=\u0012œ\u0003üWñÖ\u0003\u0003\u000eŽ­Š\u001cö \u0026ï\u0002=YOóëÊ\u0018kJ_\u0006Â\u0002~}Á=\u0007í\u0000\u0014aÄWÆx@O\u001b\u001a\u0019jÙ¹øæ\u0002Ð,0©},¡\u000f\u001dJžD¿@·þ^|Ú¬cå\u0016\u0012\u0002Ã«Þ«@F€\n\rMØ2 \u000eèg ä5AÁQgÿf­IwÕÅxY\u0007Œ×-J±$sÂò\u0004\u0018uÍL\u0011:Úô\b:WŒ€ó!æ­=\u0005áçCãë÷D[lâÜ»1+mDuûŸ\u0002ëQf87!¬ã?\u0010)ŸÄ³Ø)Mñ\"{S¹ë¢«\u001c\u001cÓ)æ\u001ed*²F±ìÛ7\u001bâ9_ß\u000b{°ù@Fq?ŠkÐ5q\u0005ð6z8\u0019¿8.ŠÖ©\u0000ØmÂG!t²ßŠh.ë\u001e4ôa\u0001ï|W¬X®Vë0g\\Wä\u0019Ï°GÇkqäíÍ8žŠWrFÃóms6ÖdÿÄmj²Ðf+St1*/ÌåyNÏRAywsŠ=\nGÅTU_\"BßaÁÿcÕúáõÕ€è\u001e\t3\u001f·Où!~ºïZ)M¯ßãÛTüýðæžæã\r·/+yjIòdG\u000bÜñwÕº|\u001b-ßt¶¶2¥v\u0007Ûú§êS\u0000\u0026\u0027\u0001»`JÛlÇÊs)\u001eõP\u001b²}-(õTãÞ1{ô/khâÔ\u000fåMù:ä\u001bç­÷\fÿ\u001d¬LÏ÷U(Xç¢:m\u0007»ìº;R\u0011\u001fv²~9UFOšµÍ¯\u0006-Ô1öx×øYO\u0016ÖÐ|Y!ûåù»ì²`QDÉè×%ú\u0005gëG\u0013\u0027R65€\u001eÉÖå\"v{\u0005Ï\u0012ŸÔö\u0005{ºçIÛ\u0012ÿ²~\u001b¿÷äyGÜ!?ÌÅnZgEü gKv\u0013ïågÒ\u003eñÏDŠqW¥\u001d\u001cßÐéN¬}\u000f9ÆËw\u0027ùF«Ð\u0019æ×á-cO¯xŠ]:Ý\b·¢üò(]Ì\r%K:d¿×²?ûÄ}S¯_­¿üìŸ\u0001b^ß#¬Fn#ŸÈ4îü3`[€\u001eµ€ýFÞc*£þ\u0013ãùÞâÔLšad}-ÒM=ó@¬p#|ñÆQ;+l×\u0007\u001eóêÄÏddiòµÍ~ñ7Àû Ý^3Û3bþ24«öS9µú8)Ò§öoã9ýë\u0026\u0016ŸšÜ\u0015h\"Õq\u001cUÈã\u0017ðŒŸãÝÜë2Òõ7nU¬«U\\mÚ2ïFý¹zïxoÐò®yo\t»KÒQ/QËxß\u0005Þ±áäû\u0015»7ŸefÍv_\u001bËwßöVBoc\u003c`æ\u0011ßÑšÕöþh\u000fîéÓXðþ\u0015ñÝ÷2ÎPK\u0003\u0004\u0014\u0000\u0000\u0000\b\u0000TpYÌ®ÉÅ7\u0001\u0000\u0000Ÿ\n\u0000\u0000L\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/registry.polÝMNÃ@\f_%\u000e\u000bp\u0002VA DiÕ X\u0010\u0016!MKDIQ\u0012(Çç³Û šøS6e4±ýìñóh\u003cãI1\u001fHºV¢¥fjµRŠZRÑ,T*g\u0014jÐ\f]ªÑ7\u001btª+tŠÈ+ŽÀÎ\u0018Š+ÀŠðÏŽ¯\u000b°\u000fH\u0011±-JË:g.YWdqwIL·à7Ïvã7t\\ŒÄßö»×Þ»ÙŸ?Êçqôì:x\u003e§\u001a)ÖåèPxÐÆ rß¿\tO5ÃbŒ¶ïÐ1º\u000e\u0017\u001a\u0027»#`:~Bž3g¬rG\u0027ØZ·YÖ#úE3V\u0016÷¿õ~ŒÃí)ýøß{úñ\u000eÿmÿ-ïmŠ]÷²zÔ;\u003eç\u0010\u0011ïÅ\u000b=w\u0001ÂÎ\u0026Ò\u003c)ÞçÎ{å\u0027vÿM¥bü\u0017ŸÇGÏðv\u001fÖY%ÁºÛ\u0019xe^\u0001PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000H\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/Scripts/PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000Q\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/Scripts/Shutdown/PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000P\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/Scripts/Startup/PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000=\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/User/PK\u0003\u0004\u0014\u0000\u0000\u0000\b\u0000ñTpYµaQ\u0016\u0000\u0000\u0026\u0012\u0001\u00003\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/gpreport.xmlí]ëSÛH\u0012ïÏWuÿ*_nS\u0015ÀÍ\u0003e`¥\u000e\u0002Éæö/Æ6à\u0003?Ö2a©«û×ï®\u001f\u001aÏC%Ûmâ)\u0017Æ\u001aÍôôôô¯»ç%ýï¿»ð\u000bü\t\u001dž\u0000ŸA\u000b\u0006\u0010B\u001bzÐá\u0005lÂ:TðwºÐÀô\u0026ÞíÂ\rß}!\\Ã\u001aæzW¿À\u001eü\u0015þ\u0002»ð\tÎà\u0014Ë\bÝ.RÜÁß!¥R·Xj\b}LÛÀÏ#Öñï5~÷°þ\u001bLÝÂZ+Hw\u0003þ\u0001\u0027p\f5¬û\u0016yè@¹q)·\u000b¡ŒÆm\u000bF[ÛrêJ¯£%\u001bXC\u000fsõP\u0026CL#iu0Ï\u0027NÀ2gøÿs\u003eaz\ré\u0013-gŽE~\u0001~vá\b¥E2§û×øG=£ï§ç)ß\u000büîc\u001dÂé¿±ÏßÀ\u0001üÈð\u001e¥÷#Tñï\rÿz2\u003eÄ_Ûð\u0001S·ñ×;,QÁ¿·ð\u0011?ôœiÛð\u001flÉF®öVÃ:Kl^íìàœ!þ5Xú#M\"M~ÌŸËjÍ.|ÆR\u001dLÝC.zªµ\b5TZß5õ4ò\u001eù%Ê\u0007\\s\u0027ª#ÄC¬á\u0001¯¥öñy5Õ\u0003,ÕÂÚøÝÄ·£z\t%[ØíMþ~w)m\u0007ÑDßNu¥QÐuDVCä0Ÿ·xw\u0013ujyß[X/ÕNC×sÎ|ä§¿Íß\u0015ìQªk5s\u000b?ÿä\u001aãÔtMÜ\u0006Jw÷š-UÖ\u0006_÷Y[âº[Ã\\UŽ7óÐÛ\u0018€É§XG\u00151÷)ú_Åÿgøÿ\b~À{ûð\u0013öå\u0011ã7I¹4®ñÿ{¶ò×ø¹BY4,Ñ+î\u0026k/YÕ:þ5P®o¹Ä6Ëø\u0027üìÃ\u0017xµìóÕ\u0001~ªøw5øµá÷\u0019Š]`Ú)Kê\u001cï}Åÿ_ñú\u0027þ\u0010ÇâSÓQ4šä?\u001e¿
šzóÓ©±ÜÖØ:nñ/\u001cy¢w¬yd7·ø\u001e¥ocê(¿÷ø¡\u0012ïÙÚŸfnGt(Í\u0004q¡%q|äÉgöÒl-ýÝ¢sÄwŠ£u¿^âœ~\u0019Q­b:Õñ)U9ÿ5#ºßWš[ìHo+Ö\u0027z\u001di-}®QÂ\u0015¶\u0003ï°Ü\u0026S\u0015©5:µÚõ]áÿéë»bÄÐu\u001d?o8/Yï·#JD³mz\u001fÝ­pÎ\nÓ© ¶lcî­)9¿^\"ÎwÙ~µt­è)ZÇ.Ì+ÎI¶£\u0026GÊ¶tçÁ\u0011Õ_%Ù€NíHj¡HæÕÆ\u0013ìé\u000bü;`\u000bu\u0006`Ç~ûšU\u001dh=9bRÖ\u0018÷æd\u001e­òºôüuI×çÞ;c\r#*!šñs©\u0003æB\"ïyŽ7YËÌ±A\u001eNóµnqíë\u0014xnKÊ\u0015âØrÀua_\u000eF­ºÆ«{n¥\u001a%e×uÁÒ€Y\u0016~e\u0013/T69ä|þv`{¬\u001dÐ-]Œ=8äŸŠ~ì³6ÌM\u003e» Û±«wwGÜ\u0004ÑÌÕ\u000eë5¥P«ôIHÒ}Mw\\É=lÍ=~z(Ã4+ óŠ·o|\u000e\u001bQ4\u001c9ÉLk\u001fkêG}XÇ\u0018³Í¿IRãdp-!qõÚvÏŸ3\u001aÏ\r Q0iÇ)òð/ [$s(v»òŒÞ\u0003îaä­d~6Þ²ü%³8h³í#~hØ¢.¶û)E\u0002ùK§éØ€ýNRækl·Ó4JòÊ\u001c¶\u0013€ûXS¹\rÙ\u0012\u003c .öðWë}å¬7-ÖXºŠ9AzÂ«\u0010l\u000f%BÞzÒä¯U»\u0016Õ\u0013Ì\u001bÂ\u001dæ­D²Lº\u0017÷h®åÊëÓŸ_ž¬\u003eì3^\u0007\u003ccs\u0001¿²\u001f;Â_¿³/£{ìÙ(µ¿\u0003äþ\u00145æP\u003eã\u0015y\u003eÊuÿñC¹kÞÇy\u001fç}\u001c¬Sk\u001cÞceK*»\u001eV·Ï¢\u0015\u001a{­\u0013ïŒ\u0017ò^h¥Œ\u001fieûUð[ÏÎoí\u0003í»\u0005µÓp$¶6ÀÜad\tŒGó\u001eÍ{ŽUòh\u000fòYæ*³ieŒïÊ*Tv9}WQ+fãWÎuKçí\u0001YA×ü{oçœ]V©ÉëõÞn1ÞÎß²}÷ù|`%êçà\u0003µ×ksß\f Îß=ï\u0003œ\u000fô\u003e\u0010VÑ\u0007\u0006¬5æ©ŸÕðqiV\"æÌDV\"¡eÙ#këçx.uv\u0013š)]Šëøi°]øÈZ:diUÙgÔ±ŸoŒ{Öb lÔæ-£k9`yôá!*åöÃo \u0018~2±Hü\u0012~ÈSÝÙ9ÇQ®a\u00109¥ŸH£iç±©\u00116TûTÜ{nÉ?¹í]w\\ÖÇsÛ§ÿÀ\b¥Xt-E^\u0026{}âe\u0027Û¥æÿwSÊ²¶EÍòÇòOFCû\u000eàWÞctÈ«º\"GýÔÃÒ%|e~@±FÔi¶ý\u0012é\u0010_j\u0017¶­-ª\fÅ\u00277QWÔ\f\u003c5;gù\u0005Næ8«¶Dk¬{ò{\u000fèlü\u000böžŒYõ\u0010ŠBöcõ±\u0011YF·ìÍ7l55à}\u001daÄ\u0001á4`y¬ñ~¯\u0013Œª\u001b `\u001c\u0007#éÝÌ[to\u0018Yk\u0011\u001e\u001eØ\u0002\u000eðW\u000fÄ3ëögKÕäþ\u000btYëšþel)}\u001e£©Å~Ñ¶\u000byò§÷Irùtß\u003c=V\u0001\u001fù¢Ž6kGcòV2!€y4z4Æ\u0003Ö®[ÖãQzÈÑá\u0003Ó(\u000b%Áã\u0011·äTgôµù)7!%Âèg\u001e]ðtß}ó7î\u0003÷Áœ!AÔÆHÂ\u0001üÀmŽSšÿô:I\u0003d=`Ý¿jk3µ.ôØ6ÔcQýË\u0002pœgñ®é9òPŽûÂ\u001aefçóX/\u0007ë\u001fÆcäIŸDw\u001a8Â×š/\névonŠ¢\u003co¯çïs·Ì€(\u0027Oü\u0007r%#X:\u0015a¢SÍÙè¬CÒ\u001e\u001f5B\u0014\u001bð`È;À\u003e€~žc¯óÎaï§+k/\u0003¯YHÕ£~©\u0027Ùµ\u000e\u0016î¥ô\u0019×Õáv}ÀŽ[ö\bmÖ)œâð=cù\u000bšžVf,U€â\"\u0010íJHùîaäe5òÙŸ!aÅ{\u0011ÎVszÜAd!Žühæ(\u0011uzz\u003c£ÊÄUv¯\u0012\u001dév\\uØÎ\u0006ëisdÏdÖ3\u0000eÏDná\bg\u0012ÅÞÞ±\u003cú©žÏ\u001bÕy«QÕ0ç\u003eQwöœMlÂ9ß\u000b@FÏß\u0007²œ\u000f_n4ë3Éû\u0002HßhÕókðX\u0015¬æÃö^Ê?}à($Ÿ\u0016C°+u5Ã\u0016ñÈºÙBb³eÓ5Ë/#iUüOk\u0006\u0005Dó²2Šk\"ÎenFVðQÉ\u003ekE9~³\u0014Î7Ÿ\u003e\u0001\u000b#þè®;5«}Ç)tMh\u001epOÜrÏ4\u000bÀæ\u001e×.\u0016€\rMÇmBr\u00159\u0013föÙž|\u001eÏåâù3Þ\u0017Ó\u0005Ù±@žUþ©\u001cŒŸ^\nŒÚWÖ¡\u003e£ËÞE«lÉ\\Ìî\u0027í€ê/¢×`Oø·ß\u0026ã[|Œ \\c\u001f[Ž¥ãøX-ŽÚ3T\u0026\ní(NtüÒIœÄ1iÔi*o\u0015xâû-ö$úÙä!ÖÛå;OÐ\u0001Yg)\u0007¥Àåg®YÍ\u0010Ûk¿ÑcŸ\u001fÄ€F³Vtíî®#\nú¬ÌF×c\u0012ÕkÅDµ\u001bÍÚ;îòð\b\u0006\u001f±,Í1¯\u0014ÙDi/»Ë±\u001cä-ÇšT·pŠ¯ôR0¢f?06ï@NnÊÞ[œ£\u0007\b®L\u0007_~t9\u000ft\u001dC­òã+ä]lÔøÅ±rß#ºâñŠ\u001aùÉ¬;*Žqw5\"¡Ë#aCíº\u0010M\u0010ýµÇxôíwC­\u001e\u0012mVûìæ\u0015Y.\u0007\u0002³\"Ë*ãFï2Rç»ãEÿ\u0003SyTµv*\u0018¥÷Hè}Ä\u001aõÚOŒ*+s;\u001e\u001e¶~þx4F»ÕÂ]\rË^E\u0011§\u001c€U\u0002iö\u001eŸÕnÙÃGxÓçeoË _!\fõGžR{\u0002$Æ€3|²sú\u0001$Ê€ý|!ïì[\u001elùYrÑ%³\u0026]Ÿ\u0027;ªhŽßd\t\u0019}$Õ\u0013þ\u000eÜr\u0012x`\u0005¹\u001c¥š²û\u003c­ËPz\u0015dFAòÜåðñ2rÊö[Ô?æ¬%í\u0000\u00180ÒeÇì­%L\u000bßj\u0026FIö¬%Ë1[\u0026·ÅãÕûÂ2Ñª9€µû6Ûv\u0017u²ÆH9nàÒð\fdéé\u0014°¬p±Gžå\u0012öºvQ4Wò®:ÿÆZÿÀµÍ.-±gäßšÅvoêVuÎG³÷Ô\u001e!õŒâ¹|:ÏiÉžK³Íyõ¥\u0018ë59ç\u003eíqßÊê£\u001díL\r\"µAF¯?BÖâ¬r^YºTÕíbñW\u001eea0ãeÀ¡pìeóê÷ÒexéçàËÑ`s\u003c26ÏS»LQÜÎª{îxN\u0019\u0016Çc|€x8\u001a\u0005ÉÊVQåéëS~wú\u0019è\u0011,}\u0017ÅÁ€²qûO]K#Ö°\u0016FíËÂß\u0005KKv¢\u0013Ýåâx./G{î€Ü5æ+N\u0007Ëææ\u0015hVfí-¡:NæÎÖ®\u003cØÆÊsÕè!\u0014U\u0017Åí€œ\u0010·QB£Ã¹§°R«3Î1×Ei~í;\u001a\u0003§õÓÇ9óçvÖX\u0027ãIqZnŒS\u001ceÄ\u003céÜåé÷¢ââdT^ìS\u001eEÇ?âŽš\u0018hqü\u001f\u0007¥·-\u000fÞŠ±³³ÆBÅõFññðæçÊoÒ§\u0026hµ¶\u000e7\u0011Rd\u001ev\brFLrÅÏüÏ6£Ž+°Šdi\u0027ùôq}EëZÌz\u0006\u003c\rDÛô)²;IÇ\u001bÊJcj¥gšµ`\u001dë[çúX\u0016=ÙfÙSÜå\u001d\u0018E\u003c\u0015mÚÈù\u0003ø5ÝòÐ\u001b·¬æ\u001e\u000bÛÇ±ºUT{É\u0018º(j¬%îI\rÕyí²IÁô\u0005ô6\u0013üþ\b\u0026ô\u0016ÏcôlÊ\\NÚÔÙfÈ9Îí]JÞ\u0018ß\u0005¹Ø\u001dýy¥êR)Š¯¢\fÁ¶œ»Ùµ5û.\u0017ee1vÈBŸ+§äÍf)µïRÕAv@­\u000e çÐíx¶lÍvÌn\u0011|\f°\bvøû+$=a3\r±@§ÌÓ±4\t-4zŠ7\u003ežgõÊÁle)0ô,®ã\u0006ÇÚÒ7âÁ[\u0011î\u001e8o)\u003c±\bFÝSz\nÇC^§\u0014ï\u001e°n\u0011Å\u0013Dœ\u000f{Lc\u001b¿£z9±L^E?Á×mk\rhV«Ët\u001e8G9h^\u000e\u000f\u003c\r«,¡6šÝÓòVFèàç1eïî¢9yd^ýø{ð*±ù¬ñ|è\u0014œ:Å«\u001aËŸ¬HËGû$R%.5§!ÏöŠêIF\u001aáH7hÜàžWeEóhM·YydŠç\u0006]«L¡L\b\u0011.W\u0017¶d\u0002\b\rÙ\u0010²ÜUª-~Gm\u0005ôsÇê_ Ö\\ižs€-W³\r\u001efËŠ)k_\u0026\u003c*šÛDï¬3íûê\"2§Ìï\u0019\u001fGëV}è¹gËûIË8.%öòžÌËibUHHBä\u0005J€ÄcÖ\u003eÏÞÊÓß\u001b1,~\u0000Í\u0004)å sk\tÙ°d¬rqùd\u0007c\u0018ÉŸãhŒ²ä\u0026óµw\u0011\u0026©\u001fu\u003cÜzuó³æ\nç\u001e\u0004S#Ý4lÙ%\u003c2FŠh*IßG »|nF-óhLC£ò\n}Ëžø\bÙäõ0hbÌ\\í7ßî®{Ì\\}Ôï(±i¶k\u0012ÚÙŠ#€2\u0003{?|âÈÊú~®ìôýp\fôŒº}p÷š\u001cŽsº\u0017=wy\u0011ý1ËHì9ö\u0007\u001f!ýíI*ç|úÂö\u001a/Rø\"O;ËÛ¥o?iËµØ~\u0011\u003e(ÆX|?è÷Ð~äý\u001bn\u001e\u001eå\u003cäý@-®QjNÊ§%èòL4åLœ\n2\u0027âæÍ3-w)\u001dl/¥ì`û·àgì¥[î\u003eŠlàç?ë-{\u000fÁ:È.\rìã\u0001ÛæŸ¥A\u001bN/B\u0011¢yöõ\u0005ó@üì°dh\u0007\u001fñ@ŒìÄr»ô^éo*or3^)·î\u000bÞDQqèÔèÆð\"³Trê¢vw¿cÒ\u0011õ.w\u001fSO+Qû¡Èsšôù+ÉÑæÚ%~Kz{~W\u0001yË\u0026ÈÓÒ©\u003ewuª\u0006z€±\u001eé¿-,yÕ@öáž1SÓ fæÉ¢Gú)Q};(ùu\r4;X\u0005ótÉK€\u0010XeøTÉg\u0027çº§ÙÈÍ¥þ\nâûcúcz1þtÞÅö\u0026IÁÝ;Ér²óŒâúÇœ\rUíË·ñð} ÁÎçÛW û\u0014åTÂpd!\\Ÿê±VQœd×ä\fn\u0017#.ÔûDLÙÛòJVzt\u0016Jús\u0012\u000eµ\u001f|5\u00057ô\u0006-y®ôù{Q\u001fœâÖ*}xä\u001a)W\u003e|iÚ€²34O\u001fÚR\u0017ëíJý\u001bšó\u0014ê\u0004Úd-7­æ8Ûdëjì-ûL}\b\u0012iìsÛd äßã[Hû\u000b6á-KØÍ¹Éû\u000eì3±ú\u000eÓ·-û\u001cç#÷\u0003\u0010~Ã¥È³ºµ­í0Õ.š9ªÄ]bÃ\u00156šUû_Þ3àñ^Þª\u000fz\u0011æ)ò$irŽmŽTâ-LIóÅ\u0019³F$qï\u0015ùŠ\u0014;N!}\u0016-¡Sìz/®:\u0026\tõ`0Ê\rò^\"}vBðH³ŽÄ¿Pý\"»³E§ Ç\u001c©=¡}Œ\u001arÝ³Æ\u0014®W.\u0026ªÐ±]ßèž\u0004ãþ\u0026d)ØrO³²2ã¬¯XŽ\u001e\u0011:eô\fyŽ\u0018W{v¢\"k·b×%\u001f]Qù\u0003K«ãÑø#áFögš\u003e5œÍò¶®÷¹\u0027®¹\u0015D©apŠ[ œ\u0006éÉ\u001dç§\u003e%¶-MKCUÜAvPÇq=\u001aßê4^\u0026oÕŽò[\u000e¿¶è×Þ€ìÞ9G~n~í\u001cdo×\u001aßép_xÏl\u0007Û¬­œhDBw=wDDŒm\u001bœO*Â\u0027\u0015Ó\u0017Þ\u000by/äœË»÷BõBadyô®z€ïÒ\u0003]Š[çRMÐöM,±XÁ:×%Ovwixßå{â= h\u0014Õ\u0013ÞóxÏã=Ë»÷\u003cõ\u003cr\u0012]Y\u001e±:ŽÞð-ÒðäšÜ{|^%4œgðÁ{\u0006wï\u0019\u0016ã\u0019 OÇ±ýÂ A6I«§Þ3dyÙäë}÷\u0015ÞWžŒ{_1¯8\u00013\u0016-gÕwV`î·7Ð;ÃBÐCìwm(zM=ËÙöž\b\u000bVt\u000bâûŽL-t­ôby·¹izk\u000bÞÚfÉÊÜ¯¢³¢fWÉ¶Îc~~ÞÖ¶ü6ÍÓþ.¢5Þ\"{\u0027§[ÛÊ\u000bc\f~Ízw\u0014\u003e«å­:z;_Û«æ\u001eÂ)Z®RI\u0004\nåwÐðM±\u0018ÑRïW}ñ6žåV\u0017ÅŸŽ\u0018-t¥l~ËðÛÚ\u0026ôÄFŽ\u001e0òv#ô\u0005#~4\u0005±O-C\nâ¹Ú,Õ!(×æ»ôTëQœsÀõd²,tÚÌ8\rx5Žµ\rV~ÏÔsQi-\u0015=çQ74 \u001cµ\u003e[[²œ³ë©\u0026÷ÏóØ|$5o\u001fø\u001bKx÷^Lµh1^l~+žÏiìO\"Y\u0016Šøø?\u001f_óá§åÈÇáÞåÉiæN·`â%i}#ôÔ\u001dYªØ®5êñüñ«èŸ¡U²ù¥;¹TÕÈBâfóÍõJ¢{\u0014BC\u000fóãÑÍ#{\rn×}\u0014\u000fAÊ-W\u001a\u0007eÙÒâ}¬.§õIÒ9g±ÆíH¯Ê i\\6œ7ÉÛ2%»yµÐû\u0026ïŠõM!ËÞú6ží\\%?2^\u0012Yv€xK:yFÑrâ£go¡²\u0013Ç¥G9\u0027}NØ9ØÏ»\"\u001aÉÖ+z%b\u003eýò©RóæÝ/\u0010:iþ\u001bÈl¢+OtmÀp$ë\nÓÎÎ7n\rsš\u0005Ô/É\u0014í\u001c6-ÛBïù\u001cv÷)xw·_`]nM5~\u001f¯î\u000ekeíâ\u0000%KTÝ\u003cI\u0014Îžn\u0013(¬óÿ\u001bÎ;{«õ²œ_Ò.Ã](ý\u0013ò{×ÿ\u0007PK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\b\u0000ïTpYcÎÀU\u0005\u0000\u0000W\u0019\u0000\u00001\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0000 \u0000\u0000\u0000\u0000\u0000\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/Backup.xmlPK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\b\u0000ïTpY§rÖ\u0019K\u0001\u0000\u0000\u003e\u0002\u0000\u00003\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0000\u0002\u0000\u0000\u0000€\u0005\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/bkupInfo.xmlPK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u00004\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0010\u0000\u0000\u0000@\u0007\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/PK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u00008\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0010\u0000\u0000\u0000\u0007\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/PK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000@\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0010\u0000\u0000\u0000è\u0007\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/PK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000M\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0010\u0000\u0000\u0000F\b\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/Applications/PK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\b\u0000TpYm\u0001¶@,\u0001\u0000\u0000*\u0002\u0000\u0000L\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0000 \u0000\u0000\u0000±\b\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/comment.cmtxPK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000J\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0010\u0000\u0000\u0000G\n\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/microsoft/PK\u0001\u0002\u0014\
u0000\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000U\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0010\u0000\u0000\u0000¯\n\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/microsoft/windows nt/PK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000]\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0010\u0000\u0000\u0000\"\u000b\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/PK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\b\u0000œSpYŽ0{Q\u0004\u0000\u0000ì\u001a\u0000\u0000h\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0000 \u0000\u0000\u0000\u000b\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.infPK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\b\u0000TpYÌ®ÉÅ7\u0001\u0000\u0000Ÿ\n\u0000\u0000L\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000 \u0000\u0000\u0000t\u0010\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/registry.polPK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000H\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0010\u0000\u0000\u0000\u0015\u0012\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/Scripts/PK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000Q\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0010\u0000\u0000\u0000{\u0012\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/Scripts/Shutdown/PK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000P\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0010\u0000\u0000\u0000ê\u0012\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/Machine/Scripts/Startup/PK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\u0000\u0000ïTpY\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000=\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0010\u0000\u0000\u0000X\u0013\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/DomainSysvol/GPO/User/PK\u0001\u0002\u0014\u0000\u0014\u0000\u0000\u0000\b\u0000ñTpYµaQ\u0016\u0000\u0000\u0026\u0012\u0001\u00003\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u0000 \u0000\u0000\u0000³\u0013\u0000\u0000{763B6AB7-0846-482A-9285-9BA6CA798A3A}/gpreport.xmlPK\u0005\u0006\u0000\u0000\u0000\u0000\u0011\u0000\u0011\u0000À\u0007\u0000\u0000U*\u0000\u0000\u0000\u0000\r\n"
"@

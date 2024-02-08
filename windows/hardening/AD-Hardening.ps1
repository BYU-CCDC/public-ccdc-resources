Import-Module ActiveDirectory
Import-Module GroupPolicy

$ccdcRepoWindowsHardeningPath = "https://github.com/BYU-CCDC/public-ccdc-resources/tree/main/windows/hardening/"
$portsFile = "ports.json"
$usersFile = "users.txt"
$advancedAuditingFile = "advancedAuditing.ps1"
$patchURLFile = "patchURLs.json"

$neededFiles = @($portsFile, $usersFile, $advancedAuditingFile, $patchURLFile)
foreach ($file in $neededFiles) {
    try {
        if (-not (Test-Path "$pwd\$file")) {
            $wc = New-Object net.webclient
            $wc.DownloadFile("$ccdcRepoWindowsHardeningPath/$file", "$pwd\$file")
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
        Write-Host "Download $file from $ccdcRepoWindowsHardeningPath"
        exit
    }
}

# Get OS version and current user
$OSVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Load userfile and portdata
[string[]]$UserArray = Get-Content -Path ".\users.txt"
$PortsObject = Get-Content -Path ".\ports.json" -Raw | ConvertFrom-Json

# Get all computer names in the domain
$ADcomputers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

# Set GPO Name
$GPOName = "Good-GPO"

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
function MassDisable {
    try {
    $currentSamAccountName = $CurrentUser.Split('\')[-1]

    Get-ADUser -Filter {SamAccountName -ne $currentSamAccountName} |
    ForEach-Object { Disable-ADAccount -Identity $_ }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

function Disable-Users {
    try {
        $confirmation = Prompt-Yes-No -Message "Mass disable users (y/n)?"
            if ($confirmation.toLower() -eq "y") {
                MassDisable
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

                while ($true) {
                    Get-Set-Password -user $user
                }
            }

            if ($UserArray.indexOf($user) -eq 1) {
                Add-ADGroupMember -Identity "Remote Desktop Users" -Members $user

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
        Get-AdUser -Filter * |
        Where-Object {$_.name -ne $UserArray[0] -and $_.name -ne $UserArray[1]} |
        ForEach-Object {
            Remove-ADGroupMember -identity "Remote Desktop Users" -members $_ -Confirm:$false
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

function Handle-First-Policy-in-GPO {
    try {
    # Install RSAT features
    Install-WindowsFeature -Name RSAT -IncludeAllSubFeature

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
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
    }
}

function Configure-Secure-GPO {
    try {
        Handle-First-Policy-in-GPO

        # Define configurations
        $configurations = @{
            "Moderating Access to Control Panel" = @{
                "Key" = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                "ValueName" = "NoControlPanel"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Prevent Windows from Storing LAN Manager Hash" = @{
                "Key" = "HKLM\System\CurrentControlSet\Control\Lsa"
                "ValueName" = "NoLMHash"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Control Access to Command Prompt" = @{
                "Key" = "HKCU\Software\Policies\Microsoft\Windows\System"
                "ValueName" = "DisableCMD"
                "Value" = 2
                "Type" = "DWORD"
            }
            "Disable Forced System Restarts" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
                "ValueName" = "NoAutoRebootWithLoggedOnUsers"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Disallow Removable Media Drives, DVDs, CDs, and Floppy Drives" = @{
                "Key" = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                "ValueName" = "NoViewOnDrive"
                "Value" = 12
                "Type" = "DWORD"
            }
            "Restrict Software Installations" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows\Installer"
                "ValueName" = "DisableMSI"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Disable Guest Account" = @{
                "Key" = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
                "ValueName" = "AllowGuest"
                "Value" = 0
                "Type" = "DWORD"
            }
            "Set Minimum Password Length to Higher Limits" = @{
                "Key" = "HKLM\Software\Policies\Microsoft Services\AdmPwd"
                "ValueName" = "MinimumPasswordLength"
                "Value" = 8
                "Type" = "DWORD"
            }
            "Set Maximum Password Age to Lower Limits" = @{
                "Key" = "HKLM\Software\Policies\Microsoft Services\AdmPwd"
                "ValueName" = "MaximumPasswordAge"
                "Value" = 90
                "Type" = "DWORD"
            }
            "Set Password History to 3 Passwords" = @{
                "Key" = "HKLM\Software\Policies\Microsoft Services\AdmPwd"
                "ValueName" = "PasswordHistorySize"
                "Value" = 3
                "Type" = "DWORD"
            }
            "Add Complexity Requirements" = @{
                "Key" = "HKLM\Software\Policies\Microsoft Services\AdmPwd"
                "ValueName" = "PasswordComplexity"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Set Minimum Password Length to 8 Characters" = @{
                "Key" = "HKLM\Software\Policies\Microsoft Services\AdmPwd"
                "ValueName" = "PasswordLength"
                "Value" = 8
                "Type" = "DWORD"
            }
            "Store Password Using Reversible Encryption" = @{
                "Key" = "HKLM\Software\Policies\Microsoft Services\AdmPwd"
                "ValueName" = "ClearTextPassword"
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
            "Disable Powershell" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows\PowerShell"
                "ValueName" = "EnableScripts"
                "Value" = 0
                "Type" = "DWORD"
            }
            "Enable Domain Profile Windows Defender" = @{
                "Key" = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
                "ValueName" = "EnableFirewall"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Enable Public Profile Windows Defender" = @{
                "Key" = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile"
                "ValueName" = "EnableFirewall"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Enable Private Profile Windows Defender" = @{
                "Key" = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
                "ValueName" = "EnableFirewall"
                "Value" = 1
                "Type" = "DWORD"
            }
            "Set Domain Profile Block Inbound" = @{
                "Key" = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
                "ValueName" = "DefaultInboundAction"
                "Value" = "Block"
                "Type" = "String"
            }
            "Set Domain Profile Allow Outbound" = @{
                "Key" = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile"
                "ValueName" = "DefaultOutboundAction"
                "Value" = "Allow"
                "Type" = "String"
            }
            "Set Standard Profile Block Inbound" = @{
                "Key" = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile"
                "ValueName" = "DefaultInboundAction"
                "Value" = "Block"
                "Type" = "String"
            }
            "Set Standard Profile Allow Outbound" = @{
                "Key" = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile"
                "ValueName" = "DefaultOutboundAction"
                "Value" = "Allow"
                "Type" = "String"
            }
            "Set Public Profile Block Inbound" = @{
                "Key" = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
                "ValueName" = "DefaultInboundAction"
                "Value" = "Block"
                "Type" = "String"
            }
            "Set Public Profile Allow Outbound" = @{
                "Key" = "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile"
                "ValueName" = "DefaultOutboundAction"
                "Value" = "Allow"
                "Type" = "String"
            }
            "Enable Defender Antivirus Protection" = @{
                "Key" = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
                "ValueName" = "DisableRealtimeMonitoring"
                "Value" = 0
                "Type" = "DWORD"
            }
        }

# # Configure Windows Defender Antivirus settings via Group Policy to enable real-time monitoring


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
    param([string]$IP)
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $downloadURL = "https://download.splunk.com/products/universalforwarder/releases/9.0.1/windows/splunkforwarder-9.0.1-82c987350fde-x64-release.msi"
        $splunkServer = "$($IP):9997" # Replace with your Splunk server IP and receiving port

        $securedValue = Read-Host -AsSecureString "Please enter a password for the new splunk user (splunkf)"
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedValue)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        # Download the Splunk Forwarder
        $path = "$env:TEMP\splunkforwarder.msi"

        Write-Host "Grabbing the installer file. Downloading it to $path" -ForegroundColor Cyan
        $wc = New-Object net.webclient
        $wc.Downloadfile($downloadURL, $path)

        Write-Host "Installing Splunk Forwarder with username" -ForegroundColor Cyan -NoNewline
        Write-Host " splunkf" -ForegroundColor Green -NoNewline
        Write-Host " and the" -ForegroundColor Cyan -NoNewline
        Write-Host " password" -ForegroundColor Green -NoNewline
        Write-Host " you provided above" -ForegroundColor Cyan
        # Install Splunk Forwarder
        Start-Process -Wait msiexec -ArgumentList "/i $path SPLUNKUSERNAME=splunkf SPLUNKPASSWORD=$password RECEIVING_INDEXER=$splunkServer WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 WINEVENTLOG_APP_ENABLE=1 AGREETOLICENSE=Yes /quiet"

        # Start Splunk forwarder service
        Start-Service SplunkForwarder

        # Clean up the downloaded MSI file
        Remove-Item $path
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..."
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
        # Restart Windows Update service
        Restart-Service -Name wuauserv

        # Clear Windows Update cache
        Stop-Service -Name wuauserv
        Remove-Item -Path C:\Windows\SoftwareDistribution\* -Recurse -Force
        Start-Service -Name wuauserv

        # Check for disk space
        $diskSpace = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -ExpandProperty FreeSpace
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




$confirmation = Prompt-Yes-No -Message "Enter the 'Create Blank GPO with Correct Permissions' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Creating Blank GPO and applying to Root of domain***" -ForegroundColor Magenta
	Create-Good-GPO
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


# $confirmation = Prompt-Yes-No -Message "Enter the 'Configure Secure GPO' function? (y/n)"
# if ($confirmation.toLower() -eq "y") {
#     Write-Host "`n***Configuring Secure GPO***" -ForegroundColor Magenta
#     Configure-Secure-GPO
# } else {
#     Write-Host "Skipping..." -ForegroundColor Red
# }


Write-Host "`n***Enabling advanced auditing***" -ForegroundColor Magenta
.\advancedAuditing.ps1
Write-Host "Enabling Firewall logging successful and blocked connections" -ForegroundColor Green
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True


$confirmation = Prompt-Yes-No -Message "Enter the 'Configure Splunk' function? (y/n)"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Configuring Splunk***" -ForegroundColor Magenta
    $SplunkIP = Read-Host "`nInput IP address of Splunk Server"
    Download-Install-Setup-Splunk -IP $SplunkIP
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


Write-Host "`n***Installing EternalBlue Patch***" -ForegroundColor Magenta
Install-EternalBluePatch


Write-Host "`n***Upgrading SMB***" -ForegroundColor Magenta
Upgrade-SMB


Write-Host "`n***Patching DCSync Vulns***" -ForegroundColor Magenta
Patch-DCSync-Vuln


Write-Host "`n***Patching Mimikatz***" -ForegroundColor Magenta
Patch-Mimikatz


$confirmation = Prompt-Yes-No -Message "Enter the 'Run Windows Updates' function? (y/n) This might take a while"
if ($confirmation.toLower() -eq "y") {
    Write-Host "`n***Running Windows Updater***" -ForegroundColor Magenta
    Run-Windows-Updates
} else {
    Write-Host "Skipping..." -ForegroundColor Red
}


Write-Host "***Setting Execution Policy back to Restricted***" -ForegroundColor Red
Set-ExecutionPolicy Restricted

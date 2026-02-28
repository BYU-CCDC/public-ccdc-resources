# Local Admin passwords
if (!(Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'")) {
    $length = 12
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    $adminpassword = -join ((1..$length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    $adminpassword += "!"
    
    net user Administrator "$adminpassword"
    
    Write-Output "LOCALADMINPASSWORD: $env:COMPUTERNAME,$adminpassword"
}


# Local User passwords
if (!(Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'")) {
    # $outputFile = "C:\Users\Administrator\Documents\passwords_output.txt"
    Write-Output $env:COMPUTERNAME

    function Generate-RandomPassword {
        $length = 10
        $upper   = (65..90   | ForEach-Object {[char]$_}) # A-Z
        $lower   = (97..122  | ForEach-Object {[char]$_}) # a-z
        $numbers = (48..57   | ForEach-Object {[char]$_}) # 0-9
        $special = "!@#$%^&*()-_=+[]{}<>?|".ToCharArray() # Special characters
        $all     = $upper + $lower + $numbers + $special
        $passwordArray = @(
            ($upper   | Get-Random -Count 1) +
            ($lower   | Get-Random -Count 1) +
            ($numbers | Get-Random -Count 1) +
            ($special | Get-Random -Count 1) +
            ($all     | Get-Random -Count ($length - 4))
        )
        $passwordArray    = $passwordArray -join ''
        $shuffledPassword = ($passwordArray.ToCharArray() | Sort-Object {Get-Random}) -join ''
        $finalPassword = $shuffledPassword -replace '\s', ''
        return $finalPassword
    }

    Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount = True" | ForEach-Object {
        if ($_.Name -ne "Administrator" -and $_.Disabled -eq $false -and $_.Name -ne "hacker1") {
            try {
                $username = $_.Name
                $password = Generate-RandomPassword
                net user $username $password
            }catch{
                Write-Host "Failed to change password for $username" -ForegroundColor Red
            }
            try{
                # "$username,$password" | Out-File -FilePath $outputFile -Append -Encoding UTF8
                Write-Output "$username,$password"
            }catch{
                Write-Host "Failed to write password in file for $username" -ForegroundColor Red
            }
            
        }
    }
}
else {
    $hostname = $env:computername
    Write-Host "$hostname is a Domain Controller..."
}

# Domain-User Passwords
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    function Generate-RandomPassword {
        $length = 10
        $upper   = (65..90   | ForEach-Object {[char]$_}) # A-Z
        $lower   = (97..122  | ForEach-Object {[char]$_}) # a-z
        $numbers = (48..57   | ForEach-Object {[char]$_}) # 0-9
        $special = "!@#$%^&*()-_=+[]{}<>?|".ToCharArray() # Special characters
        $all     = $upper + $lower + $numbers + $special
        $passwordArray = @(
            ($upper   | Get-Random -Count 1) +
            ($lower   | Get-Random -Count 1) +
            ($numbers | Get-Random -Count 1) +
            ($special | Get-Random -Count 1) +
            ($all     | Get-Random -Count ($length - 4))
        )
        $passwordArray    = $passwordArray -join ''
        $shuffledPassword = ($passwordArray.ToCharArray() | Sort-Object {Get-Random}) -join ''
        $finalPassword = $shuffledPassword -replace '\s', ''
        return $finalPassword
    }
    # $outputFilePath = "C:\Users\Administrator\Documents\passwords_output.txt"
    Write-Output $env:ComputerName
    Import-Module ActiveDirectory
    $excludedGroups = @("Domain Admins", "Enterprise Admins")
    $excludedUsers = foreach ($group in $excludedGroups) {
        Get-ADGroupMember -Identity $group -Recursive | Select-Object -ExpandProperty SamAccountName
    }
    $excludedUsers = $excludedUsers | Select-Object -Unique
    $excludedUsers += @("Administrator", "krbtgt")
    $users = Get-ADUser -Filter * | Where-Object {
        ($_.SamAccountName -notin $excludedUsers) -and
        ($_.SamAccountName -ne "Administrator") -and
        ($_.SamAccountName -ne "krbtgt") 
    }
    # Set-Content -Path $outputFilePath -Value "Username,Password"
    Write-Output "Username,Password"
    $GroupUserMap = @{}

    foreach ($user in $users) {
        try {
            $newPassword    = Generate-RandomPassword
            $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
            Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword $securePassword -Reset
            Write-Host "$($user.SamAccountName),$newPassword" -ForegroundColor Green
            $outputLine = "$($user.SamAccountName),$newPassword"
            # Add-Content -Path $outputFilePath -Value $outputLine
            Write-Output $outputLine
            
            $usersgroups = Get-ADPrincipalGroupMembership -Identity $user | Select-Object -ExpandProperty Name
            
            if ($usersgroups) {
                foreach ($groupName in $usersgroups) {
                    if(!($GroupUserMap.ContainsKey($groupName))) {
                        $GroupUserMap[$groupName] = New-Object System.Collections.ArrayList
                    }
                    
                    if (($user.SamAccountName -ne "Guest") -and ($user.SamAccountName -ne "DefaultAccount")){
                        $null = $GroupUserMap[$groupName].Add([PSCustomObject]@{
                            User     = $user.SamAccountName
                            Password = $newPassword
                        })
                    }
                }
            }
        } 
        catch {
            Write-Error "Failed to set password for user $($user.SamAccountName): $_"
        }
    }

    Write-Host "`n=== GROUP MEMBERSHIP & PASSWORDS ===" -ForegroundColor Cyan
    Write-Output "`n=== GROUP MEMBERSHIP & PASSWORDS ==="
    foreach ($groupName in $GroupUserMap.Keys) {
        
        if ($GroupUserMap[$groupName].Count -gt 0){
            # Add-Content -Path $outputFilePath -Value ""
            Write-Host "`nGroup: $groupName" -ForegroundColor Yellow
            Write-Output "`nGroup: $groupName"
            Write-Output "$($userEntry.User),$($userEntry.Password)"
            # Add-Content -Path $outputFilePath -Value "`n`nGroup: $groupName"
            
            foreach ($userEntry in $GroupUserMap[$groupName]) {
                Write-Host "$($userEntry.User),$($userEntry.Password)"
                Write-Output "$($userEntry.User),$($userEntry.Password)"
                # Add-Content -Path $outputFilePath -Value "$($userEntry.User),$($userEntry.Password)"
            }
        }
    }

    # Write-Host "Password rotation complete. Output saved to $outputFilePath" -ForegroundColor Cyan
}
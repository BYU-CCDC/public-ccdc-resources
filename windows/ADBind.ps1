Write-Host "Please enter the following info to bind your computer to the AD Domain" -ForegroundColor Green
$ComputerName= Read-Host -Prompt "Enter Computer Name"
Write-Host "The entered Computer Name is" $ComputerName -ForegroundColor Green

$Domain= Read-Host -Prompt "Enter Domain Name (exclude .local. For example: motocorp for 'motocorp.local')"
Write-Host "The entered Domain Name is" $Domain -ForegroundColor Green
Write-Host "Binding to $domain.local"

Add-Computer -NewName $ComputerName -DomainName "$domain.local" -OUPath "OU=Computers,DC=$domain,DC=local" -Credential (Get-Credential) -Restart
Read-Host -Prompt "Press Enter to Reboot Computer"

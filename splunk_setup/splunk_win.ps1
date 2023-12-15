Write-Host "Please Run as an admin. CTRL + C if you are not an admin"
Start-Sleep -Seconds 3
$ip=$args[0]
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$indexer = $ip + ":9997"
$securedValue = Read-Host -AsSecureString "Please enter a password for the new splunk user (splunkf)"
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedValue)
$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
$url = "https://download.splunk.com/products/universalforwarder/releases/9.0.1/windows/splunkforwarder-9.0.1-82c987350fde-x64-release.msi"
$path = $(Get-Location).path + "\splunkuniversalforwarder_x86.msi"
Write-Host "Grabbing the installer file. Downloading it to $path"
$wc = New-Object net.webclient
$wc.Downloadfile($downloadURL, $path)
write-host "The Installation will now take place in the background. The login creds should you need them are splunkf:<the password you just entered>"
msiexec.exe /i $path SPLUNKUSERNAME=splunkf SPLUNKPASSWORD=$value RECEIVING_INDEXER=$indexer WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 AGREETOLICENSE=Yes /quiet
Write-Host "Setting Execution Policty back to Restricted"
Set-ExecutionPolicy Restricted
Start-Service SplunkForwarder
Write-Host "DONE"
#IIS PowerShell
#---------------------------------------------------------------------------------------------------------------------------------------
Import Web-Administration
Import IIS-Administration
#Set application privelages to minimum
Foreach($item in (Get-ChildItem IIS:\AppPools)) { $tempPath="IIS:\AppPools\"; $tempPath+=$item.name; Set-ItemProperty -Path $tempPath -name processModel.identityType -value 4}
#Disable Directory Browse
Foreach($item in (Get-ChildItem IIS:\Sites)) { $tempPath="IIS:\Sites\"; $tempPath+=$item.name; Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name enabled -PSPath $tempPath -value False}
#Allow Powershell to Write the anonymousAuthentication value
Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -metadata overrideMode -value Allow -PSPath IIS:/
#Disable Anonymous Authenitcation
Foreach($item in (Get-ChildItem IIS:\Sites)) { $tempPath="IIS:\Sites\"; $tempPath+=$item.name; Set-WebConfiguration -filter /system.webServer/security/authentication/anonymousAuthentication $tempPath -value 0}
#Deny Powershell to Write the anonymousAuthentication value
Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -metadata overrideMode -value Deny-PSPath IIS:/
#Delete Custom Error Pages
$sysDrive=$Env:Path.Substring(0,3); $tempPath=((Get-WebConfiguration "//httperrors/error").prefixLanguageFilePath | Select-Object -First 1) ; $sysDrive+=$tempPath.Substring($tempPath.IndexOf('\')+1); Get-ChildItem -Path $sysDrive -Include *.* -File -Recurse | foreach { $_.Delete()}





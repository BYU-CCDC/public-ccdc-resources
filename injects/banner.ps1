# Define the login banner text
$BannerText = @"
******** WARNING ********
This system is the property of a private organization and is for authorized use only. By accessing this system, users agree to comply with the company’s Acceptable Use Policy.

All activities on this system may be monitored, recorded, and disclosed to authorized personnel for security purposes. There is no expectation of privacy while using this system. 

Unauthorized or improper use may result in disciplinary action or legal penalties. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use.

**************************
"@

# Define the path to the registry key for the login banner
$RegistryKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Set the legal notice text
Set-ItemProperty -Path $RegistryKey -Name "legalnoticecaption" -Value "WARNING"
Set-ItemProperty -Path $RegistryKey -Name "legalnoticetext" -Value $BannerText

Write-Output "Login banner installed successfully."

# Ideally make this a group policy setting applied to the whole domain.
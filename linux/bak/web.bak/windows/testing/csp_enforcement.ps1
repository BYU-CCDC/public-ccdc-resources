# Define the Content Security Policy (CSP) header value
# Adjust the policy below based on your requirements
$cspHeaderValue = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';"

# Log file to track the changes
$logFile = "C:\WebBackups\CSP_Enforcement_Log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Function to set CSP header for each IIS site
function Set-CSPHeader {
    Write-Output "$currentDateTime - Starting CSP Header Enforcement..." | Out-File -FilePath $logFile -Append

    # Get all IIS websites
    $sites = Get-WebSite

    foreach ($site in $sites) {
        $siteName = $site.Name

        try {
            # Add or update CSP header for the website
            $headerExists = Get-WebConfigurationProperty -Filter system.webServer/httpProtocol/customHeaders -PSPath "IIS:\Sites\$siteName" -Name Collection | Where-Object { $_.name -eq "Content-Security-Policy" }

            if ($headerExists) {
                # Update the CSP header if it already exists
                Set-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders" -PSPath "IIS:\Sites\$siteName" -Name Collection -AtElement @{name="Content-Security-Policy";value=$cspHeaderValue} -Force
                Write-Output "$currentDateTime - Updated CSP header for site '$siteName'." | Out-File -FilePath $logFile -Append
            } else {
                # Add a new CSP header if it doesn't exist
                Add-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders" -PSPath "IIS:\Sites\$siteName" -Name Collection -Value @{name="Content-Security-Policy";value=$cspHeaderValue}
                Write-Output "$currentDateTime - Added CSP header to site '$siteName'." | Out-File -FilePath $logFile -Append
            }
        } catch {
            Write-Error "Failed to set CSP header for site '$siteName'. Error: $_" | Out-File -FilePath $logFile -Append
        }
    }

    Write-Output "$currentDateTime - CSP Header Enforcement completed." | Out-File -FilePath $logFile -Append
}

# Execute the function to set the CSP header
try {
    Set-CSPHeader
    Write-Output "$currentDateTime - CSP Enforcement completed successfully." | Out-File -FilePath $logFile -Append
} catch {
    Write-Error "An error occurred during CSP Enforcement: $_" | Out-File -FilePath $logFile -Append
}

#!/bin/bash

# Define log file
logFile="/var/log/Security_Policy_Enforcement_Log.txt"
currentDateTime=$(date '+%Y-%m-%d %H:%M:%S')

# Content Security Policy (CSP) header value
cspHeaderValue="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';"

# 1. Configuration Compliance Check
echo "$currentDateTime - Starting Configuration Compliance Check..." | tee -a $logFile

# Check if HTTPS is enforced (assumes Apache or Nginx)
if grep -q "443" /etc/apache2/sites-available/*.conf 2>/dev/null || grep -q "443" /etc/nginx/sites-available/*.conf 2>/dev/null; then
    echo "$currentDateTime - HTTPS is enabled on some websites." | tee -a $logFile
else
    echo "$currentDateTime - Warning: No HTTPS configuration found for websites. Consider enabling HTTPS." | tee -a $logFile
fi

# Check for strong cipher suites (TLS 1.2 and above)
sslConfigFile="/etc/ssl/openssl.cnf"
if grep -q "TLSv1.2" $sslConfigFile || grep -q "TLSv1.3" $sslConfigFile; then
    echo "$currentDateTime - Strong TLS cipher suites (TLS 1.2 or higher) are enforced." | tee -a $logFile
else
    echo "$currentDateTime - Warning: Strong TLS cipher suites not enforced. Update $sslConfigFile to enforce TLS 1.2 or higher." | tee -a $logFile
fi

# Check directory permissions for web root folder
webRoot="/var/www/html"
expectedPermissions="root:www-data"
currentPermissions=$(stat -c "%U:%G" $webRoot)
if [ "$currentPermissions" != "$expectedPermissions" ]; then
    echo "$currentDateTime - Warning: Unexpected permissions on $webRoot. Expected $expectedPermissions, found $currentPermissions." | tee -a $logFile
else
    echo "$currentDateTime - Directory permissions for $webRoot are correctly set." | tee -a $logFile
fi

echo "$currentDateTime - Configuration Compliance Check completed." | tee -a $logFile

# 2. Policy Validation
echo "$currentDateTime - Starting Policy Validation..." | tee -a $logFile

# Check if UFW (firewall) is active and enabled
if sudo ufw status | grep -q "Status: active"; then
    echo "$currentDateTime - UFW firewall is enabled." | tee -a $logFile
else
    echo "$currentDateTime - Warning: UFW firewall is not enabled. Enabling it now." | tee -a $logFile
    sudo ufw enable
    echo "$currentDateTime - UFW firewall enabled." | tee -a $logFile
fi

# Check minimum password length (assumes PAM configuration)
minPasswordLength=$(grep -oP 'minlen=\K\d+' /etc/security/pwquality.conf)
if [ "$minPasswordLength" -lt 12 ]; then
    echo "$currentDateTime - Warning: Minimum password length is less than recommended. Updating to 12 characters." | tee -a $logFile
    sudo sed -i '/minlen=/c\minlen=12' /etc/security/pwquality.conf
    echo "$currentDateTime - Minimum password length policy updated to 12 characters." | tee -a $logFile
else
    echo "$currentDateTime - Minimum password length policy is correctly set." | tee -a $logFile
fi

# Check audit policy (Auditd must be installed and active)
if systemctl is-active --quiet auditd; then
    echo "$currentDateTime - Auditd is running, auditing enabled for critical events." | tee -a $logFile
else
    echo "$currentDateTime - Warning: Auditd service is not running. Installing and starting Auditd." | tee -a $logFile
    sudo apt install -y auditd
    sudo systemctl enable --now auditd
    echo "$currentDateTime - Auditd service started and enabled." | tee -a $logFile
fi

echo "$currentDateTime - Policy Validation completed." | tee -a $logFile

# 3. Enforcing Content Security Policy (CSP)
echo "$currentDateTime - Starting CSP Header Enforcement..." | tee -a $logFile

# For Nginx: Add CSP header to the main configuration file
if [ -d "/etc/nginx" ]; then
    cspNginxConfig="/etc/nginx/conf.d/csp.conf"
    echo "add_header Content-Security-Policy \"$cspHeaderValue\";" | sudo tee $cspNginxConfig > /dev/null
    echo "$currentDateTime - CSP header added to Nginx configuration." | tee -a $logFile
    sudo systemctl reload nginx
    echo "$currentDateTime - Nginx reloaded to apply CSP header." | tee -a $logFile
fi

# For Apache: Add CSP header to all virtual host configurations
if [ -d "/etc/apache2" ]; then
    for site in /etc/apache2/sites-available/*.conf; do
        if ! grep -q "Header set Content-Security-Policy" "$site"; then
            echo "Header set Content-Security-Policy \"$cspHeaderValue\"" | sudo tee -a "$site" > /dev/null
            echo "$currentDateTime - CSP header added to Apache site configuration: $site" | tee -a $logFile
        fi
    done
    sudo systemctl reload apache2
    echo "$currentDateTime - Apache reloaded to apply CSP header." | tee -a $logFile
fi

echo "$currentDateTime - CSP Header Enforcement completed." | tee -a $logFile

echo "$currentDateTime - Security Policy Enforcement completed successfully." | tee -a $logFile

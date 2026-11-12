#!/bin/bash

# Define variables
zapDownloadUrl="https://github.com/zaproxy/zaproxy/releases/download/v2.13.0/ZAP_2_13_0_unix.sh"  # Replace with the latest ZAP URL if necessary
zapInstaller="/tmp/ZAP_Installer.sh"
zapInstallDir="/opt/zap"
logFile="/var/log/zap_install_log.txt"
currentDateTime=$(date '+%Y-%m-%d %H:%M:%S')
targetUrl="http://example.com"  # Replace with your target URL

# Function to log events
log_event() {
    echo "$currentDateTime - $1" | tee -a "$logFile"
}

# Step 1: Install Java (required by OWASP ZAP)
if ! command -v java &> /dev/null; then
    log_event "Java is not installed. Installing Java..."
    sudo apt update
    sudo apt install -y default-jre
    log_event "Java installation completed."
else
    log_event "Java is already installed."
fi

# Step 2: Download OWASP ZAP installer
log_event "Downloading OWASP ZAP..."
wget -O "$zapInstaller" "$zapDownloadUrl"

# Verify download success
if [[ -f "$zapInstaller" ]]; then
    log_event "OWASP ZAP installer downloaded successfully."
else
    log_event "Error: OWASP ZAP installer download failed."
    exit 1
fi

# Step 3: Install OWASP ZAP
log_event "Installing OWASP ZAP..."
chmod +x "$zapInstaller"
sudo "$zapInstaller" -q -dir "$zapInstallDir"

# Verify installation success
if [[ -d "$zapInstallDir" ]]; then
    log_event "OWASP ZAP installed successfully to $zapInstallDir."
else
    log_event "Error: OWASP ZAP installation failed."
    exit 1
fi

# Step 4: Run OWASP ZAP in headless mode
log_event "Starting OWASP ZAP in headless mode to scan $targetUrl..."
"$zapInstallDir/zap.sh" -daemon -host 127.0.0.1 -port 8080 -config api.key=changeme -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true &

# Wait for OWASP ZAP to start
sleep 15

# Step 5: Launch an automated scan of the target URL
log_event "Initiating scan on $targetUrl..."
curl "http://127.0.0.1:8080/JSON/ascan/action/scan/?url=$targetUrl&recurse=true&inScopeOnly=false&scanPolicyName=&method=&postData=&contextId="

# Step 6: Wait for the scan to complete (polling every 10 seconds)
scanProgress=100
while [[ "$scanProgress" -gt 0 ]]; do
    scanProgress=$(curl -s "http://127.0.0.1:8080/JSON/ascan/view/status/" | jq '.status' | tr -d '"')
    log_event "Scan progress: $scanProgress%"
    sleep 10
done

log_event "Scan completed."

# Step 7: Save the scan report
log_event "Saving scan report to /tmp/zap_report.html..."
curl "http://127.0.0.1:8080/OTHER/core/other/htmlreport/?apikey=changeme" -o /tmp/zap_report.html

# Cleanup
rm -f "$zapInstaller"
log_event "OWASP ZAP installation and scanning process completed. Report saved to /tmp/zap_report.html."

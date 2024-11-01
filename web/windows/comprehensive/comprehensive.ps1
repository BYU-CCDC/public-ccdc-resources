# Define log file for tracking changes
$logFile = "C:\ComprehensiveSetup\setup_log.txt"
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Function to log actions
function Write-Log {
    param (
        [string]$message
    )
    Write-Output "$currentDateTime - $message" | Out-File -FilePath $logFile -Append
}

Write-Log "Starting Comprehensive Setup..."

# === Compliance and Security Audit ===
function Invoke-ComplianceAudit {
    Write-Log "Running Compliance Audit..."
    # Compliance GPO Check
    ./compliance_gpo_audit.ps1
    # CSP Enforcement
    ./csp_enforcement.ps1
    Write-Log "Compliance Audit completed."
}

function Enable-DLP {
    Write-Log "Enabling Data Loss Prevention..."
    ./dlp.ps1
    Write-Log "Data Loss Prevention setup completed."
}

# === Service Management ===
function Install-CaddyReverseProxy {
    Write-Log "Setting up Caddy Reverse Proxy..."
    ./caddy_reverse_proxy.ps1
    Write-Log "Caddy Reverse Proxy setup completed."
}

function ConvertTo-DockerServices {
    Write-Log "Dockerizing Services..."
    ./dockerize.ps1
    Write-Log "Dockerization of services completed."
}

function Install-KubernetesCluster {
    Write-Log "Setting up Kubernetes Cluster..."
    ./k8_cluster.ps1
    Write-Log "Kubernetes Cluster setup completed."
}

# === Monitoring and Security Tools ===
function Install-Nessus {
    Write-Log "Setting up Nessus Vulnerability Scanner..."
    ./nessus.ps1
    Write-Log "Nessus setup completed."
}

function Install-OSSEC {
    Write-Log "Setting up OSSEC for Host-based Intrusion Detection..."
    ./ossec.ps1
    Write-Log "OSSEC setup completed."
}

function Install-Wazuh {
    Write-Log "Setting up Wazuh for Endpoint Monitoring..."
    ./wazuh.ps1
    Write-Log "Wazuh setup completed."
}

function Enable-FIM {
    Write-Log "Setting up File Integrity Monitoring..."
    ./fim.ps1
    Write-Log "File Integrity Monitoring setup completed."
}

function Install-WAF {
    Write-Log "Setting up Web Application Firewall..."
    ./waf.ps1
    Write-Log "WAF setup completed."
}

# === Privileged Identity Management (PIM) ===
function Set-PIM {
    Write-Log "Configuring Privileged Identity Management..."
    ./pim.ps1
    Write-Log "Privileged Identity Management configured."
}

# === Backup and Recovery ===
function Initialize-Backup {
    Write-Log "Setting up Backup for Web Applications..."
    ./web_backup.ps1
    Write-Log "Backup setup completed."
}

function Protect-PII {
    Write-Log "Securing Personally Identifiable Information (PII)..."
    ./pii.ps1
    Write-Log "PII security setup completed."
}

# === Digital Forensics and Incident Response (DFIR) ===
function Install-Velociraptor {
    Write-Log "Deploying Velociraptor for DFIR..."
    ./velociraptor_dfir.ps1
    Write-Log "Velociraptor setup completed."
}

# === LLM Setup ===
function Install-LLM {
    Write-Log "Setting up Lightweight Language Model..."
    ./llm\llm.ps1
    Write-Log "LLM setup completed."
}

# === Execute All Functions ===
try {
    Write-Log "Starting Compliance and Security Audit..."
    Invoke-ComplianceAudit
    Enable-DLP

    Write-Log "Starting Service Management Setup..."
    Install-CaddyReverseProxy
    ConvertTo-DockerServices
    Install-KubernetesCluster

    Write-Log "Setting up Monitoring and Security Tools..."
    Install-Nessus
    Install-OSSEC
    Install-Wazuh
    Enable-FIM
    Install-WAF

    Write-Log "Configuring Privileged Identity Management..."
    Set-PIM

    Write-Log "Setting up Backup and PII Security..."
    Initialize-Backup
    Protect-PII

    Write-Log "Deploying DFIR tools..."
    Install-Velociraptor

    Write-Log "Setting up Language Model environment..."
    Install-LLM

    Write-Log "Comprehensive setup completed successfully."
} catch {
    Write-Log "Error encountered: $_"
}

Write-Output "Comprehensive setup completed. Check the log file at $logFile for details."

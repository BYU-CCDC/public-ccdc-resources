# This will get updated. 
# Windows Scripts Collection

This repository contains a collection of PowerShell scripts designed for various Windows administrative and cybersecurity tasks, including compliance audits, file integrity monitoring, privileged identity management, and setting up large language models (LLM). Each script automates essential system management functions, especially in security-focused environments.

## Table of Contents

- [Comprehensive Scripts](#comprehensive-scripts)
  - [comprehensive.ps1](#comprehensiveps1)
- [LLM Setup](#llm-setup)
  - [llm.ps1](#llmps1)
- [Proxy and Compliance](#proxy-and-compliance)
  - [caddy_reverse_proxy.ps1](#caddy_reverse_proxyps1)
  - [compliance_gpo_audit.ps1](#compliance_gpo_auditps1)
  - [csp_enforcement.ps1](#csp_enforcementps1)
- [Data Loss Prevention (DLP)](#data-loss-prevention-dlp)
  - [dlp.ps1](#dlpps1)
- [Docker and Kubernetes](#docker-and-kubernetes)
  - [dockerize.ps1](#dockerizeps1)
  - [k8_cluster.ps1](#k8_clusterps1)
- [File Integrity Monitoring (FIM)](#file-integrity-monitoring-fim)
  - [fim.ps1](#fimps1)
- [Vulnerability Scanning and Security](#vulnerability-scanning-and-security)
  - [nessus.ps1](#nessusps1)
  - [ossec.ps1](#ossecps1)
  - [owasp_zap.ps1](#owasp_zapps1)
- [Personally Identifiable Information (PII)](#personally-identifiable-information-pii)
  - [pii.ps1](#piips1)
- [Privileged Identity Management (PIM)](#privileged-identity-management-pim)
  - [pim.ps1](#pimps1)
- [Digital Forensics and Incident Response (DFIR)](#digital-forensics-and-incident-response-dfir)
  - [velociraptor_dfir.ps1](#velociraptor_dfirps1)
- [Web Application Firewall (WAF)](#web-application-firewall-waf)
  - [waf.ps1](#wafps1)
- [Endpoint Monitoring and Security](#endpoint-monitoring-and-security)
  - [wazuh.ps1](#wazuhps1)
- [Backup Management](#backup-management)
  - [web_backup.ps1](#web_backupps1)
- [YARA Rule Setup](#yara-rule-setup)
  - [YARA.md](#yaramd)

---

## Comprehensive Scripts

### comprehensive.ps1

**Description**: Provides a full system audit and configuration review for compliance and security. This script is essential for initial hardening.

**Usage**:
```powershell
./comprehensive.ps1
```

## LLM Setup

### llm.ps1

**Description**: Sets up a local lightweight language model (LLM) environment for personal use, configured to run efficiently on CPU using Ollama or similar tools.

**Usage**:
```powershell
./llm.ps1
```

## Proxy and Compliance

### caddy_reverse_proxy.ps1

**Description**: Configures a Caddy reverse proxy server to handle traffic management and SSL/TLS encryption.

**Usage**:
```powershell
./caddy_reverse_proxy.ps1
```

### compliance_gpo_audit.ps1

**Description**: Runs a Group Policy Object (GPO) compliance audit, ensuring the system adheres to the necessary security policies.

**Usage**:
```powershell
./compliance_gpo_audit.ps1
```

### csp_enforcement.ps1

**Description**: Enforces Content Security Policy (CSP) headers to limit resource loading and enhance security.

**Usage**:
```powershell
./csp_enforcement.ps1
```

## Data Loss Prevention (DLP)

### dlp.ps1

**Description**: Implements Data Loss Prevention strategies by scanning files for sensitive data patterns and configuring alerts.

**Usage**:
```powershell
./dlp.ps1
```

## Docker and Kubernetes

### dockerize.ps1

**Description**: Converts Windows services into Docker containers and automates their setup.

**Usage**:
```powershell
./dockerize.ps1
```

### k8_cluster.ps1

**Description**: Sets up a Kubernetes cluster for deploying containerized applications on Windows, focusing on scalability and resource efficiency.

**Usage**:
```powershell
./k8_cluster.ps1
```

## File Integrity Monitoring (FIM)

### fim.ps1

**Description**: Monitors files for changes and provides alerts on integrity violations, useful for detecting unauthorized modifications.

**Usage**:
```powershell
./fim.ps1
```

## Vulnerability Scanning and Security

### nessus.ps1

**Description**: Configures and initiates a Nessus vulnerability scan on Windows, identifying security risks.

**Usage**:
```powershell
./nessus.ps1
```

### ossec.ps1

**Description**: Installs and configures OSSEC as a host-based intrusion detection system on Windows.

**Usage**:
```powershell
./ossec.ps1
```

### owasp_zap.ps1

**Description**: Sets up and runs OWASP ZAP for web application vulnerability scanning.

**Usage**:
```powershell
./owasp_zap.ps1
```

## Personally Identifiable Information (PII)

### pii.ps1

**Description**: Scans for Personally Identifiable Information (PII) on the system and offers options to encrypt or redact sensitive data.

**Usage**:
```powershell
./pii.ps1
```

## Privileged Identity Management (PIM)

### pim.ps1

**Description**: Automates Privileged Identity Management by enforcing security policies and restricting access to high-privilege accounts.

**Usage**:
```powershell
./pim.ps1
```

## Digital Forensics and Incident Response (DFIR)

### velociraptor_dfir.ps1

**Description**: Deploys and configures Velociraptor for DFIR purposes, enabling data collection and analysis on Windows endpoints.

**Usage**:
```powershell
./velociraptor_dfir.ps1
```

## Web Application Firewall (WAF)

### waf.ps1

**Description**: Installs and configures a Web Application Firewall (WAF) to protect Windows-based web applications from attacks.

**Usage**:
```powershell
./waf.ps1
```

## Endpoint Monitoring and Security

### wazuh.ps1

**Description**: Sets up Wazuh for endpoint monitoring and alerting on Windows, integrating security analytics to detect threats.

**Usage**:
```powershell
./wazuh.ps1
```

## Backup Management

### web_backup.ps1

**Description**: Automates backup for web applications and configurations, creating secure copies for quick recovery.

**Usage**:
```powershell
./web_backup.ps1
```

## YARA Rule Setup

### YARA.md

**Description**: This file contains guidelines for setting up and utilizing YARA rules on Windows systems to detect malware and suspicious file patterns.

---

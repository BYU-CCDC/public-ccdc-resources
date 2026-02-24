## General Cybersecurity Frameworks/Comprehensive Docs

    Center for Internet Security/CIS Critical Security Controls: https://learn.cisecurity.org/CIS-Controls-v8-guide-pdf 
        Useful Controls/Sections
            Data Protection, Secure Configuration of Enterprise Assets and Software, Audit Log Management, Network Infrastructure Management, Network Monitoring and Defense, Security Awareness and Skills Training
    NIST SP 800-53 Security and Privacy Controls for Information Systems and Organizations: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf 
    Open Worldwide Application Security Project/OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/index.html 
        Includes Authentication, Content Security Policy, Kubernetes Security, Microservices Security, Multifactor Authentication, Password Storage, Threat Modeling, Vulnerability Disclosure, and many more...


## Incident Response Policy/Form

    National Institute of Standards and Technology/NIST Computer Security Incident Handling Guide: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r2.pdf
        See pages 21 to 42
        In table of contents, see section 3
    National Institute of Standards and Technology/NIST Cybersecurity Framework Quick Start Guide: https://www.nist.gov/cyberframework/getting-started/quick-start-guide


## Password Policy

    Center for Internet Security/CIS Benchmarks: https://downloads.cisecurity.org/#/ 
        For Windows rules:
            Go to "Operating Systems" -> "Microsoft Windows Desktop" -> "CIS Microsoft Windows 10 Stand-alone Benchmark v2.0.0" -> "Download PDF"
            See pages 32 to 48
            In table of contents, see section 1.1
        For Linux rules:
            Go to "Operating Systems" -> "Ubuntu Linux" -> "CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0" -> "Download PDF"
            See pages 686 to 700
            In table of contents, see section 5.4
    Microsoft - Password policy recommendations for Microsoft 365 passwords: https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations?view=o365-worldwide 


## PII Policy

    NIST SP 800-122 Guide to Protecting the Confidentiality of Personally Identifiable Information (PII): https://csrc.nist.gov/pubs/sp/800/122/final 
        Review the Executive Summary
        Section 3
        Section 4.1.1 - Policy and Procedure Creation
        Section 4.2.4 - Anonymizing PII
        pg. 1-35 hold most useful information
    US General Service Administration (GSA) Rules of Behavior for Handling Personally Identifiable Information (PII): https://www.gsa.gov/directives-library/gsa-rules-of-behavior-for-handling-personally-identifiable-information-pii-2
    Meeting Data Compliance with a Wave of New Privacy Regulations: GDPR, CCPA, PIPEDA, POPI, LGPD, HIPAA, PCI-DSS, and More: https://bluexp.netapp.com/blog/data-compliance-regulations-hipaa-gdpr-and-pci-dss 


## Containers

    NIST SP 800-190 Application Container Security Guide: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-190.pdf 
    Kubernetes Resources:
        Krzysztof Prancszk's Intro to K8s Security for Security Professionals: https://itnext.io/introduction-to-kubernetes-security-for-security-professionals-a61b424f7a2a 
        K8s Official Documentation (specifically Overview, K8s Capabilities): https://kubernetes.io/docs/concepts/overview/ 
        OWASP Kubernetes Top 10: https://owasp.org/www-project-kubernetes-top-ten/ 
            GitHub version: https://github.com/OWASP/www-project-kubernetes-top-ten 
        OWASP Kubernetes Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html 
    Docker Resources:
        OWASP Docker Top 10: https://owasp.org/www-project-docker-top-10/ 
            PDF version: https://github.com/OWASP/Docker-Security/blob/main/dist/owasp-docker-security.pdf 
        OWASP Docker Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html 
    Rancher Resources:
        Rancher Security Best Practices: https://ranchermanager.docs.rancher.com/reference-guides/rancher-security/rancher-security-best-practices 
        Rancher Best Practices Guide: https://ranchermanager.docs.rancher.com/reference-guides/best-practices 
        Rancher Security Advisories and CVEs: https://ranchermanager.docs.rancher.com/reference-guides/rancher-security/security-advisories-and-cves 


## Single Sign-On

    SANS Remote Access Policy Template: https://assets.contentstack.io/v3/assets/blt36c2e63521272fdc/bltc96a4c2cb0dcef43/636db4142e16be076e6e003f/Remote_Access_Policy.pdf 
    University of Dallas OIT SSO Policy: https://udallas.edu/offices/technology/_documents/Single%20Sign%20On%20Policy.pdf 


## Application Security

    OWASP Web Application Security Top 10: https://owasp.org/www-project-top-ten/ 
        OWASP App Sec Program Quick Start Guide: https://owasp.org/www-pdf-archive/OWASP_Quick_Start_Guide.pdf 
        OWASP Web Security Testing Guide: https://github.com/OWASP/wstg/tree/master/document 
    Snyk - 15 Application Security Best Practices: https://snyk.io/learn/application-security/best-practices/#app-sec-problems 
        Snyk - Complete Guide to Application Security: Tools, Trends & Best Practice: https://snyk.io/learn/application-security/#trends 
    C Security:
        https://w3.cs.jmu.edu/lam2mo/cs261_2023_08/c_funcs.html (see Unsafe Functions section)
        https://github.com/git/git/blob/master/banned.h (Git's list of banned C functions)
        https://libreswan.org/wiki/Discouraged_or_forbidden_C_functions (discouraged or forbidden C functions)
        https://stackoverflow.com/questions/9398046/useful-gcc-flags-to-improve-security-of-your-programs (gcc flags to enable ASLR, other memory defenses)
    NodeJS Security: 
        https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html (OWASP nodejs cheat sheet)
        https://nodejs.org/en/learn/getting-started/security-best-practices (nodejs security best practices)
        https://snyk.io/learn/nodejs-security-best-practice/ (snyk nodejs best practices)


## Usage of LLMs 

    Research
        "Taking Flight with Copilot: Early Insights and Opportunities of AI-Powered Pair-Programming Tools": https://dl.acm.org/doi/pdf/10.1145/3582083 
            Shortened version, news article: https://cacm.acm.org/magazines/2023/6/273221-taking-flight-with-copilot/fulltext 
    Kaspersky - How to use ChatGPT, Baard, and other AI securely: https://www.kaspersky.com/blog/how-to-use-chatgpt-ai-assistants-securely-2024/50562/ 
    Cloud Security Alliance - How ChatGPT Can Be Used in Cybersecurity: https://cloudsecurityalliance.org/blog/2023/06/16/how-chatgpt-can-be-used-in-cybersecurity 
    Microsoft - Staying ahead of threat actors in the age of AI: https://www.microsoft.com/en-us/security/blog/2024/02/14/staying-ahead-of-threat-actors-in-the-age-of-ai/ 


Third-Party/External Applications

    Wazuh: https://documentation.wazuh.com/current/index.html 
        Wazuh Installation Guide: https://documentation.wazuh.com/current/installation-guide/index.html 
        Wazuh Use Cases: https://documentation.wazuh.com/current/getting-started/use-cases/index.html 
    Rsyslog: https://www.rsyslog.com/doc/index.html 
        Rsyslog Installation Guide: https://www.rsyslog.com/doc/installation/index.html 
        Rsyslog Use Cases: https://www.rsyslog.com/doc/examples/index.html 
    Filebeat: https://www.elastic.co/guide/en/beats/filebeat/current/index.html 
        Winlogbeat/Sysmon Module: https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-module-sysmon.html 
        Sending Logs to ELK with Winlogbeat and Sysmon: https://burnhamforensics.com/2018/11/18/sending-logs-to-elk-with-winlogbeat-and-sysmon/ 
    AWS Network and Application Protection: https://aws.amazon.com/products/security/network-application-protection/ 
    AWS Amazon Elastic Container Service - Best Practices Guide: https://docs.aws.amazon.com/pdfs/AmazonECS/latest/bestpracticesguide/bestpracticesguide.pdf 
    Microsoft Security (general resources): https://learn.microsoft.com/en-us/security/ 
 


## OBS (Video Presentation)

    Tutorial: https://www.youtube.com/watch?v=nWbJJ4RnPx8/

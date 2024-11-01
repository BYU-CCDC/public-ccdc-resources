### 1. **OSSEC (ossec.ps1)**

OSSEC can natively use YARA rules by configuring it to scan files for YARA matches. This involves setting up YARA and linking it to OSSEC’s configuration.

#### ossec.ps1: Adding YARA Support

1. **Install YARA** on the system.
   ```powershell
   Invoke-WebRequest -Uri "https://github.com/VirusTotal/yara/releases/download/v4.1.3/yara-4.1.3.zip" -OutFile "$env:TEMP\yara.zip"
   Expand-Archive -Path "$env:TEMP\yara.zip" -DestinationPath "C:\YARA"
   ```

2. **Update OSSEC Configuration** (`ossec.conf`).
   - Add the YARA directory to the `ossec.conf` file in OSSEC’s installation directory.
   - Add a `localfile` section to configure OSSEC to scan specific files with YARA rules.

   ```powershell
   $configFilePath = "C:\Program Files (x86)\OSSEC Agent\ossec.conf"
   [xml]$config = Get-Content -Path $configFilePath
   $yaraNode = $config.CreateElement("localfile")
   $yaraNode.InnerXml = "<log_format>syslog</log_format><location>C:\path\to\scan\*</location><yara_file>C:\YARA\rules\myrules.yara</yara_file>"
   $config.ossec_config.AppendChild($yaraNode)
   $config.Save($configFilePath)
   ```

3. **Place YARA Rules** in the designated directory.
   - Create or download your YARA rules and save them to `C:\YARA\rules\myrules.yara`.

4. **Restart OSSEC** to apply the new configuration.
   ```powershell
   Restart-Service -Name "ossec_agent"
   ```

### 2. **Wazuh (wazuh.ps1)**

Wazuh, being based on OSSEC, also supports YARA rule integration. You can configure YARA rules in Wazuh similarly to OSSEC, but the configuration path may differ based on your Wazuh installation.

#### wazuh.ps1: Adding YARA Support

1. **Install YARA** on the Wazuh manager and agents.
   ```powershell
   Invoke-WebRequest -Uri "https://github.com/VirusTotal/yara/releases/download/v4.1.3/yara-4.1.3.zip" -OutFile "$env:TEMP\yara.zip"
   Expand-Archive -Path "$env:TEMP\yara.zip" -DestinationPath "C:\YARA"
   ```

2. **Configure Wazuh to Use YARA Rules**.
   - Modify the Wazuh `ossec.conf` file to add YARA rule monitoring.

   ```powershell
   $configFilePath = "C:\Program Files (x86)\Wazuh Agent\ossec.conf"
   [xml]$config = Get-Content -Path $configFilePath
   $yaraNode = $config.CreateElement("localfile")
   $yaraNode.InnerXml = "<log_format>syslog</log_format><location>C:\path\to\scan\*</location><yara_file>C:\YARA\rules\myrules.yara</yara_file>"
   $config.ossec_config.AppendChild($yaraNode)
   $config.Save($configFilePath)
   ```

3. **Deploy YARA Rules**.
   - Add or create your YARA rules in `C:\YARA\rules\myrules.yara`.

4. **Restart the Wazuh Agent** to apply the configuration.
   ```powershell
   Restart-Service -Name "wazuh_agent"
   ```

### 3. **Velociraptor (velociraptor_dfir.ps1)**

Velociraptor can use YARA rules for file scanning during threat hunting and incident response. This setup is slightly different since Velociraptor uses hunt artifacts to apply YARA rules.

#### velociraptor_dfir.ps1: Adding YARA Support

1. **Install YARA** on the Velociraptor server.
   ```powershell
   Invoke-WebRequest -Uri "https://github.com/VirusTotal/yara/releases/download/v4.1.3/yara-4.1.3.zip" -OutFile "$env:TEMP\yara.zip"
   Expand-Archive -Path "$env:TEMP\yara.zip" -DestinationPath "C:\YARA"
   ```

2. **Create a Velociraptor Artifact** that uses YARA.
   - Velociraptor uses YAML-based artifacts to define tasks. You’ll need to create a custom artifact that instructs Velociraptor to scan files with YARA.

   ```yaml
   name: Custom.YaraScan
   type: COMPOUND
   parameters:
     - name: yara_rules
       default: "C:\\YARA\\rules\\myrules.yara"
       type: string
       description: "Path to YARA rules file"
   sources:
     - precondition: True
       query: |
         LET yara_rules = parameters.yara_rules;
         SELECT collect(filename) FROM glob(glob="C:\\path\\to\\scan\\*") | foreach(filename, yara.scan(filename=filename, rules=yara_rules))
   ```

3. **Upload the Custom Artifact**.
   - Save the artifact YAML configuration above as `Custom.YaraScan.yaml` and upload it to Velociraptor’s server interface under the Artifacts section.

4. **Run the Artifact** on your endpoints.
   - Using the Velociraptor UI, select the `Custom.YaraScan` artifact, choose your endpoints, and execute the scan.

5. **Review Scan Results** in the Velociraptor UI.
   - The scan results will appear in the Velociraptor interface, detailing any YARA rule matches across the scanned files.

### Summary of Steps

- **OSSEC** and **Wazuh**: Modify the `ossec.conf` file to include a `localfile` section that points to the YARA rules and specify directories/files to scan.
- **Velociraptor**: Create and upload a custom artifact to scan files with YARA rules and execute it via the Velociraptor UI.

These configurations will enable YARA-based scanning in each tool, providing a powerful method to detect suspicious patterns and threats in monitored files. Let me know if you need further customization!
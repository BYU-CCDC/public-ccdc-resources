### 1. **OSSEC + YARA Integration**

OSSEC supports YARA through custom configuration, allowing it to scan files for specific patterns.

#### Step-by-Step Setup

1. **Install YARA**:
   - Install YARA on your OSSEC server:
     ```bash
     sudo apt update
     sudo apt install yara -y
     ```

2. **Download or Create YARA Rules**:
   - Place your YARA rules in a directory accessible to OSSEC, e.g., `/var/ossec/rules/yara_rules/`.

3. **Configure OSSEC to Use YARA**:
   - Edit the OSSEC configuration file (`/var/ossec/etc/ossec.conf`) to include a `<command>` section that runs YARA scans.
   - Example:
     ```xml
     <command>
         <name>yara-scan</name>
         <executable>yara</executable>
         <args>-r /var/ossec/rules/yara_rules/*.yara /var/ossec/logs/active-response.log</args>
     </command>
     ```
   - Add a `<localfile>` directive to specify which files/directories to monitor and run the YARA command on them.

4. **Create an OSSEC Active Response Script**:
   - OSSEC supports active responses for real-time reactions. Create a script to run YARA on specific files.
   - Example (`/var/ossec/active-response/bin/yara_scan.sh`):
     ```bash
     #!/bin/bash
     /usr/bin/yara -r /var/ossec/rules/yara_rules/*.yara "$1" >> /var/ossec/logs/yara_scan_results.log
     ```

5. **Test the Integration**:
   - Restart OSSEC:
     ```bash
     sudo systemctl restart ossec
     ```
   - Check logs (`/var/ossec/logs/yara_scan_results.log`) to see if YARA detections are logged.

---

### 2. **Wazuh + YARA Integration**

Wazuh, built on OSSEC, has native support for YARA and can be configured similarly to OSSEC, but Wazuh has additional features for managing YARA rules.

#### Step-by-Step Setup

1. **Install YARA**:
   - Install YARA on your Wazuh manager:
     ```bash
     sudo apt update
     sudo apt install yara -y
     ```

2. **Download or Add YARA Rules**:
   - Add YARA rules in `/var/ossec/ruleset/rules/extra/yara_rules/`.

3. **Enable YARA Scanning in Wazuh**:
   - Edit the Wazuh configuration file (`/var/ossec/etc/ossec.conf`) to include a YARA scan:
     ```xml
     <command>
         <name>yara-scan</name>
         <executable>yara</executable>
         <args>-r /var/ossec/ruleset/rules/extra/yara_rules/*.yara /var/ossec/logs/active-response.log</args>
     </command>
     ```

4. **Add a Custom Decoder**:
   - You may add a custom decoder in Wazuh if you want specific handling of YARA alerts.
   - Example (`/var/ossec/etc/decoders/yara_decoder.xml`):
     ```xml
     <decoder name="yara-decoder">
         <regex>.*YARA alert.*</regex>
         <order>command</order>
     </decoder>
     ```

5. **Monitor Specific Directories for YARA Scans**:
   - In `ossec.conf`, specify which directories to monitor for YARA scanning.
   - Example:
     ```xml
     <localfile>
         <location>/path/to/monitor/</location>
         <command>yara-scan</command>
     </localfile>
     ```

6. **Restart Wazuh**:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

7. **Review YARA Alerts**:
   - Wazuh logs YARA findings in the agent logs or Wazuh dashboard (if configured).

---

### 3. **Velociraptor + YARA Integration**

Velociraptor allows YARA integration for endpoint detection, scanning files with YARA rules on demand or as scheduled queries.

#### Step-by-Step Setup

1. **Install YARA**:
   - Install YARA on the Velociraptor server (optional for client-side only).
   - For each endpoint, ensure YARA is accessible.

2. **Upload YARA Rules to Velociraptor**:
   - In the Velociraptor Web UI, go to **"Files"** > **"Upload"** to upload YARA rules. You can store these in the `/etc/velociraptor/yara_rules/` directory on the Velociraptor server if you manage it outside the Web UI.

3. **Create a YARA Hunt in Velociraptor**:
   - In the Web UI, go to **"Hunt Manager"** > **"Create New Hunt"**.
   - Select **"Artifact"** > Choose `Generic.YaraProcessScan` or `Generic.YaraFileScan`:
     - **`Generic.YaraProcessScan`**: Scans running processes for memory-based YARA signatures.
     - **`Generic.YaraFileScan`**: Scans specific files or directories for file-based YARA rules.
   - Configure the artifact by specifying the path to your YARA rules and the target directories or process IDs.

4. **Define Hunt Parameters**:
   - Configure the hunt to use the uploaded YARA rules by specifying the path or selecting them from the repository.
   - Set the target files or directories to scan.

5. **Deploy the Hunt**:
   - Launch the hunt and select the clients (endpoints) to apply it to.
   - Monitor hunt progress in the **"Hunt Manager"**.

6. **Review Results**:
   - Once complete, check the hunt results for YARA matches. Velociraptor will log any detections in the hunt results, accessible in the Web UI.

---

### Summary

- **OSSEC and Wazuh**: Both integrate with YARA similarly by adding YARA as a command in the configuration file and targeting specific files/directories for monitoring. Wazuh has additional support for decoders and custom rules.
- **Velociraptor**: Offers YARA scanning as part of its hunting capabilities, with artifacts specifically designed for both file and process memory scanning using YARA.

These setups will enable each tool to leverage YARA rules for detecting malware and other indicators of compromise based on pattern matching.
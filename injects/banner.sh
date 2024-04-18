#!/bin/bash

# Login Banner Installation Script
# Usage: sudo bash banner.sh

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root. Use sudo !!"
  exit 1
fi

# Define the login banner text
BANNER_TEXT="******** WARNING ********
This system is the property of a private organization and is for authorized use only. By accessing this system, users agree to comply with the company’s Acceptable Use Policy.

All activities on this system may be monitored, recorded, and disclosed to authorized personnel for security purposes. There is no expectation of privacy while using this system. 

Unauthorized or improper use may result in disciplinary action or legal penalties. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use.

**************************"

# Define the paths to possible login banner files (linux variants)
BANNER_FILES=("/etc/issue" "/etc/motd" "/etc/issue.net" "/etc/login.warn")

# Backup the original login banner file(s)
for FILE in "${BANNER_FILES[@]}"; do
    if [ -e "$FILE" ]; then
        cp "$FILE" "$FILE.bak"
    fi
done

# Write the new login banner text to the available banner file(s)
for FILE in "${BANNER_FILES[@]}"; do
    echo "$BANNER_TEXT" > "$FILE"
done

echo "Login banner installed successfully."

# May need to edit #Banner in /etc/ssh/sshd_config to point to /etc/issue.net or /etc/login.warn
# eg: Banner /etc/login.warn
# Then restart sshd service
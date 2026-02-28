#!/bin/sh

sep () {
    echo "======================================================================================================="
}

dash_sep () {
    echo "-------------------------------------------------------------------------------------------------------"
}

command_exists() {
  command -v "$1" > /dev/null 2>&1
}

if [ "$(id -u)" -ne 0 ]; then
    printf 'Must be run as root, exiting!\n'
    exit 1
fi

if ! command_exists awk; then
    echo "Command awk not found. Install and try again."
    exit 1
fi
sep
echo "Hardening SSH keys..."
sep

# Update permissions for root's SSH keys
if [ -d "/root/.ssh" ]; then
    for file in "/root/.ssh/id_"*; do
        [ -f "$file" ] && chmod 600 "$file" && echo "Found and changed $file." 2>/dev/null || echo "$file not found for root."
    done
    echo "[+] All root id keys locked down."
    dash_sep
else
    echo "[-] SSH directory not found for root."
    dash_sep
fi

awk -F: '($3 >= 1000) && $1 != "nobody" {print $1}' /etc/passwd | while read -r user; do
    if [ -d "/home/$user/.ssh" ]; then
	for file in "/home/$user/.ssh/id_"*; do
            [ -f "$file" ] && chmod 600 "$file" && echo "Found and changed $file." 2>/dev/null || echo "$file not found for user $user."
        done
        echo "[+] All id keys for user $user locked down."
    	dash_sep
    else
	
        echo "[-] SSH directory not found for user $user."
	dash_sep
    fi
done

echo "...SSH keys that were found have updated permissions."


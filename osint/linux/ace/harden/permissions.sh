# set standard permissions
chown root:root /etc/shadow
chown root:root /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/passwd

# Search for SUID binaries
echo "[+] SUID binaries:"
find / -perm -4000 2>/dev/null

# Search for world-writeable files
echo "[+] 777 files:"
find / -maxdepth 3 -type d -perm -777 2>/dev/null

# Check for caps, facls
echo "[+] Files with capabilities:"
getcap -r / 2>/dev/null

echo "[+] Files with extended ACLs in critical directories:"
getfacl -sR /etc/ /usr/ /root/

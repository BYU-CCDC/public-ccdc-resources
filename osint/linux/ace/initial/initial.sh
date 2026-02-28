#/usr/bin/env bash
#Credits to UCI

HOSTNAME=$(hostname || cat /etc/hostname)
echo -e "HOST: $HOSTNAME"
echo "------------------"

if [ "$#" -lt 1 ]; then
    if [ -n "$AAA" ]; then
        backup_dir="$AAA"
    else
        echo "Usage: $0 <backup_path>"
        echo "Alternatively, set environment variable AAA."
        exit 1
    fi
else
    backup_dir="$1"
fi

if [ -n "$2" ]; then 
    quiet=true
elif [ -n "$BBB" ]; then
    quiet=true
else
    quiet=false
fi

echo_if_not_quiet () {
    if [ "$quiet" = false ]; then
        echo "$1"
    fi
}


sep () {
    echo_if_not_quiet "======================================================================================================="
}

dash_sep () {
    echo_if_not_quiet "-------------------------------------------------------------------------------------------------------"
}


echo_if_not_quiet "Commencing General Backup"
sep
# Ensure the backup directory exists
mkdir -p "$backup_dir" && echo_if_not_quiet "Backup directory created at $backup_dir"
chmod 600 "$backup_dir"
sep

echo_if_not_quiet "Default Firewall Backups"
dash_sep
firewall_backup_dir=$backup_dir/firewall_rules
mkdir -p $firewall_backup_dir && echo_if_not_quiet "Firewall backup directory created at $firewall_backup_dir"
chmod 600 "$firewall_backup_dir"
# Backup iptables rules
if command -v iptables-save >/dev/null 2>&1; then
    echo_if_not_quiet "Backing up iptables rules..."
    iptables-save > "$firewall_backup_dir/iptables_rules.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$firewall_backup_dir/iptables_rules.bak"
        echo_if_not_quiet "Done backing up iptables rules."
    else
        echo "[!] Error: Failed to create backup for iptables rules."
    fi
else
    echo_if_not_quiet "[-] iptables-save command not found. Skipping iptables backup."
fi

# Backup ufw rules
if command -v ufw >/dev/null 2>&1; then
    echo_if_not_quiet "Backing up ufw rules..."
    ufw status numbered > "$firewall_backup_dir/ufw_rules.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$firewall_backup_dir/ufw_rules.bak"
        echo_if_not_quiet "Done backing up ufw rules."
    else
        echo "[!] Error: Failed to create backup for ufw rules."
    fi
else
    echo_if_not_quiet "[-] ufw command not found. Skipping ufw backup."
fi

# Backup nftables rules
if command -v nft >/dev/null 2>&1; then
    echo_if_not_quiet "Backing up nftables rules..."
    nft list ruleset > "$firewall_backup_dir/nftables_rules.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$firewall_backup_dir/nftables_rules.bak"
        echo_if_not_quiet "Done backing up nftables rules."
    else
        echo "[!] Error: Failed to create backup for nftables rules."
    fi
else
    echo_if_not_quiet "[-] nft command not found. Skipping nftables backup."
fi

# Backup firewalld rules
if command -v firewall-cmd >/dev/null 2>&1; then
    echo_if_not_quiet "Backing up firewalld rules..."
    firewall-cmd --list-all > "$firewall_backup_dir/firewalld_rules.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$firewall_backup_dir/firewalld_rules.bak"
        echo_if_not_quiet "Done backing up firewalld rules."
    else
        echo "[!] Error: Failed to create backup for firewalld rules."
    fi
else
    echo_if_not_quiet "[-] firewall-cmd command not found. Skipping firewalld backup."
fi


# Backup /etc/profile
if [ -f "/etc/profile" ]; then
    echo_if_not_quiet "Backing up /etc/profile..."
    cp /etc/profile "$backup_dir/etc_profile.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$backup_dir/etc_profile.bak"
        echo_if_not_quiet "Done backing up /etc/profile."
    else
        echo "[!] Error: Failed to create backup for /etc/profile."
        exit 1
    fi
else
    echo_if_not_quiet "[-] /etc/profile not found."
fi
sep

# Backup /etc/profile.d if it is non-empty
profile_d_dir="/etc/profile.d"
if [ -d "$profile_d_dir" ] && [ "$(ls -A "$profile_d_dir")" ]; then
    echo_if_not_quiet "Backing up $profile_d_dir..."
    tar -czf "$backup_dir/etc_profile.d.tar.gz" -C /etc profile.d
    if [ $? -eq 0 ]; then
        chmod 600 "$backup_dir/etc_profile.d.tar.gz"
        echo_if_not_quiet "Done backing up $profile_d_dir."
    else
        echo "[!] Error: Failed to create backup for $profile_d_dir."
        exit 1
    fi
else
    echo_if_not_quiet "[-] $profile_d_dir is empty or not found. Skipping backup."
fi
sep

# backup /etc/pam.d if it is non-empty
pam_d_dir="/etc/pam.d"
if [ -d "$pam_d_dir" ] && [ "$(ls -A "$pam_d_dir")" ]; then
    echo_if_not_quiet "Backing up $pam_d_dir..."
    tar -czf "$backup_dir/etc_pam.d.tar.gz" -C /etc pam.d
    if [ $? -eq 0 ]; then
        chmod 600 "$backup_dir/etc_pam.d.tar.gz"
        echo_if_not_quiet "Done backing up $pam_d_dir."
    else
        echo "[!] Error: Failed to create backup for $pam_d_dir."
        exit 1
    fi
else
    echo_if_not_quiet "[-] $pam_d_dir is empty or not found. Skipping backup."
fi

# Backup current user's .profile
user_profile="$HOME/.profile"
if [ -f "$user_profile" ]; then
    echo_if_not_quiet "Backing up $user_profile..."
    cp "$user_profile" "$backup_dir/user_profile.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$backup_dir/user_profile.bak"
        echo_if_not_quiet "Done backing up $user_profile."
    else
        echo "[!] Error: Failed to create backup for $user_profile."
        exit 1
    fi
else
    echo_if_not_quiet "[-] $user_profile not found."
fi
sep

# Backup /etc/passwd
if [ -f "/etc/passwd" ]; then
    echo_if_not_quiet "Backing up /etc/passwd..."
    cp /etc/passwd "$backup_dir/passwd.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$backup_dir/passwd.bak"
        echo_if_not_quiet "Done backing up /etc/passwd."
    else
        echo "[!] Error: Failed to create backup for /etc/passwd."
    fi
else
    echo_if_not_quiet "[!] Error: /etc/passwd not found."
fi
sep

# Backup aliases from .bash_aliases (assuming Bash)
if [ -f "$HOME/.bash_aliases" ]; then
    echo_if_not_quiet "Backing up aliases from .bash_aliases..."
    cp "$HOME/.bash_aliases" "$backup_dir/bash_aliases.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$backup_dir/bash_aliases.bak"
        echo_if_not_quiet "Done backing up aliases from .bash_aliases."
    else
        echo "[!] Error: Failed to create backup for .bash_aliases."
    fi
else
    echo_if_not_quiet "[-] .bash_aliases not found."
fi
sep

# Backup entire .bashrc (assuming Bash)
if [ -f "$HOME/.bashrc" ]; then
    echo_if_not_quiet "Backing up entire .bashrc..."
    cp "$HOME/.bashrc" "$backup_dir/bashrc.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$backup_dir/bashrc.bak"
        echo_if_not_quiet "Done backing up entire .bashrc."
    else
        echo "[!] Error: Failed to create backup for .bashrc."
    fi
else
    echo_if_not_quiet "[-] Error: .bashrc not found."
fi
sep

# Backup aliases from .bashrc (assuming Bash)
if [ -f "$HOME/.bashrc" ]; then
    echo_if_not_quiet "Checking .bashrc for aliases..."
    grep -E '^\s*alias ' "$HOME/.bashrc" | sed 's/^\s*//' > "$backup_dir/bashrc_aliases.bak"
    if [ $? -eq 0 ]; then
        chmod 600 "$backup_dir/bashrc_aliases.bak"
        echo_if_not_quiet "Done backing up aliases from .bashrc."
    else
        echo_if_not_quiet "No aliases found in .bashrc."
    fi
else
    echo_if_not_quiet "[-] Error: .bashrc not found."
fi
sep

# Backup environment variables
echo_if_not_quiet "Backing up environment variables..."
env > "$backup_dir/environment_variables.bak"
if [ $? -eq 0 ]; then
    chmod 600 "$backup_dir/environment_variables.bak"
    echo_if_not_quiet "Done backing up environment variables."
else
    echo "[!] Error: Failed to create backup for environment variables."
fi
sep

# Backup PATH
echo_if_not_quiet "Backing up PATH..."
echo_if_not_quiet "$PATH" > "$backup_dir/path.bak"
if [ $? -eq 0 ]; then
    chmod 600 "$backup_dir/path.bak"
    echo_if_not_quiet "Done backing up PATH."
else
    echo "[!] Error: Failed to create backup for PATH."
fi
sep

echo_if_not_quiet "Baselining network, kernel mods and processes..."

mkdir "$backup_dir/baseline"


lsmod > "$backup_dir/baseline/kmods"
ps auxf > "$backup_dir/baseline/processes"

command_exists() {
    command -v "$1" > /dev/null 2>&1
}
if command_exists ss; then
    ss -plunt > "$backup_dir/baseline/listening"
    ss -peunt > "$backup_dir/baseline/established"
elif command_exists sockstat; then
    sockstat -4l > "$backup_dir/baseline/listening"
    sockstat -4c > "$backup_dir/baseline/connected"
else
    netstat -an | grep LISTEN > "$backup_dir/baseline/listening"
fi
# netstat -plt > "$backup_dir/baseline/listening"
# netstat -pat | grep ESTABLISHED > "$backup_dir/baseline/listening"
# netstat -a | grep LISTEN > "$backup_dir/baseline/listening"

echo_if_not_quiet "Done baselining the system at $backup_dir/baseline."
sep

echo "General backup finished. Find files in $backup_dir"




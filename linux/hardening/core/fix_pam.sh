#!/usr/bin/env bash

function fix_pam {
    print_banner "Fixing PAM Configuration and Enforcing Password Policies"

    # Temporarily set iptables OUTPUT policy to ACCEPT.
    local ipt
    ipt=$(command -v iptables || command -v /sbin/iptables || command -v /usr/sbin/iptables)
    sudo "$ipt" -P OUTPUT ACCEPT

    if grep -qi 'debian\|ubuntu' /etc/os-release; then
        log_info "Detected Debian/Ubuntu system; configuring PAM password policies."

        # Install libpam-pwquality if not already installed.
        sudo apt-get install -y libpam-pwquality

        # Update /etc/pam.d/common-password.
        local common_pass="/etc/pam.d/common-password"
        if [ -f "$common_pass" ]; then
            # Remove any existing password policy options.
            sudo sed -i 's/ minlen=[0-9]\+//g' "$common_pass"
            sudo sed -i 's/ retry=[0-9]\+//g' "$common_pass"
            sudo sed -i 's/ dcredit=[-0-9]\+//g' "$common_pass"
            sudo sed -i 's/ ucredit=[-0-9]\+//g' "$common_pass"
            sudo sed -i 's/ lcredit=[-0-9]\+//g' "$common_pass"
            sudo sed -i 's/ ocredit=[-0-9]\+//g' "$common_pass"
            sudo sed -i 's/ remember=[0-9]\+//g' "$common_pass"
            # Append the desired settings.
            sudo sed -i '/^password.*pam_unix\.so/ s/$/ minlen=12 retry=5 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 remember=5 sha512/' "$common_pass"
            log_info "Updated $common_pass with policy settings."
        else
            log_error "$common_pass not found."
        fi

        # Update /etc/login.defs for password aging.
        local login_defs="/etc/login.defs"
        if [ -f "$login_defs" ]; then
            sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   99999/' "$login_defs"
            sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   2/' "$login_defs"
            sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   10/' "$login_defs"
            log_info "Updated $login_defs with login definitions."
        else
            log_error "$login_defs not found."
        fi

    elif command -v yum >/dev/null; then
        if command -v authconfig >/dev/null; then
            sudo authconfig --updateall
            sudo yum -y reinstall pam
        else
            log_error "No authconfig found; cannot fix PAM on this system."
        fi
    elif command -v apk >/dev/null; then
        if [ -d /etc/pam.d ]; then
            sudo apk fix --purge linux-pam
            for file in $(find /etc/pam.d -name "*.apk-new" 2>/dev/null); do
                sudo mv "$file" "$(echo $file | sed 's/.apk-new//g')"
            done
        else
            log_error "PAM is not installed."
        fi
    elif command -v pacman >/dev/null; then
        if [ -n "$BACKUPDIR" ]; then
            sudo mv /etc/pam.d /etc/pam.d.backup
            sudo cp -R "$BACKUPDIR" /etc/pam.d
        else
            log_error "No backup directory provided for PAM configs."
        fi
        sudo pacman -S pam --noconfirm
    else
        log_error "Unknown OS; PAM configuration not fixed."
    fi

    # Restore iptables OUTPUT policy to DROP.
    sudo "$ipt" -P OUTPUT DROP
}

function install_modsecurity_manual {
    # Only for Debian/Ubuntu systems
    if ! command -v apt-get &>/dev/null; then
        log_error "Manual ModSecurity installation is only implemented for Debian-based systems."
        return 1
    fi

    log_info "Updating package list..."
    sudo apt-get update -qq
    log_info "Installing libapache2-mod-security2 and modsecurity-crs..."
    sudo apt-get install -y libapache2-mod-security2 modsecurity-crs

    # Locate the recommended configuration file
    local recommended_conf=""
    for candidate in /etc/modsecurity/modsecurity.conf-recommended \
                      /usr/share/doc/libapache2-mod-security2/examples/modsecurity.conf-recommended \
                      /usr/share/modsecurity-crs/modsecurity.conf-recommended; do
        if [ -f "$candidate" ]; then
            recommended_conf="$candidate"
            break
        fi
    done

    if [ -z "$recommended_conf" ]; then
        log_error "ERROR: Could not locate modsecurity.conf-recommended."
        echo "    Please locate it manually and copy it to /etc/modsecurity/modsecurity.conf"
        return 1
    fi

    log_info "Found recommended config at: $recommended_conf"
    sudo mkdir -p /etc/modsecurity
    log_info "Copying configuration to /etc/modsecurity/modsecurity.conf"
    sudo cp "$recommended_conf" /etc/modsecurity/modsecurity.conf
    if [ $? -ne 0 ]; then
        log_error "ERROR: Failed to copy the configuration file."
        return 1
    fi

    log_info "Enabling ModSecurity (setting SecRuleEngine to On)..."
    sudo sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
    if [ $? -ne 0 ]; then
        log_error "ERROR: Failed to modify modsecurity configuration."
        return 1
    fi

    # Set proper ownership and permissions
    sudo chown root:root /etc/modsecurity/modsecurity.conf
    sudo chmod 644 /etc/modsecurity/modsecurity.conf

    # Ensure audit log exists with correct permissions
    local audit_log="/var/log/apache2/modsec_audit.log"
    sudo mkdir -p /var/log/apache2
    if [ ! -f "$audit_log" ]; then
        sudo touch "$audit_log"
    fi
    sudo chown www-data:www-data "$audit_log"
    sudo chmod 640 "$audit_log"

    # Enable the security2 module
    if command -v a2enmod &>/dev/null; then
        log_info "Enabling security2 module..."
        sudo a2enmod security2
    fi

    # Restart Apache (check for apache2 or httpd)
    if systemctl is-active apache2 &>/dev/null; then
        log_info "Restarting apache2..."
        sudo systemctl restart apache2
    elif systemctl is-active httpd &>/dev/null; then
        log_info "Restarting httpd..."
        sudo systemctl restart httpd
    else
        log_warning "WARNING: Apache service not detected as active. Please restart manually."
    fi

    log_info "Manual ModSecurity installation completed successfully."
}

function configure_modsecurity {
    print_banner "Configuring ModSecurity (Block Mode) with a Single CRS Setup File"

    # 1) Ensure /etc/modsecurity directory exists
    if [ ! -d "/etc/modsecurity" ]; then
        sudo mkdir -p /etc/modsecurity
    fi

    # 2) Copy modsecurity.conf-recommended -> modsecurity.conf (set SecRuleEngine On)
    local recommended_conf="/etc/modsecurity/modsecurity.conf-recommended"
    local main_conf="/etc/modsecurity/modsecurity.conf"
    if [ -f "$recommended_conf" ]; then
        sudo cp "$recommended_conf" "$main_conf"
        sudo sed -i 's/^SecRuleEngine\s\+DetectionOnly/SecRuleEngine On/i' "$main_conf"
    else
        log_error "ERROR: $recommended_conf not found! Cannot configure ModSecurity."
        return 1
    fi

    # Fix ownership/permissions
    sudo chown root:root "$main_conf"
    sudo chmod 644 "$main_conf"

    # 3) Ensure the audit log file is in place
    if [ ! -d "/var/log/apache2" ]; then
        sudo mkdir -p /var/log/apache2
    fi
    local audit_log="/var/log/apache2/modsec_audit.log"
    if [ ! -f "$audit_log" ]; then
        sudo touch "$audit_log"
    fi
    sudo chown www-data:www-data "$audit_log"
    sudo chmod 640 "$audit_log"

    # 4) Download or confirm OWASP CRS
    #    (Adjust path if you prefer to store it in /etc/modsecurity/crs manually.)
    if [ ! -d "/usr/share/owasp-modsecurity-crs" ]; then
        log_info "OWASP CRS not found; cloning from GitHub..."
        if command -v git &>/dev/null; then
            sudo git clone https://github.com/coreruleset/coreruleset.git /usr/share/owasp-modsecurity-crs
            if [ $? -ne 0 ]; then
                log_error "ERROR: Failed to clone OWASP CRS."
                return 1
            fi
        else
            log_error "ERROR: git is not installed. Install git and try again."
            return 1
        fi
    else
        log_info "OWASP CRS found; you may pull updates if needed."
    fi

    # 5) If you keep your crs-setup.conf in /etc/modsecurity/crs/, ensure it’s there:
    if [ ! -d "/etc/modsecurity/crs" ]; then
        sudo mkdir -p /etc/modsecurity/crs
    fi
    # If you want to copy crs-setup.conf.example -> /etc/modsecurity/crs/crs-setup.conf
    if [ -f "/usr/share/owasp-modsecurity-crs/crs-setup.conf.example" ] && [ ! -f "/etc/modsecurity/crs/crs-setup.conf" ]; then
        sudo cp /usr/share/owasp-modsecurity-crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf
    fi

    # 6) Reconfigure Apache’s security2.conf
    local sec_conf="/etc/apache2/mods-enabled/security2.conf"
    local backup_sec_conf="/etc/apache2/mods-enabled/security2.conf.bak"

    if [ -f "$sec_conf" ]; then
        # Backup first
        sudo cp "$sec_conf" "$backup_sec_conf"

        # Comment out any line referencing /usr/share/modsecurity-crs
        sudo sed -i 's|^\([ \t]*Include.*usr/share/modsecurity-crs.*\)|#\1|' "$sec_conf"

        # Optionally comment out "IncludeOptional" lines referencing modsecurity-crs:
        sudo sed -i 's|^\([ \t]*IncludeOptional.*usr/share/modsecurity-crs.*\)|#\1|' "$sec_conf"

        # Ensure our correct lines are appended:
        # (1) "Include /etc/modsecurity/crs/crs-setup.conf"
        grep -q "Include /etc/modsecurity/crs/crs-setup.conf" "$sec_conf" || \
            echo "Include /etc/modsecurity/crs/crs-setup.conf" | sudo tee -a "$sec_conf" >/dev/null

        # (2) "Include /usr/share/modsecurity-crs/rules/*.conf" (assuming you place rules here)
        grep -q "Include /usr/share/modsecurity-crs/rules/*.conf" "$sec_conf" || \
            echo "Include /usr/share/modsecurity-crs/rules/*.conf" | sudo tee -a "$sec_conf" >/dev/null
    else
        log_error "ERROR: $sec_conf not found. ModSecurity might not be enabled with 'a2enmod security2'."
        return 1
    fi

    # 7) Test config before restarting
    log_info "Testing Apache config..."
    if ! sudo apachectl -t; then
        log_error "ERROR: Apache config test failed. Reverting changes..."
        [ -f "$backup_sec_conf" ] && sudo mv "$backup_sec_conf" "$sec_conf"
        return 1
    fi

    # 8) If all good, restart
    log_info "Config OK. Restarting Apache..."
    if ! sudo systemctl restart apache2; then
        log_error "ERROR: Apache restart failed. Reverting security2.conf..."
        [ -f "$backup_sec_conf" ] && sudo mv "$backup_sec_conf" "$sec_conf"
        return 1
    fi

    log_info "ModSecurity configured in blocking mode; /etc/modsecurity/crs/crs-setup.conf is used."
    log_info "Any old /usr/share/... references have been commented out in security2.conf."

    # 9) Append 'SecRuleEngine On' in the Apache default site configuration file
    local default_site="/etc/apache2/sites-enabled/000-default.conf"
    if [ -f "$default_site" ]; then
        sudo sed -i '/CustomLog ${APACHE_LOG_DIR}\/access.log combined/ a \
        SecRuleEngine On
' "$default_site"
        log_info "Inserted 'SecRuleEngine On' into $default_site"
    else
        log_error "ERROR: $default_site not found!"
        return 1
    fi

    return 0
}

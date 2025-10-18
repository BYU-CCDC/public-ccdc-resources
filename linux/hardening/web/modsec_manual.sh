#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
COMMON_LIB="$SCRIPT_DIR/../lib/common.sh"

if ! declare -F log_info >/dev/null 2>&1 && [ -f "$COMMON_LIB" ]; then
    # shellcheck source=/dev/null
    source "$COMMON_LIB"
fi

if ! declare -F log_info >/dev/null 2>&1; then
    LOG_LEVEL="${LOG_LEVEL:-INFO}"
    NC='\033[0m'
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    ORANGE='\033[38;5;208m'
    AQUA='\033[38;5;45m'

    _modsec_emit() {
        local level="$1"
        local color="$2"
        shift 2 || true
        printf '%b[%s]%b %s\n' "$color" "$level" "$NC" "$*"
    }

    log_info() { _modsec_emit "INFO" "$AQUA" "$@"; }
    log_success() { _modsec_emit "SUCCESS" "$GREEN" "$@"; }
    log_warning() { _modsec_emit "WARNING" "$ORANGE" "$@"; }
    log_error() { _modsec_emit "ERROR" "$RED" "$@"; }
fi

ensure_directive_line() {
    local file="$1"
    local directive="$2"
    local replacement="$3"

    if sudo grep -Eq "^\\s*${directive}\\b" "$file"; then
        sudo sed -Ei "s|^\\s*${directive}\\b.*|${replacement}|" "$file"
    else
        echo "$replacement" | sudo tee -a "$file" >/dev/null
    fi
}

harden_modsecurity_base() {
    local conf="$1"

    log_info "Applying opinionated ModSecurity base hardening to $conf"
    ensure_directive_line "$conf" "SecRequestBodyLimit" "SecRequestBodyLimit 13107200"
    ensure_directive_line "$conf" "SecRequestBodyNoFilesLimit" "SecRequestBodyNoFilesLimit 131072"
    ensure_directive_line "$conf" "SecRequestBodyInMemoryLimit" "SecRequestBodyInMemoryLimit 131072"
    ensure_directive_line "$conf" "SecRequestBodyLimitAction" "SecRequestBodyLimitAction Reject"
    ensure_directive_line "$conf" "SecRequestBodyAccess" "SecRequestBodyAccess On"
    ensure_directive_line "$conf" "SecResponseBodyAccess" "SecResponseBodyAccess Off"
    ensure_directive_line "$conf" "SecDefaultAction" "SecDefaultAction \"phase:1,deny,log,status:403\""
    ensure_directive_line "$conf" "SecPcreMatchLimit" "SecPcreMatchLimit 1000"
    ensure_directive_line "$conf" "SecPcreMatchLimitRecursion" "SecPcreMatchLimitRecursion 1000"
    ensure_directive_line "$conf" "SecAuditLogType" "SecAuditLogType Serial"
    ensure_directive_line "$conf" "SecAuditLogParts" "SecAuditLogParts ABCEFHJKZ"
    ensure_directive_line "$conf" "SecAuditEngine" "SecAuditEngine RelevantOnly"
    ensure_directive_line "$conf" "SecAuditLog" "SecAuditLog /var/log/apache2/modsec_audit.log"
    ensure_directive_line "$conf" "SecTmpDir" "SecTmpDir /var/cache/modsecurity/tmp"
    ensure_directive_line "$conf" "SecDataDir" "SecDataDir /var/cache/modsecurity/data"
}

refresh_crs_tuning_block() {
    local file="$1"
    local begin="# --- BEGIN CCDC Managed CRS Tuning ---"
    local end="# --- END CCDC Managed CRS Tuning ---"

    if sudo grep -q "$begin" "$file"; then
        sudo sed -i "/$begin/,/$end/d" "$file"
    fi

    cat <<'EOF' | sudo tee -a "$file" >/dev/null
# --- BEGIN CCDC Managed CRS Tuning ---
SecAction \
 "id:900100,\
  phase:1,\
  nolog,\
  pass,\
  t:none,\
  setvar:'tx.paranoia_level=2',\
  setvar:'tx.blocking_paranoia_level=2',\
  setvar:'tx.enforce_bodyproc_urlencoded=1',\
  setvar:'tx.inbound_anomaly_score_threshold=5',\
  setvar:'tx.outbound_anomaly_score_threshold=4',\
  setvar:'tx.allowed_methods=GET HEAD POST OPTIONS',\
  setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded|multipart/form-data|text/xml|application/json|application/xml|text/plain|image/png|image/jpeg|image/gif|',\
  setvar:'tx.allowed_request_content_type_charset=utf-8|iso-8859-1|',\
  setvar:'tx.restricted_extensions=.cmd .exe .com .bat .cgi .reg .dll .scr .pif .jar .jsp .asp .aspx .php .php3 .php4 .php5 .phtml .pl .py .rb .war',\
  setvar:'tx.restricted_headers=/proxy/ /if-modified-since/ /if-unmodified-since/ /if-match/ /if-none-match/ /referer/ /via/ /x-forwarded-for/',\
  setvar:'tx.dos_burst_time_slice=60',\
  setvar:'tx.dos_counter_threshold=75',\
  setvar:'tx.dos_block_timeout=600'"

SecRule REQUEST_METHOD "!^(?:GET|POST|HEAD|OPTIONS)$" \
 "id:1101100,\
  phase:1,\
  log,\
  deny,\
  status:405,\
  msg:'CCDC Hardening: HTTP method not allowed',\
  severity:WARNING"

SecRule REQUEST_HEADERS:User-Agent "^\s*$" \
 "id:1101110,\
  phase:1,\
  log,\
  deny,\
  status:403,\
  msg:'CCDC Hardening: Empty User-Agent blocked',\
  severity:WARNING"

SecRule REQUEST_HEADERS:Content-Length "@gt 0" \
 "id:1101120,\
  phase:1,\
  log,\
  deny,\
  status:400,\
  msg:'CCDC Hardening: Requests with a body must declare an allowed Content-Type',\
  chain"
    SecRule &REQUEST_HEADERS:Content-Type "@eq 0" "t:none"

SecRule REQUEST_HEADERS:Content-Type "!@rx ^(?:application|text|image|multipart)/" \
 "id:1101121,\
  phase:1,\
  log,\
  deny,\
  status:415,\
  msg:'CCDC Hardening: Unsupported Content-Type for request body',\
  severity:WARNING"
# --- END CCDC Managed CRS Tuning ---
EOF
}

ensure_crs_setup_profile() {
    local destination="/etc/modsecurity/crs/crs-setup.conf"
    local sources=(
        "/etc/modsecurity/crs/crs-setup.conf"
        "/usr/share/owasp-modsecurity-crs/crs-setup.conf.example"
        "/usr/share/modsecurity-crs/crs-setup.conf.example"
        "/usr/share/owasp-modsecurity-crs/crs-setup.conf"
        "/usr/share/modsecurity-crs/crs-setup.conf"
    )

    sudo mkdir -p "$(dirname "$destination")"

    if [ ! -f "$destination" ]; then
        local source=""
        for candidate in "${sources[@]}"; do
            if [ -f "$candidate" ]; then
                source="$candidate"
                break
            fi
        done

        if [ -n "$source" ]; then
            log_info "Populating CRS setup file from $source"
            sudo cp "$source" "$destination"
        else
            log_error "Unable to locate a CRS setup template. Install OWASP CRS before continuing."
            return 1
        fi
    else
        log_info "Existing CRS setup file detected at $destination"
    fi

    sudo chown root:root "$destination"
    sudo chmod 640 "$destination"
    refresh_crs_tuning_block "$destination"

    return 0
}

install_modsecurity_manual() {
    if ! command -v apt-get >/dev/null 2>&1; then
        log_error "Manual ModSecurity installation is only implemented for Debian-based systems."
        return 1
    fi

    log_info "Updating package list..."
    sudo apt-get update -qq
    log_info "Installing libapache2-mod-security2 and modsecurity-crs..."
    if ! sudo apt-get install -y libapache2-mod-security2 modsecurity-crs; then
        log_error "Failed to install required ModSecurity packages."
        return 1
    fi

    local recommended_conf=""
    local candidate
    for candidate in \
        /etc/modsecurity/modsecurity.conf-recommended \
        /usr/share/doc/libapache2-mod-security2/examples/modsecurity.conf-recommended \
        /usr/share/modsecurity-crs/modsecurity.conf-recommended; do
        if [ -f "$candidate" ]; then
            recommended_conf="$candidate"
            break
        fi
    done

    if [ -z "$recommended_conf" ]; then
        log_error "Could not locate modsecurity.conf-recommended. Please copy it manually to /etc/modsecurity/modsecurity.conf"
        return 1
    fi

    log_info "Found recommended config at: $recommended_conf"
    sudo mkdir -p /etc/modsecurity
    if ! sudo cp "$recommended_conf" /etc/modsecurity/modsecurity.conf; then
        log_error "Failed to copy the configuration file."
        return 1
    fi

    if ! sudo sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf; then
        log_error "Failed to enable blocking mode in /etc/modsecurity/modsecurity.conf"
        return 1
    fi

    sudo chown root:root /etc/modsecurity/modsecurity.conf
    sudo chmod 644 /etc/modsecurity/modsecurity.conf
    harden_modsecurity_base "/etc/modsecurity/modsecurity.conf"

    sudo mkdir -p /var/cache/modsecurity/tmp /var/cache/modsecurity/data
    sudo chown root:root /var/cache/modsecurity /var/cache/modsecurity/tmp /var/cache/modsecurity/data
    sudo chmod 750 /var/cache/modsecurity /var/cache/modsecurity/tmp /var/cache/modsecurity/data

    local audit_log="/var/log/apache2/modsec_audit.log"
    sudo mkdir -p /var/log/apache2
    if [ ! -f "$audit_log" ]; then
        sudo touch "$audit_log"
    fi
    sudo chown www-data:www-data "$audit_log"
    sudo chmod 640 "$audit_log"

    if ! ensure_crs_setup_profile; then
        log_error "CRS setup provisioning failed"
        return 1
    fi

    if command -v a2enmod >/dev/null 2>&1; then
        if sudo a2enmod security2 >/dev/null 2>&1; then
            log_info "Enabled Apache security2 module"
        else
            log_warning "security2 module enablement returned a non-zero status; continuing"
        fi
    fi

    local restart_cmd=""
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files apache2.service >/dev/null 2>&1; then
            restart_cmd="systemctl restart apache2"
        elif systemctl list-unit-files httpd.service >/dev/null 2>&1; then
            restart_cmd="systemctl restart httpd"
        fi
    fi

    if [ -z "$restart_cmd" ] && command -v service >/dev/null 2>&1; then
        if service apache2 status >/dev/null 2>&1; then
            restart_cmd="service apache2 restart"
        elif service httpd status >/dev/null 2>&1; then
            restart_cmd="service httpd restart"
        fi
    fi

    if [ -z "$restart_cmd" ]; then
        if command -v apachectl >/dev/null 2>&1; then
            restart_cmd="apachectl -k restart"
        elif command -v apache2ctl >/dev/null 2>&1; then
            restart_cmd="apache2ctl -k restart"
        fi
    fi

    if [ -n "$restart_cmd" ]; then
        log_info "Restarting Apache via: $restart_cmd"
        if ! sudo bash -c "$restart_cmd"; then
            log_warning "Apache restart command failed ($restart_cmd). Please restart manually."
        fi
    else
        log_warning "Apache service not detected as active. Please restart manually."
    fi

    log_info "Manual ModSecurity installation completed successfully."
}

configure_modsecurity() {
    print_banner "Configuring ModSecurity (Block Mode) with a Single CRS Setup File"

    sudo mkdir -p /etc/modsecurity

    local recommended_conf=""
    local main_conf="/etc/modsecurity/modsecurity.conf"
    local candidate
    for candidate in \
        /etc/modsecurity/modsecurity.conf-recommended \
        /usr/share/doc/libapache2-mod-security2/examples/modsecurity.conf-recommended \
        /usr/share/modsecurity-crs/modsecurity.conf-recommended \
        /usr/share/owasp-modsecurity-crs/modsecurity.conf-recommended; do
        if [ -f "$candidate" ]; then
            recommended_conf="$candidate"
            break
        fi
    done

    if [ -z "$recommended_conf" ]; then
        log_error "modsecurity.conf-recommended not found. Install ModSecurity packages first."
        return 1
    fi

    log_info "Using recommended ModSecurity config from $recommended_conf"
    sudo cp "$recommended_conf" "$main_conf"
    if ! sudo sed -Ei 's/^\s*SecRuleEngine\s+.*/SecRuleEngine On/I' "$main_conf"; then
        log_error "Failed to enable blocking mode in $main_conf"
        return 1
    fi
    if ! sudo grep -qE '^\s*SecRuleEngine\s+On' "$main_conf"; then
        log_error "SecRuleEngine On not detected in $main_conf after update"
        return 1
    fi
    log_success "SecRuleEngine enforced in $main_conf"

    sudo chown root:root "$main_conf"
    sudo chmod 644 "$main_conf"
    harden_modsecurity_base "$main_conf"

    sudo mkdir -p /var/log/apache2
    local audit_log="/var/log/apache2/modsec_audit.log"
    if [ ! -f "$audit_log" ]; then
        sudo touch "$audit_log"
    fi
    sudo chown www-data:www-data "$audit_log"
    sudo chmod 640 "$audit_log"

    sudo mkdir -p /var/cache/modsecurity/tmp /var/cache/modsecurity/data
    sudo chown root:root /var/cache/modsecurity /var/cache/modsecurity/tmp /var/cache/modsecurity/data
    sudo chmod 750 /var/cache/modsecurity /var/cache/modsecurity/tmp /var/cache/modsecurity/data

    local crs_repo="/usr/share/owasp-modsecurity-crs"
    if [ -d "$crs_repo/.git" ]; then
        log_info "Updating existing OWASP CRS repository at $crs_repo"
        if ! sudo git -C "$crs_repo" pull --ff-only; then
            log_warning "Unable to automatically update OWASP CRS; continuing with existing ruleset"
        fi
    elif [ -d "$crs_repo" ]; then
        log_info "OWASP CRS directory detected at $crs_repo"
    else
        log_info "OWASP CRS not found; cloning from GitHub (coreruleset/coreruleset)"
        if command -v git >/dev/null 2>&1; then
            if ! sudo git clone https://github.com/coreruleset/coreruleset.git "$crs_repo"; then
                log_error "Failed to clone OWASP CRS."
                return 1
            fi
        else
            log_error "git is not installed. Install git and try again."
            return 1
        fi
    fi

    if ! ensure_crs_setup_profile; then
        return 1
    fi

    local sec_conf="/etc/apache2/mods-enabled/security2.conf"
    local backup_sec_conf="/etc/apache2/mods-enabled/security2.conf.bak"

    if [ -f "$sec_conf" ]; then
        sudo cp "$sec_conf" "$backup_sec_conf"
        sudo sed -i 's|^\([ \t]*Include\(Optional\)\?.*modsecurity-crs.*\)|#\1|' "$sec_conf"
        sudo sed -i 's|^\([ \t]*Include\(Optional\)\?.*owasp-modsecurity-crs.*\)|#\1|' "$sec_conf"
        if ! grep -q "Include /etc/modsecurity/crs/crs-setup.conf" "$sec_conf"; then
            echo "Include /etc/modsecurity/crs/crs-setup.conf" | sudo tee -a "$sec_conf" >/dev/null
        fi
        if ! grep -q "Include /usr/share/owasp-modsecurity-crs/rules/*.conf" "$sec_conf"; then
            echo "Include /usr/share/owasp-modsecurity-crs/rules/*.conf" | sudo tee -a "$sec_conf" >/dev/null
        fi
        if ! grep -q "IncludeOptional /etc/modsecurity/crs/custom/*.conf" "$sec_conf"; then
            echo "IncludeOptional /etc/modsecurity/crs/custom/*.conf" | sudo tee -a "$sec_conf" >/dev/null
        fi
    else
        log_error "$sec_conf not found. ModSecurity might not be enabled with 'a2enmod security2'."
        return 1
    fi

    log_success "security2.conf updated to use CRS includes"

    local apachectl_cmd=""
    if command -v apachectl >/dev/null 2>&1; then
        apachectl_cmd="apachectl"
    elif command -v apache2ctl >/dev/null 2>&1; then
        apachectl_cmd="apache2ctl"
    fi

    if [ -n "$apachectl_cmd" ]; then
        log_info "Testing Apache config via $apachectl_cmd -t"
        if ! sudo "$apachectl_cmd" -t; then
            log_error "Apache config test failed. Reverting changes..."
            [ -f "$backup_sec_conf" ] && sudo mv "$backup_sec_conf" "$sec_conf"
            return 1
        fi
    else
        log_warning "apachectl not available; skipping automatic config test."
    fi

    local restart_cmd=""
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files apache2.service >/dev/null 2>&1; then
            restart_cmd="systemctl restart apache2"
        elif systemctl list-unit-files httpd.service >/dev/null 2>&1; then
            restart_cmd="systemctl restart httpd"
        fi
    fi

    if [ -z "$restart_cmd" ] && command -v service >/dev/null 2>&1; then
        if service apache2 status >/dev/null 2>&1; then
            restart_cmd="service apache2 restart"
        elif service httpd status >/dev/null 2>&1; then
            restart_cmd="service httpd restart"
        fi
    fi

    if [ -z "$restart_cmd" ]; then
        if command -v apachectl >/dev/null 2>&1; then
            restart_cmd="apachectl -k restart"
        elif command -v apache2ctl >/dev/null 2>&1; then
            restart_cmd="apache2ctl -k restart"
        fi
    fi

    if [ -n "$restart_cmd" ]; then
        log_info "Restarting Apache via: $restart_cmd"
        if ! sudo bash -c "$restart_cmd"; then
            log_error "Apache restart failed. Reverting security2.conf..."
            [ -f "$backup_sec_conf" ] && sudo mv "$backup_sec_conf" "$sec_conf"
            return 1
        fi
    else
        log_warning "No Apache restart command available; please restart manually to apply changes."
    fi

    local servername_conf="/etc/apache2/conf-available/servername.conf"
    if [ -d "/etc/apache2/conf-available" ] && [ ! -f "$servername_conf" ]; then
        echo "ServerName localhost" | sudo tee "$servername_conf" >/dev/null
        if command -v a2enconf >/dev/null 2>&1; then
            sudo a2enconf servername >/dev/null 2>&1 || true
        fi
        log_info "Registered default ServerName localhost to silence Apache warnings."
    fi

    log_success "ModSecurity configured in blocking mode with OWASP CRS"
    log_info "Main config: $main_conf"
    log_info "CRS setup: /etc/modsecurity/crs/crs-setup.conf"
    log_info "Rules include: /usr/share/owasp-modsecurity-crs/rules/*.conf"

    return 0
}

if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
    configure_modsecurity "$@"
fi
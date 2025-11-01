#!/usr/bin/env bash

WEB_SCANNER_LOG_DIR="/var/log/ccdc/web-scanners"
ZAP_INSTALL_DIR="/opt/owasp-zap"
ZAP_DOWNLOAD_URL="https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz"

ensure_web_scanner_dirs() {
    mkdir -p "$WEB_SCANNER_LOG_DIR"
}

install_nikto() {
    if command -v nikto >/dev/null 2>&1; then
        return 0
    fi

    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    case "$pm" in
        apt-get)
            sudo apt-get install -y nikto
            ;;
        dnf)
            sudo dnf install -y nikto
            ;;
        yum)
            sudo yum install -y nikto
            ;;
        zypper)
            sudo zypper install -y nikto
            ;;
        *)
            log_warning "Unable to install Nikto automatically"
            return 1
            ;;
    esac
}

install_gobuster() {
    if command -v gobuster >/dev/null 2>&1; then
        return 0
    fi

    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    case "$pm" in
        apt-get)
            sudo apt-get install -y gobuster
            ;;
        dnf)
            sudo dnf install -y gobuster
            ;;
        yum)
            sudo yum install -y gobuster
            ;;
        zypper)
            sudo zypper install -y gobuster
            ;;
        *)
            log_warning "Unable to install Gobuster automatically"
            return 1
            ;;
    esac
}

install_zap() {
    if command -v zap.sh >/dev/null 2>&1 || [ -x "$ZAP_INSTALL_DIR/zap.sh" ]; then
        return 0
    fi

    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    case "$pm" in
        apt-get)
            if sudo apt-get install -y zaproxy >/dev/null 2>&1; then
                return 0
            fi
            ;;
        dnf)
            if sudo dnf install -y zaproxy >/dev/null 2>&1; then
                return 0
            fi
            ;;
        yum)
            if sudo yum install -y zaproxy >/dev/null 2>&1; then
                return 0
            fi
            ;;
        zypper)
            if sudo zypper install -y zaproxy >/dev/null 2>&1; then
                return 0
            fi
            ;;
    esac

    if ! command -v curl >/dev/null 2>&1; then
        log_warning "curl not available; unable to download OWASP ZAP"
        return 1
    fi

    local tmpdir
    tmpdir=$(mktemp -d)
    if curl -fsSL "$ZAP_DOWNLOAD_URL" -o "$tmpdir/zap.tgz"; then
        sudo mkdir -p "$ZAP_INSTALL_DIR"
        sudo tar -xzf "$tmpdir/zap.tgz" -C "$ZAP_INSTALL_DIR" --strip-components=1
        sudo ln -sf "$ZAP_INSTALL_DIR/zap.sh" /usr/local/bin/zap.sh
        sudo ln -sf "$ZAP_INSTALL_DIR/zap-baseline.py" /usr/local/bin/zap-baseline.py || true
    fi
    rm -rf "$tmpdir"

    if [ -x "$ZAP_INSTALL_DIR/zap.sh" ]; then
        return 0
    fi

    log_warning "Unable to install OWASP ZAP automatically"
    return 1
}

_find_default_wordlist() {
    local candidates=(
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
        "/usr/share/seclists/Discovery/Web-Content/common.txt"
    )
    local candidate
    for candidate in "${candidates[@]}"; do
        if [ -f "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    echo ""
}

_prompt_web_targets() {
    local default_target="$1"
    local provided_targets="$2"

    if [ "$ANSIBLE" == "true" ]; then
        if [ -n "${provided_targets:-}" ]; then
            echo "$provided_targets"
        else
            echo "${WEB_SCANNER_TARGET:-$default_target}"
        fi
        return 0
    fi

    cat <<'EOF'

Select web scanning scope:
  1) Single URL
  2) Multiple URLs (comma separated)
Press Enter to use the default.
EOF

    local choice
    choice=$(get_input_string "Choice [default: 1]: ")
    choice=${choice:-1}

    case "$choice" in
        1)
            local url
            url=$(get_input_string "Target URL [default: $default_target]: ")
            url=${url:-$default_target}
            echo "$url"
            ;;
        2)
            local urls
            urls=$(get_input_string "Enter comma separated URLs: ")
            urls=${urls//,/ }
            urls=${urls:-$default_target}
            echo "$urls"
            ;;
        *)
            log_warning "Unknown selection; using default target"
            echo "$default_target"
            ;;
    esac
}

run_web_scanner_suite() {
    print_banner "Web Scanner Suite (ZAP + Nikto + Gobuster)"

    ensure_web_scanner_dirs

    install_zap || log_warning "OWASP ZAP could not be installed"
    install_nikto || log_warning "Nikto installation failed"
    install_gobuster || log_warning "Gobuster installation failed"

    local default_url="http://127.0.0.1"
    local targets_input wordlist

    targets_input=$(_prompt_web_targets "$default_url" "${WEB_SCANNER_TARGETS:-}")

    if [ -z "$targets_input" ]; then
        log_warning "No target URL provided; skipping web scanner suite"
        return 0
    fi

    read -r -a target_urls <<<"$targets_input"

    if [ "$ANSIBLE" == "true" ]; then
        wordlist="${WEB_SCANNER_WORDLIST:-$(_find_default_wordlist)}"
    else
        wordlist=$(get_input_string "Enter wordlist for Gobuster (leave blank to auto-detect): ")
        if [ -z "$wordlist" ]; then
            wordlist=$(_find_default_wordlist)
        fi
    fi

    local target_url timestamp safe_target zap_report nikto_log gobuster_log
    timestamp=$(date +"%Y%m%d_%H%M%S")

    for target_url in "${target_urls[@]}"; do
        if [ -z "$target_url" ]; then
            continue
        fi

        safe_target=$(echo "$target_url" | tr -c '[:alnum:].-' '_')
        zap_report="$WEB_SCANNER_LOG_DIR/${safe_target}_${timestamp}_zap.html"
        nikto_log="$WEB_SCANNER_LOG_DIR/${safe_target}_${timestamp}_nikto.log"
        gobuster_log="$WEB_SCANNER_LOG_DIR/${safe_target}_${timestamp}_gobuster.log"

        if command -v zap-baseline.py >/dev/null 2>&1; then
            log_info "Running OWASP ZAP baseline scan against $target_url"
            if ! zap-baseline.py -t "$target_url" -r "$zap_report" -J "$WEB_SCANNER_LOG_DIR/${safe_target}_${timestamp}_zap.json" -w "$WEB_SCANNER_LOG_DIR/${safe_target}_${timestamp}_zap.md" >/dev/null 2>&1; then
                log_warning "OWASP ZAP baseline scan reported issues or failed"
            fi
        else
            log_warning "OWASP ZAP baseline script not available; skipping ZAP scan"
        fi

        if command -v nikto >/dev/null 2>&1; then
            log_info "Running Nikto scan against $target_url"
            if ! nikto -h "$target_url" -o "$nikto_log" -Format txt >/dev/null 2>&1; then
                log_warning "Nikto scan encountered errors"
            fi
        fi

        if command -v gobuster >/dev/null 2>&1 && [ -n "$wordlist" ] && [ -f "$wordlist" ]; then
            log_info "Running Gobuster directory enumeration against $target_url"
            if ! gobuster dir -u "$target_url" -w "$wordlist" -o "$gobuster_log" >/dev/null 2>&1; then
                log_warning "Gobuster enumeration encountered errors"
            fi
        elif command -v gobuster >/dev/null 2>&1; then
            log_warning "Gobuster wordlist $wordlist not found; skipping enumeration"
        fi
    done

    log_success "Web scanner suite completed. Reports saved to $WEB_SCANNER_LOG_DIR"
}


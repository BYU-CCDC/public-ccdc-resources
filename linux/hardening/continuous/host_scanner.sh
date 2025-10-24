#!/usr/bin/env bash

HOST_SCANNER_LOG_DIR="/var/log/ccdc/host-scanners"
BINARY_INTEGRITY_DEFAULTS="sshd apache2 nginx httpd"

ensure_host_scanner_dir() {
    mkdir -p "$HOST_SCANNER_LOG_DIR"
}

_install_lynis() {
    if command -v lynis >/dev/null 2>&1; then
        return 0
    fi

    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    case "$pm" in
        apt-get)
            sudo apt-get install -y lynis
            ;;
        dnf)
            sudo dnf install -y lynis
            ;;
        yum)
            sudo yum install -y lynis
            ;;
        zypper)
            sudo zypper install -y lynis
            ;;
        *)
            log_warning "Unable to install Lynis automatically"
            return 1
            ;;
    esac
}

run_lynis_audit() {
    ensure_host_scanner_dir

    _install_lynis || {
        log_warning "Skipping Lynis audit; installer failed"
        return 1
    }

    local timestamp report
    timestamp=$(date +"%Y%m%d_%H%M%S")
    report="$HOST_SCANNER_LOG_DIR/lynis_audit_${timestamp}.log"

    log_info "Running Lynis audit. Report -> $report"
    if ! lynis audit system --cronjob --quiet >"$report" 2>&1; then
        log_warning "Lynis reported errors; review $report"
        return 1
    fi
    log_success "Lynis audit completed"
}

run_host_integrity_suite() {
    print_banner "Host Integrity Scanners (Lynis + RKhunter)"

    ensure_host_scanner_dir

    local proceed
    if [ "$ANSIBLE" == "true" ]; then
        proceed="${HOST_SCANNER_RUN:-y}"
    else
        proceed=$(get_input_string "Run host integrity scanners now? (y/N): ")
    fi

    if [[ ! "$proceed" =~ ^[Yy]$ ]]; then
        log_info "Skipping host integrity scanners as requested"
        return 0
    fi

    run_lynis_audit || true
    if declare -F run_rkhunter >/dev/null; then
        run_rkhunter || true
    else
        log_warning "run_rkhunter function not available"
    fi

    run_binary_integrity_checks || true

    log_success "Host integrity scanner suite finished"
}

_prompt_binary_integrity_targets() {
    local defaults="$1"
    local provided="$2"

    if [ "$ANSIBLE" == "true" ]; then
        echo "${provided:-$defaults}"
        return 0
    fi

    cat <<'EOF'

Select binary integrity scope:
  1) Single service/binary
  2) Multiple entries (comma separated)
  3) Custom space separated list
Press Enter to use the default set.
EOF

    local choice
    choice=$(get_input_string "Choice [default: 2]: ")
    choice=${choice:-2}

    case "$choice" in
        1)
            local entry
            entry=$(get_input_string "Service or binary [default: $defaults]: ")
            entry=${entry:-$defaults}
            echo "$entry"
            ;;
        2)
            local list
            list=$(get_input_string "Comma separated services/binaries: ")
            list=${list//,/ }
            list=${list:-$defaults}
            echo "$list"
            ;;
        3)
            local space_list
            space_list=$(get_input_string "Space separated services/binaries: ")
            space_list=${space_list:-$defaults}
            echo "$space_list"
            ;;
        *)
            log_warning "Unknown selection; using default entries"
            echo "$defaults"
            ;;
    esac
}

_resolve_binary_path() {
    local identifier="$1"
    local candidate=""

    if [[ "$identifier" == /* ]]; then
        candidate="$identifier"
    elif command -v "$identifier" >/dev/null 2>&1; then
        candidate=$(command -v "$identifier")
    elif command -v systemctl >/dev/null 2>&1; then
        local exec_line
        exec_line=$(systemctl show "$identifier.service" -p ExecStart --value 2>/dev/null)
        if [ -n "$exec_line" ]; then
            candidate=$(echo "$exec_line" | awk '{print $1}')
            candidate=${candidate#-}
            candidate=${candidate#"}
            candidate=${candidate%"}
        fi
    fi

    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        readlink -f "$candidate"
    else
        echo ""
    fi
}

_resolve_package_for_binary() {
    local binary_path="$1"

    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    case "$pm" in
        apt-get)
            dpkg -S "$binary_path" 2>/dev/null | head -n1 | cut -d: -f1
            ;;
        dnf|yum|zypper)
            rpm -qf "$binary_path" 2>/dev/null
            ;;
        *)
            echo ""
            ;;
    esac
}

_verify_package_integrity() {
    local package="$1"
    local log_file="$2"
    local status=0

    : >"$log_file"

    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    case "$pm" in
        apt-get)
            sudo dpkg -V "$package" >"$log_file" 2>&1 || status=$?
            ;;
        dnf|yum|zypper)
            sudo rpm -V "$package" >"$log_file" 2>&1 || status=$?
            ;;
        *)
            log_warning "Package manager $pm does not support automated verification"
            return 1
            ;;
    esac

    if [ -s "$log_file" ] || [ $status -ne 0 ]; then
        return 1
    fi

    return 0
}

_derive_service_name() {
    local identifier="$1"
    local service_name
    service_name=$(basename "$identifier")
    echo "$service_name"
}

_restart_service_if_possible() {
    local service="$1"
    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl start "$service" >/dev/null 2>&1 || sudo systemctl start "$service.service" >/dev/null 2>&1 || true
    fi
}

_stop_service_if_possible() {
    local service="$1"
    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl stop "$service" >/dev/null 2>&1 || sudo systemctl stop "$service.service" >/dev/null 2>&1 || true
    fi
}

_remediate_compromised_package() {
    local identifier="$1"
    local package="$2"

    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    local service
    service=$(_derive_service_name "$identifier")

    _stop_service_if_possible "$service"

    local reinstall_status=1

    case "$pm" in
        apt-get)
            sudo apt-get install --reinstall -y "$package" && reinstall_status=0
            ;;
        dnf)
            sudo dnf reinstall -y "$package" && reinstall_status=0
            ;;
        yum)
            sudo yum reinstall -y "$package" && reinstall_status=0
            ;;
        zypper)
            sudo zypper install --force -y "$package" && reinstall_status=0
            ;;
        *)
            log_warning "Package manager $pm does not support automatic remediation"
            reinstall_status=1
            ;;
    esac

    if [ $reinstall_status -ne 0 ]; then
        log_error "Automatic remediation failed for $package"
        return 1
    fi

    _restart_service_if_possible "$service"

    log_success "Remediation attempted for package $package"
    return 0
}

_check_binary_integrity() {
    local identifier="$1"
    local timestamp log_file binary_path package

    binary_path=$(_resolve_binary_path "$identifier")
    if [ -z "$binary_path" ]; then
        log_warning "Unable to resolve binary path for $identifier"
        return 1
    fi

    package=$(_resolve_package_for_binary "$binary_path")
    if [ -z "$package" ]; then
        log_warning "Unable to determine package owning $binary_path"
        return 1
    fi

    timestamp=$(date +"%Y%m%d_%H%M%S")
    log_file="$HOST_SCANNER_LOG_DIR/${package}_${timestamp}_integrity.log"

    if _verify_package_integrity "$package" "$log_file"; then
        log_success "Integrity check passed for $package ($binary_path)"
        return 0
    fi

    log_warning "Integrity anomalies detected for $package ($binary_path). Review $log_file"

    local remediate
    if [ "$ANSIBLE" == "true" ]; then
        remediate="${BINARY_INTEGRITY_REMEDIATE:-n}"
    else
        remediate=$(get_input_string "Attempt automatic remediation for $package? (y/N): ")
    fi

    if [[ "$remediate" =~ ^[Yy]$ ]]; then
        if _remediate_compromised_package "$identifier" "$package"; then
            local verify_log
            verify_log="$HOST_SCANNER_LOG_DIR/${package}_${timestamp}_postfix.log"
            if _verify_package_integrity "$package" "$verify_log"; then
                log_success "Post-remediation integrity check passed for $package"
            else
                log_warning "Integrity issues persist for $package after remediation. Review $verify_log"
            fi
        fi
    else
        log_info "Remediation skipped for $package"
    fi

    return 0
}

run_binary_integrity_checks() {
    local targets_input
    targets_input=$(_prompt_binary_integrity_targets "$BINARY_INTEGRITY_DEFAULTS" "${BINARY_INTEGRITY_TARGETS:-}")

    if [ -z "$targets_input" ]; then
        log_warning "No targets specified for binary integrity checks"
        return 0
    fi

    read -r -a integrity_targets <<<"$targets_input"

    local target
    for target in "${integrity_targets[@]}"; do
        if [ -n "$target" ]; then
            _check_binary_integrity "$target"
        fi
    done
}


#!/usr/bin/env bash

# ClamAV automation helpers sourced by the orchestrator.  These functions are
# intentionally defensive so the continuous workflow can run on hosts where
# ClamAV is not yet installed without aborting the entire hardening run.

CLAMAV_DEFAULT_SCAN_DIRS=(
    "/var/www"
    "/srv/www"
    "/home"
    "/etc"
)
CLAMAV_SCAN_LOG="/var/log/ccdc/clamav_scan.log"

function _clamav_detect_service {
    local service
    for service in clamav-freshclam freshclam clamd@scan; do
        if command -v systemctl >/dev/null 2>&1; then
            systemctl list-unit-files "$service" >/dev/null 2>&1 && {
                echo "$service"
                return 0
            }
        fi
    done
    return 1
}

function _clamav_install_packages {
    if command -v clamscan >/dev/null 2>&1 || command -v clamdscan >/dev/null 2>&1; then
        log_debug "ClamAV already installed."
        return 0
    fi

    log_info "Installing ClamAV packages..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y clamav clamav-freshclam || sudo apt-get install -y clamav
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y clamav clamav-update
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y clamav clamav-update
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper install -y clamav
    else
        log_error "Unsupported package manager for ClamAV installation."
        return 1
    fi
}

function _clamav_update_definitions {
    if ! command -v freshclam >/dev/null 2>&1; then
        log_warning "freshclam command not found; skipping definition update."
        return 0
    fi

    local service
    local service_was_running="false"
    service=$(_clamav_detect_service) || true
    if [ -n "$service" ] && command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet "$service"; then
            log_debug "Stopping $service to update definitions."
            service_was_running="true"
            systemctl stop "$service"
        fi
    fi

    if ! freshclam; then
        log_warning "freshclam exited with a non-zero status; ClamAV definitions may be stale."
    fi

    if [ "$service_was_running" == "true" ] && command -v systemctl >/dev/null 2>&1; then
        log_debug "Restarting $service after definition update."
        systemctl start "$service"
    fi
}

function _clamav_resolve_scan_paths {
    local -n _result=$1
    local provided_paths="$2"
    _result=()

    local path
    if [ -n "$provided_paths" ]; then
        read -r -a _result <<<"$provided_paths"
    else
        for path in "${CLAMAV_DEFAULT_SCAN_DIRS[@]}"; do
            [ -d "$path" ] && _result+=("$path")
        done
    fi

    if [ ${#_result[@]} -eq 0 ]; then
        _result=("/var/www" "/home")
    fi
}

function _clamav_select_command {
    if command -v clamdscan >/dev/null 2>&1; then
        echo "clamdscan"
    elif command -v clamscan >/dev/null 2>&1; then
        echo "clamscan"
    else
        echo ""
    fi
}

function run_clamav_scan {
    print_banner "Running ClamAV Malware Scan"

    local run_scan="n"
    if [ "$ANSIBLE" == "true" ]; then
        run_scan="${CLAMAV_SCAN_ENABLED:-n}"
    else
        run_scan=$(get_input_string "Would you like to run a ClamAV malware scan? (y/N): ")
    fi

    if [[ ! "$run_scan" =~ ^[Yy]$ ]]; then
        log_info "Skipping ClamAV scan as requested."
        return 0
    fi

    if ! _clamav_install_packages; then
        log_warning "Unable to install ClamAV packages; skipping scan."
        return 0
    fi

    mkdir -p "$(dirname "$CLAMAV_SCAN_LOG")"

    local user_paths=""
    if [ "$ANSIBLE" == "true" ]; then
        user_paths="${CLAMAV_SCAN_PATHS:-}"
    else
        user_paths=$(get_input_string "Enter additional directories to scan (space separated, leave blank for defaults): ")
    fi

    local scan_paths=()
    _clamav_resolve_scan_paths scan_paths "$user_paths"

    local scan_cmd
    scan_cmd=$(_clamav_select_command)
    if [ -z "$scan_cmd" ]; then
        log_error "ClamAV scan command not found after installation attempt."
        return 1
    fi

    _clamav_update_definitions

    log_info "Running $scan_cmd on: ${scan_paths[*]}"
    local log_output
    log_output=$(mktemp)

    local exit_code=0
    if [ "$scan_cmd" == "clamscan" ]; then
        "$scan_cmd" --recursive --infected --log="$log_output" "${scan_paths[@]}" || exit_code=$?
    else
        "$scan_cmd" --log="$log_output" "${scan_paths[@]}" || exit_code=$?
    fi

    cat "$log_output" >>"$CLAMAV_SCAN_LOG"
    rm -f "$log_output"

    case $exit_code in
        0)
            log_success "ClamAV scan completed with no detections."
            ;;
        1)
            log_warning "ClamAV detected malware. Review $CLAMAV_SCAN_LOG for details."
            ;;
        *)
            log_error "ClamAV scan failed with exit code $exit_code. See $CLAMAV_SCAN_LOG."
            return $exit_code
            ;;
    esac
}

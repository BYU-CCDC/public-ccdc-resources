#!/usr/bin/env bash

FAST_CVE_LOG_DIR="/var/log/ccdc/fast-cve"
NUCLEI_TEMPLATES_DIR="/var/lib/ccdc/nuclei-templates"
NUCLEI_RELEASE_VERSION="2.9.10"
NUCLEI_RELEASE_BASE="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_RELEASE_VERSION}"

ensure_fast_cve_dirs() {
    mkdir -p "$FAST_CVE_LOG_DIR" "$NUCLEI_TEMPLATES_DIR"
}

_detect_nuclei_archive() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)
            echo "nuclei_Linux_x86_64.zip"
            ;;
        arm64|aarch64)
            echo "nuclei_Linux_arm64.zip"
            ;;
        armv7l)
            echo "nuclei_Linux_armv7.zip"
            ;;
        *)
            echo "nuclei_Linux_x86_64.zip"
            ;;
    esac
}

_install_zip_if_needed() {
    if command -v unzip >/dev/null 2>&1; then
        return 0
    fi

    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    case "$pm" in
        apt-get)
            sudo apt-get install -y unzip
            ;;
        dnf)
            sudo dnf install -y unzip
            ;;
        yum)
            sudo yum install -y unzip
            ;;
        zypper)
            sudo zypper install -y unzip
            ;;
        *)
            log_warning "Unable to install unzip automatically"
            return 1
            ;;
    esac
}

install_nuclei() {
    if command -v nuclei >/dev/null 2>&1; then
        return 0
    fi

    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    case "$pm" in
        apt-get)
            if sudo apt-get install -y nuclei >/dev/null 2>&1; then
                return 0
            fi
            ;;
        dnf)
            if sudo dnf install -y nuclei >/dev/null 2>&1; then
                return 0
            fi
            ;;
        yum)
            if sudo yum install -y nuclei >/dev/null 2>&1; then
                return 0
            fi
            ;;
        zypper)
            if sudo zypper install -y nuclei >/dev/null 2>&1; then
                return 0
            fi
            ;;
    esac

    if ! command -v curl >/dev/null 2>&1; then
        log_warning "curl not available; cannot download nuclei release"
        return 1
    fi

    _install_zip_if_needed || true

    local archive tmpdir
    archive=$(_detect_nuclei_archive)
    tmpdir=$(mktemp -d)

    if curl -fsSL "${NUCLEI_RELEASE_BASE}/${archive}" -o "$tmpdir/$archive"; then
        (cd "$tmpdir" && unzip -o "$archive" >/dev/null 2>&1 && sudo install -m 755 nuclei /usr/local/bin/nuclei)
        rm -rf "$tmpdir"
        if command -v nuclei >/dev/null 2>&1; then
            return 0
        fi
    fi

    rm -rf "$tmpdir"
    log_warning "Unable to install nuclei automatically"
    return 1
}

update_nuclei_templates() {
    if ! command -v nuclei >/dev/null 2>&1; then
        return 1
    fi

    local template_dir
    template_dir="$NUCLEI_TEMPLATES_DIR"

    nuclei -update-templates -ud "$template_dir" >/dev/null 2>&1 || true
}

_prompt_fast_cve_targets() {
    local default_targets="$1"
    local provided_targets="$2"

    if [ "$ANSIBLE" == "true" ]; then
        echo "${provided_targets:-$default_targets}"
        return 0
    fi

    cat <<'EOF'

Select vulnerability scan scope:
  1) Single host/IP
  2) Single subnet/CIDR
  3) Multiple hosts/subnets (comma separated)
  4) Custom list (space separated)
  5) Web URLs (comma separated)
Press Enter to use the default.
EOF

    local choice
    choice=$(get_input_string "Choice [default: 1]: ")
    choice=${choice:-1}

    case "$choice" in
        1)
            local host
            host=$(get_input_string "Host/IP [default: $default_targets]: ")
            host=${host:-$default_targets}
            echo "$host"
            ;;
        2)
            local subnet
            subnet=$(get_input_string "Subnet/CIDR [default: $default_targets]: ")
            subnet=${subnet:-$default_targets}
            echo "$subnet"
            ;;
        3)
            local items
            items=$(get_input_string "Enter comma separated hosts/subnets: ")
            items=${items//,/ }
            items=${items:-$default_targets}
            echo "$items"
            ;;
        4)
            local list
            list=$(get_input_string "Enter space separated targets: ")
            list=${list:-$default_targets}
            echo "$list"
            ;;
        5)
            local urls
            urls=$(get_input_string "Enter comma separated URLs: ")
            urls=${urls//,/ }
            urls=${urls:-$default_targets}
            echo "$urls"
            ;;
        *)
            log_warning "Unknown selection; using default targets"
            echo "$default_targets"
            ;;
    esac
}

run_fast_cve_mapping() {
    print_banner "Fast CVE Mapping (Nuclei + Nmap NSE)"

    ensure_fast_cve_dirs

    if ! install_nmap; then
        log_error "nmap is required to run NSE vulnerability scans"
        return 1
    fi

    install_nuclei || log_warning "nuclei installation failed; continuing with nmap-only vulnerability checks."
    update_nuclei_templates || log_warning "Unable to refresh nuclei templates"

    local default_targets="127.0.0.1"
    local targets_input

    targets_input=$(_prompt_fast_cve_targets "$default_targets" "${FAST_CVE_TARGETS:-}")

    read -r -a targets <<<"$targets_input"
    if [ ${#targets[@]} -eq 0 ]; then
        targets=($default_targets)
    fi

    local timestamp target safe_target nmap_log nuclei_log
    timestamp=$(date +"%Y%m%d_%H%M%S")

    for target in "${targets[@]}"; do
        safe_target=$(echo "$target" | tr -c '[:alnum:].-' '_')
        nmap_log="$FAST_CVE_LOG_DIR/${safe_target}_${timestamp}_nmap.log"
        nuclei_log="$FAST_CVE_LOG_DIR/${safe_target}_${timestamp}_nuclei.log"

        log_info "Running nmap NSE vulnerability scan against $target"
        if ! nmap -sV --script vuln -oN "$nmap_log" "$target"; then
            log_warning "nmap vulnerability scan encountered errors for $target"
        fi

        if command -v nuclei >/dev/null 2>&1; then
            log_info "Running nuclei templates against $target"
            if ! nuclei -target "$target" -ud "$NUCLEI_TEMPLATES_DIR" -o "$nuclei_log"; then
                log_warning "nuclei scan failed for $target"
            fi
        fi
    done

    log_success "Fast CVE mapping complete. Reports stored in $FAST_CVE_LOG_DIR"
}


#!/usr/bin/env bash

DISCOVERY_LOG_DIR="/var/log/ccdc/discovery"
RUSTSCAN_INSTALL_VERSION="2.3.0"
RUSTSCAN_INSTALL_BASE_URL="https://github.com/RustScan/RustScan/releases/download/${RUSTSCAN_INSTALL_VERSION}"

ensure_discovery_log_dir() {
    mkdir -p "$DISCOVERY_LOG_DIR"
}

_detect_arch_suffix() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)
            echo "x86_64"
            ;;
        arm64|aarch64)
            echo "aarch64"
            ;;
        armv7l)
            echo "armv7"
            ;;
        *)
            echo "x86_64"
            ;;
    esac
}

if ! declare -F install_nmap >/dev/null; then
    install_nmap() {
        if command -v nmap >/dev/null 2>&1; then
            return 0
        fi

        if [ -z "${pm:-}" ]; then
            detect_system_info
        fi

        log_info "Installing nmap via $pm"
        case "$pm" in
            apt-get)
                sudo apt-get install -y nmap
                ;;
            dnf)
                sudo dnf install -y nmap
                ;;
            yum)
                sudo yum install -y nmap
                ;;
            zypper)
                sudo zypper install -y nmap
                ;;
            *)
                log_error "Unsupported package manager for nmap installation."
                return 1
                ;;
        esac
    }
fi

install_rustscan() {
    if command -v rustscan >/dev/null 2>&1; then
        return 0
    fi

    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    log_info "Attempting to install rustscan (version $RUSTSCAN_INSTALL_VERSION)"

    case "$pm" in
        apt-get)
            if sudo apt-get install -y rustscan >/dev/null 2>&1; then
                log_success "Installed rustscan via apt-get"
                return 0
            fi
            ;;
        dnf)
            if sudo dnf install -y rustscan >/dev/null 2>&1; then
                log_success "Installed rustscan via dnf"
                return 0
            fi
            ;;
        yum)
            if sudo yum install -y rustscan >/dev/null 2>&1; then
                log_success "Installed rustscan via yum"
                return 0
            fi
            ;;
        zypper)
            if sudo zypper install -y rustscan >/dev/null 2>&1; then
                log_success "Installed rustscan via zypper"
                return 0
            fi
            ;;
    esac

    if ! command -v curl >/dev/null 2>&1; then
        log_warning "curl not available; unable to fetch rustscan binary."
        return 1
    fi

    local arch suffix archive tmpdir target
    arch=$(_detect_arch_suffix)

    if [[ "$arch" == "x86_64" ]]; then
        suffix="amd64"
    else
        suffix="$arch"
    fi

    if [[ "$pm" == "apt-get" ]]; then
        archive="rustscan_${RUSTSCAN_INSTALL_VERSION}_${suffix}.deb"
    else
        archive="rustscan-${RUSTSCAN_INSTALL_VERSION}-1.${arch}.rpm"
    fi

    tmpdir=$(mktemp -d)
    target="$tmpdir/$archive"

    if curl -fsSL "${RUSTSCAN_INSTALL_BASE_URL}/${archive}" -o "$target"; then
        if [[ "$archive" == *.deb ]]; then
            if sudo dpkg -i "$target" >/dev/null 2>&1; then
                rm -rf "$tmpdir"
                return 0
            fi
        else
            if sudo rpm -i "$target" >/dev/null 2>&1; then
                rm -rf "$tmpdir"
                return 0
            fi
        fi
    fi

    rm -rf "$tmpdir"

    if command -v rustscan >/dev/null 2>&1; then
        return 0
    fi

    if ! command -v cargo >/dev/null 2>&1; then
        if command -v curl >/dev/null 2>&1; then
            log_info "Installing Rust toolchain to build rustscan"
            curl -fsSL https://sh.rustup.rs -o /tmp/rustup.sh
            sh /tmp/rustup.sh -y --no-modify-path >/dev/null 2>&1
            # shellcheck source=/dev/null
            source "$HOME/.cargo/env"
        else
            log_warning "cargo is required to build rustscan but curl is unavailable"
            return 1
        fi
    else
        # shellcheck source=/dev/null
        source "$HOME/.cargo/env" 2>/dev/null || true
    fi

    if command -v cargo >/dev/null 2>&1; then
        if cargo install rustscan >/dev/null 2>&1; then
            sudo install -m 755 "$HOME/.cargo/bin/rustscan" /usr/local/bin/rustscan
            return 0
        fi
    fi

    log_warning "Unable to install rustscan automatically."
    return 1
}

_sanitize_target_name() {
    echo "$1" | tr -c '[:alnum:].-' '_'
}

_prompt_discovery_targets() {
    local default_targets="$1"
    local provided_targets="$2"

    if [ "$ANSIBLE" == "true" ]; then
        echo "${provided_targets:-$default_targets}"
        return 0
    fi

    cat <<'EOF'

Select discovery scope:
  1) Single host/IP
  2) Single subnet/CIDR (e.g., 10.0.0.0/24)
  3) Multiple hosts/subnets (comma separated)
  4) Enter custom list (space separated)
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
        *)
            log_warning "Unknown selection; using default targets"
            echo "$default_targets"
            ;;
    esac
}

run_discovery_enumeration() {
    print_banner "Discovery Scanning (RustScan + Nmap)"

    ensure_discovery_log_dir

    if ! install_nmap; then
        log_error "nmap is required for discovery scanning."
        return 1
    fi

    install_rustscan || log_warning "rustscan installation failed; falling back to nmap-only scans."

    local default_targets="127.0.0.1"
    local targets_input

    targets_input=$(_prompt_discovery_targets "$default_targets" "${DISCOVERY_TARGETS:-}")

    read -r -a targets <<<"$targets_input"
    if [ ${#targets[@]} -eq 0 ]; then
        targets=($default_targets)
    fi

    local target log_file timestamp exit_code scan_cmd
    timestamp=$(date +"%Y%m%d_%H%M%S")

    for target in "${targets[@]}"; do
        local safe_target
        safe_target=$(_sanitize_target_name "$target")
        log_file="$DISCOVERY_LOG_DIR/${safe_target}_${timestamp}.log"

        log_info "Enumerating $target (results -> $log_file)"
        exit_code=0

        if command -v rustscan >/dev/null 2>&1; then
            scan_cmd=(rustscan -a "$target" --ulimit 65000 --tries 3 --timeout 500)
            scan_cmd+=(-- -sV -sS -O -oN "$log_file")
            if ! "${scan_cmd[@]}"; then
                exit_code=$?
                log_warning "rustscan reported a non-zero exit code ($exit_code) for $target"
            else
                log_success "rustscan completed for $target"
            fi
        fi

        if [ $exit_code -ne 0 ] || ! command -v rustscan >/dev/null 2>&1; then
            log_info "Running fallback nmap verification for $target"
            if ! nmap -sS -sV -O -oN "$log_file" "$target"; then
                log_warning "nmap fallback scan failed for $target"
            fi
        else
            log_info "Appending nmap --script host discovery results"
            {
                echo
                echo "===== Supplemental nmap host discovery ($(date)) ====="
                nmap -sn "$target"
            } >>"$log_file" || true
        fi
    done

    log_success "Discovery scanning routine finished. Review logs in $DISCOVERY_LOG_DIR"
}


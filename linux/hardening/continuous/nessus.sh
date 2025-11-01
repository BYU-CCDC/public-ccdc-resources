#!/usr/bin/env bash

NESSUS_LOG_DIR="/var/log/ccdc/nessus"
NESSUS_DOWNLOAD_BASE="https://www.tenable.com/downloads/api/v2/pages/nessus/files"
NESSUS_DEFAULT_VERSION="10.7.2"

ensure_nessus_log_dir() {
    mkdir -p "$NESSUS_LOG_DIR"
}

_detect_nessus_package() {
    local arch package
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)
            package="Nessus-${NESSUS_DEFAULT_VERSION}-x86_64.rpm"
            ;;
        arm64|aarch64)
            package="Nessus-${NESSUS_DEFAULT_VERSION}-aarch64.rpm"
            ;;
        *)
            package="Nessus-${NESSUS_DEFAULT_VERSION}-x86_64.rpm"
            ;;
    esac

    if [ -n "${pm:-}" ] && [ "$pm" = "apt-get" ]; then
        case "$arch" in
            x86_64|amd64)
                package="Nessus-${NESSUS_DEFAULT_VERSION}-ubuntu1404_amd64.deb"
                ;;
            arm64|aarch64)
                package="Nessus-${NESSUS_DEFAULT_VERSION}-debian10_aarch64.deb"
                ;;
        esac
    fi

    echo "$package"
}

_install_nessus_package() {
    local package url tmpdir

    if [ -z "${pm:-}" ]; then
        detect_system_info
    fi

    package=$(_detect_nessus_package)
    url="${NESSUS_DOWNLOAD_BASE}/${package}"

    tmpdir=$(mktemp -d)
    if ! command -v curl >/dev/null 2>&1; then
        log_warning "curl not available; cannot download Nessus"
        rm -rf "$tmpdir"
        return 1
    fi

    if ! curl -fsSL "$url" -o "$tmpdir/$package"; then
        rm -rf "$tmpdir"
        log_warning "Failed to download Nessus package from $url"
        return 1
    fi

    case "$package" in
        *.deb)
            sudo dpkg -i "$tmpdir/$package" >/dev/null 2>&1 || sudo apt-get install -f -y
            ;;
        *.rpm)
            if command -v dnf >/dev/null 2>&1; then
                sudo dnf localinstall -y "$tmpdir/$package" >/dev/null 2>&1
            else
                sudo rpm -i "$tmpdir/$package" >/dev/null 2>&1 || sudo rpm -Uvh "$tmpdir/$package" >/dev/null 2>&1
            fi
            ;;
        *)
            log_warning "Unknown Nessus package type: $package"
            rm -rf "$tmpdir"
            return 1
            ;;
    esac

    rm -rf "$tmpdir"
    sudo systemctl enable nessusd --now || true
    log_success "Nessus service enabled"
}

_configure_nessus_agent() {
    local manager_ip registration_code
    manager_ip="$1"
    registration_code="$2"

    if ! command -v nessuscli >/dev/null 2>&1; then
        log_warning "nessuscli not available; cannot register Nessus agent"
        return 1
    fi

    if [ -n "$manager_ip" ] && [ -n "$registration_code" ]; then
        nessuscli agent link --key "$registration_code" --groups "CCDC" --name "$(hostname)" --host "$manager_ip" || true
    fi
}

run_nessus_authenticated_setup() {
    print_banner "Nessus Authenticated Scanning"

    ensure_nessus_log_dir

    local proceed
    if [ "$ANSIBLE" == "true" ]; then
        proceed="${NESSUS_SETUP:-n}"
    else
        proceed=$(get_input_string "Run Nessus authenticated scanning setup? (y/N): ")
    fi

    if [[ ! "$proceed" =~ ^[Yy]$ ]]; then
        log_info "Skipping Nessus automation"
        return 0
    fi

    local nessus_present="false"
    if command -v nessuscli >/dev/null 2>&1; then
        nessus_present="true"
    elif command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files nessusd.service >/dev/null 2>&1; then
        nessus_present="true"
    fi

    if [ "$nessus_present" != "true" ]; then
        log_info "Nessus not detected; preparing installation"
        if ! _install_nessus_package; then
            log_warning "Nessus installation failed; skipping authenticated scanning setup"
            return 1
        fi
    fi

    local manager_ip registration_code

    if [ "$ANSIBLE" == "true" ]; then
        manager_ip="${NESSUS_MANAGER_HOST:-}"
        registration_code="${NESSUS_REGISTRATION_CODE:-}"
    else
        manager_ip=$(get_input_string "Enter Nessus manager hostname/IP (leave blank to skip linking agents): ")
        registration_code=$(get_input_string "Enter Nessus linking key (optional): ")
    fi

    if [ -n "$manager_ip" ] && [ -n "$registration_code" ]; then
        log_info "Linking Nessus agent to manager $manager_ip"
        _configure_nessus_agent "$manager_ip" "$registration_code"
    else
        log_info "Skipping Nessus agent linking; missing manager or registration key"
    fi

    local policy_note
    policy_note="$NESSUS_LOG_DIR/README.txt"
    if [ ! -f "$policy_note" ]; then
        cat <<POLICY >"$policy_note"
Nessus Authenticated Scanning Notes
-----------------------------------
1. Access the Nessus UI at https://<host>:8834/ to complete the initial setup.
2. Upload privileged credential policies for SSH/WinRM as needed.
3. Distribute credentials through Nessus Manager and ensure agents inherit the policy.
4. Review scan results regularly and export for long-term retention.
POLICY
    fi

    log_success "Nessus authenticated scanning helper completed"
}


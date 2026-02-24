#!/usr/bin/env bash
# bunkerweb.sh - BunkerWeb reverse-proxy WAF for CCDC environments
# Revised from the previous iteration to restore and maintain readable structure.
#
# Sits in front of Apache or Nginx backends as a separate NGINX-based WAF
# with ModSecurity + OWASP CRS in blocking mode. Forces all external traffic
# through the WAF by rebinding the backend to loopback-only ports.
#
# Supports three modes:
#   --local   (default) Auto-detect local Apache/Nginx and protect those sites
#   --remote  Operator provides remote backend IPs (e.g., Windows IIS servers)
#   --hybrid  Auto-detect local + operator-provided remote backends
#
# Execution phases:
#   1. Pre-flight checks (distro support, root, deps)
#   2. Detect backend web server and enumerate virtual hosts / collect remotes
#   3. Install BunkerWeb (BEFORE rebinding -- ensures rollback path)
#   4. Rebind backend to 127.0.0.1:8080+ so it cannot serve external traffic
#   5. Generate /etc/bunkerweb/variables.env with per-site reverse proxy config
#   6. Drop Nginx location blocks to 403-block dangerous endpoints
#   7. Handle SELinux / firewall, start BunkerWeb, validate full proxy path
#
# Public functions:
#   install_and_configure_bunkerweb  - Main entry point (called by menu/orchestrator)
#   rollback_bunkerweb               - Restore pre-migration state from backup
#
# Standalone:  sudo bash bunkerweb.sh [--local|--remote|--hybrid] [--manifest FILE]
# Sourced:     source bunkerweb.sh && install_and_configure_bunkerweb
# Rollback:    source bunkerweb.sh && rollback_bunkerweb [/path/to/backup]

# NOTE: No `set -euo pipefail` here. This file is sourced by ccdc.sh via
# load_modules inside a function scope. Strict mode is set only in the
# standalone guard at the bottom. Error propagation is handled via explicit
# return-code checks in the main function.

# ---------------------------------------------------------------------------
# Library sourcing
# ---------------------------------------------------------------------------

BW_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

if ! declare -F log_info >/dev/null 2>&1 && [[ -f "$BW_SCRIPT_DIR/../lib/common.sh" ]]; then
    # shellcheck source=/dev/null
    source "$BW_SCRIPT_DIR/../lib/common.sh"
fi

if [[ -f "$BW_SCRIPT_DIR/../lib/os_detect.sh" ]] && ! declare -F detect_system_info >/dev/null 2>&1; then
    # shellcheck source=/dev/null
    source "$BW_SCRIPT_DIR/../lib/os_detect.sh"
fi

# Standalone fallback if common.sh is unavailable
if ! declare -F log_info >/dev/null 2>&1; then
    _BW_NC='\033[0m'
    _BW_RED='\033[0;31m'
    _BW_GREEN='\033[0;32m'
    _BW_ORANGE='\033[38;5;208m'
    _BW_AQUA='\033[38;5;45m'
    _BW_CYAN='\033[0;36m'

    function _bw_emit {
        local level="$1" color="$2"
        shift 2 || true
        printf '%b[%s]%b %s - %s\n' "$color" "$level" "$_BW_NC" "$(date +"%Y-%m-%d %H:%M:%S")" "$*"
    }

    function log_info    { _bw_emit "INFO"    "$_BW_AQUA"   "$@"; }
    function log_success { _bw_emit "SUCCESS" "$_BW_GREEN"  "$@"; }
    function log_warning { _bw_emit "WARNING" "$_BW_ORANGE" "$@"; }
    function log_error   { _bw_emit "ERROR"   "$_BW_RED"    "$@"; }
    function print_banner {
        echo -e "${_BW_CYAN}"
        echo "================================================"
        echo "   $1"
        echo "================================================"
        echo -e "${_BW_NC}"
    }
fi

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BW_VERSION="1.6.8"
BW_INSTALL_URL="https://github.com/bunkerity/bunkerweb/releases/download/v${BW_VERSION}/install-bunkerweb.sh"
BW_SHA256_URL="${BW_INSTALL_URL}.sha256"
BW_CONF_DIR="/etc/bunkerweb"
BW_VARIABLES="${BW_CONF_DIR}/variables.env"
BW_SERVICE="bunkerweb"
BW_SCHEDULER_SERVICE="bunkerweb-scheduler"
BW_UI_SERVICE="bunkerweb-ui"
BW_BACKEND_BASE_PORT=8080
BW_BACKEND_PORT_MAX=9999
BW_BACKUP_PREFIX="/var/backups/bunkerweb-migration"

# CSP profiles -- CCDC-safe default allows inline scripts/styles for CMS compat
BW_CSP_CCDC="default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https:; font-src 'self' data: https:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; frame-ancestors 'self'; form-action 'self' https:"
BW_CSP_STRICT="default-src 'self'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'"
BW_CSP_OFF=""

# Supported distros for BunkerWeb 1.6.8
declare -a BW_SUPPORTED_DISTRO_LIST=(
    "ubuntu:22.04" "ubuntu:24.04"
    "debian:12" "debian:13"
    "rhel:8" "rhel:9" "rhel:10"
    "rocky:8" "rocky:9" "rocky:10"
    "almalinux:8" "almalinux:9" "almalinux:10"
    "centos:8" "centos:9"
    "fedora:42" "fedora:43"
)

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

function bw_backup_file {
    local src="$1"
    [[ -f "$src" ]] || return 0
    local dest="${BW_BACKUP_DIR}${src}"
    sudo mkdir -p "$(dirname "$dest")"
    sudo cp -a "$src" "$dest"
    log_info "Backed up $src"
}

function bw_get_primary_ip {
    local ip=""
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    if [[ -n "$ip" ]]; then
        printf '%s' "$ip"
        return 0
    fi

    if command -v ip >/dev/null 2>&1; then
        ip="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
        if [[ -n "$ip" ]]; then
            printf '%s' "$ip"
            return 0
        fi
    fi

    return 1
}

function bw_pkg_install {
    local pkg_manager="${pm:-}"

    if [[ -z "$pkg_manager" ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            pkg_manager="apt-get"
        elif command -v dnf >/dev/null 2>&1; then
            pkg_manager="dnf"
        elif command -v yum >/dev/null 2>&1; then
            pkg_manager="yum"
        elif command -v zypper >/dev/null 2>&1; then
            pkg_manager="zypper"
        else
            log_error "No supported package manager found (apt-get, dnf, yum, zypper)."
            return 1
        fi
    fi

    case "$pkg_manager" in
        apt-get)
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
            ;;
        dnf|yum)
            sudo "$pkg_manager" install -y "$@"
            ;;
        zypper)
            sudo zypper --non-interactive install "$@"
            ;;
    esac
}

function bw_pkg_update {
    if [[ -n "${pm:-}" ]]; then
        case "$pm" in
            apt-get) sudo apt-get update -qq ;;
            dnf|yum) sudo "$pm" makecache -y >/dev/null 2>&1 ;;
            zypper)  sudo zypper refresh >/dev/null 2>&1 ;;
        esac
        return
    fi

    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf makecache -y >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        sudo yum makecache -y >/dev/null 2>&1
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper refresh >/dev/null 2>&1
    fi
}

function bw_service_restart {
    local svc="$1"
    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl restart "$svc"
    elif command -v service >/dev/null 2>&1; then
        sudo service "$svc" restart
    else
        log_error "Cannot restart $svc: no init system found."
        return 1
    fi
}

function bw_service_enable {
    local svc="$1"
    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl enable "$svc" 2>/dev/null || true
    fi
}

function bw_service_stop {
    local svc="$1"
    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl stop "$svc" 2>/dev/null || true
    elif command -v service >/dev/null 2>&1; then
        sudo service "$svc" stop 2>/dev/null || true
    fi
}

function bw_service_is_active {
    local svc="$1"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active "$svc" >/dev/null 2>&1
    else
        service "$svc" status >/dev/null 2>&1
    fi
}

function bw_sanitize_hostname {
    local raw="$1"
    local clean
    clean="$(printf '%s' "$raw" | tr -d '[:space:]' | tr -d '\r' | sed 's/\.$//')"

    if [[ -z "$clean" ]]; then
        return 1
    fi

    # Security: reject path traversal characters
    if [[ "$clean" == */* ]] || [[ "$clean" == ".." ]] || [[ "$clean" == "." ]]; then
        log_warning "Hostname '$clean' contains path traversal characters; skipping"
        return 1
    fi

    # Reject wildcards
    if [[ "$clean" == *\** ]]; then
        log_warning "Wildcard hostname '$clean' not supported; skipping"
        return 1
    fi

    # Underscores break BunkerWeb variable prefixes; replace with hyphens
    if [[ "$clean" == *_* ]]; then
        log_warning "Hostname '$clean' contains underscores; replacing with hyphens for BunkerWeb compatibility"
        clean="${clean//_/-}"
    fi

    # Validate: only allow alphanumeric, hyphens, dots
    if ! [[ "$clean" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        log_warning "Hostname '$clean' contains invalid characters; skipping"
        return 1
    fi

    # Reject overly long hostnames (DNS max is 253)
    if [[ ${#clean} -gt 253 ]]; then
        log_warning "Hostname '$clean' exceeds 253 characters; skipping"
        return 1
    fi

    printf '%s' "$clean"
}

function bw_check_port_available {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ! ss -tln 2>/dev/null | grep -qE "[: ]${port}\b"
    elif command -v netstat >/dev/null 2>&1; then
        ! sudo netstat -tln 2>/dev/null | grep -qE ":${port}\s"
    else
        return 0
    fi
}

function bw_find_free_port {
    local port="$1"
    local used_ports="${2:-}"

    while true; do
        if [[ $port -gt $BW_BACKEND_PORT_MAX ]]; then
            log_error "No free ports found in range ${BW_BACKEND_BASE_PORT}-${BW_BACKEND_PORT_MAX}"
            return 1
        fi

        # Check against already-assigned ports
        if [[ " $used_ports " == *" $port "* ]]; then
            ((port++))
            continue
        fi

        # Check if port is actually in use on the system
        if ! bw_check_port_available "$port"; then
            log_info "Port $port in use, trying next..."
            ((port++))
            continue
        fi

        echo "$port"
        return 0
    done
}

# Helper: check listening ports with ss or netstat fallback
function bw_check_listening {
    local pattern="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -qE "$pattern"
    elif command -v netstat >/dev/null 2>&1; then
        sudo netstat -tln 2>/dev/null | awk 'NR>2 {print $4}' | grep -qE "$pattern"
    else
        return 1
    fi
}

# Helper: get process name on a port
function bw_get_port_process {
    local port="$1"
    local proc=""

    if command -v ss >/dev/null 2>&1; then
        proc="$(ss -ltnp "( sport = :${port} )" 2>/dev/null | awk '
            /users:\(\(/ {
                match($0, /users:\(\("([^"]+)"/, m)
                if (m[1] != "") { print m[1]; exit }
            }'
        )"
    elif command -v netstat >/dev/null 2>&1; then
        proc="$(sudo netstat -tlnp 2>/dev/null | awk -v p=":${port}" '$4 ~ p"$" {print $NF; exit}')"
    fi

    echo "${proc:-unknown}"
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

function bw_check_distro_support {
    local os_id="" os_version_id="" os_major=""

    if [[ -f /etc/os-release ]]; then
        os_id="$(. /etc/os-release && echo "${ID:-}")"
        os_version_id="$(. /etc/os-release && echo "${VERSION_ID:-}")"
    fi

    if [[ -z "$os_id" ]]; then
        log_warning "Cannot determine OS from /etc/os-release. Proceeding anyway."
        return 0
    fi

    # Extract major version (e.g., "22.04" -> "22.04", "9.3" -> "9")
    os_major="${os_version_id%%.*}"

    local found=false
    local entry
    for entry in "${BW_SUPPORTED_DISTRO_LIST[@]}"; do
        local d_id="${entry%%:*}"
        local d_ver="${entry#*:}"

        if [[ "$os_id" == "$d_id" ]]; then
            # For Ubuntu: match full version (22.04, 24.04)
            if [[ "$os_id" == "ubuntu" ]]; then
                [[ "$os_version_id" == "$d_ver" ]] && found=true && break
            else
                # For others: match major version
                [[ "$os_major" == "${d_ver%%.*}" ]] && found=true && break
            fi
        fi

        # Handle ID_LIKE (e.g., Rocky -> rhel)
        if [[ -f /etc/os-release ]]; then
            local id_like
            id_like="$(. /etc/os-release && echo "${ID_LIKE:-}")"
            for like_id in $id_like; do
                if [[ "$like_id" == "$d_id" ]] && [[ "$os_major" == "${d_ver%%.*}" ]]; then
                    found=true
                    break 2
                fi
            done
        fi
    done

    if [[ "$found" == false ]]; then
        log_error "BunkerWeb ${BW_VERSION} does not have packages for: ${os_id} ${os_version_id}"
        log_error "Supported: Ubuntu 22.04/24.04, Debian 12+, RHEL/Rocky/Alma 8/9, Fedora 42+"
        log_error "Aborting to prevent leaving the system in a broken state."
        return 1
    fi

    log_info "Distro check passed: ${os_id} ${os_version_id}"
    return 0
}

function bw_preflight {
    print_banner "Pre-flight Checks"

    # Require root or passwordless sudo
    if [[ "$EUID" -ne 0 ]] && ! sudo -n true 2>/dev/null; then
        log_error "This script requires root privileges. Run with sudo."
        return 1
    fi

    # Check distro support
    if ! bw_check_distro_support; then
        return 1
    fi

    log_success "Pre-flight checks passed."
}

# ---------------------------------------------------------------------------
# Phase 2: Detect backend web server and virtual hosts
# ---------------------------------------------------------------------------

function bw_detect_backend_server {
    print_banner "Phase 2a: Detecting Backend Web Server"

    BW_BACKEND_SERVER=""
    BW_BACKEND_SERVICE=""
    BW_BACKEND_CONF_DIR=""

    # Check Apache
    if command -v apache2ctl >/dev/null 2>&1 || command -v apachectl >/dev/null 2>&1; then
        if [[ -d "/etc/apache2" ]]; then
            BW_BACKEND_SERVER="apache"
            BW_BACKEND_SERVICE="apache2"
            BW_BACKEND_CONF_DIR="/etc/apache2"
        elif [[ -d "/etc/httpd" ]]; then
            BW_BACKEND_SERVER="apache"
            BW_BACKEND_SERVICE="httpd"
            BW_BACKEND_CONF_DIR="/etc/httpd"
        fi
    fi

    # Check Nginx (only if Apache not found)
    if [[ -z "$BW_BACKEND_SERVER" ]]; then
        if command -v nginx >/dev/null 2>&1 && [[ -d "/etc/nginx" ]]; then
            BW_BACKEND_SERVER="nginx"
            BW_BACKEND_SERVICE="nginx"
            BW_BACKEND_CONF_DIR="/etc/nginx"
        fi
    fi

    # Fallback: probe port 80 to identify the bound process
    if [[ -z "$BW_BACKEND_SERVER" ]]; then
        local port80_proc=""
        port80_proc="$(bw_get_port_process 80)"

        case "${port80_proc,,}" in
            *apache*|*httpd*)
                BW_BACKEND_SERVER="apache"
                if [[ -d "/etc/apache2" ]]; then
                    BW_BACKEND_SERVICE="apache2"
                    BW_BACKEND_CONF_DIR="/etc/apache2"
                else
                    BW_BACKEND_SERVICE="httpd"
                    BW_BACKEND_CONF_DIR="/etc/httpd"
                fi
                ;;
            *nginx*)
                BW_BACKEND_SERVER="nginx"
                BW_BACKEND_SERVICE="nginx"
                BW_BACKEND_CONF_DIR="/etc/nginx"
                ;;
        esac
    fi

    if [[ -z "$BW_BACKEND_SERVER" ]]; then
        log_warning "No local web server (Apache or Nginx) detected."
        log_warning "If you want to protect remote backends, use --remote or --hybrid mode."
        return 1
    fi

    log_success "Detected backend: $BW_BACKEND_SERVER (service=$BW_BACKEND_SERVICE, config=$BW_BACKEND_CONF_DIR)"
}

function bw_detect_apache_vhosts {
    local used_ports=""
    local vhost_files=()
    local deferred_default_files=()

    # Debian-style: sites-enabled
    if [[ -d "${BW_BACKEND_CONF_DIR}/sites-enabled" ]]; then
        while IFS= read -r -d '' f; do
            vhost_files+=("$f")
        done < <(find "${BW_BACKEND_CONF_DIR}/sites-enabled" \( -type f -o -type l \) -print0 2>/dev/null)
    fi

    # RHEL-style: conf.d
    if [[ -d "${BW_BACKEND_CONF_DIR}/conf.d" ]]; then
        while IFS= read -r -d '' f; do
            vhost_files+=("$f")
        done < <(find "${BW_BACKEND_CONF_DIR}/conf.d" -name "*.conf" -type f -print0 2>/dev/null)
    fi

    for vhost_file in "${vhost_files[@]}"; do
        [[ -f "$vhost_file" ]] || continue

        local basename_file
        basename_file="$(basename "$vhost_file")"

        # Defer default sites. They may be the only real site.
        case "$basename_file" in
            000-default*|default-ssl*)
                deferred_default_files+=("$vhost_file")
                log_info "Deferring default vhost for fallback handling: $basename_file"
                continue
                ;;
            *phpmyadmin*|*adminer*|*status*|autoindex*|ssl.conf)
                log_info "Skipping non-essential vhost: $basename_file"
                continue
                ;;
        esac

        # Extract ServerName
        local server_name=""
        server_name="$(grep -i '^\s*ServerName' "$vhost_file" 2>/dev/null | head -1 | awk '{print $2}')"
        server_name="$(bw_sanitize_hostname "${server_name:-}" 2>/dev/null)" || true

        # Fall back to filename if no ServerName directive
        if [[ -z "$server_name" ]]; then
            server_name="${basename_file%.conf}"
            server_name="${server_name%.vhost}"
            server_name="$(bw_sanitize_hostname "$server_name" 2>/dev/null)" || true
        fi

        [[ -z "$server_name" ]] && continue

        # Dedup across sites-enabled and conf.d
        if [[ -n "${BW_DETECTED_SITES[$server_name]+x}" ]]; then
            continue
        fi

        # Check if already rebound to loopback (idempotency)
        local existing_port=""
        existing_port="$(grep -oE '<VirtualHost\s+127\.0\.0\.1:[0-9]+' "$vhost_file" 2>/dev/null \
            | head -1 | grep -oE '[0-9]+$')"

        if [[ -n "$existing_port" ]]; then
            BW_DETECTED_SITES["$server_name"]="${existing_port}|${vhost_file}|rebound"
            used_ports="$used_ports $existing_port"
            log_info "Found vhost (already rebound): $server_name -> 127.0.0.1:${existing_port}"
        else
            local port
            port="$(bw_find_free_port "$BW_BACKEND_BASE_PORT" "$used_ports")" || return 1
            BW_DETECTED_SITES["$server_name"]="${port}|${vhost_file}|needs_rebind"
            used_ports="$used_ports $port"
            log_info "Found vhost: $server_name -> will use backend port $port"
        fi

        # Extract ServerAlias entries and register them pointing to the same backend
        local aliases=""
        aliases="$(grep -i '^\s*ServerAlias' "$vhost_file" 2>/dev/null | sed 's/[Ss]erver[Aa]lias//;s/^\s*//' | tr '\n' ' ')"
        for alias_raw in $aliases; do
            local alias_name
            alias_name="$(bw_sanitize_hostname "$alias_raw" 2>/dev/null)" || continue
            [[ -z "$alias_name" ]] && continue
            [[ -n "${BW_DETECTED_SITES[$alias_name]+x}" ]] && continue

            local site_data="${BW_DETECTED_SITES[$server_name]}"
            local port="${site_data%%|*}"
            BW_DETECTED_SITES["$alias_name"]="${port}|${vhost_file}|alias"
            log_info "  Alias: $alias_name -> same backend port $port"
        done
    done

    # Fallback: if no explicit vhosts found, use the deferred default site
    if [[ ${#BW_DETECTED_SITES[@]} -eq 0 ]]; then
        local default_file=""
        local f
        for f in "${deferred_default_files[@]}"; do
            if [[ -f "$f" ]]; then
                default_file="$f"
                break
            fi
        done

        # Debian fallback if sites-enabled symlink is missing
        if [[ -z "$default_file" && -f "${BW_BACKEND_CONF_DIR}/sites-available/000-default.conf" ]]; then
            default_file="${BW_BACKEND_CONF_DIR}/sites-available/000-default.conf"
        fi

        if [[ -n "$default_file" ]]; then
            local port
            port="$(bw_find_free_port "$BW_BACKEND_BASE_PORT" "$used_ports")" || return 1

            local primary_ip=""
            primary_ip="$(bw_get_primary_ip 2>/dev/null || true)"

            if [[ -n "$primary_ip" ]]; then
                BW_DETECTED_SITES["$primary_ip"]="${port}|${default_file}|needs_rebind"
                log_warning "No explicit vhosts found. Using default Apache site for IP access: ${primary_ip} -> port ${port}"
            else
                local hostname_val=""
                hostname_val="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "localhost")"
                hostname_val="$(bw_sanitize_hostname "$hostname_val" 2>/dev/null)" || hostname_val="localhost"
                BW_DETECTED_SITES["$hostname_val"]="${port}|${default_file}|needs_rebind"
                log_warning "No explicit vhosts found. Using default Apache site: ${hostname_val} -> port ${port}"
            fi

            # Add hostname alias too (same backend)
            local host_alias=""
            host_alias="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
            host_alias="$(bw_sanitize_hostname "${host_alias:-}" 2>/dev/null)" || true
            if [[ -n "$host_alias" && -z "${BW_DETECTED_SITES[$host_alias]+x}" ]]; then
                local seed_key=""
                for seed_key in "${!BW_DETECTED_SITES[@]}"; do
                    local seed_data="${BW_DETECTED_SITES[$seed_key]}"
                    local seed_status="${seed_data##*|}"
                    [[ "$seed_status" == "remote" ]] && continue
                    BW_DETECTED_SITES["$host_alias"]="${seed_data%%|*}|${default_file}|alias"
                    break
                done
            fi
        else
            # Last resort synthetic catch-all (unsafe for automated rebind, but preserved as fallback)
            local hostname_val=""
            hostname_val="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "localhost")"
            hostname_val="$(bw_sanitize_hostname "$hostname_val" 2>/dev/null)" || hostname_val="localhost"
            local port
            port="$(bw_find_free_port "$BW_BACKEND_BASE_PORT" "")" || return 1
            BW_DETECTED_SITES["$hostname_val"]="${port}||needs_rebind"
            log_warning "No explicit/default Apache vhost file found. Using synthetic catch-all: $hostname_val -> port $port"
        fi
    fi
}

function bw_detect_nginx_server_blocks {
    local used_ports=""
    local block_files=()

    if [[ -d "${BW_BACKEND_CONF_DIR}/sites-enabled" ]]; then
        while IFS= read -r -d '' f; do
            block_files+=("$f")
        done < <(find "${BW_BACKEND_CONF_DIR}/sites-enabled" \( -type f -o -type l \) -print0 2>/dev/null)
    fi

    if [[ -d "${BW_BACKEND_CONF_DIR}/conf.d" ]]; then
        while IFS= read -r -d '' f; do
            block_files+=("$f")
        done < <(find "${BW_BACKEND_CONF_DIR}/conf.d" -name "*.conf" -type f -print0 2>/dev/null)
    fi

    for block_file in "${block_files[@]}"; do
        [[ -f "$block_file" ]] || continue

        local basename_file
        basename_file="$(basename "$block_file")"

        case "$basename_file" in
            default|default.conf|*phpmyadmin*|*adminer*)
                log_info "Skipping non-essential block: $basename_file"
                continue
                ;;
        esac

        # Extract server_name directive (first name only)
        local server_name=""
        server_name="$(grep -i '^\s*server_name' "$block_file" 2>/dev/null | head -1 \
            | sed 's/.*server_name\s\+//;s/\s*;.*//' | awk '{print $1}')"
        server_name="$(bw_sanitize_hostname "${server_name:-}" 2>/dev/null)" || true

        if [[ -z "$server_name" ]] || [[ "$server_name" == "_" ]]; then
            server_name="${basename_file%.conf}"
            server_name="$(bw_sanitize_hostname "$server_name" 2>/dev/null)" || true
        fi

        [[ -z "$server_name" ]] && continue

        if [[ -n "${BW_DETECTED_SITES[$server_name]+x}" ]]; then
            continue
        fi

        local existing_port=""
        existing_port="$(grep -oE 'listen\s+127\.0\.0\.1:[0-9]+' "$block_file" 2>/dev/null \
            | head -1 | grep -oE '[0-9]+$')"
        if [[ -n "$existing_port" ]]; then
            BW_DETECTED_SITES["$server_name"]="${existing_port}|${block_file}|rebound"
            used_ports="$used_ports $existing_port"
            log_info "Found server block (already rebound): $server_name -> 127.0.0.1:${existing_port}"
        else
            local port
            port="$(bw_find_free_port "$BW_BACKEND_BASE_PORT" "$used_ports")" || return 1
            BW_DETECTED_SITES["$server_name"]="${port}|${block_file}|needs_rebind"
            used_ports="$used_ports $port"
            log_info "Found server block: $server_name -> will use backend port $port"
        fi

        # Extract additional server_name entries (aliases)
        local all_names
        all_names="$(grep -i '^\s*server_name' "$block_file" 2>/dev/null | head -1 \
            | sed 's/.*server_name\s\+//;s/\s*;.*//')"
        local idx=0
        for name_raw in $all_names; do
            ((idx++))
            [[ $idx -le 1 ]] && continue  # Skip primary name
            local alias_name
            alias_name="$(bw_sanitize_hostname "$name_raw" 2>/dev/null)" || continue
            [[ -z "$alias_name" || "$alias_name" == "_" ]] && continue
            [[ -n "${BW_DETECTED_SITES[$alias_name]+x}" ]] && continue

            local site_data="${BW_DETECTED_SITES[$server_name]}"
            local port="${site_data%%|*}"
            BW_DETECTED_SITES["$alias_name"]="${port}|${block_file}|alias"
            log_info "  Alias: $alias_name -> same backend port $port"
        done
    done

    if [[ ${#BW_DETECTED_SITES[@]} -eq 0 ]]; then
        local hostname_val
        hostname_val="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "localhost")"
        hostname_val="$(bw_sanitize_hostname "$hostname_val" 2>/dev/null)" || hostname_val="localhost"
        local port
        port="$(bw_find_free_port "$BW_BACKEND_BASE_PORT" "")" || return 1
        BW_DETECTED_SITES["$hostname_val"]="${port}||needs_rebind"
        log_warning "No explicit server blocks found. Using catch-all: $hostname_val -> port $port"
    fi
}

function bw_detect_virtual_hosts {
    print_banner "Phase 2b: Enumerating Virtual Hosts"

    case "$BW_BACKEND_SERVER" in
        apache) bw_detect_apache_vhosts || return 1 ;;
        nginx)  bw_detect_nginx_server_blocks || return 1 ;;
    esac

    local site_key
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        local site_data="${BW_DETECTED_SITES[$site_key]}"
        local status="${site_data##*|}"
        local rem="${site_data#*|}"
        local conf_file="${rem%%|*}"
        if [[ "$status" == "needs_rebind" && ( -z "$conf_file" || ! -f "$conf_file" ) ]]; then
            log_warning "Site '$site_key' has no backing config file and may fail rebinding."
        fi
    done

    log_success "Detected ${#BW_DETECTED_SITES[@]} site(s) to protect"
}
# ---------------------------------------------------------------------------
# Remote backend support
# ---------------------------------------------------------------------------

function bw_add_remote_site {
    local hostname="$1"
    local backend_url="$2"
    local csp_profile="${3:-ccdc}"
    local antibot="${4:-no}"

    hostname="$(bw_sanitize_hostname "$hostname")" || return 1

    if [[ -n "${BW_DETECTED_SITES[$hostname]+x}" ]]; then
        log_warning "Site '$hostname' already registered; skipping duplicate."
        return 0
    fi

    BW_DETECTED_SITES["$hostname"]="${backend_url}||remote"
    BW_SITE_CSP["$hostname"]="$csp_profile"
    BW_SITE_ANTIBOT["$hostname"]="$antibot"

    log_info "Added remote backend: $hostname -> $backend_url (CSP=$csp_profile, antibot=$antibot)"
}

function bw_interactive_add_remotes {
    print_banner "Remote Backend Configuration"
    log_info "Add remote backends (e.g., Windows IIS servers on the network)."
    log_info "BunkerWeb on this machine will proxy traffic to them."
    echo ""

    while true; do
        local add_more="n"
        read -r -p "Add a remote backend? [y/N]: " add_more
        [[ "${add_more,,}" == "y" ]] || break

        local hostname="" backend_url=""
        read -r -p "  Hostname (as seen by clients, e.g., iis-app.example.com): " hostname
        read -r -p "  Backend URL (e.g., http://10.0.0.5:80): " backend_url

        if [[ -z "$hostname" || -z "$backend_url" ]]; then
            log_warning "Hostname and backend URL are required. Skipping."
            continue
        fi

        # Test connectivity
        local remote_host remote_port
        remote_host="$(echo "$backend_url" | sed -E 's|https?://||;s|:.*||;s|/.*||')"
        remote_port="$(echo "$backend_url" | grep -oE ':[0-9]+' | tr -d ':' | head -1)"
        remote_port="${remote_port:-80}"

        if timeout 5 bash -c "echo >/dev/tcp/${remote_host}/${remote_port}" 2>/dev/null; then
            log_success "  Connectivity OK: $remote_host:$remote_port"
        else
            log_warning "  Cannot reach $remote_host:$remote_port (network may not be ready). Adding anyway."
        fi

        echo "  CSP profile:"
        echo "    1) ccdc        - Permissive (CMS-safe, allows inline JS/CSS) (Recommended)"
        echo "    2) strict      - Tight CSP (static sites only)"
        echo "    3) off         - No CSP header (maximum compatibility)"
        local csp_choice=""
        read -r -p "  Select [1-3, default=1]: " csp_choice
        local csp_profile="ccdc"
        case "$csp_choice" in
            2) csp_profile="strict" ;;
            3) csp_profile="off" ;;
            *) csp_profile="ccdc" ;;
        esac

        echo "  Antibot challenge:"
        echo "    1) no          - No challenge (recommended for APIs/scoring) (Recommended)"
        echo "    2) cookie      - Cookie-based (no JavaScript required)"
        echo "    3) javascript  - JS challenge (breaks API clients & scoring bots)"
        local antibot_choice=""
        read -r -p "  Select [1-3, default=1]: " antibot_choice
        local antibot="no"
        case "$antibot_choice" in
            2) antibot="cookie" ;;
            3) antibot="javascript" ;;
            *) antibot="no" ;;
        esac

        bw_add_remote_site "$hostname" "$backend_url" "$csp_profile" "$antibot"
        echo ""
    done
}

function bw_parse_manifest {
    local manifest_file="$1"
    if [[ ! -f "$manifest_file" ]]; then
        log_error "Manifest not found: $manifest_file"
        return 1
    fi

    log_info "Parsing manifest: $manifest_file"
    while IFS= read -r line; do
        # Skip comments and blank lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// /}" ]] && continue

        local hostname="" backend_url="" csp_profile="" antibot=""
        read -r hostname backend_url csp_profile antibot <<< "$line"

        bw_add_remote_site "$hostname" "$backend_url" "${csp_profile:-ccdc}" "${antibot:-no}"
    done < "$manifest_file"
}

# ---------------------------------------------------------------------------
# Phase 3: Install BunkerWeb (runs BEFORE rebinding for safety)
# ---------------------------------------------------------------------------

function bw_install_via_official_script {
    log_info "Attempting BunkerWeb installation via official install script (v${BW_VERSION})..."

    bw_pkg_install curl ca-certificates

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    local installer="${tmp_dir}/install-bunkerweb.sh"
    local checksum_file="${tmp_dir}/install-bunkerweb.sh.sha256"
    local rc=0

    if ! curl -fsSL -o "$installer" "$BW_INSTALL_URL" 2>/dev/null; then
        log_warning "Failed to download official install script from GitHub."
        rm -rf "$tmp_dir"
        return 1
    fi

    if ! curl -fsSL -o "$checksum_file" "$BW_SHA256_URL" 2>/dev/null; then
        log_warning "Failed to download SHA256 checksum. Skipping official installer."
        rm -rf "$tmp_dir"
        return 1
    fi

    if ! (cd "$tmp_dir" && sha256sum -c "install-bunkerweb.sh.sha256" >/dev/null 2>&1); then
        log_warning "SHA256 verification failed. Skipping official installer."
        rm -rf "$tmp_dir"
        return 1
    fi

    chmod +x "$installer"
    if ! sudo "$installer" 2>&1; then
        log_warning "Official install script exited with errors."
        rc=1
    fi

    rm -rf "$tmp_dir"
    return $rc
}

function bw_install_via_packagecloud_deb {
    log_info "Falling back to packagecloud repository (Debian/Ubuntu)..."

    bw_pkg_install curl gnupg2 ca-certificates lsb-release apt-transport-https

    local codename=""
    if command -v lsb_release >/dev/null 2>&1; then
        codename="$(lsb_release -sc 2>/dev/null)"
    fi
    if [[ -z "$codename" ]] && [[ -f /etc/os-release ]]; then
        codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
    fi

    curl -fsSL https://packagecloud.io/bunkerity/bunkerweb/gpgkey \
        | sudo gpg --dearmor -o /usr/share/keyrings/bunkerweb-archive-keyring.gpg 2>/dev/null || true

    local distro_id="ubuntu"
    if [[ -f /etc/os-release ]]; then
        distro_id="$(. /etc/os-release && echo "${ID:-ubuntu}")"
    fi

    echo "deb [signed-by=/usr/share/keyrings/bunkerweb-archive-keyring.gpg] https://packagecloud.io/bunkerity/bunkerweb/${distro_id}/ ${codename:-jammy} main" \
        | sudo tee /etc/apt/sources.list.d/bunkerweb.list >/dev/null

    sudo apt-get update -qq

    # Pin to specific version
    if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "bunkerweb=${BW_VERSION}*" 2>/dev/null; then
        log_warning "Version-pinned install failed. Trying latest available..."
        if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y bunkerweb; then
            log_error "apt install of bunkerweb failed."
            return 1
        fi
    fi
}

function bw_install_via_packagecloud_rpm {
    log_info "Falling back to packagecloud repository (RHEL/Fedora)..."

    bw_pkg_install curl

    # Determine correct repo URL (el/ for RHEL-like, fedora/ for Fedora)
    local os_id=""
    [[ -f /etc/os-release ]] && os_id="$(. /etc/os-release && echo "${ID:-}")"

    local baseurl_path="el/\$releasever/\$basearch"
    if [[ "$os_id" == "fedora" ]]; then
        baseurl_path="fedora/\$releasever/\$basearch"
    fi

    local yum_repo="/etc/yum.repos.d/bunkerweb.repo"
    if [[ ! -f "$yum_repo" ]]; then
        sudo tee "$yum_repo" >/dev/null <<REPO
[bunkerweb]
name=BunkerWeb
baseurl=https://packagecloud.io/bunkerity/bunkerweb/${baseurl_path}
repo_gpgcheck=1
gpgcheck=0
enabled=1
gpgkey=https://packagecloud.io/bunkerity/bunkerweb/gpgkey
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
REPO
        log_info "Added BunkerWeb yum/dnf repo."
    fi

    local pkg_mgr="yum"
    command -v dnf >/dev/null 2>&1 && pkg_mgr="dnf"

    # Pin to specific version
    if ! sudo "$pkg_mgr" install -y "bunkerweb-${BW_VERSION}" 2>/dev/null; then
        log_warning "Version-pinned install failed. Trying latest available..."
        if ! sudo "$pkg_mgr" install -y bunkerweb; then
            log_error "$pkg_mgr install of bunkerweb failed."
            return 1
        fi
    fi
}

function bw_install_bunkerweb {
    print_banner "Phase 3: Installing BunkerWeb"

    # Skip if already installed with a compatible version
    if [[ -f "/usr/share/bunkerweb/VERSION" ]]; then
        local installed_ver
        installed_ver="$(cat /usr/share/bunkerweb/VERSION 2>/dev/null || echo "unknown")"
        local installed_major="${installed_ver%%.*}"
        local target_major="${BW_VERSION%%.*}"
        if [[ "$installed_major" == "$target_major" ]]; then
            log_info "BunkerWeb already installed (version: $installed_ver). Skipping installation."
            return 0
        else
            log_warning "BunkerWeb $installed_ver is installed but v${BW_VERSION} is expected."
            log_warning "Proceeding with reinstall..."
        fi
    fi

    bw_pkg_update

    # Try official install script first, fall back to packagecloud
    if bw_install_via_official_script; then
        log_success "BunkerWeb installed via official script."
    else
        log_info "Official install script unavailable. Trying packagecloud..."
        if command -v apt-get >/dev/null 2>&1; then
            bw_install_via_packagecloud_deb || return 1
        elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
            bw_install_via_packagecloud_rpm || return 1
        else
            log_error "Unsupported package manager. BunkerWeb requires apt, dnf, or yum."
            return 1
        fi
    fi

    # Verify the service exists (use systemctl cat which returns non-zero if not found)
    if command -v systemctl >/dev/null 2>&1; then
        if ! systemctl cat "${BW_SERVICE}.service" >/dev/null 2>&1; then
            log_error "BunkerWeb service unit not found after installation."
            log_error "Check: journalctl -xe for installation errors."
            return 1
        fi
    fi

    log_success "BunkerWeb installed successfully."
}

# ---------------------------------------------------------------------------
# Phase 4: Rebind backend web server off port 80
# ---------------------------------------------------------------------------

function bw_needs_rebinding {
    local site_key
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        local site_data="${BW_DETECTED_SITES[$site_key]}"
        local status="${site_data##*|}"
        if [[ "$status" == "needs_rebind" ]]; then
            return 0
        fi
    done
    return 1
}

function bw_rebind_apache {
    print_banner "Phase 4: Rebinding Apache to Localhost-Only Ports"

    # Apache can declare listeners in multiple include files (custom hardening,
    # distro snippets, panel-managed drop-ins). If we only edit ports.conf/main
    # we can leave stray listeners on :80/:443 active and restart will fail when
    # BunkerWeb has already claimed these public ports.
    # Match common Apache forms:
    #   Listen 80
    #   Listen 443 https
    #   Listen *:80
    #   Listen 0.0.0.0:443 https
    #   Listen [::]:80
    local apache_listen_cleanup_regex='^\s*Listen\s+([^[:space:]]*:)?(80|443)(\s+https)?\s*$'

    # Backup ports.conf or main config
    if [[ -f "${BW_BACKEND_CONF_DIR}/ports.conf" ]]; then
        bw_backup_file "${BW_BACKEND_CONF_DIR}/ports.conf"
    fi

    local main_conf_file=""
    if [[ -f "${BW_BACKEND_CONF_DIR}/apache2.conf" ]]; then
        main_conf_file="${BW_BACKEND_CONF_DIR}/apache2.conf"
    elif [[ -f "${BW_BACKEND_CONF_DIR}/conf/httpd.conf" ]]; then
        main_conf_file="${BW_BACKEND_CONF_DIR}/conf/httpd.conf"
    fi
    [[ -n "$main_conf_file" ]] && bw_backup_file "$main_conf_file"

    # Also backup ssl.conf on RHEL (has Listen 443)
    local ssl_conf="${BW_BACKEND_CONF_DIR}/conf.d/ssl.conf"
    if [[ -f "$ssl_conf" ]]; then
        bw_backup_file "$ssl_conf"
        # Strip Listen 443 from ssl.conf
        sudo sed -i '/^\s*Listen\s\+443\b/d' "$ssl_conf"
        log_info "Removed Listen 443 from ssl.conf"
    fi

    # Remove public-facing Listen directives
    local ports_conf="${BW_BACKEND_CONF_DIR}/ports.conf"
    if [[ -f "$ports_conf" ]]; then
        sudo sed -i '/^\s*Listen\s\+\(80\|443\)\b/d' "$ports_conf"
        sudo sed -i '/^\s*Listen\s\+\[::\]:\(80\|443\)\b/d' "$ports_conf"

        # Add loopback listeners for each backend port (deduped)
        local ports_added=()
        local site_key
        for site_key in "${!BW_DETECTED_SITES[@]}"; do
            local site_data="${BW_DETECTED_SITES[$site_key]}"
            local status="${site_data##*|}"
            [[ "$status" == "remote" || "$status" == "alias" ]] && continue
            local port="${site_data%%|*}"
            if [[ ! " ${ports_added[*]:-} " =~ " ${port} " ]]; then
                if ! grep -q "Listen 127.0.0.1:${port}" "$ports_conf" 2>/dev/null; then
                    echo "Listen 127.0.0.1:${port}" | sudo tee -a "$ports_conf" >/dev/null
                fi
                ports_added+=("$port")
                log_info "Ensured Listen 127.0.0.1:${port} in ports.conf"
            fi
        done
    elif [[ -n "$main_conf_file" ]]; then
        # RHEL-style: modify httpd.conf directly
        sudo sed -i '/^\s*Listen\s\+\(80\|443\)\b/d' "$main_conf_file"
        sudo sed -i '/^\s*Listen\s\+\[::\]:\(80\|443\)\b/d' "$main_conf_file"
        local ports_added=()
        local site_key
        for site_key in "${!BW_DETECTED_SITES[@]}"; do
            local site_data="${BW_DETECTED_SITES[$site_key]}"
            local status="${site_data##*|}"
            [[ "$status" == "remote" || "$status" == "alias" ]] && continue
            local port="${site_data%%|*}"
            if [[ ! " ${ports_added[*]:-} " =~ " ${port} " ]]; then
                if ! grep -q "Listen 127.0.0.1:${port}" "$main_conf_file" 2>/dev/null; then
                    echo "Listen 127.0.0.1:${port}" | sudo tee -a "$main_conf_file" >/dev/null
                fi
                ports_added+=("$port")
            fi
        done
    fi

    # Safety sweep: remove public listeners from any Apache include files.
    # This catches custom snippets that are not covered by ports.conf/httpd.conf.
    local listen_files=()
    while IFS= read -r listen_file; do
        listen_files+=("$listen_file")
    done < <(sudo rg -l -g '*.conf' "$apache_listen_cleanup_regex" "$BW_BACKEND_CONF_DIR" 2>/dev/null || true)

    local listen_file
    for listen_file in "${listen_files[@]}"; do
        bw_backup_file "$listen_file"
        sudo sed -Ei "/$apache_listen_cleanup_regex/d" "$listen_file"
        log_info "Removed public Listen directives from $listen_file"
    done

    # Rewrite each VirtualHost directive to use the assigned backend port
    local site_key
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        local site_data="${BW_DETECTED_SITES[$site_key]}"
        local port="${site_data%%|*}"
        local remainder="${site_data#*|}"
        local vhost_file="${remainder%%|*}"
        local status="${site_data##*|}"

        [[ "$status" == "rebound" || "$status" == "remote" || "$status" == "alias" ]] && continue
        [[ -z "$vhost_file" || ! -f "$vhost_file" ]] && continue

        bw_backup_file "$vhost_file"

        sudo sed -Ei "s|<VirtualHost\s+[^>]*:80\s*>|<VirtualHost 127.0.0.1:${port}>|gi" "$vhost_file"
        sudo sed -Ei "s|<VirtualHost\s+[^>]*:443\s*>|<VirtualHost 127.0.0.1:${port}>|gi" "$vhost_file"

        # Disable SSL directives (backend now serves plain HTTP behind the WAF)
        sudo sed -Ei 's/^(\s*SSLEngine\s)/# BW_DISABLED: \1/gi' "$vhost_file"
        sudo sed -Ei 's/^(\s*SSLCertificate)/# BW_DISABLED: \1/gi' "$vhost_file"
        sudo sed -Ei 's/^(\s*SSLProtocol\s)/# BW_DISABLED: \1/gi' "$vhost_file"
        sudo sed -Ei 's/^(\s*SSLCipherSuite\s)/# BW_DISABLED: \1/gi' "$vhost_file"
        sudo sed -Ei 's/^(\s*SSLHonorCipherOrder\s)/# BW_DISABLED: \1/gi' "$vhost_file"

        log_info "Rewrote $vhost_file VirtualHost to 127.0.0.1:${port} (SSL directives disabled)"
    done

    # Safety check: ensure every local needs_rebind site has a real vhost file to rewrite
    local bad_rebind=false
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        local site_data="${BW_DETECTED_SITES[$site_key]}"
        local status="${site_data##*|}"
        [[ "$status" != "needs_rebind" ]] && continue

        local rem="${site_data#*|}"
        local vhost_file="${rem%%|*}"
        if [[ -z "$vhost_file" || ! -f "$vhost_file" ]]; then
            log_error "Local site '$site_key' requires rebinding but no real Apache vhost file was found to rewrite."
            bad_rebind=true
        fi
    done

    if [[ "$bad_rebind" == true ]]; then
        log_error "Aborting before Apache restart to avoid breaking the backend."
        log_error "Originals backed up to: $BW_BACKUP_DIR"
        return 1
    fi

    # Disable default vhosts ONLY if they are not the selected backend
    local using_default_vhost=false
    local site_key_scan
    for site_key_scan in "${!BW_DETECTED_SITES[@]}"; do
        local site_data_scan="${BW_DETECTED_SITES[$site_key_scan]}"
        local rem_scan="${site_data_scan#*|}"
        local vf_scan="${rem_scan%%|*}"
        if [[ "$vf_scan" == *"/000-default.conf" ]]; then
            using_default_vhost=true
            break
        fi
    done

    if [[ "$using_default_vhost" == false ]] && [[ -d "${BW_BACKEND_CONF_DIR}/sites-enabled" ]]; then
        local default_vhost
        for default_vhost in "000-default" "default-ssl"; do
            local link="${BW_BACKEND_CONF_DIR}/sites-enabled/${default_vhost}.conf"
            if [[ -L "$link" || -f "$link" ]]; then
                if command -v a2dissite >/dev/null 2>&1; then
                    sudo a2dissite "$default_vhost" >/dev/null 2>&1 || true
                else
                    sudo rm -f "$link"
                fi
                log_info "Disabled default vhost: $default_vhost"
            fi
        done
    elif [[ "$using_default_vhost" == true ]]; then
        log_info "Keeping Apache default vhost enabled because it is the selected backend site."
    fi

    # Disable admin endpoint configs
    local admin_conf
    for admin_conf in phpmyadmin adminer server-status server-info; do
        local conf_link="${BW_BACKEND_CONF_DIR}/conf-enabled/${admin_conf}.conf"
        if [[ -L "$conf_link" || -f "$conf_link" ]]; then
            if command -v a2disconf >/dev/null 2>&1; then
                sudo a2disconf "$admin_conf" >/dev/null 2>&1 || true
            else
                sudo rm -f "$conf_link"
            fi
            log_info "Disabled admin endpoint: $admin_conf"
        fi
    done

    # Validate Apache config
    local apachectl_bin=""
    if command -v apache2ctl >/dev/null 2>&1; then
        apachectl_bin="apache2ctl"
    elif command -v apachectl >/dev/null 2>&1; then
        apachectl_bin="apachectl"
    fi

    if [[ -n "$apachectl_bin" ]]; then
        if ! sudo "$apachectl_bin" configtest 2>&1; then
            log_error "Apache config test failed after rebinding."
            log_error "Originals backed up to: $BW_BACKUP_DIR"
            return 1
        fi
        log_success "Apache config test passed."
    fi

    if ! bw_service_restart "$BW_BACKEND_SERVICE"; then
        log_error "Apache failed to restart after rebinding."
        log_error "Collect diagnostics with:"
        log_error "  systemctl status ${BW_BACKEND_SERVICE} --no-pager -l"
        log_error "  journalctl -xeu ${BW_BACKEND_SERVICE} --no-pager | tail -100"
        log_error "  apache2ctl -t && apache2ctl -S"
        log_error "  grep -Rin '^[[:space:]]*Listen' ${BW_BACKEND_CONF_DIR}"
        log_error "  grep -Rin '<VirtualHost' ${BW_BACKEND_CONF_DIR}/sites-enabled ${BW_BACKEND_CONF_DIR}/conf-enabled 2>/dev/null"
        log_error "Originals backed up to: $BW_BACKUP_DIR"
        return 1
    fi
    log_success "Apache restarted on loopback-only backend ports."
}

function bw_rebind_nginx {
    print_banner "Phase 4: Rebinding Nginx to Localhost-Only Ports"

    local site_key
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        local site_data="${BW_DETECTED_SITES[$site_key]}"
        local port="${site_data%%|*}"
        local remainder="${site_data#*|}"
        local block_file="${remainder%%|*}"
        local status="${site_data##*|}"

        [[ "$status" == "rebound" || "$status" == "remote" || "$status" == "alias" ]] && continue
        [[ -z "$block_file" || ! -f "$block_file" ]] && continue

        bw_backup_file "$block_file"

        sudo sed -Ei "s|listen\s+80\b[^;]*;|listen 127.0.0.1:${port};|gi" "$block_file"
        sudo sed -Ei "s|listen\s+\[::\]:80\b[^;]*;|listen 127.0.0.1:${port};|gi" "$block_file"
        sudo sed -Ei "s|listen\s+443\b[^;]*;|listen 127.0.0.1:${port};|gi" "$block_file"
        sudo sed -Ei "s|listen\s+\[::\]:443\b[^;]*;|listen 127.0.0.1:${port};|gi" "$block_file"

        # Disable SSL directives (backend now serves plain HTTP behind the WAF)
        sudo sed -Ei 's/^(\s*ssl_certificate)/# BW_DISABLED: \1/gi' "$block_file"
        sudo sed -Ei 's/^(\s*ssl_certificate_key)/# BW_DISABLED: \1/gi' "$block_file"
        sudo sed -Ei 's/^(\s*ssl_protocols\s)/# BW_DISABLED: \1/gi' "$block_file"
        sudo sed -Ei 's/^(\s*ssl_ciphers\s)/# BW_DISABLED: \1/gi' "$block_file"
        sudo sed -Ei 's/^(\s*ssl_prefer_server_ciphers\s)/# BW_DISABLED: \1/gi' "$block_file"
        sudo sed -Ei 's/^(\s*ssl_session)/# BW_DISABLED: \1/gi' "$block_file"

        log_info "Rewrote $block_file listen directives to 127.0.0.1:${port} (SSL disabled)"
    done

    # Safety check: ensure every local needs_rebind site has a real nginx server block file
    local bad_rebind=false
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        local site_data="${BW_DETECTED_SITES[$site_key]}"
        local status="${site_data##*|}"
        [[ "$status" != "needs_rebind" ]] && continue

        local rem="${site_data#*|}"
        local block_file="${rem%%|*}"
        if [[ -z "$block_file" || ! -f "$block_file" ]]; then
            log_error "Local site '$site_key' requires rebinding but no real Nginx config file was found to rewrite."
            bad_rebind=true
        fi
    done

    if [[ "$bad_rebind" == true ]]; then
        log_error "Aborting before Nginx restart to avoid breaking the backend."
        log_error "Originals backed up to: $BW_BACKUP_DIR"
        return 1
    fi

    # Disable default blocks
    local default_block
    for default_block in "default" "default.conf"; do
        local link="${BW_BACKEND_CONF_DIR}/sites-enabled/${default_block}"
        if [[ -L "$link" || -f "$link" ]]; then
            bw_backup_file "$link"
            sudo rm -f "$link"
            log_info "Removed default nginx block: $default_block"
        fi
    done

    local default_confd="${BW_BACKEND_CONF_DIR}/conf.d/default.conf"
    if [[ -f "$default_confd" ]]; then
        bw_backup_file "$default_confd"
        sudo mv "$default_confd" "${default_confd}.disabled"
        log_info "Disabled default conf.d block"
    fi

    if ! sudo nginx -t 2>&1; then
        log_error "Nginx config test failed after rebinding."
        log_error "Originals backed up to: $BW_BACKUP_DIR"
        return 1
    fi
    log_success "Nginx config test passed."

    if ! bw_service_restart "$BW_BACKEND_SERVICE"; then
        log_error "Nginx failed to restart after rebinding."
        log_error "Collect diagnostics with:"
        log_error "  systemctl status ${BW_BACKEND_SERVICE} --no-pager -l"
        log_error "  journalctl -xeu ${BW_BACKEND_SERVICE} --no-pager | tail -100"
        log_error "  nginx -t"
        log_error "  grep -Rin 'listen' ${BW_BACKEND_CONF_DIR}"
        log_error "Originals backed up to: $BW_BACKUP_DIR"
        return 1
    fi
    log_success "Nginx restarted on loopback-only backend ports."
}

function bw_rebind_backend {
    sudo mkdir -p "$BW_BACKUP_DIR"
    log_info "Backup directory: $BW_BACKUP_DIR"

    if ! bw_needs_rebinding; then
        log_info "Backend is already bound to loopback ports. Skipping rebinding."
        return 0
    fi

    case "$BW_BACKEND_SERVER" in
        apache) bw_rebind_apache || return 1 ;;
        nginx)  bw_rebind_nginx || return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Phase 5: Configure BunkerWeb
# ---------------------------------------------------------------------------

function bw_check_modsecurity_conflict {
    if [[ "${BW_BACKEND_SERVER:-}" != "apache" ]]; then
        return 0
    fi

    local has_modsec=false
    local apachectl_bin=""
    if command -v apache2ctl >/dev/null 2>&1; then
        apachectl_bin="apache2ctl"
    elif command -v apachectl >/dev/null 2>&1; then
        apachectl_bin="apachectl"
    fi

    if [[ -n "$apachectl_bin" ]]; then
        if "$apachectl_bin" -M 2>/dev/null | grep -qi "security2_module"; then
            has_modsec=true
        fi
    fi

    if [[ "$has_modsec" == true ]]; then
        local apache_svc="${BW_BACKEND_SERVICE:-apache2}"
        log_warning "ModSecurity is active as an Apache module."
        log_warning "BunkerWeb includes its own ModSecurity. Running both may cause conflicts."
        if command -v a2dismod >/dev/null 2>&1; then
            log_warning "Consider: sudo a2dismod security2 && sudo systemctl restart ${apache_svc}"
        else
            log_warning "Disable Apache ModSecurity/security2 module before using BunkerWeb to avoid duplicate filtering."
        fi
    fi
}

function bw_configure_bunkerweb {
    print_banner "Phase 5: Configuring BunkerWeb"

    bw_check_modsecurity_conflict

    sudo mkdir -p "$BW_CONF_DIR"

    # Add direct-IP host alias for local testing/CCDC scoring when clients hit the box by IP.
    # BunkerWeb routes by Host header; without this, IP requests hit the default BunkerWeb server (/setup).
    local primary_ip=""
    primary_ip="$(bw_get_primary_ip 2>/dev/null || true)"
    if [[ -n "$primary_ip" && -z "${BW_DETECTED_SITES[$primary_ip]+x}" ]]; then
        local first_local_key=""
        for first_local_key in "${!BW_DETECTED_SITES[@]}"; do
            local sd="${BW_DETECTED_SITES[$first_local_key]}"
            local st="${sd##*|}"
            [[ "$st" == "remote" ]] && continue
            BW_DETECTED_SITES["$primary_ip"]="$sd"
            log_info "Added direct-IP BunkerWeb host mapping: ${primary_ip} -> ${sd%%|*}"
            break
        done
    fi

    # Build SERVER_NAME list
    local all_server_names=""
    local site_key
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        if [[ -n "$all_server_names" ]]; then
            all_server_names="${all_server_names} ${site_key}"
        else
            all_server_names="${site_key}"
        fi
    done

    # Back up existing variables.env
    if [[ -f "$BW_VARIABLES" ]]; then
        bw_backup_file "$BW_VARIABLES"
    fi

    # Write main configuration
    # CCDC-SAFE DEFAULTS: No antibot, permissive CSP, SAMEORIGIN frames,
    # REST methods allowed, reasonable rate limits, no auto-ban
    sudo tee "$BW_VARIABLES" >/dev/null <<ENVEOF
# BunkerWeb configuration - generated by CCDC bunkerweb.sh
# Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Backup: ${BW_BACKUP_DIR}

# --- Multisite: one BunkerWeb instance fronts all detected sites ---
MULTISITE=yes
SERVER_NAME=${all_server_names}
HTTP_PORT=80
HTTPS_PORT=443
DISABLE_DEFAULT_SERVER=yes

# --- TLS (disabled by default for CCDC environments) ---
AUTO_LETS_ENCRYPT=no
LISTEN_HTTP=yes
# To enable HTTPS with Let's Encrypt, uncomment:
#   AUTO_LETS_ENCRYPT=yes
#   EMAIL_LETS_ENCRYPT=admin@example.com
# To enable HTTPS with manual certs, add per-site:
#   <hostname>_USE_CUSTOM_SSL=yes
#   <hostname>_CUSTOM_SSL_CERT=/path/to/fullchain.pem
#   <hostname>_CUSTOM_SSL_KEY=/path/to/privkey.pem

# --- WAF: ModSecurity + OWASP CRS ---
USE_MODSECURITY=yes
USE_MODSECURITY_CRS=yes
MODSECURITY_SEC_RULE_ENGINE=on
MODSECURITY_SEC_AUDIT_ENGINE=RelevantOnly
MODSECURITY_SEC_AUDIT_LOG=/var/log/bunkerweb/modsec_audit.log

# --- Rate limiting ---
USE_LIMIT_REQ=yes
LIMIT_REQ_RATE=30r/s

# --- Bad behavior detection ---
# CCDC-safe: only trigger on clearly malicious codes, short ban time
USE_BAD_BEHAVIOR=yes
BAD_BEHAVIOR_STATUS_CODES=400 405 429 444
BAD_BEHAVIOR_BAN_TIME=300
BAD_BEHAVIOR_THRESHOLD=20

# --- Antibot: DISABLED for CCDC ---
# Scoring bots cannot execute JavaScript challenges. Setting this to
# anything other than "no" will cause ALL scored services to fail.
USE_ANTIBOT=no

# --- Security headers (CCDC-safe: permissive for CMS compatibility) ---
X_CONTENT_TYPE_OPTIONS=nosniff
X_FRAME_OPTIONS=SAMEORIGIN
REFERRER_POLICY=strict-origin-when-cross-origin
PERMISSIONS_POLICY=camera=(), microphone=(), geolocation=()
CONTENT_SECURITY_POLICY=${BW_CSP_CCDC}

# Note: HSTS intentionally omitted -- HTTPS is not configured by default.
# Add per-site if you enable TLS:
#   <hostname>_STRICT_TRANSPORT_SECURITY=max-age=63072000

# --- HTTP method restrictions (includes REST API methods for CMS compat) ---
ALLOWED_METHODS=GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH

# --- Deny status for blocked requests ---
DENY_HTTP_STATUS=403

# --- Real IP (trust loopback for proxied setups) ---
REAL_IP_FROM=127.0.0.0/8
REAL_IP_HEADER=X-Forwarded-For

# --- Logging ---
LOG_LEVEL=warning
ACCESS_LOG=/var/log/bunkerweb/access.log
ERROR_LOG=/var/log/bunkerweb/error.log
ENVEOF

    # Append per-site reverse proxy blocks
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        local site_data="${BW_DETECTED_SITES[$site_key]}"
        local status="${site_data##*|}"
        local backend_target=""

        if [[ "$status" == "remote" ]]; then
            # Remote: first field is the full URL
            backend_target="${site_data%%|*}"
        else
            # Local: first field is the port number
            local port="${site_data%%|*}"
            backend_target="http://127.0.0.1:${port}"
        fi

        sudo tee -a "$BW_VARIABLES" >/dev/null <<SITEEOF

# --- Site: ${site_key} (${status}) ---
${site_key}_USE_REVERSE_PROXY=yes
${site_key}_REVERSE_PROXY_URL=/
${site_key}_REVERSE_PROXY_HOST=${backend_target}
SITEEOF

        # Per-site overrides for remote backends
        if [[ -n "${BW_SITE_ANTIBOT[$site_key]+x}" ]]; then
            echo "${site_key}_USE_ANTIBOT=${BW_SITE_ANTIBOT[$site_key]}" \
                | sudo tee -a "$BW_VARIABLES" >/dev/null
        fi

        if [[ -n "${BW_SITE_CSP[$site_key]+x}" ]]; then
            local csp_val=""
            case "${BW_SITE_CSP[$site_key]}" in
                ccdc)   csp_val="$BW_CSP_CCDC" ;;
                strict) csp_val="$BW_CSP_STRICT" ;;
                off)    csp_val="" ;;
            esac
            if [[ -n "$csp_val" ]]; then
                echo "${site_key}_CONTENT_SECURITY_POLICY=${csp_val}" \
                    | sudo tee -a "$BW_VARIABLES" >/dev/null
            fi
        fi

        # For remote HTTPS backends, enable SSL SNI
        if [[ "$backend_target" == https://* ]]; then
            echo "${site_key}_REVERSE_PROXY_SSL_SNI=yes" \
                | sudo tee -a "$BW_VARIABLES" >/dev/null
        fi

        log_info "Configured reverse proxy: ${site_key} -> ${backend_target}"
    done

    # Write custom CRS tuning
    # PL1 with high threshold: prevents false positives blocking CMS content editing
    local modsec_crs_dir="${BW_CONF_DIR}/configs/modsec-crs"
    sudo mkdir -p "$modsec_crs_dir"
    sudo tee "${modsec_crs_dir}/ccdc-crs-tuning.conf" >/dev/null <<'CRSEOF'
# CCDC CRS tuning - paranoia level 1 with high anomaly threshold
# PL1 provides strong protection with minimal false positives for CMS apps.
# The high threshold (25) prevents ModSecurity from blocking CMS admin edits
# that contain HTML/SQL-like patterns in legitimate content.
SecAction \
 "id:900100,\
  phase:1,\
  nolog,\
  pass,\
  t:none,\
  setvar:'tx.paranoia_level=1',\
  setvar:'tx.blocking_paranoia_level=1',\
  setvar:'tx.enforce_bodyproc_urlencoded=1',\
  setvar:'tx.inbound_anomaly_score_threshold=25',\
  setvar:'tx.outbound_anomaly_score_threshold=4'"
CRSEOF
    log_info "Wrote CRS tuning (PL1, threshold 25) to ${modsec_crs_dir}/ccdc-crs-tuning.conf"

    # Ensure log directory exists
    sudo mkdir -p /var/log/bunkerweb
    sudo chown root:root /var/log/bunkerweb
    sudo chmod 750 /var/log/bunkerweb

    log_success "BunkerWeb configuration written to $BW_VARIABLES"
}

# ---------------------------------------------------------------------------
# Phase 6: Endpoint hardening
# ---------------------------------------------------------------------------

function bw_harden_endpoints {
    print_banner "Phase 6: Endpoint Hardening"

    local custom_conf_dir="${BW_CONF_DIR}/configs/server-http"
    sudo mkdir -p "$custom_conf_dir"

    local site_key
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        local site_data="${BW_DETECTED_SITES[$site_key]}"
        local status="${site_data##*|}"
        local site_dir="${custom_conf_dir}/${site_key}"
        sudo mkdir -p "$site_dir"

        # Block database tools, info endpoints, and dangerous file types.
        # NOTE: CMS admin paths (wp-admin, /administrator, /admin) are
        # intentionally NOT blocked -- CCDC teams must maintain these for
        # scoring. The WAF (ModSecurity) protects them instead.
        sudo tee "${site_dir}/block-dangerous.conf" >/dev/null <<'SNIPPET'
# Block database management tools and info disclosure endpoints
# Applied by CCDC bunkerweb.sh endpoint hardening
#
# CMS admin panels (wp-admin, /administrator, etc.) are intentionally
# left accessible -- teams need them for scoring and management.

location ~* ^/(phpmyadmin|pma|adminer|myadmin|mysqladmin|dbadmin|sql|phpinfo\.php|server-status|server-info|info\.php|test\.php) {
    return 403;
}

# Block dotfiles (.git, .env, .htaccess, etc.)
location ~ /\. {
    return 403;
}

# Block backup/config file extensions
location ~* \.(bak|old|orig|save|swp|sql|tar\.gz|log|ini|conf|cfg)$ {
    return 403;
}
SNIPPET

        # For remote backends (likely Windows/IIS), add IIS-specific blocks
        if [[ "$status" == "remote" ]]; then
            sudo tee "${site_dir}/block-iis.conf" >/dev/null <<'IISSNIPPET'
# Block IIS/ASP.NET sensitive endpoints and metadata
# Applied by CCDC bunkerweb.sh for remote Windows backends

location ~* ^/(elmah\.axd|trace\.axd) {
    return 403;
}

location ~* ^/(_vti_bin|_vti_cnf|_vti_log|_vti_pvt|_vti_txt)/ {
    return 403;
}

location ~* (web\.config|applicationhost\.config|machine\.config)$ {
    return 403;
}
IISSNIPPET
            log_info "Wrote IIS-specific endpoint hardening for $site_key"
        fi

        log_info "Wrote endpoint hardening for $site_key"
    done

    log_success "Endpoint hardening complete."
}

# ---------------------------------------------------------------------------
# SELinux and Firewall handling
# ---------------------------------------------------------------------------

function bw_handle_selinux {
    # Only relevant on RHEL-family systems
    if ! command -v getenforce >/dev/null 2>&1; then
        return 0
    fi

    local mode
    mode="$(getenforce 2>/dev/null || echo "Disabled")"
    if [[ "$mode" == "Disabled" ]] || [[ "$mode" == "Permissive" ]]; then
        log_info "SELinux is ${mode}. No changes needed."
        return 0
    fi

    log_info "SELinux is Enforcing. Configuring policies for BunkerWeb..."

    # Allow NGINX (BunkerWeb) to make network connections to backends
    if command -v setsebool >/dev/null 2>&1; then
        sudo setsebool -P httpd_can_network_connect on 2>/dev/null || true
        log_info "Set httpd_can_network_connect=on"
    fi

    # Label backend ports as http_port_t
    if command -v semanage >/dev/null 2>&1; then
        local site_key
        for site_key in "${!BW_DETECTED_SITES[@]}"; do
            local site_data="${BW_DETECTED_SITES[$site_key]}"
            local status="${site_data##*|}"
            [[ "$status" == "remote" ]] && continue
            local port="${site_data%%|*}"
            sudo semanage port -a -t http_port_t -p tcp "$port" 2>/dev/null \
                || sudo semanage port -m -t http_port_t -p tcp "$port" 2>/dev/null \
                || true
        done
        log_info "Labeled backend ports as http_port_t"
    else
        log_warning "semanage not found. Install policycoreutils-python-utils if SELinux blocks ports."
    fi

    # Fix file contexts on BunkerWeb directories
    if command -v restorecon >/dev/null 2>&1; then
        sudo restorecon -Rv /etc/bunkerweb /var/log/bunkerweb 2>/dev/null || true
        log_info "Restored SELinux file contexts for BunkerWeb directories"
    fi

    log_success "SELinux configuration applied."
}

function bw_handle_firewall {
    local opened=false

    # firewalld (RHEL/CentOS/Fedora)
    if command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state >/dev/null 2>&1; then
            log_info "firewalld is active. Opening HTTP/HTTPS ports..."
            sudo firewall-cmd --permanent --add-service=http >/dev/null 2>&1 || true
            sudo firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
            sudo firewall-cmd --reload >/dev/null 2>&1 || true
            opened=true
            log_success "Opened HTTP/HTTPS in firewalld."
        fi
    fi

    # ufw (Ubuntu/Debian)
    if [[ "$opened" == false ]] && command -v ufw >/dev/null 2>&1; then
        local ufw_status
        ufw_status="$(sudo ufw status 2>/dev/null || echo "inactive")"
        if [[ "$ufw_status" == *"active"* ]]; then
            log_info "ufw is active. Opening HTTP/HTTPS ports..."
            sudo ufw allow 80/tcp >/dev/null 2>&1 || true
            sudo ufw allow 443/tcp >/dev/null 2>&1 || true
            opened=true
            log_success "Opened HTTP/HTTPS in ufw."
        fi
    fi

    if [[ "$opened" == false ]]; then
        log_info "No active firewall (firewalld/ufw) detected or ports already open."
    fi
}

# ---------------------------------------------------------------------------
# Phase 7: Start BunkerWeb and validate
# ---------------------------------------------------------------------------

function bw_start_and_validate {
    print_banner "Phase 7: Starting BunkerWeb and Validating Traffic Flow"

    # Stop BunkerWeb services for a clean start
    bw_service_stop "$BW_SERVICE"
    bw_service_stop "$BW_SCHEDULER_SERVICE"

    # Verify local backends are running on expected loopback ports
    local has_local_sites=false
    local backend_ok=false
    local site_key
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        local site_data="${BW_DETECTED_SITES[$site_key]}"
        local status="${site_data##*|}"
        [[ "$status" == "remote" ]] && continue
        has_local_sites=true
        local port="${site_data%%|*}"
        if bw_check_listening ":${port}\b"; then
            backend_ok=true
            break
        fi
    done

    if [[ "$has_local_sites" == true ]] && [[ "$backend_ok" == false ]]; then
        log_warning "Local backend not detected on loopback ports. Attempting restart..."
        if [[ -n "${BW_BACKEND_SERVICE:-}" ]]; then
            bw_service_restart "$BW_BACKEND_SERVICE" || true
            sleep 2
        fi
    fi

    # Verify port 80 is free before starting BunkerWeb
    if bw_check_listening '(\*|0\.0\.0\.0|:::):80\b'; then
        local blocking_proc
        blocking_proc="$(bw_get_port_process 80)"
        log_error "Port 80 is still occupied by: ${blocking_proc}."
        log_error "BunkerWeb cannot bind. Check backend rebinding or stop the blocking service."
        return 1
    fi

    # Enable and start BunkerWeb services (scheduler first, then main service)
    bw_service_enable "$BW_SERVICE"
    bw_service_enable "$BW_SCHEDULER_SERVICE"

    log_info "Starting bunkerweb-scheduler (reads config and generates NGINX confs)..."
    bw_service_restart "$BW_SCHEDULER_SERVICE"

    # Wait for scheduler to become active
    local max_wait=30
    local waited=0
    while [[ $waited -lt $max_wait ]]; do
        if bw_service_is_active "$BW_SCHEDULER_SERVICE"; then
            break
        fi
        sleep 1
        ((waited++))
    done

    if ! bw_service_is_active "$BW_SCHEDULER_SERVICE"; then
        log_error "bunkerweb-scheduler failed to start."
        log_error "Check: sudo journalctl -u bunkerweb-scheduler --no-pager -n 50"
        return 1
    fi
    log_info "bunkerweb-scheduler is active. Waiting for config generation..."
    sleep 5

    log_info "Starting bunkerweb..."
    bw_service_restart "$BW_SERVICE"
    sleep 3

    # Validate BunkerWeb owns port 80
    if ! bw_check_listening ":80\b"; then
        log_error "BunkerWeb failed to bind to port 80."
        log_error "Check: sudo journalctl -u bunkerweb --no-pager -n 50"
        return 1
    fi

    local port80_owner
    port80_owner="$(bw_get_port_process 80)"
    case "${port80_owner,,}" in
        *apache*|*httpd*|*nginx*)
            log_error "Port 80 is held by backend process (${port80_owner}), not BunkerWeb. Migration failed."
            return 1
            ;;
    esac

    log_success "BunkerWeb is listening on port 80."

    # Validate proxy path for each site
    local all_ok=true
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        local site_data="${BW_DETECTED_SITES[$site_key]}"
        local status="${site_data##*|}"

        if [[ "$status" == "remote" ]]; then
            # For remote backends: test TCP connectivity
            local backend_url="${site_data%%|*}"
            local remote_host remote_port
            remote_host="$(echo "$backend_url" | sed -E 's|https?://||;s|:.*||;s|/.*||')"
            remote_port="$(echo "$backend_url" | grep -oE ':[0-9]+' | tr -d ':' | head -1)"
            remote_port="${remote_port:-80}"

            if timeout 5 bash -c "echo >/dev/tcp/${remote_host}/${remote_port}" 2>/dev/null; then
                log_success "Remote backend reachable: $site_key -> ${remote_host}:${remote_port}"
            else
                log_warning "Remote backend unreachable: $site_key -> ${remote_host}:${remote_port}"
                all_ok=false
            fi
        else
            # For local backends: check loopback connectivity
            local port="${site_data%%|*}"
            local backend_code=""
            backend_code="$(curl -so /dev/null -w '%{http_code}' --max-time 5 \
                "http://127.0.0.1:${port}/" 2>/dev/null || echo "000")"

            if [[ "$backend_code" == "000" ]]; then
                log_warning "Backend for $site_key (port $port) not responding."
                all_ok=false
            else
                log_info "Backend OK: $site_key (port $port) -> HTTP $backend_code"
            fi
        fi

        # Check WAF proxy path
        local waf_code=""
        waf_code="$(curl -so /dev/null -w '%{http_code}' --max-time 5 \
            -H "Host: ${site_key}" "http://127.0.0.1:80/" 2>/dev/null || echo "000")"

        if [[ "$waf_code" == "000" || "$waf_code" == "502" ]]; then
            log_warning "BunkerWeb -> $site_key returned $waf_code."
            all_ok=false
        else
            log_success "Validated: $site_key | waf=$waf_code"
        fi
    done

    if [[ "$all_ok" == true ]]; then
        log_success "All sites validated through BunkerWeb WAF."
    else
        log_warning "Some sites had validation issues. Review warnings above."
        log_warning "Backups available at: $BW_BACKUP_DIR"
    fi
}

# ---------------------------------------------------------------------------
# Post-deployment information
# ---------------------------------------------------------------------------

function bw_print_routing_instructions {
    local has_remote=false
    local site_key
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        local status="${BW_DETECTED_SITES[$site_key]##*|}"
        [[ "$status" == "remote" ]] && has_remote=true && break
    done

    [[ "$has_remote" == false ]] && return 0

    local waf_ip
    waf_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"

    print_banner "IMPORTANT: Routing Required for Remote Backends"
    log_info "Remote backends are configured but traffic must be routed through this WAF."
    log_info "WAF box IP: ${waf_ip:-<this machine>}"
    echo ""
    log_info "Option A - Update DNS A records to point to ${waf_ip:-WAF_IP}:"
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        local status="${BW_DETECTED_SITES[$site_key]##*|}"
        [[ "$status" != "remote" ]] && continue
        echo "    ${site_key}  A  ${waf_ip:-WAF_IP}"
    done
    echo ""
    log_info "Option B - Firewall DNAT (redirect on the network firewall):"
    for site_key in "${!BW_DETECTED_SITES[@]}"; do
        local site_data="${BW_DETECTED_SITES[$site_key]}"
        local status="${site_data##*|}"
        [[ "$status" != "remote" ]] && continue
        local backend_url="${site_data%%|*}"
        local remote_ip
        remote_ip="$(echo "$backend_url" | sed -E 's|https?://||;s|:.*||;s|/.*||')"
        echo "    Traffic for ${remote_ip}:80 -> DNAT to ${waf_ip:-WAF_IP}:80"
    done
    echo ""
    log_info "BunkerWeb routes by Host header, so the same port 80 serves all sites."
}

# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

function rollback_bunkerweb {
    local backup_dir="${1:-}"

    # Auto-detect the most recent backup if no argument given
    if [[ -z "$backup_dir" ]]; then
        backup_dir="$(ls -dt ${BW_BACKUP_PREFIX}-* 2>/dev/null | head -1)"
    fi

    if [[ -z "$backup_dir" || ! -d "$backup_dir" ]]; then
        log_error "No backup directory found at ${BW_BACKUP_PREFIX}-*"
        log_error "Usage: rollback_bunkerweb [/path/to/backup/dir]"
        return 1
    fi

    print_banner "Rolling Back BunkerWeb Migration"
    log_info "Using backup: $backup_dir"

    # Stop all BunkerWeb services
    bw_service_stop "$BW_SERVICE"
    bw_service_stop "$BW_SCHEDULER_SERVICE"
    bw_service_stop "$BW_UI_SERVICE"

    # Restore all backed-up files
    local restored=0
    while IFS= read -r -d '' backup_file_path; do
        local original_path="${backup_file_path#"${backup_dir}"}"
        if [[ -n "$original_path" ]]; then
            sudo mkdir -p "$(dirname "$original_path")"
            sudo cp -a "$backup_file_path" "$original_path"
            log_info "Restored: $original_path"
            ((restored++))
        fi
    done < <(find "$backup_dir" -type f -print0 2>/dev/null)

    if [[ $restored -eq 0 ]]; then
        log_warning "No files found in backup directory."
    else
        log_info "Restored $restored file(s)."
    fi

    # Re-enable default vhosts that may have been disabled
    if command -v a2ensite >/dev/null 2>&1; then
        sudo a2ensite 000-default >/dev/null 2>&1 || true
    fi

    # Restart the backend web server (auto-detect)
    if [[ -d "/etc/apache2" ]] && command -v apache2ctl >/dev/null 2>&1; then
        sudo apache2ctl configtest 2>&1 && bw_service_restart "apache2" || \
            log_warning "Apache config test failed after rollback. Check manually."
    elif [[ -d "/etc/httpd" ]] && command -v apachectl >/dev/null 2>&1; then
        sudo apachectl configtest 2>&1 && bw_service_restart "httpd" || \
            log_warning "Apache config test failed after rollback. Check manually."
    fi

    if [[ -d "/etc/nginx" ]] && command -v nginx >/dev/null 2>&1; then
        sudo nginx -t 2>&1 && bw_service_restart "nginx" || \
            log_warning "Nginx config test failed after rollback. Check manually."
    fi

    log_success "Rollback complete. Original web server configuration restored."
    log_info "BunkerWeb services stopped. Backend web server restarted."
}

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

function install_and_configure_bunkerweb {
    print_banner "BunkerWeb WAF Deployment"

    # Initialize per-run state
    declare -gA BW_DETECTED_SITES=()
    declare -gA BW_SITE_CSP=()
    declare -gA BW_SITE_ANTIBOT=()
    BW_BACKEND_SERVER=""
    BW_BACKEND_SERVICE=""
    BW_BACKEND_CONF_DIR=""
    BW_BACKUP_DIR="${BW_BACKUP_PREFIX}-$(date +%Y%m%d_%H%M%S)"

    # Parse arguments
    local _bw_mode="local"
    local _bw_manifest=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --remote)  _bw_mode="remote"; shift ;;
            --hybrid)  _bw_mode="hybrid"; shift ;;
            --local)   _bw_mode="local"; shift ;;
            --manifest)
                _bw_manifest="$2"
                [[ "$_bw_mode" == "local" ]] && _bw_mode="remote"
                shift 2
                ;;
            --add-remote)
                local _ar_host="$2" _ar_url="$3"
                shift 3
                local _ar_csp="ccdc" _ar_ab="no"
                while [[ $# -gt 0 ]]; do
                    case "$1" in
                        --csp-profile) _ar_csp="$2"; shift 2 ;;
                        --antibot)     _ar_ab="$2"; shift 2 ;;
                        *) break ;;
                    esac
                done
                bw_add_remote_site "$_ar_host" "$_ar_url" "$_ar_csp" "$_ar_ab"
                [[ "$_bw_mode" == "local" ]] && _bw_mode="hybrid"
                ;;
            *) shift ;;
        esac
    done

    # Phase 1: Pre-flight checks
    if ! bw_preflight; then
        return 1
    fi

    # Phase 2: Detect local backend + collect remote backends
    local _has_local_backend=false
    if [[ "$_bw_mode" == "local" || "$_bw_mode" == "hybrid" ]]; then
        if bw_detect_backend_server; then
            _has_local_backend=true
            if ! bw_detect_virtual_hosts; then
                log_error "Failed to enumerate virtual hosts."
                return 1
            fi
        elif [[ "$_bw_mode" == "local" ]]; then
            log_error "No local web server found and running in --local mode."
            log_error "Use --remote to protect remote backends or --hybrid for both."
            return 1
        fi
    fi

    if [[ "$_bw_mode" == "remote" || "$_bw_mode" == "hybrid" ]]; then
        if [[ -n "$_bw_manifest" ]]; then
            if ! bw_parse_manifest "$_bw_manifest"; then
                return 1
            fi
        elif [[ "${ANSIBLE:-false}" != "true" ]]; then
            bw_interactive_add_remotes
        fi
    fi

    if [[ ${#BW_DETECTED_SITES[@]} -eq 0 ]]; then
        log_error "No sites configured (local or remote). Nothing to protect."
        return 1
    fi

    # Phase 3: Install BunkerWeb FIRST (before rebinding!)
    # This ensures backend stays functional if installation fails.
    if ! bw_install_bunkerweb; then
        log_error "BunkerWeb installation failed. Backend is untouched."
        return 1
    fi

    # Phase 4: Rebind backend (only for local sites, safe now that BunkerWeb is installed)
    if [[ "$_has_local_backend" == true ]]; then
        if ! bw_rebind_backend; then
            # Prevent stock BunkerWeb setup wizard from hijacking port 80 if deployment failed mid-flight
            bw_service_stop "$BW_SERVICE"
            bw_service_stop "$BW_SCHEDULER_SERVICE"
            bw_service_stop "$BW_UI_SERVICE"
            log_error "Backend rebinding failed. BunkerWeb services were stopped to avoid exposing the setup wizard."
            log_error "Run: rollback_bunkerweb $BW_BACKUP_DIR"
            return 1
        fi
    else
        # In pure remote mode, check that port 80 is free
        sudo mkdir -p "$BW_BACKUP_DIR"
        if bw_check_listening '(\*|0\.0\.0\.0|:::):80\b'; then
            local blocking_proc
            blocking_proc="$(bw_get_port_process 80)"
            log_error "Port 80 is occupied by: ${blocking_proc}."
            log_error "BunkerWeb needs port 80. Stop the blocking service or use --hybrid mode."
            return 1
        fi
    fi

    # Phase 5: Configure BunkerWeb
    if ! bw_configure_bunkerweb; then
        log_error "BunkerWeb configuration failed."
        return 1
    fi

    # Phase 6: Harden endpoints
    if ! bw_harden_endpoints; then
        log_error "Endpoint hardening failed."
        return 1
    fi

    # SELinux and firewall (after install/config, before start)
    bw_handle_selinux
    bw_handle_firewall

    # Phase 7: Start and validate
    if ! bw_start_and_validate; then
        log_error "BunkerWeb startup/validation failed."
        log_error "To rollback: source bunkerweb.sh && rollback_bunkerweb $BW_BACKUP_DIR"
        return 1
    fi

    # Post-deployment info
    bw_print_routing_instructions

    print_banner "BunkerWeb Deployment Complete"
    log_success "WAF is active on port 80."
    [[ -n "${BW_BACKEND_SERVER:-}" ]] && \
        log_success "Backend ($BW_BACKEND_SERVER) is on loopback only."
    log_info "Configuration: $BW_VARIABLES"
    log_info "Backups: $BW_BACKUP_DIR"
    log_info "Logs: /var/log/bunkerweb/"
    log_info "Audit log: /var/log/bunkerweb/modsec_audit.log"
    log_info "To rollback: source bunkerweb.sh && rollback_bunkerweb"
}

# ---------------------------------------------------------------------------
# Standalone execution guard
# ---------------------------------------------------------------------------

if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
    set -euo pipefail
    install_and_configure_bunkerweb "$@"
fi

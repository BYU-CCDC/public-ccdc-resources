#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON_LIB="$SCRIPT_DIR/../lib/common.sh"

if [ -f "$COMMON_LIB" ]; then
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
    CYAN='\033[0;36m'

    __ua_log_emit() {
        local level="$1" color="$2"
        shift 2 || true
        printf '%b[%s]%b %s\n' "$color" "$level" "$NC" "$*"
    }

    log_info()    { __ua_log_emit "INFO" "$AQUA" "$@"; }
    log_success() { __ua_log_emit "SUCCESS" "$GREEN" "$@"; }
    log_warning() { __ua_log_emit "WARNING" "$ORANGE" "$@"; }
    log_error()   { __ua_log_emit "ERROR" "$RED" "$@"; }
    log_verbose() {
        if [ "${LOG_LEVEL^^}" = "VERBOSE" ] || [ "${LOG_LEVEL^^}" = "DEBUG" ]; then
            __ua_log_emit "VERBOSE" "$CYAN" "$@"
        fi
    }
fi

PRIMARY_URL="https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list"
FALLBACK_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/main/linux/bad_ua.txt"

CONF_BASENAME="zz-ua-block.conf"
CONF_TAG="# Managed by install-apache-ua-block.sh"

CACHE_DIR="${UA_BLOCKER_CACHE_DIR:-/var/cache/ua-block}"
CACHE_LIST="$CACHE_DIR/bad-user-agents.list"
LOCAL_FALLBACK_LIST="$SCRIPT_DIR/data/bad-user-agents.defaults"
HTACCESS_SOURCE="$SCRIPT_DIR/data/htaccess_list.txt"
MAX_REGEX_CHARS=${MAX_REGEX_CHARS:-3500}

WHITELIST_UA=""
WHITELIST_IPS=""
REFRESH_ONLY="false"
SKIP_RELOAD="false"

usage() {
cat <<EOF
Usage: sudo $(basename "$0") [options]

Options:
  --refresh                    Force re-fetch of UA lists and reload Apache
  --whitelist-ua "REGEX"       UA regex(es) to whitelist
  --whitelist-ip "IP[,CIDR]"   Comma-separated IPs/CIDRs to whitelist
  --no-reload                  Generate configuration but skip Apache reload
  -h, --help                   Show this help
EOF
}

escape_regex_literal() { sed -e 's/[][(){}?+*.^$|\\/]/\\&/g'; }

split_chunks() {
    local max="${MAX_REGEX_CHARS:-3500}"
    awk -v max="$max" '
BEGIN{c=""}
{
  n=split($0,a,/\|/)
  for(i=1;i<=n;i++){
    if(c==""){c=a[i]; continue}
    if(length(c)+1+length(a[i])<=max){c=c"|"a[i]; continue}
    print c
    c=a[i]
  }
}
END{if(c!="")print c}'
}

detect_layout() {
    if [[ -d /etc/apache2 ]]; then
        APACHE_ETC="/etc/apache2"
        CONF_DIR="$APACHE_ETC/conf-available"
        CONF_PATH="$CONF_DIR/$CONF_BASENAME"
        LOG_DIR="${UA_BLOCKER_LOG_DIR:-${APACHE_LOG_DIR:-/var/log/apache2}}"
        RELOAD_CMD="systemctl reload apache2 || service apache2 reload"
        CTL="apache2ctl"
    elif [[ -d /etc/httpd ]]; then
        APACHE_ETC="/etc/httpd"
        CONF_DIR="$APACHE_ETC/conf.d"
        CONF_PATH="$CONF_DIR/$CONF_BASENAME"
        LOG_DIR="${UA_BLOCKER_LOG_DIR:-/var/log/httpd}"
        RELOAD_CMD="systemctl reload httpd || service httpd reload"
        CTL="apachectl"
    else
        log_error "Apache configuration directory not found. Expected /etc/apache2 or /etc/httpd."
        exit 1
    fi
    mkdir -p "$CONF_DIR" "$LOG_DIR"
    log_verbose "Using Apache configuration directory $CONF_DIR"
}

enable_module() {
    local mod="$1"

    if command -v "$CTL" >/dev/null 2>&1; then
        if "$CTL" -M 2>/dev/null | grep -qiE "\\b${mod}_module\\b"; then
            return 0
        fi
    fi

    if command -v a2query >/dev/null 2>&1; then
        if a2query -m "$mod" 2>/dev/null | grep -qiE 'enabled|static'; then
            return 0
        fi
    fi

    if command -v a2enmod >/dev/null 2>&1; then
        if a2enmod "$mod" >/dev/null 2>&1; then
            return 0
        fi

        if [[ ! -f "/etc/apache2/mods-available/${mod}.load" ]]; then
            log_warning "Module $mod not available on this platform; skipping enable."
            return 0
        fi
    fi
}

safe_write() {
    local path="$1" content="$2" tmp
    tmp="$(mktemp)"
    printf "%s\n" "$content" >"$tmp"
    local needs_write=0
    if [[ ! -f "$path" ]]; then
        needs_write=1
    elif ! cmp -s "$tmp" "$path"; then
        needs_write=1
    fi
    if (( needs_write )); then
        if [[ -f "$path" ]] && ! grep -qF "$CONF_TAG" "$path"; then
            local backup="$path.bak.$(date +%Y%m%d_%H%M%S)"
            cp -a "$path" "$backup"
            log_warning "Existing configuration at $path was not previously managed; backup saved to $backup"
        fi
        mv "$tmp" "$path"
        log_success "Wrote updated configuration to $path"
    else
        rm -f "$tmp"
        log_verbose "No changes required for $path"
    fi
}

download_to_file() {
    local url="$1" dest="$2" tool=""

    if command -v wget >/dev/null 2>&1; then
        tool="wget"
        if wget -q -O "$dest" --tries=2 --timeout=5 "$url"; then
            log_verbose "Downloaded $url with wget"
            return 0
        fi
        log_warning "wget failed for $url"
    else
        log_verbose "wget not found; will try curl for $url"
    fi

    if command -v curl >/dev/null 2>&1; then
        tool="curl"
        if curl --connect-timeout 5 --retry 2 --retry-delay 2 -fsSL "$url" -o "$dest"; then
            log_verbose "Downloaded $url with curl"
            return 0
        fi
        log_warning "curl failed for $url"
    else
        log_verbose "curl not found while attempting $url"
    fi

    if [[ -z "$tool" ]]; then
        log_warning "Neither wget nor curl is available to download $url"
    fi
    return 1
}

fetch_list() {
    mkdir -p "$CACHE_DIR"
    log_info "Fetching remote User-Agent block lists"
    local tmp_file="$CACHE_LIST.tmp"
    rm -f "$tmp_file"

    if download_to_file "$PRIMARY_URL" "$tmp_file"; then
        log_success "Fetched primary UA list"
    elif download_to_file "$FALLBACK_URL" "$tmp_file"; then
        log_warning "Primary UA list unavailable; using fallback mirror"
    elif [[ -f "$LOCAL_FALLBACK_LIST" ]]; then
        log_warning "Remote UA lists unavailable; using bundled fallback list"
        cp "$LOCAL_FALLBACK_LIST" "$tmp_file"
    else
        log_error "No remote or local UA lists available; falling back to minimal defaults"
        printf "sqlmap\nnikto\nnmap\ncurl\npython\nmasscan\nwpscan\n" >"$tmp_file"
    fi

    if [[ -s "$tmp_file" ]]; then
        tr -d '\r' <"$tmp_file" | grep -Ev '^(#|$)' >"$CACHE_LIST"
    else
        log_error "Downloaded UA list is empty; writing minimal defaults"
        printf "sqlmap\nnikto\nnmap\ncurl\npython\nmasscan\nwpscan\n" >"$CACHE_LIST"
    fi
    rm -f "$tmp_file"
}

build_chunks() {
    local list_path="${1:-$CACHE_LIST}"
    local joined
    joined="$(awk '{print}' "$list_path" | escape_regex_literal | paste -sd'|' -)"
    if [[ -z "$joined" ]]; then
        log_error "Downloaded UA list is empty"
        exit 1
    fi
    echo "$joined" | split_chunks
}

load_htaccess_block() {
    local source_path="${1:-$HTACCESS_SOURCE}"
    if [[ ! -f "$source_path" ]]; then
        log_warning "htaccess pattern list not found at $source_path"
        return 0
    fi
    awk '{print "    "$0}' "$source_path"
}

generate_apache_conf() {
    local log_dir="$1"
    local conf_tag="$2"
    local ua_expr="$3"
    local ip_rules="$4"
    local ua_allow_block="$5"
    local rewrite_block="$6"
    shift 6
    local chunks=("$@")

    local setenvif_block=""
    local chunk
    for chunk in "${chunks[@]}"; do
        setenvif_block+=$(printf '    SetEnvIfNoCase User-Agent "%s" bad_ua\n' "$chunk")
    done

    {
        printf '%s\n\n' "$conf_tag"
        printf '# Generated on %s\n\n' "$(date -u)"
        printf '# Sources:\n# %s\n# %s\n' "$PRIMARY_URL" "$FALLBACK_URL"
        if [[ -n "$rewrite_block" ]]; then
            printf '# Additional rewrite conditions sourced from %s\n\n' "$HTACCESS_SOURCE"
        else
            printf '\n'
        fi
        if [[ -n "$ua_allow_block" ]]; then
            printf '%s\n\n' "$ua_allow_block"
        fi
        printf '<IfModule mod_setenvif.c>\n'
        printf '%s' "$setenvif_block"
        printf '</IfModule>\n\n'
        if [[ -n "$rewrite_block" ]]; then
            printf '%s\n\n' "$rewrite_block"
        fi
        printf '<IfModule mod_authz_core.c>\n'
        printf '    <Location "/">\n'
        if [[ -n "$ip_rules" ]]; then
            printf '%s' "$ip_rules"
        fi
        printf '        Require all granted\n'
        printf '        %s\n' "$ua_expr"
        printf '    </Location>\n'
        printf '</IfModule>\n\n'
        printf 'CustomLog %s/ua_block.log combined env=bad_ua\n' "$log_dir"
    }
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --refresh)
                REFRESH_ONLY="true"
                shift
                ;;
            --whitelist-ua)
                WHITELIST_UA="$2"
                shift 2
                ;;
            --whitelist-ip)
                WHITELIST_IPS="$2"
                shift 2
                ;;
            --no-reload)
                SKIP_RELOAD="true"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option $1"
                usage
                exit 1
                ;;
        esac
    done
}

main() {
    parse_args "$@"

    detect_layout
    enable_module setenvif
    enable_module authz_core
    enable_module log_config

    if [[ "$REFRESH_ONLY" = "true" || ! -s "$CACHE_LIST" ]]; then
        fetch_list
    else
        log_info "Using cached UA list at $CACHE_LIST"
    fi

    mapfile -t CHUNKS < <(build_chunks "$CACHE_LIST")
    log_info "Prepared ${#CHUNKS[@]} User-Agent regex chunk(s)"

    local ip_rules=""
    if [[ -n "$WHITELIST_IPS" ]]; then
        IFS=',' read -ra IP_ARR <<<"$WHITELIST_IPS"
        local ip
        for ip in "${IP_ARR[@]}"; do
            local trimmed
            trimmed="$(echo "$ip" | xargs)"
            if [[ -n "$trimmed" ]]; then
                printf -v ip_rules '%s        Require ip %s\n' "$ip_rules" "$trimmed"
            fi
        done
    fi

    local ua_allow_block=""
    local ua_expr="Require not env bad_ua"
    if [[ -n "$WHITELIST_UA" ]]; then
        ua_allow_block=$'<IfModule mod_setenvif.c>\n    SetEnvIfNoCase User-Agent "'"$WHITELIST_UA"'" ua_allowed\n</IfModule>'
        ua_expr="Require expr ! env('bad_ua') || env('ua_allowed')"
    fi

    local rewrite_block
    rewrite_block="$(load_htaccess_block "$HTACCESS_SOURCE")"

    local content
    content="$(generate_apache_conf "$LOG_DIR" "$CONF_TAG" "$ua_expr" "$ip_rules" "$ua_allow_block" "$rewrite_block" "${CHUNKS[@]}")"

    safe_write "$CONF_PATH" "$content"

    if [[ "$SKIP_RELOAD" == "true" ]]; then
        log_info "Skipping Apache reload (--no-reload specified)"
        return 0
    fi
    if command -v "$CTL" >/dev/null 2>&1; then
        if "$CTL" configtest; then
            log_success "Apache configuration syntax check passed"
            if ! eval "$RELOAD_CMD"; then
                log_warning "Unable to reload Apache automatically with: $RELOAD_CMD"
            else
                log_success "Apache reloaded with: $RELOAD_CMD"
            fi
        else
            log_error "Apache configuration test failed"
            exit 1
        fi
    else
        log_warning "$CTL not found; skipping configtest and reload"
    fi

    log_info "User-Agent block configuration installed at $CONF_PATH"
    log_info "Block log located at ${LOG_DIR}/ua_block.log"
    log_verbose "UA list cache stored at $CACHE_LIST"
    log_info "Whitelisted IPs: ${WHITELIST_IPS:-none}"
    log_info "Whitelisted UAs: ${WHITELIST_UA:-none}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi

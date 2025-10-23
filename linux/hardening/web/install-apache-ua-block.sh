#!/usr/bin/env bash

# Sources:
# 1. https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list
# 2. https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/main/linux/bad_ua.txt
# Apache: 2.4+

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
        local level="$1"
        local color="$2"
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

# Tunables

PRIMARY_URL="https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list"
FALLBACK_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/main/linux/bad_ua.txt"

CONF_BASENAME="zz-ua-block.conf"
CONF_TAG="# Managed by [install-apache-ua-block.sh](http://install-apache-ua-block.sh/)"

CACHE_DIR="/var/cache/ua-block"
CACHE_LIST="$CACHE_DIR/bad-user-agents.list"
LOCAL_FALLBACK_LIST="$SCRIPT_DIR/data/bad-user-agents.defaults"
MAX_REGEX_CHARS=3500

# CLI defaults
WHITELIST_UA=""
WHITELIST_IPS=""
REFRESH_ONLY="false"

# Helpers

usage() {
cat <<EOF
Usage: sudo $(basename "$0") [options]

Options:
  --refresh                    Force re-fetch of UA lists and reload Apache
  --whitelist-ua "REGEX"       UA regex(es) to whitelist
  --whitelist-ip "IP[,CIDR]"   Comma-separated IPs/CIDRs to whitelist
  -h, --help                   Show this help
EOF
}

escape_regex_literal() { sed -e 's/[][(){}?+*.^$|\\/]/\\&/g'; }

split_chunks() {
awk -v max="$MAX_REGEX_CHARS" '
BEGIN{c=""}
{n=split($0,a,/\|/);
 for(i=1;i<=n;i++){
   if(c==""){c=a[i]; next}
   if(length(c)+1+length(a[i])<=max){c=c"|"a[i]; next}
   print c; c=a[i];
 }}
END{if(c!="")print c}'
}

detect_layout() {
    if [[ -d /etc/apache2 ]]; then
        APACHE_ETC="/etc/apache2"
        CONF_DIR="$APACHE_ETC/conf-available"
        CONF_PATH="$CONF_DIR/$CONF_BASENAME"
        LOG_DIR="${APACHE_LOG_DIR:-/var/log/apache2}"
        RELOAD_CMD="systemctl reload apache2 || service apache2 reload"
        CTL="apache2ctl"
    elif [[ -d /etc/httpd ]]; then
        APACHE_ETC="/etc/httpd"
        CONF_DIR="$APACHE_ETC/conf.d"
        CONF_PATH="$CONF_DIR/$CONF_BASENAME"
        LOG_DIR="/var/log/httpd"
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
            echo "Module $mod not available on this platform; skipping enable." >&2
            return 0
        fi
    fi
}

safe_write() {
    local path="$1" tmp
    tmp="$(mktemp)"
    printf "%s\n" "$2" >"$tmp"
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
    # Prefer wget, fall back to curl. Log both attempts.
    # Timeout and retry kept short to avoid blocking automation.
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
    local joined
    joined="$(awk '{print}' "$CACHE_LIST" | escape_regex_literal | paste -sd'|' -)"
    if [[ -z "$joined" ]]; then
        log_error "Downloaded UA list is empty"
        exit 1
    fi
    echo "$joined" | split_chunks
}

# Parse CLI

while [[ $# -gt 0 ]]; do
    case "$1" in
        --refresh) REFRESH_ONLY="true"; shift;;
        --whitelist-ua) WHITELIST_UA="$2"; shift 2;;
        --whitelist-ip) WHITELIST_IPS="$2"; shift 2;;
        -h|--help) usage; exit 0;;
        *)
            log_error "Unknown option $1"
            usage
            exit 1
            ;;
    esac
done

# Main

detect_layout
enable_module setenvif
enable_module authz_core
enable_module log_config

if [[ "$REFRESH_ONLY" = "true" || ! -s "$CACHE_LIST" ]]; then
    fetch_list
else
    log_info "Using cached UA list at $CACHE_LIST"
fi

mapfile -t CHUNKS < <(build_chunks)
log_info "Prepared ${#CHUNKS[@]} User-Agent regex chunk(s)"

# Whitelist IPs
IP_RULES=""
if [[ -n "$WHITELIST_IPS" ]]; then
    IFS=',' read -ra IP_ARR <<<"$WHITELIST_IPS"
    for ip in "${IP_ARR[@]}"; do
        IP_RULES+="        Require ip $(echo "$ip" | xargs)\n"
    done
fi

# Whitelist UAs
UA_ALLOW_BLOCK=""
UA_EXPR="Require not env bad_ua"
if [[ -n "$WHITELIST_UA" ]]; then
    UA_ALLOW_BLOCK=$'<IfModule mod_setenvif.c>\n    SetEnvIfNoCase User-Agent "'"$WHITELIST_UA"'" ua_allowed\n</IfModule>'
    UA_EXPR="Require expr ! env('bad_ua') || env('ua_allowed')"
fi

CONTENT=$(cat <<EOF
$CONF_TAG

# Generated on $(date -u)

# Sources:
# $PRIMARY_URL
# $FALLBACK_URL

${UA_ALLOW_BLOCK}

<IfModule mod_setenvif.c>
EOF
)
for c in "${CHUNKS[@]}"; do
    CONTENT+="\n    SetEnvIfNoCase User-Agent \"$c\" bad_ua"
done
CONTENT+="\n</IfModule>\n\n<IfModule mod_authz_core.c>\n    <Location \"/\">\n${IP_RULES}        Require all granted\n        $UA_EXPR\n    </Location>\n</IfModule>\n\nCustomLog ${LOG_DIR}/ua_block.log combined env=bad_ua\n"

safe_write "$CONF_PATH" "$CONTENT"

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

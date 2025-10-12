#!/usr/bin/env bash

# [install-apache-ua-block.sh](http://install-apache-ua-block.sh/)

# Purpose : Global, high-performance User-Agent blocking for Apache

# Sources :

# 1. https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list
# 2. https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/main/linux/bad_ua.txt

# Apache : 2.4+

# OS : Debian/Ubuntu (/etc/apache2) or RHEL/Amazon (/etc/httpd)

# License : MIT

set -euo pipefail

# ------------------------------------------------------------------
# Tunables
# ------------------------------------------------------------------

PRIMARY_URL="https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list"
FALLBACK_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/main/linux/bad_ua.txt"

CONF_BASENAME="zz-ua-block.conf"
CONF_TAG="# Managed by [install-apache-ua-block.sh](http://install-apache-ua-block.sh/)"

CACHE_DIR="/var/cache/ua-block"
CACHE_LIST="$CACHE_DIR/bad-user-agents.list"
MAX_REGEX_CHARS=3500

# CLI defaults

WHITELIST_UA=""
WHITELIST_IPS=""
REFRESH_ONLY="false"

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

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
echo "Apache config dir not found" >&2; exit 1
fi
mkdir -p "$CONF_DIR" "$LOG_DIR"
}

enable_module() {
local mod="$1"
if command -v a2enmod >/dev/null 2>&1; then
apache2ctl -M 2>/dev/null | grep -qiE "\\b${mod}_module\\b" || a2enmod "$mod" >/dev/null
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
cp -a "$path" "$path.bak.$(date +%Y%m%d_%H%M%S)"
fi
mv "$tmp" "$path"
else
rm -f "$tmp"
fi
}

fetch_list() {
mkdir -p "$CACHE_DIR"
echo "Fetching UA lists..."
if curl -fsSL "$PRIMARY_URL" -o "$CACHE_LIST.tmp"; then
echo "Fetched primary list"
elif curl -fsSL "$FALLBACK_URL" -o "$CACHE_LIST.tmp"; then
echo "Primary failed, using fallback list"
else
echo "Both remote lists unavailable, using built-in defaults"
printf "sqlmap\nnikto\nnmap\ncurl\npython\nmasscan\nwpscan\n" >"$CACHE_LIST.tmp"
fi
tr -d '\r' <"$CACHE_LIST.tmp" | grep -Ev '^(#|$)' >"$CACHE_LIST"
rm -f "$CACHE_LIST.tmp"
}

build_chunks() {
local joined
joined="$(awk '{print}' "$CACHE_LIST" | escape_regex_literal | paste -sd'|' -)"
[[ -z "$joined" ]] && { echo "Empty UA list"; exit 1; }
echo "$joined" | split_chunks
}

# ------------------------------------------------------------------
# Parse CLI
# ------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
case "$1" in
--refresh) REFRESH_ONLY="true"; shift;;
--whitelist-ua) WHITELIST_UA="$2"; shift 2;;
--whitelist-ip) WHITELIST_IPS="$2"; shift 2;;
-h|--help) usage; exit 0;;
*) echo "Unknown option $1"; usage; exit 1;;
esac
done

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

detect_layout
enable_module setenvif
enable_module authz_core
enable_module log_config

[[ "$REFRESH_ONLY" == "true" || ! -s "$CACHE_LIST" ]] && fetch_list || echo "Using cached list: $CACHE_LIST"

mapfile -t CHUNKS < <(build_chunks)
echo "Prepared ${#CHUNKS[@]} UA regex chunk(s)"

# Whitelist IP

IP_RULES=""
if [[ -n "$WHITELIST_IPS" ]]; then
IFS=',' read -ra IP_ARR <<<"$WHITELIST_IPS"
for ip in "${IP_ARR[@]}"; do
IP_RULES+="        Require ip $(echo "$ip"|xargs)\n"
done
fi

# Whitelist UA

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
for c in "${CHUNKS[@]}"; do CONTENT+="\n    SetEnvIfNoCase User-Agent \"$c\" bad_ua"; done
CONTENT+="\n</IfModule>\n\n<IfModule mod_authz_core.c>\n    <Location \"/\">\n${IP_RULES}        Require all granted\n        $UA_EXPR\n    </Location>\n</IfModule>\n\nCustomLog ${LOG_DIR}/ua_block.log combined env=bad_ua\n"

safe_write "$CONF_PATH" "$CONTENT"

if command -v "$CTL" >/dev/null 2>&1; then
    if "$CTL" configtest; then
        if ! eval "$RELOAD_CMD"; then
            echo "Warning: Unable to reload Apache using configured command: $RELOAD_CMD" >&2
        fi
    else
        echo "Apache configuration test failed" >&2
        exit 1
    fi
else
    echo "Warning: $CTL not found; skipping configtest and reload" >&2
fi

echo "Installed at $CONF_PATH"
echo "Block log: ${LOG_DIR}/ua_block.log"
echo "Cache: $CACHE_LIST"
echo "Whitelist IPs: ${WHITELIST_IPS:-none}"
echo "Whitelist UAs: ${WHITELIST_UA:-none}"

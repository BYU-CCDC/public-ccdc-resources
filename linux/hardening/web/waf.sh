#!/bin/bash
#
# Usage:
#   sudo ./waf-safe.sh
#   sudo ./waf-safe.sh --paranoia 1|2|3|4 --inbound-threshold N --outbound-threshold N
#   sudo ./waf-safe.sh --crs-source distro
#   sudo ./waf-safe.sh --crs-source git --crs-dir /etc/apache2/modsecurity-crs/coreruleset
#
set -euo pipefail

PARANOIA_LEVEL=1
ANOMALY_INBOUND=5
ANOMALY_OUTBOUND=4
CRS_SOURCE="distro"
CRS_GIT_DIR="/etc/apache2/modsecurity-crs/coreruleset"

usage() {
  echo "Usage: $0 [--paranoia 1-4] [--inbound-threshold N] [--outbound-threshold N] [--crs-source distro|git] [--crs-dir PATH]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --paranoia) PARANOIA_LEVEL="${2:?}"; shift 2 ;;
    --inbound-threshold) ANOMALY_INBOUND="${2:?}"; shift 2 ;;
    --outbound-threshold) ANOMALY_OUTBOUND="${2:?}"; shift 2 ;;
    --crs-source) CRS_SOURCE="${2:?}"; shift 2 ;;
    --crs-dir) CRS_GIT_DIR="${2:?}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown: $1"; usage; exit 1 ;;
  esac
done

[[ ${EUID} -eq 0 ]] || { echo "Run as root"; exit 1; }
[[ "$PARANOIA_LEVEL" =~ ^[1-4]$ ]] || { echo "Invalid paranoia"; exit 1; }
[[ "$ANOMALY_INBOUND" =~ ^[0-9]+$ ]] || { echo "Invalid inbound threshold"; exit 1; }
[[ "$ANOMALY_OUTBOUND" =~ ^[0-9]+$ ]] || { echo "Invalid outbound threshold"; exit 1; }
[[ "$CRS_SOURCE" == "distro" || "$CRS_SOURCE" == "git" ]] || { echo "Invalid --crs-source"; exit 1; }

APACHE_SERVICE=""
APACHE_CONF_DIR=""

if systemctl status apache2 >/dev/null 2>&1; then
  APACHE_SERVICE="apache2"
  APACHE_CONF_DIR="/etc/apache2"
elif systemctl status httpd >/dev/null 2>&1; then
  APACHE_SERVICE="httpd"
  APACHE_CONF_DIR="/etc/httpd"
else
  echo "Apache service not found (tried apache2, httpd)"
  exit 1
fi

WEB_USER="www-data"
WEB_GROUP="www-data"

if [[ "$APACHE_SERVICE" == "apache2" && -f /etc/apache2/envvars ]]; then
  set +u
  . /etc/apache2/envvars
  set -u
  WEB_USER="${APACHE_RUN_USER:-www-data}"
  WEB_GROUP="${APACHE_RUN_GROUP:-www-data}"
else
  WEB_USER="$(ps -o user= -C apache2 -C httpd 2>/dev/null | head -1 | awk '{print $1}')"
  WEB_USER="${WEB_USER:-www-data}"
  WEB_GROUP="$(id -gn "$WEB_USER" 2>/dev/null || echo "$WEB_USER")"
fi

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 libapache2-mod-security2 git curl logrotate
  DEBIAN_FRONTEND=noninteractive apt-get install -y modsecurity-crs || true
  a2enmod security2 >/dev/null 2>&1 || true
  a2enmod unique_id >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y httpd mod_security git curl logrotate mod_security_crs || true
elif command -v yum >/dev/null 2>&1; then
  yum install -y httpd mod_security git curl logrotate mod_security_crs || true
else
  echo "No supported package manager"
  exit 1
fi

mkdir -p /etc/modsecurity

if [[ -f /etc/modsecurity/modsecurity.conf-recommended ]]; then
  cp -f /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
elif [[ -f /etc/modsecurity/modsecurity.conf ]]; then
  :
else
  echo "Missing /etc/modsecurity/modsecurity.conf-recommended (package layout differs)"
  exit 1
fi

sed -i 's/^[[:space:]]*SecRuleEngine[[:space:]].*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

if grep -q '^[[:space:]]*SecAuditLogParts' /etc/modsecurity/modsecurity.conf; then
  sed -i 's/^[[:space:]]*SecAuditLogParts[[:space:]].*/SecAuditLogParts ABCEFHJKZ/' /etc/modsecurity/modsecurity.conf || true
fi

AUDIT_LOG_DIR="/var/log/apache2"
AUDIT_LOG_FILE="${AUDIT_LOG_DIR}/modsec_audit.log"
DEBUG_LOG_FILE="${AUDIT_LOG_DIR}/modsec_debug.log"

touch "$AUDIT_LOG_FILE" "$DEBUG_LOG_FILE" 2>/dev/null || true
chown "${WEB_USER}:${WEB_GROUP}" "$AUDIT_LOG_FILE" "$DEBUG_LOG_FILE" 2>/dev/null || true
chmod 640 "$AUDIT_LOG_FILE" "$DEBUG_LOG_FILE" 2>/dev/null || true

if grep -q '^[[:space:]]*SecAuditLog[[:space:]]' /etc/modsecurity/modsecurity.conf; then
  sed -i "s|^[[:space:]]*SecAuditLog[[:space:]].*|SecAuditLog ${AUDIT_LOG_FILE}|" /etc/modsecurity/modsecurity.conf || true
else
  printf '\nSecAuditLog %s\n' "$AUDIT_LOG_FILE" >> /etc/modsecurity/modsecurity.conf
fi

if grep -q '^[[:space:]]*SecDebugLog[[:space:]]' /etc/modsecurity/modsecurity.conf; then
  sed -i "s|^[[:space:]]*SecDebugLog[[:space:]].*|SecDebugLog ${DEBUG_LOG_FILE}|" /etc/modsecurity/modsecurity.conf || true
else
  printf 'SecDebugLog %s\n' "$DEBUG_LOG_FILE" >> /etc/modsecurity/modsecurity.conf
fi

CRS_SETUP=""
CRS_RULES_DIR=""

if [[ "$CRS_SOURCE" == "git" ]]; then
  mkdir -p "$(dirname "$CRS_GIT_DIR")"
  if [[ ! -d "$CRS_GIT_DIR/.git" ]]; then
    rm -rf "$CRS_GIT_DIR" 2>/dev/null || true
    git clone --depth 1 https://github.com/coreruleset/coreruleset.git "$CRS_GIT_DIR"
  fi
  [[ -f "$CRS_GIT_DIR/crs-setup.conf.example" ]] || { echo "Missing crs-setup.conf.example in $CRS_GIT_DIR"; exit 1; }
  cp -f "$CRS_GIT_DIR/crs-setup.conf.example" "$CRS_GIT_DIR/crs-setup.conf"
  CRS_SETUP="$CRS_GIT_DIR/crs-setup.conf"
  CRS_RULES_DIR="$CRS_GIT_DIR/rules"
else
  if [[ -d /usr/share/modsecurity-crs ]]; then
    CRS_SETUP="/usr/share/modsecurity-crs/crs-setup.conf"
    CRS_RULES_DIR="/usr/share/modsecurity-crs/rules"
  elif [[ -d /usr/share/owasp-modsecurity-crs ]]; then
    CRS_SETUP="/usr/share/owasp-modsecurity-crs/crs-setup.conf"
    CRS_RULES_DIR="/usr/share/owasp-modsecurity-crs/rules"
  else
    echo "Distro CRS not found under /usr/share/modsecurity-crs or /usr/share/owasp-modsecurity-crs"
    exit 1
  fi

  if [[ -f "${CRS_SETUP}.example" && ! -f "$CRS_SETUP" ]]; then
    cp -f "${CRS_SETUP}.example" "$CRS_SETUP"
  fi

  if [[ -f "$(dirname "$CRS_SETUP")/crs-setup.conf.example" ]]; then
    cp -f "$(dirname "$CRS_SETUP")/crs-setup.conf.example" "$CRS_SETUP"
  fi

  [[ -f "$CRS_SETUP" ]] || { echo "Missing CRS setup at $CRS_SETUP"; exit 1; }
  [[ -d "$CRS_RULES_DIR" ]] || { echo "Missing CRS rules dir at $CRS_RULES_DIR"; exit 1; }
fi

if grep -q '^# WAF_SAFE_TUNING_BEGIN$' "$CRS_SETUP" 2>/dev/null; then
  sed -i '/^# WAF_SAFE_TUNING_BEGIN$/,/^# WAF_SAFE_TUNING_END$/d' "$CRS_SETUP"
fi

cat >> "$CRS_SETUP" <<EOF

# WAF_SAFE_TUNING_BEGIN
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=${PARANOIA_LEVEL}"
SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.enforcing_anomaly_scoring=1"
SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=${ANOMALY_INBOUND}"
SecAction "id:900111,phase:2,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=${ANOMALY_OUTBOUND}"
# WAF_SAFE_TUNING_END
EOF

if [[ "$APACHE_SERVICE" == "apache2" ]]; then
  if [[ -f "${APACHE_CONF_DIR}/mods-enabled/security2.conf" ]]; then
    S2CONF="${APACHE_CONF_DIR}/mods-enabled/security2.conf"
  else
    S2CONF="${APACHE_CONF_DIR}/mods-available/security2.conf"
  fi

  if [[ ! -f "$S2CONF" ]]; then
    mkdir -p "${APACHE_CONF_DIR}/mods-available"
    cat > "${APACHE_CONF_DIR}/mods-available/security2.conf" <<'EOF'
<IfModule security2_module>
    IncludeOptional /etc/modsecurity/*.conf
</IfModule>
EOF
    a2enmod security2 >/dev/null 2>&1 || true
    S2CONF="${APACHE_CONF_DIR}/mods-enabled/security2.conf"
  fi

  if grep -q 'IncludeOptional[[:space:]]\+/usr/share/modsecurity-crs/\*\.load' "$S2CONF" 2>/dev/null; then
    sed -i 's|^.*IncludeOptional[[:space:]]\+/usr/share/modsecurity-crs/\*\.load.*$||' "$S2CONF" || true
  fi

  if ! grep -qF "$CRS_SETUP" "$S2CONF"; then
    printf '\nIncludeOptional %s\n' "$CRS_SETUP" >> "$S2CONF"
  fi
  if ! grep -qF "$CRS_RULES_DIR" "$S2CONF"; then
    printf 'IncludeOptional %s/*.conf\n' "$CRS_RULES_DIR" >> "$S2CONF"
  fi

  apache2ctl -t
else
  mkdir -p "${APACHE_CONF_DIR}/conf.d"
  cat > "${APACHE_CONF_DIR}/conf.d/mod_security.conf" <<EOF
LoadModule security2_module modules/mod_security2.so
LoadModule unique_id_module modules/mod_unique_id.so
<IfModule security2_module>
    IncludeOptional /etc/modsecurity/*.conf
    IncludeOptional ${CRS_SETUP}
    IncludeOptional ${CRS_RULES_DIR}/*.conf
</IfModule>
EOF
  httpd -t
fi

cat > /etc/logrotate.d/modsecurity <<'EOF'
/var/log/apache2/modsec_*.log {
  daily
  rotate 14
  missingok
  notifempty
  compress
  delaycompress
}
EOF

systemctl restart "$APACHE_SERVICE"
systemctl is-active --quiet "$APACHE_SERVICE" || { systemctl status "$APACHE_SERVICE" --no-pager || true; exit 1; }

cat > /usr/local/bin/waf-status <<EOF
#!/bin/bash
set -euo pipefail
svc="${APACHE_SERVICE}"

if systemctl is-active --quiet "\$svc"; then
  echo "service ok"
else
  echo "service down"
  systemctl status "\$svc" --no-pager || true
fi

if command -v apache2ctl >/dev/null 2>&1; then
  apache2ctl -M 2>/dev/null | grep -qi security2_module && echo "security2 ok" || echo "security2 missing"
elif command -v httpd >/dev/null 2>&1; then
  httpd -M 2>/dev/null | grep -qi security2_module && echo "security2 ok" || echo "security2 missing"
else
  echo "no apache ctl"
fi

tail -n 200 "${AUDIT_LOG_FILE}" 2>/dev/null | grep -Ei 'ModSecurity|Access denied|disruptive|Action: Intercepted|id "' | tail -n 5 || echo "no recent audit matches"
EOF
chmod +x /usr/local/bin/waf-status

echo "done"

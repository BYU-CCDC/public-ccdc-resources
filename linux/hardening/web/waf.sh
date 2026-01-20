#!/bin/bash
#
# Usage:
#   sudo ./waf-safe.sh
#   sudo ./waf-safe.sh --paranoia 1|2|3|4 --inbound-threshold N --outbound-threshold N
#
set -euo pipefail

PARANOIA_LEVEL=1
ANOMALY_INBOUND=5
ANOMALY_OUTBOUND=4

usage() {
  echo "Usage: $0 [--paranoia 1-4] [--inbound-threshold N] [--outbound-threshold N]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --paranoia) PARANOIA_LEVEL="${2:?}"; shift 2 ;;
    --inbound-threshold) ANOMALY_INBOUND="${2:?}"; shift 2 ;;
    --outbound-threshold) ANOMALY_OUTBOUND="${2:?}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown: $1"; usage; exit 1 ;;
  esac
done

[[ ${EUID} -eq 0 ]] || { echo "Run as root"; exit 1; }
[[ "$PARANOIA_LEVEL" =~ ^[1-4]$ ]] || { echo "Invalid paranoia"; exit 1; }
[[ "$ANOMALY_INBOUND" =~ ^[0-9]+$ ]] || { echo "Invalid inbound threshold"; exit 1; }
[[ "$ANOMALY_OUTBOUND" =~ ^[0-9]+$ ]] || { echo "Invalid outbound threshold"; exit 1; }

APACHE_SERVICE=""
if systemctl status apache2 >/dev/null 2>&1; then
  APACHE_SERVICE="apache2"
elif systemctl status httpd >/dev/null 2>&1; then
  APACHE_SERVICE="httpd"
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
  DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 libapache2-mod-security2 modsecurity-crs curl logrotate
  a2enmod security2 >/dev/null 2>&1 || true
  a2enmod unique_id >/dev/null 2>&1 || true
else
  echo "apt-get not found (this script targets Debian/Ubuntu layout you showed)"
  exit 1
fi

mkdir -p /etc/modsecurity

if [[ -f /etc/modsecurity/modsecurity.conf-recommended ]]; then
  cp -f /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
elif [[ -f /etc/modsecurity/modsecurity.conf ]]; then
  :
else
  echo "Missing /etc/modsecurity/modsecurity.conf-recommended"
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

CRS_LOAD="/usr/share/modsecurity-crs/owasp-crs.load"
CRS_DIR="/usr/share/modsecurity-crs"
CRS_RULES_DIR="${CRS_DIR}/rules"
CRS_SETUP="/etc/modsecurity/crs/crs-setup.conf"
CRS_EXC_BEFORE="/etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
CRS_EXC_AFTER="/etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"

[[ -f "$CRS_LOAD" ]] || { echo "Missing $CRS_LOAD"; exit 1; }
[[ -d "$CRS_RULES_DIR" ]] || { echo "Missing $CRS_RULES_DIR"; exit 1; }

mkdir -p /etc/modsecurity/crs

if [[ -f "${CRS_DIR}/crs-setup.conf.example" ]]; then
  cp -f "${CRS_DIR}/crs-setup.conf.example" "$CRS_SETUP"
elif [[ -f "${CRS_DIR}/crs-setup.conf" ]]; then
  cp -f "${CRS_DIR}/crs-setup.conf" "$CRS_SETUP"
else
  echo "Missing ${CRS_DIR}/crs-setup.conf.example"
  exit 1
fi

touch "$CRS_EXC_BEFORE" "$CRS_EXC_AFTER"
chmod 644 "$CRS_SETUP" "$CRS_EXC_BEFORE" "$CRS_EXC_AFTER"

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

S2CONF="/etc/apache2/mods-enabled/security2.conf"
[[ -f "$S2CONF" ]] || S2CONF="/etc/apache2/mods-available/security2.conf"
[[ -f "$S2CONF" ]] || { echo "Missing security2.conf"; exit 1; }

if ! grep -qF "IncludeOptional ${CRS_LOAD}" "$S2CONF"; then
  printf '\nIncludeOptional %s\n' "${CRS_LOAD}" >> "$S2CONF"
fi

apache2ctl -t
systemctl restart "$APACHE_SERVICE"
systemctl is-active --quiet "$APACHE_SERVICE" || { systemctl status "$APACHE_SERVICE" --no-pager || true; exit 1; }

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

apache2ctl -M 2>/dev/null | grep -qi security2_module && echo "security2 ok" || echo "security2 missing"

tail -n 200 "${AUDIT_LOG_FILE}" 2>/dev/null | grep -Ei 'ModSecurity|Access denied|disruptive|Action: Intercepted|id "' | tail -n 5 || echo "no recent audit matches"
EOF
chmod +x /usr/local/bin/waf-status

echo "done"

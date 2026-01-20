#!/bin/bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "run as root"; exit 1; }

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 libapache2-mod-security2 modsecurity-crs

a2enmod security2 >/dev/null 2>&1 || true
a2enmod unique_id >/dev/null 2>&1 || true

if [[ -f /etc/modsecurity/modsecurity.conf-recommended ]]; then
  mv -f /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
fi
[[ -f /etc/modsecurity/modsecurity.conf ]] || { echo "missing /etc/modsecurity/modsecurity.conf"; exit 1; }

sed -i 's/^[[:space:]]*SecRuleEngine[[:space:]]\+.*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
if grep -q '^[[:space:]]*SecAuditLogParts[[:space:]]' /etc/modsecurity/modsecurity.conf; then
  sed -i 's/^[[:space:]]*SecAuditLogParts[[:space:]]\+.*/SecAuditLogParts ABCEFHJKZ/' /etc/modsecurity/modsecurity.conf
else
  printf '\nSecAuditLogParts ABCEFHJKZ\n' >> /etc/modsecurity/modsecurity.conf
fi

mkdir -p /etc/modsecurity/crs
cat > /etc/modsecurity/crs/crs-setup.conf <<'EOF'
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=1"
SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.enforcing_anomaly_scoring=1"
SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=5"
SecAction "id:900111,phase:2,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=4"
EOF
: > /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
: > /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf

grep -qF "IncludeOptional /usr/share/modsecurity-crs/owasp-crs.load" /etc/apache2/mods-enabled/security2.conf || \
  printf '\nIncludeOptional /usr/share/modsecurity-crs/owasp-crs.load\n' >> /etc/apache2/mods-enabled/security2.conf

apache2ctl -t
systemctl restart apache2
systemctl is-active --quiet apache2 || { systemctl status apache2 --no-pager || true; exit 1; }

echo "ok"

#!/bin/bash
set -euo pipefail

PARANOIA_LEVEL=1
ANOMALY_INBOUND=5
ANOMALY_OUTBOUND=4
CRS_MODE="distro"            # distro|git
CRS_GIT_VERSION="v3.3.0"     # only for CRS_MODE=git

while [[ $# -gt 0 ]]; do
  case "$1" in
    --paranoia) PARANOIA_LEVEL="${2:?}"; shift 2 ;;
    --inbound-threshold) ANOMALY_INBOUND="${2:?}"; shift 2 ;;
    --outbound-threshold) ANOMALY_OUTBOUND="${2:?}"; shift 2 ;;
    --crs-mode) CRS_MODE="${2:?}"; shift 2 ;;
    --crs-git-version) CRS_GIT_VERSION="${2:?}"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 [--paranoia 1-4] [--inbound-threshold N] [--outbound-threshold N] [--crs-mode distro|git] [--crs-git-version vX.Y.Z]"
      exit 0
      ;;
    *) echo "Unknown: $1"; exit 1 ;;
  esac
done

[[ ${EUID} -eq 0 ]] || { echo "Run as root"; exit 1; }
[[ "$PARANOIA_LEVEL" =~ ^[1-4]$ ]] || { echo "Invalid paranoia"; exit 1; }
[[ "$ANOMALY_INBOUND" =~ ^[0-9]+$ ]] || { echo "Invalid inbound"; exit 1; }
[[ "$ANOMALY_OUTBOUND" =~ ^[0-9]+$ ]] || { echo "Invalid outbound"; exit 1; }
[[ "$CRS_MODE" == "distro" || "$CRS_MODE" == "git" ]] || { echo "Invalid crs-mode"; exit 1; }

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 libapache2-mod-security2 modsecurity-crs curl

a2enmod security2 >/dev/null 2>&1 || true
a2enmod unique_id >/dev/null 2>&1 || true

# 1) Use /etc/modsecurity/modsecurity.conf-recommended as base (rename it)
mkdir -p /etc/modsecurity
if [[ -f /etc/modsecurity/modsecurity.conf-recommended && ! -f /etc/modsecurity/modsecurity.conf ]]; then
  mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
fi
[[ -f /etc/modsecurity/modsecurity.conf ]] || { echo "Missing /etc/modsecurity/modsecurity.conf"; exit 1; }

# 2) Set SecRuleEngine On and SecAuditLogParts ABCEFHJKZ
sed -i 's/^[[:space:]]*SecRuleEngine[[:space:]]\+.*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
if grep -q '^[[:space:]]*SecAuditLogParts[[:space:]]' /etc/modsecurity/modsecurity.conf; then
  sed -i 's/^[[:space:]]*SecAuditLogParts[[:space:]]\+.*/SecAuditLogParts ABCEFHJKZ/' /etc/modsecurity/modsecurity.conf
else
  printf '\nSecAuditLogParts ABCEFHJKZ\n' >> /etc/modsecurity/modsecurity.conf
fi

S2CONF="/etc/apache2/mods-enabled/security2.conf"
[[ -f "$S2CONF" ]] || { echo "Missing $S2CONF"; exit 1; }

if [[ "$CRS_MODE" == "git" ]]; then
  # 4) Git CRS method (blog Step 3 second half)
  DEBIAN_FRONTEND=noninteractive apt-get install -y wget tar >/dev/null 2>&1 || true

  mkdir -p /etc/apache2/modsecurity-crs
  cd /etc/apache2/modsecurity-crs

  rm -rf "coreruleset-${CRS_GIT_VERSION#v}" "coreruleset-${CRS_GIT_VERSION#v}.tar.gz" 2>/dev/null || true
  wget -q "https://github.com/coreruleset/coreruleset/archive/${CRS_GIT_VERSION}.tar.gz" -O "coreruleset-${CRS_GIT_VERSION#v}.tar.gz"
  tar xzf "coreruleset-${CRS_GIT_VERSION#v}.tar.gz"

  CRS_DIR="/etc/apache2/modsecurity-crs/coreruleset-${CRS_GIT_VERSION#v}"
  [[ -f "$CRS_DIR/crs-setup.conf.example" ]] || { echo "Missing $CRS_DIR/crs-setup.conf.example"; exit 1; }
  mv -f "$CRS_DIR/crs-setup.conf.example" "$CRS_DIR/crs-setup.conf"

  # Force Apache to use Git CRS instead of distro *.load
  sed -i '\|IncludeOptional /usr/share/modsecurity-crs/.*\.load|d' "$S2CONF" || true

  grep -qF "IncludeOptional $CRS_DIR/crs-setup.conf" "$S2CONF" || {
    printf '\nIncludeOptional %s\nIncludeOptional %s\n' \
      "$CRS_DIR/crs-setup.conf" \
      "$CRS_DIR/rules/*.conf" >> "$S2CONF"
  }

else
  # 3) Distro CRS: ensure owasp-crs.load can include /etc/modsecurity/crs/crs-setup.conf
  CRS_LOAD="/usr/share/modsecurity-crs/owasp-crs.load"
  [[ -f "$CRS_LOAD" ]] || { echo "Missing $CRS_LOAD"; exit 1; }

  mkdir -p /etc/modsecurity/crs
  CRS_SETUP="/etc/modsecurity/crs/crs-setup.conf"

  # Ensure file exists (package does not create it)
  if [[ ! -f "$CRS_SETUP" ]]; then
    cat > "$CRS_SETUP" <<EOF
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=${PARANOIA_LEVEL}"
SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.enforcing_anomaly_scoring=1"
SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=${ANOMALY_INBOUND}"
SecAction "id:900111,phase:2,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=${ANOMALY_OUTBOUND}"
EOF
  fi

  # Keep Apache using distro loader
  grep -qF "IncludeOptional $CRS_LOAD" "$S2CONF" || printf '\nIncludeOptional %s\n' "$CRS_LOAD" >> "$S2CONF"

  # Optional include files referenced by owasp-crs.load
  touch /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
  touch /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
fi

apache2ctl -t
systemctl restart apache2
systemctl is-active --quiet apache2 || { systemctl status apache2 --no-pager || true; exit 1; }

echo "ok"

#!/usr/bin/env bash

function generate_strict_modsec_conf {
    local conf_file="/tmp/modsecurity_strict.conf"
    print_banner "Generating Strict ModSecurity Configuration"
    sudo bash -c "cat > $conf_file" <<'EOF'
# Strict ModSecurity Configuration for Maximum Protection

SecRuleEngine On
SecDefaultAction "phase:1,deny,log,status:403"
SecRequestBodyAccess On
SecResponseBodyAccess Off

# Block file uploads by denying requests with file parameters.
SecRule ARGS_NAMES "@rx .*" "id:1000,phase:2,deny,status:403,msg:'File upload detected; blocking.'"

# Set temporary directories (ensure OS-level security on these paths)
SecTmpDir /tmp/modsec_tmp
SecDataDir /tmp/modsec_data

# Enable detailed audit logging.
SecAuditEngine On
SecAuditLogParts ABIJDEFHZ
SecAuditLog /var/log/modsecurity_audit.log

# Limit PCRE usage to mitigate complex regex attacks.
SecPcreMatchLimit 1000
SecPcreMatchLimitRecursion 1000

# Restrict request and response body sizes.
SecResponseBodyLimit 524288
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
EOF
    log_info "Strict ModSecurity config generated at $conf_file"
    echo "$conf_file"
}

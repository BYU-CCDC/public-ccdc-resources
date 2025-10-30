#!/usr/bin/env bash

set -euo pipefail

REPO_BASE_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/main"
REPO_ROOT="linux"
WORKDIR="$(pwd)"
TARGET_ROOT="$WORKDIR/$REPO_ROOT"

DIRECTORIES=(
    "linux"
    "linux/hardening"
    "linux/hardening/bin"
    "linux/hardening/lib"
    "linux/hardening/core"
    "linux/hardening/web"
    "linux/hardening/continuous"
    "linux/bak"
    "linux/bak/web.bak"
    "linux/bak/web.bak/linux"
    "linux/bak/web.bak/linux/testing"
    "linux/bak/web.bak/linux/llm"
    "linux/bak/web.bak/linux/comprehensive"
    "linux/sysmon"
    "linux/configs"
)

FILES=(
    "linux/hardening/bin/ccdc.sh"
    "linux/hardening/lib/common.sh"
    "linux/hardening/lib/os_detect.sh"
    "linux/hardening/core/proxy.sh"
    "linux/hardening/core/splunk.sh"
    "linux/hardening/core/check_permissions.sh"
    "linux/hardening/core/firewall.sh"
    "linux/hardening/core/remove_profiles.sh"
    "linux/hardening/core/users.sh"
    "linux/hardening/core/fix_sysctl.sh"
    "linux/hardening/core/fork_defense.sh"
    "linux/hardening/core/services.sh"
    "linux/hardening/core/remove_unused_packages.sh"
    "linux/hardening/core/fix_pam.sh"
    "linux/hardening/core/backups.sh"
    "linux/hardening/core/patch_vulns.sh"
    "linux/hardening/core/kill_other_sessions.sh"
    "linux/hardening/core/service_integrity.sh"
    "linux/hardening/core/pii.sh"
    "linux/hardening/core/ssh.sh"
    "linux/hardening/core/security_modules.sh"
    "linux/hardening/web/menu.sh"
    "linux/hardening/web/apache.sh"
    "linux/hardening/web/modsec_docker.sh"
    "linux/hardening/web/php.sh"
    "linux/hardening/web/modsec_manual.sh"
    "linux/hardening/web/install-apache-ua-block.sh"
    "linux/hardening/web/secure_sql.sh"
    "linux/hardening/web/modsec_config.sh"
    "linux/hardening/web/web_hardening.sh"
    "linux/hardening/continuous/rkhunter.sh"
    "linux/hardening/continuous/iptables_restore.sh"
    "linux/hardening/continuous/clamAV.sh"
    "linux/hardening/continuous/nat_clear.sh"
    "linux/hardening/continuous/service_restart.sh"
    "linux/hardening/continuous/ufw_restore.sh"
    "linux/bak/fastfw.sh"
    "linux/bak/ccdc.sh"
    "linux/bak/nccdc.sh"
    "linux/bak/change_passwords.sh"
    "linux/bak/web.bak/vulscanner.sh"
    "linux/bak/web.bak/linux/llm/llm.sh"
    "linux/bak/web.bak/linux/testing/nmap.sh"
    "linux/bak/web.bak/linux/testing/caddy_reverse_proxy.sh"
    "linux/bak/web.bak/linux/testing/linPEAS.sh"
    "linux/bak/web.bak/linux/testing/fim.sh"
    "linux/bak/web.bak/linux/testing/velociraptor.sh"
    "linux/bak/web.bak/linux/testing/csp_enforcement.sh"
    "linux/bak/web.bak/linux/testing/dlp.sh"
    "linux/bak/web.bak/linux/testing/nessus.sh"
    "linux/bak/web.bak/linux/testing/pim.sh"
    "linux/bak/web.bak/linux/testing/owasp_zap.sh"
    "linux/bak/web.bak/linux/testing/nuclei.sh"
    "linux/bak/web.bak/linux/testing/pii.sh"
    "linux/bak/web.bak/linux/testing/k8_cluster.sh"
    "linux/bak/web.bak/linux/testing/ossec.sh"
    "linux/bak/web.bak/linux/testing/dockerize.sh"
    "linux/bak/web.bak/linux/testing/bloodhound.sh"
    "linux/bak/web.bak/linux/testing/waf.sh"
    "linux/bak/web.bak/linux/testing/wazuh.sh"
    "linux/bak/web.bak/linux/comprehensive/comprehensive.sh"
    "linux/sysmon/sysmon.sh"
)

DOWNLOADER=""

log() {
    local level="$1"
    shift
    printf '[%s] %s\n' "$level" "$*"
}

ensure_downloader() {
    local test_path="${REPO_BASE_URL}/linux/hardening/lib/common.sh"

    if command -v wget >/dev/null 2>&1; then
        if wget --spider -q "$test_path"; then
            DOWNLOADER="wget"
            log INFO "Using wget for downloads"
            return
        else
            log WARN "wget is present but failed the connectivity test"
        fi
    fi

    if command -v curl >/dev/null 2>&1; then
        if curl -fsI "$test_path" >/dev/null 2>&1; then
            DOWNLOADER="curl"
            log INFO "Using curl for downloads"
            return
        else
            log WARN "curl is present but failed the connectivity test"
        fi
    fi

    log ERROR "Unable to locate a working downloader (wget or curl)."
    exit 1
}

fetch() {
    local relative_path="$1"
    local destination="$WORKDIR/$relative_path"
    local url="${REPO_BASE_URL}/${relative_path}"

    if [ "$DOWNLOADER" = "wget" ]; then
        wget -qO "$destination" "$url"
    else
        curl -fsSL -o "$destination" "$url"
    fi
}

create_directories() {
    local dir
    for dir in "${DIRECTORIES[@]}"; do
        mkdir -p "$WORKDIR/$dir"
    done
}

copy_self_into_repo() {
    local source_path
    source_path="$(readlink -f "$0" 2>/dev/null || true)"

    if [ -n "$source_path" ] && [ -f "$source_path" ]; then
        cp "$source_path" "$TARGET_ROOT/hardening/bin/init.sh"
        chmod +x "$TARGET_ROOT/hardening/bin/init.sh"
    else
        log WARN "Could not determine current script path for copying"
    fi
}

download_files() {
    local file
    for file in "${FILES[@]}"; do
        log INFO "Downloading $file"
        fetch "$file"
        chmod +x "$WORKDIR/$file"
    done
}

handoff_to_orchestrator() {
    local orchestrator="$TARGET_ROOT/hardening/bin/ccdc.sh"

    if [ ! -f "$orchestrator" ]; then
        log ERROR "Expected orchestrator $orchestrator was not downloaded."
        exit 1
    fi

    if [ ! -x "$orchestrator" ]; then
        chmod +x "$orchestrator"
    fi

    log INFO "Launching $(basename "$orchestrator")"
    "$orchestrator" "$@"
}

main() {
    ensure_downloader
    create_directories
    copy_self_into_repo
    download_files
    handoff_to_orchestrator "$@"
}

main "$@"

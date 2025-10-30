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
        "linux/hardening/continuous/rust_scan.sh"
        "linux/hardening/continuous/fast_cve_nuclei.sh"
        "linux/hardening/continuous/web_scanners.sh"
        "linux/hardening/continuous/host_scanner.sh"
        "linux/hardening/continuous/rkhunter.sh"
        "linux/hardening/continuous/iptables_restore.sh"
        "linux/hardening/continuous/clamAV.sh"
        "linux/hardening/continuous/nat_clear.sh"
        "linux/hardening/continuous/service_restart.sh"
        "linux/hardening/continuous/ufw_restore.sh"
        "linux/hardening/continuous/wazuh.sh"
        "linux/hardening/continuous/nessus.sh"
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
    local level="$1"; shift
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
        cp "$source_path" "$TARGET_ROOT/hardening/bin/ccdc.sh"
        chmod +x "$TARGET_ROOT/hardening/bin/ccdc.sh"
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

execute_ccdc_workflow() {
    set +e
    set +u
    set -o pipefail

    if [ -n "${BASH_SOURCE[0]:-}" ]; then
        ROOT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
    else
        ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    fi

    LOG='/var/log/ccdc/harden.log'

    COMMON_LIB="$ROOT_DIR/lib/common.sh"
    if [ -f "$COMMON_LIB" ]; then
        # shellcheck source=/dev/null
        source "$COMMON_LIB"
    fi
    GITHUB_URL="https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/refs/heads/main"
    pm=""
    sudo_group=""
    ccdc_users=("ccdcuser1" "ccdcuser2")
    debug="false"
    ANSIBLE="false"
    IPTABLES_BACKUP="/tmp/iptables_backup.rules"
    UFW_BACKUP="/tmp/ufw_backup.rules"
    ENV_INITIALIZED="false"
    CONTINUOUS_WORKFLOW_COMPLETED="false"

    # Workflows are declared near the top so operators can see every function that
    # participates in the orchestrated runs without drilling through each helper
    # menu.
    CORE_WORKFLOW_STEPS=(
        "kill_other_sessions"
        "run_user_management"
        "run_firewall_workflow"
        "run_ssh_workflow"
        "run_security_modules_workflow"
        "run_proxy_workflow"
        "backups"
        "maybe_setup_splunk"
        "defend_against_forkbomb"
        "remove_profiles"
        "fix_pam"
        "search_ssn"
        "remove_unused_packages"
        "patch_vulnerabilities"
        "check_permissions"
        "sysctl_config"
        "kill_other_sessions"
    )

    WEB_WORKFLOW_STEPS=(
        "install_modsecurity_manual"
        "backup_databases"
        "secure_php_ini"
        "kill_other_sessions"
        "configure_apache_htaccess"
        "install_apache_user_agent_blocker"
        "my_secure_sql_installation"
        "disable_phpmyadmin"
        "kill_other_sessions"
        "configure_modsecurity"
        "update_prestashop_shop_url"
        "kill_other_sessions"
    )

    WEB_MENU_ACTIONS=(
        "install_modsecurity_manual|Install ModSecurity (manual packages)"
        "install_modsecurity_docker|Install ModSecurity (Docker container)"
        "configure_modsecurity|Configure ModSecurity ruleset"
        "backup_databases|Backup databases"
        "secure_php_ini|Secure php.ini"
        "configure_apache_htaccess|Configure Apache global security policy"
        "install_apache_user_agent_blocker|Install Apache User-Agent blocker"
        "my_secure_sql_installation|Run MySQL secure installation"
        "update_prestashop_shop_url|Update PrestaShop shop URL"
        "disable_phpmyadmin|Disable phpMyAdmin"
    )

    CONTINUOUS_WORKFLOW_STEPS=(
        "run_discovery_enumeration"
        "run_fast_cve_mapping"
        "run_web_scanner_suite"
        "run_host_integrity_suite"
        "run_clamav_scan"
        "run_wazuh_installation"
        "run_nessus_authenticated_setup"
    )

    function require_root {
        if [ "$EUID" -ne 0 ]; then
            log_error "Please run this script as root (or via sudo)."
            exit 1
        fi
    }

    function load_libraries {
        local file
        for file in "$ROOT_DIR"/lib/*.sh; do
            # shellcheck source=/dev/null
            source "$file"
        done
    }

    function load_modules {
        local dir file
        # Support legacy module locations while also sourcing the current layout.
        local module_dirs=(
            "$ROOT_DIR/core"
            "$ROOT_DIR/continuous"
            "$ROOT_DIR/web"
        )

        for dir in "${module_dirs[@]}"; do
            [ -d "$dir" ] || continue
            for file in "$dir"/*.sh; do
                [ -f "$file" ] || continue
                # shellcheck source=/dev/null
                source "$file"
            done
        done
    }

    function run_if_exists {
        local fn_name="$1"
        shift || true
        if declare -F "$fn_name" >/dev/null; then
            log_verbose "Running $fn_name"
            "$fn_name" "$@"
        else
            log_warning "Skipping $fn_name — function not yet implemented in modular tree."
        fi
    }

    function initialize_environment {
        if [ "$ENV_INITIALIZED" == "true" ]; then
            return 0
        fi

        detect_system_info
        install_prereqs
        ENV_INITIALIZED="true"
    }

    function run_workflow_sequence {
        local label="$1"
        shift
        local steps=("$@")

        if [ -n "$label" ]; then
            log_info "Starting $label workflow"
        fi

        for step in "${steps[@]}"; do
            if [ -n "$label" ]; then
                log_verbose "Executing step $step in $label workflow"
            else
                log_verbose "Executing step $step"
            fi
            run_if_exists "$step"
        done

        if [ -n "$label" ]; then
            log_success "Completed $label workflow"
        fi
    }

    function maybe_setup_splunk {
        if [ "$ANSIBLE" == "true" ]; then
            log_info "Ansible mode: Skipping Splunk installation."
            return 0
        fi

        run_if_exists setup_splunk
    }

    function run_final_checks {
        if [ "$CONTINUOUS_WORKFLOW_COMPLETED" == "true" ]; then
            run_if_exists check_service_integrity
            return 0
        fi

        run_if_exists run_rkhunter
        run_if_exists check_service_integrity
    }

    function run_user_management {
        run_if_exists create_ccdc_users
        run_if_exists change_passwords
        run_if_exists disable_users
        run_if_exists remove_sudoers
    }

    function run_firewall_workflow {
        initialize_environment
        run_if_exists audit_running_services
        run_if_exists disable_other_firewalls
        run_if_exists firewall_configuration_menu
    }

    function run_ssh_workflow {
        run_if_exists configure_login_banner
        run_if_exists secure_ssh
    }

    function run_security_modules_workflow {
        run_if_exists configure_security_modules
    }

    function run_proxy_workflow {
        run_if_exists setup_proxy_certificates_and_config
    }

    function run_web_menu {
        while true; do
            print_banner "Web Hardening Menu"

            if [ "$ANSIBLE" == "true" ]; then
                log_info "Ansible mode: Running full web hardening non-interactively."
                run_workflow_sequence "web hardening" "${WEB_WORKFLOW_STEPS[@]}"
                return 0
            fi

            echo "1) Run full web hardening workflow"
            echo "2) Install ModSecurity (manual packages)"
            echo "3) Install ModSecurity (Docker container)"
            echo "4) Configure ModSecurity ruleset"
            echo "5) Backup databases"
            echo "6) Secure php.ini"
            echo "7) Configure Apache .htaccess"
            echo "8) Run MySQL secure installation"
            echo "9) Disable phpMyAdmin"
            echo "10) Update PrestaShop shop URL"
            echo "11) Return to previous menu"

            read -r -p "Enter your choice [1-11]: " web_choice
            echo

            case "$web_choice" in
                1)
                    run_workflow_sequence "web hardening" "${WEB_WORKFLOW_STEPS[@]}"
                    ;;
                2)
                    run_if_exists install_modsecurity_manual
                    ;;
                3)
                    run_if_exists install_modsecurity_docker
                    ;;
                4)
                    run_if_exists configure_modsecurity
                    ;;
                5)
                    run_if_exists backup_databases
                    ;;
                6)
                    run_if_exists secure_php_ini
                    ;;
                7)
                    run_if_exists configure_apache_htaccess
                    ;;
                8)
                    run_if_exists my_secure_sql_installation
                    ;;
                9)
                    run_if_exists disable_phpmyadmin
                    ;;
                10)
                    run_if_exists update_prestashop_shop_url
                    ;;
                11)
                    log_info "Returning to previous menu..."
                    break
                    ;;
                *)
                    log_warning "Invalid option. Please try again."
                    ;;
            esac
            echo
        done
    }

    function show_core_menu {
        while true; do
            print_banner "Core Hardening Menu"
            echo "1) Run core hardening workflow"
            echo "2) User management"
            echo "3) Firewall configuration"
            echo "4) SSH hardening"
            echo "5) Security modules"
            echo "6) Proxy and certificate configuration"
            echo "7) Backups"
            echo "8) Splunk installation"
            echo "9) Defend against forkbomb"
            echo "10) Remove user profiles"
            echo "11) Fix PAM configuration"
            echo "12) Search for SSNs"
            echo "13) Remove unused packages"
            echo "14) Patch vulnerabilities"
            echo "15) Check permissions"
            echo "16) Apply sysctl hardening"
            echo "17) Return to main menu"
            read -r -p "Enter your choice [1-17]: " core_choice
            echo
            case "$core_choice" in
                1)
                    run_core_workflow
                    ;;
                2)
                    initialize_environment
                    run_user_management
                    ;;
                3)
                    run_firewall_workflow
                    ;;
                4)
                    initialize_environment
                    run_ssh_workflow
                    ;;
                5)
                    initialize_environment
                    run_security_modules_workflow
                    ;;
                6)
                    initialize_environment
                    run_proxy_workflow
                    ;;
                7)
                    initialize_environment
                    run_if_exists backups
                    ;;
                8)
                    initialize_environment
                    maybe_setup_splunk
                    ;;
                9)
                    initialize_environment
                    run_if_exists defend_against_forkbomb
                    ;;
                10)
                    initialize_environment
                    run_if_exists remove_profiles
                    ;;
                11)
                    initialize_environment
                    run_if_exists fix_pam
                    ;;
                12)
                    initialize_environment
                    run_if_exists search_ssn
                    ;;
                13)
                    initialize_environment
                    run_if_exists remove_unused_packages
                    ;;
                14)
                    initialize_environment
                    run_if_exists patch_vulnerabilities
                    ;;
                15)
                    initialize_environment
                    run_if_exists check_permissions
                    ;;
                16)
                    initialize_environment
                    run_if_exists sysctl_config
                    ;;
                17)
                    log_info "Returning to main menu..."
                    break
                    ;;
                *)
                    log_warning "Invalid option. Please try again."
                    ;;
            esac
            echo
        done
    }

    function show_continuous_menu {
        while true; do
            print_banner "Continuous Monitoring"
            echo "1) Run discovery scanning (rustscan + nmap)"
            echo "2) Run fast CVE mapping (nuclei + nmap NSE)"
            echo "3) Run web scanner suite (ZAP/Nikto/Gobuster)"
            echo "4) Run host integrity scanners (Lynis + rkhunter)"
            echo "5) Run ClamAV malware scan"
            echo "6) Deploy or link Wazuh"
            echo "7) Prepare Nessus authenticated scanning"
            echo "8) Run full continuous workflow"
            echo "9) Return to main menu"
            read -r -p "Enter your choice [1-9]: " adv_choice
            echo
            case "$adv_choice" in
                1)
                    initialize_environment
                    run_if_exists run_discovery_enumeration
                    ;;
                2)
                    initialize_environment
                    run_if_exists run_fast_cve_mapping
                    ;;
                3)
                    initialize_environment
                    run_if_exists run_web_scanner_suite
                    ;;
                4)
                    initialize_environment
                    run_if_exists run_host_integrity_suite
                    ;;
                5)
                    initialize_environment
                    run_if_exists run_clamav_scan
                    ;;
                6)
                    initialize_environment
                    run_if_exists run_wazuh_installation
                    ;;
                7)
                    initialize_environment
                    run_if_exists run_nessus_authenticated_setup
                    ;;
                8)
                    run_continuous_workflow
                    ;;
                9)
                    log_info "Returning to main menu..."
                    break
                    ;;
                *)
                    log_warning "Invalid option. Please try again."
                    ;;
            esac
            echo
        done
    }

    function run_core_workflow {
        initialize_environment
        run_workflow_sequence "core hardening" "${CORE_WORKFLOW_STEPS[@]}"
    }

    function run_continuous_workflow {
        initialize_environment
        CONTINUOUS_WORKFLOW_COMPLETED="true"
        run_workflow_sequence "continuous hardening" "${CONTINUOUS_WORKFLOW_STEPS[@]}"
    }

    function main {
        CONTINUOUS_WORKFLOW_COMPLETED="false"
        log_info "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
        log_info "Start of full hardening process"

        # --- Core run ---
        run_core_workflow

        # --- Optional menus (interactive unless ANSIBLE mode) ---
        if [ "$ANSIBLE" != "true" ]; then
            local web_choice
            web_choice=$(get_input_string "Would you like to perform web hardening? (y/N): ")
            if [[ "$web_choice" =~ ^[Yy]$ ]]; then
                run_web_menu
            fi

            local adv_choice
            adv_choice=$(get_input_string "Would you like to perform continuous monitoring checks? (y/N): ")
            if [[ "$adv_choice" =~ ^[Yy]$ ]]; then
                run_continuous_workflow
            fi
        else
            log_info "Ansible mode: Running web hardening non-interactively."
            run_if_exists harden_web
            log_info "Ansible mode: Skipping continuous monitoring prompts."
        fi

        # --- Final checks ---
        run_final_checks
        run_if_exists kill_other_sessions

        # RHEL/Fedora/Rocky/Alma: use 'needs-restarting -r' (exit 1 => reboot required, 0 => not required)
        # Debian/Ubuntu: presence of /var/run/reboot-required => reboot required
        log_info "Checking if a reboot is required for security updates..."
        reboot_needed="false"
        if command -v needs-restarting >/dev/null 2>&1; then
            needs-restarting -r >/dev/null 2>&1
            rc=$?
            if [ $rc -eq 1 ]; then
                reboot_needed="true"
            elif [ $rc -ne 0 ]; then
                # Unknown state from needs-restarting; fall back to file check if available
                if [ -f /var/run/reboot-required ]; then
                    reboot_needed="true"
                fi
            fi
        elif [ -f /var/run/reboot-required ]; then
            reboot_needed="true"
        fi

        if [ "$reboot_needed" = "true" ]; then
            if [ "$ANSIBLE" = "true" ]; then
                log_warning "Reboot required to apply security updates. Skipping interactive prompt due to Ansible mode."
                log_warning "Please schedule a reboot for this host as soon as possible."
            else
                log_warning "A system reboot is required to apply recent security updates."
                read -r -p "Apply updates and reboot now? (y/N): " reboot_choice
                if [[ "$reboot_choice" =~ ^[Yy]$ ]]; then
                    log_info "Rebooting system..."
                    sleep 2
                    reboot
                else
                    log_warning "Please reboot manually soon to apply critical changes."
                fi
            fi
        else
            log_success "No reboot required."
        fi

        log_success "End of full hardening process"
        log_info "Script log can be viewed at $LOG"
        log_warning "FORWARD chain is set to DROP. If this box is a router or network device, run 'sudo iptables -P FORWARD ALLOW'."
        log_warning "Please install system updates now."
    }

    function show_menu {
        while true; do
            print_banner "Script Executions Menu"
            echo "1) Comprehensive"
            echo "2) Linux Core Menu"
            echo "3) Web Core Menu"
            echo "4) Continuous Core Menu"
            echo "5) Exit"
            read -r -p "Enter your choice [1-5]: " choice
            echo
            case "$choice" in
                1)
                    # Full orchestrated run (core + optional web/continuous per main())
                    main
                    ;;
                2)
                    # Core hardening tasks menu
                    show_core_menu
                    ;;
                3)
                    # Web hardening menu
                    run_web_menu
                    ;;
                4)
                    # Continuous monitoring menu
                    show_continuous_menu
                    ;;
                5)
                    log_info "Exiting..."
                    break
                    ;;
                *)
                    log_warning "Invalid option. Please try again."
                    ;;
            esac
            echo
        done
    }


    function setup_logging {
        local log_path
        log_path=$(dirname "$LOG")

        mkdir -p "$log_path"
        chown root:root "$log_path"
        chmod 750 "$log_path"

        init_logging "$LOG"
        log_info "Verbose logging initialized at $LOG"
    }

    function parse_args {
        for arg in "$@"; do
            case "$arg" in
                --debug)
                    log_info "Debug mode enabled"
                    set_log_level DEBUG
                    ;;
                --verbose|-v)
                    log_info "Verbose mode enabled"
                    set_log_level VERBOSE
                    ;;
                --quiet)
                    log_info "Quiet mode enabled"
                    set_log_level WARNING
                    ;;
                -ansible)
                    log_info "Ansible mode enabled: Skipping interactive prompts."
                    ANSIBLE="true"
                    ;;
            esac
        done
    }

    require_root
    setup_logging
    parse_args "$@"
    load_libraries
    load_modules

    if [ "$ANSIBLE" == "true" ]; then
        main
    else
        show_menu
    fi
}

main() {
    ensure_downloader
    create_directories
    copy_self_into_repo
    download_files
    execute_ccdc_workflow "$@"
}

main "$@"

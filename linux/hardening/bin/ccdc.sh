#!/usr/bin/env bash

set -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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
    "web_hardening_menu"
    "manage_web_immutability_menu"
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
    "manage_web_immutability_menu|Manage web immutability"
    "disable_phpmyadmin|Disable phpMyAdmin"
    "web_hardening_menu|Legacy web hardening helper"
)

CONTINUOUS_WORKFLOW_STEPS=(
    "run_clamav_scan"
    "run_rkhunter"
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
        log_debug "Running $fn_name"
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

        echo "1) Run full web hardening workflow (${#WEB_WORKFLOW_STEPS[@]} steps)"
        echo "2) Install ModSecurity (manual packages)"
        echo "3) Install ModSecurity (Docker container)"
        echo "4) Configure ModSecurity ruleset"
        echo "5) Backup databases"
        echo "6) Secure php.ini"
        echo "7) Configure Apache .htaccess"
        echo "8) Run MySQL secure installation"
        echo "9) Disable phpMyAdmin"
        echo "10) Legacy web hardening helper"
        echo "11) Manage web immutability"
        echo "12) Return to previous menu"

        read -r -p "Enter your choice [1-12]: " web_choice
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
                run_if_exists web_hardening_menu
                ;;
            11)
                run_if_exists manage_web_immutability_menu
                ;;
            12)
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
        echo "1) Run ClamAV malware scan"
        echo "2) Run full continuous workflow (ClamAV + rkhunter)"
        echo "3) Return to main menu"
        read -r -p "Enter your choice [1-3]: " adv_choice
        echo
        case "$adv_choice" in
            1)
                initialize_environment
                run_if_exists run_clamav_scan
                ;;
            2)
                run_continuous_workflow
                ;;
            3)
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
                debug="true"
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
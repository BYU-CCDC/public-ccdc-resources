!/usr/bin/env bash
# Revised from the previous iteration to preserve readable menu structure.

function show_web_hardening_menu {
    print_banner "Web Hardening Menu"
    if [ "$ANSIBLE" == "true" ]; then
        log_info "Ansible mode: Running full web hardening non-interactively."
        harden_web
        disable_phpmyadmin
        return 0
    fi

    echo "1) Run Full Web Hardening Process"
    echo "2) Install ModSecurity (Manual)"
    echo "3) Install ModSecurity (Dockerized)"
    echo "4) Backup Databases"
    echo "5) Secure php.ini Files"
    echo "6) Configure Apache Global Security"
    echo "7) Install Apache User-Agent Blocker"
    echo "8) Secure MySQL/MariaDB"
    echo "9) Rotate Database Passwords"
    echo "10) Update PrestaShop Shop URL"
    echo "11) Disable phpMyAdmin"
    echo "12) Configure ModSecurity (block mode with OWASP CRS)"
    echo "13) Install BunkerWeb WAF (replaces ModSecurity)"
    echo "14) Exit Web Hardening Menu"
    read -r -p "Enter your choice [1-14]: " web_menu_choice
    echo

    case $web_menu_choice in
        1)
            print_banner "Web Hardening Initiated"
            install_modsecurity_manual
            backup_databases
            secure_php_ini
            kill_other_sessions
            configure_apache_htaccess
            install_apache_user_agent_blocker
            secure_mysql
            rotate_db_passwords
            disable_phpmyadmin
            kill_other_sessions
            configure_modsecurity
            update_prestashop_shop_url
            kill_other_sessions
            ;;
        2)
            print_banner "Installing Manual ModSecurity"
            install_modsecurity_manual
            ;;
        3)
            print_banner "Installing Dockerized ModSecurity"
            install_modsecurity_docker
            ;;
        4)
            print_banner "Backing Up Databases"
            backup_databases
            ;;
        5)
            print_banner "Securing php.ini Files"
            secure_php_ini
            ;;
        6)
            print_banner "Configuring Apache Global Security"
            configure_apache_htaccess
            ;;
        7)
            print_banner "Installing Apache User-Agent Blocker"
            install_apache_user_agent_blocker
            ;;
        8)
            print_banner "Securing MySQL/MariaDB"
            secure_mysql
            ;;
        9)
            print_banner "Rotating Database Passwords"
            rotate_db_passwords
            ;;
        10)
            print_banner "Updating PrestaShop Shop URL"
            update_prestashop_shop_url
            ;;
        11)
            print_banner "Disabling phpMyAdmin"
            disable_phpmyadmin
            ;;
        12)
            print_banner "Configuring ModSecurity (Block Mode + OWASP CRS)"
            configure_modsecurity
            ;;
        13)
            print_banner "Installing BunkerWeb WAF"

            # BunkerWeb includes ModSecurity + CRS. Running Apache security2 concurrently is usually a bad idea.
            if command -v apache2ctl >/dev/null 2>&1 && apache2ctl -M 2>/dev/null | grep -qi 'security2_module'; then
                log_warning "Apache ModSecurity (security2) is currently enabled."
                log_warning "BunkerWeb includes its own ModSecurity + OWASP CRS."
                log_warning "Running both can cause duplicate blocking and hard-to-debug failures."

                read -r -p "Disable Apache security2 before continuing? [Y/n]: " _bw_disable_modsec
                if [[ ! "${_bw_disable_modsec,,}" =~ ^n$ ]]; then
                    sudo a2dismod security2 >/dev/null 2>&1 || true
                    sudo systemctl restart apache2 >/dev/null 2>&1 || true
                    log_info "Apache security2 disabled."
                else
                    log_warning "Continuing with Apache security2 still enabled (not recommended)."
                fi
            fi

            # Stop BunkerWeb services first in case a previous failed install left the setup wizard exposed
            sudo systemctl stop bunkerweb bunkerweb-scheduler bunkerweb-ui 2>/dev/null || true

            install_and_configure_bunkerweb
            ;;
        14)
            log_info "Exiting Web Hardening Menu"
            ;;
        *)
            log_error "Invalid option."
            ;;
    esac
}

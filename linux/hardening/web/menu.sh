#!/usr/bin/env bash

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
    echo "11) Manage Web Directory Immutability"
    echo "12) Disable phpMyAdmin"
    echo "13) Configure ModSecurity (block mode with OWASP CRS)"
    echo "14) Exit Web Hardening Menu"
    read -p "Enter your choice [1-14]: " web_menu_choice
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
            manage_web_immutability_menu
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
            print_banner "Managing Web Directory Immutability"
            manage_web_immutability_menu
            ;;
        12)
            print_banner "Disabling phpMyAdmin"
            disable_phpmyadmin
            ;;
        13)
            print_banner "Configuring ModSecurity (Block Mode + OWASP CRS)"
            configure_modsecurity
            ;;
        14)
            log_info "Exiting Web Hardening Menu"
            ;;
        *)
            log_error "Invalid option."
            ;;
    esac
}

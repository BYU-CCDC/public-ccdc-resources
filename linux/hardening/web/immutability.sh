#!/usr/bin/env bash

function manage_web_immutability_menu {
    # A list of “candidate” directories that you believe should normally be immutable.
    # Adjust this list to suit your environment. 
    # Typically these are config directories or static content directories.
    # This script is subject for removal
    local default_web_dirs=(
        "/etc/nginx" 
        "/etc/apache2" 
        "/usr/share/nginx" 
        "/var/www" 
        "/var/www/html" 
        "/etc/lighttpd" 
        "/etc/mysql" 
        "/etc/postgresql" 
        "/var/lib/apache2" 
        "/var/lib/mysql" 
        "/etc/redis" 
        "/etc/phpMyAdmin" 
        "/etc/php.d" 
    )

    # An array to store discovered directories from default_web_dirs.
    local discovered_dirs=()

    # 1) Populate discovered_dirs if they actually exist on the system.
    for dir in "${default_web_dirs[@]}"; do
        if [ -d "$dir" ]; then
            discovered_dirs+=("$dir")
        fi
    done

    # Helper function to set +i
    function set_immutable {
        local path="$1"
        sudo chattr -R +i "$path" 2>/dev/null && \
            log_success "Immutable set recursively on: $path" || \
            log_warning "Failed to set immutable on: $path"
    }

    # Helper function to set -i
    function remove_immutable {
        local path="$1"
        sudo chattr -R -i "$path" 2>/dev/null && \
            log_success "Immutable removed (recursively) from: $path" || \
            log_warning "Failed to remove immutable on: $path"
    }

    # Sub-functions for each menu option

    # Detect & set discovered directories immutable
    function detect_and_set_immutable {
        # Show what we found
        log_info "The following directories have been detected:"
        for d in "${discovered_dirs[@]}"; do
            echo "    $d"
        done

        if [ ${#discovered_dirs[@]} -eq 0 ]; then
            log_warning "No default directories detected."
            return
        fi

        read -p "Would you like to set ALL of these directories to immutable (recursively)? (y/N): " imm_choice
        if [[ "$imm_choice" =~ ^[Yy]$ ]]; then
            # Set each discovered directory to +i
            for d in "${discovered_dirs[@]}"; do
                set_immutable "$d"
            done
        else
            # If user says No, let them specify manually
            log_info "Enter the directories you'd like to set as immutable (one per line)."
            echo "    Press ENTER on a blank line to finish."
            while true; do
                local custom_dir
                read -r -p "Directory (blank to finish): " custom_dir
                if [ -z "$custom_dir" ]; then
                    break
                fi
                if [ -d "$custom_dir" ]; then
                    set_immutable "$custom_dir"
                else
                    log_error "Directory '$custom_dir' not found or invalid."
                fi
            done
        fi
    }

    # Reverse discovered immutability
    function reverse_discovered_immutable {
        if [ ${#discovered_dirs[@]} -eq 0 ]; then
            log_warning "No discovered directories found to un-set."
            return
        fi
        log_info "Removing immutability for discovered directories..."
        for d in "${discovered_dirs[@]}"; do
            remove_immutable "$d"
        done
    }

    # Specify custom dirs to set +i
    function custom_set_immutable {
        log_info "Enter the directories you'd like to set as immutable (one per line)."
        echo "    Press ENTER on a blank line to finish."
        while true; do
            local custom_dir
            read -r -p "Directory to set immutable (blank to finish): " custom_dir
            if [ -z "$custom_dir" ]; then
                break
            fi
            if [ -d "$custom_dir" ]; then
                set_immutable "$custom_dir"
            else
                log_error "'$custom_dir' not found or not a directory."
            fi
        done
    }

    # Specify custom dirs to remove immutability
    function custom_remove_immutable {
        log_info "Enter the directories you'd like to remove immutability from (one per line)."
        echo "    Press ENTER on a blank line to finish."
        while true; do
            local custom_dir
            read -r -p "Directory to remove immutability (blank to finish): " custom_dir
            if [ -z "$custom_dir" ]; then
                break
            fi
            if [ -d "$custom_dir" ]; then
                remove_immutable "$custom_dir"
            else
                log_error "'$custom_dir' not found or not a directory."
            fi
        done
    }

    # sub-menu loop
    while true; do
        echo
        echo "========== WEB DIRECTORY IMMUTABILITY MENU =========="
        echo "1) Detect & Set Discovered Directories Immutable"
        echo "2) Reverse Immutability for Discovered Directories"
        echo "3) Specify Custom Directories to Set Immutable"
        echo "4) Specify Custom Directories to Remove Immutability"
        echo "5) Return to Web Hardening Menu"
        read -p "Enter your choice [1-5]: " sub_choice
        echo

        case "$sub_choice" in
            1) detect_and_set_immutable ;;
            2) reverse_discovered_immutable ;;
            3) custom_set_immutable ;;
            4) custom_remove_immutable ;;
            5) log_info "Returning to the previous menu..."; break ;;
            *) log_error "Invalid option. Please choose 1-5." ;;
        esac
    done
}

function handle_non_immutable_dirs {
    # These are the paths that failed or are known to fail with chattr
    # or for which "Operation not supported/permitted" was reported.
    # Adjust as needed for your environment.
    # Needs to be expanded 
    local non_immutable_paths=(
        "/etc/apache2/conf-enabled"
        "/etc/apache2/sites-enabled"
        "/etc/apache2/mods-enabled"
        "/etc/mysql"
        "/var/www/html/prestashop/vendor/smarty/smarty/libs/sysplugins"
        "/var/www/html/prestashop/vendor/symfony/symfony/src/Symfony/Component/Intl/Resources/data/currencies"
        "/var/www/html/prestashop/vendor/tecnickcom/tcpdf/fonts"
        "/var/www/html/prestashop/vendor/ezyang/htmlpurifier/library/HTMLPurifier/ConfigSchema/schema"
        "/var/www/html/prestashop/modules/klaviyoopsautomation/vendor/giggsey/libphonenumber-for-php/src/data"
        "/var/www/html/prestashop/modules/klaviyoopsautomation/vendor/giggsey/locale/data"
        "/var/www/html/prestashop/modules/ps_shoppingcart/vendor/svix/go-internal/openapi"
        "/var/www/html/prestashop/modules/ps_facebook/vendor/facebook/php-business-sdk/examples"
        "/var/www/html/prestashop/modules/ps_facebook/vendor/facebook/php-business-sdk/src/FacebookAds/Object"
        "/var/www/html/prestashop/modules/ps_checkout/vendor/giggsey/libphonenumber-for-php/src/data"
        "/var/www/html/prestashop/modules/ps_checkout/vendor/giggsey/locale/data"
        "/var/www/html/prestashop/modules/ps_gamification/views/img/badges"
        "/var/www/html/prestashop/modules/ps_xmarketintegration/vendor/giggsey/libphonenumber-for-php/src/data"
        "/var/www/html/prestashop/modules/ps_xmarketintegration/vendor/giggsey/locale/data"
        "/var/www/html/prestashop/var/cache/prod/ContainerDuzmaSE"
        "/var/www/html/prestashop/var/cache/prod/ContainerBSdrPE"
        "/var/www/html/prestashop/translations/default"
        "/var/www/html/prestashop/translations/en-US"
        "/var/www/html/prestashop/themes/classic/assets/fonts"
        "/var/www/html/prestashop/themes/new-theme/public"
        "/var/www/html/prestashop/img/su"
        "/var/www/html/prestashop/img/l"
        "/var/www/html/prestashop/img/c"
        "/var/www/html/prestashop/img/p"
        "/var/www/html/prestashop/localization/CLDR/core/common/main"
    )

    print_banner "Manage Non-Immutable Directories"

    # Another sub-menu
    while true; do
        echo "These directories/files cannot be made immutable."
        echo "1) Backup (rename) them with a .bak extension"
        echo "2) Restore them from .bak to original"
        echo "3) Return to previous menu"
        read -rp "Enter your choice [1-3]: " sub_choice
        echo

        case "$sub_choice" in
            1)
                # Rename each path -> path.bak
                log_info "Backing up directories/files (renaming -> .bak)..."
                for path in "${non_immutable_paths[@]}"; do
                    if [ -e "$path" ] && [ ! -e "${path}.bak" ]; then
                        sudo mv "$path" "${path}.bak"
                        echo "  Renamed: $path -> ${path}.bak"
                    else
                        # Either $path doesn't exist or $path.bak already exists
                        echo "  Skipped: $path"
                    fi
                done
                log_info "Backup (rename) complete."
                ;;
            2)
                # Rename each .bak -> original
                log_info "Restoring directories/files from .bak -> original..."
                for path in "${non_immutable_paths[@]}"; do
                    if [ -e "${path}.bak" ] && [ ! -e "$path" ]; then
                        sudo mv "${path}.bak" "$path"
                        echo "  Restored: ${path}.bak -> $path"
                    else
                        # Either ${path}.bak doesn't exist or original already exists
                        echo "  Skipped: $path"
                    fi
                done
                log_info "Restore complete."
                ;;
            3)
                log_info "Returning to previous menu."
                break
                ;;
            *)
                log_error "Invalid option."
                ;;
        esac

        echo
    done
}

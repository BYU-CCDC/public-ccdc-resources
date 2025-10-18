#!/usr/bin/env bash

CMS_CONFIG_HELPER="$(dirname "${BASH_SOURCE[0]}")/cms_config_updater.py"

function _mysql_exec_internal {
    local password="$1"
    local include_connect_expired="$2"
    shift 2
    local args=("$@")
    local cmd=()

    if [ "$EUID" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
        cmd+=("sudo")
    fi

    cmd+=("mysql" "-u" "root")

    if [ "$include_connect_expired" == "true" ]; then
        cmd+=("--connect-expired-password")
    fi

    if [ -n "$password" ]; then
        cmd+=("--password=$password")
    fi

    cmd+=("${args[@]}")

    "${cmd[@]}"
}

function _mysql_exec {
    local password="$1"
    shift
    local args=("$@")
    local output
    local status

    output=$(_mysql_exec_internal "$password" "true" "${args[@]}" 2>&1)
    status=$?
    if [ $status -eq 0 ]; then
        printf '%s' "$output"
        return 0
    fi

    if [[ "$output" == *"unknown option '--connect-expired-password'"* ]]; then
        output=$(_mysql_exec_internal "$password" "false" "${args[@]}" 2>&1)
        status=$?
        printf '%s' "$output"
        return $status
    fi

    printf '%s' "$output"
    return $status
}

function _mysql_connection_ok {
    local password="$1"
    if _mysql_exec "$password" -e "SELECT 1;" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

function _escape_sql_string {
    local input="$1"
    local backslash="\\"
    local single_quote="'"
    input="${input//${backslash}/${backslash}${backslash}}"
    input="${input//${single_quote}/${backslash}${single_quote}}"
    echo "$input"
}

function _escape_mysql_identifier {
    local input="$1"
    local backtick=$'\x60'
    local double_backtick=$'\x60\x60'
    input="${input//${backtick}/${double_backtick}}"
    echo "$input"
}

function _run_mysql_query {
    local password="$1"
    local description="$2"
    local query="$3"
    local output
    if output=$(_mysql_exec "$password" -e "$query" 2>&1); then
        log_success "$description"
        return 0
    else
        log_warning "$description failed: $output"
        return 1
    fi
}

function _verify_mysql_application_login {
    local user="$1"
    local host="$2"
    local password="$3"
    local database="$4"

    if ! command -v mysql >/dev/null 2>&1; then
        log_warning "mysql client not available; skipping credential verification for ${user}@${host:-localhost}."
        return 0
    fi

    local -a cmd=(mysql "-u" "$user")
    if [ -n "$host" ]; then
        cmd+=("-h" "$host")
    fi
    if [ -n "$database" ]; then
        cmd+=("-D" "$database")
    fi
    cmd+=("-e" "SELECT 1;")

    local -a runner=()
    if [ "$EUID" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
        runner=(sudo -E)
    fi

    log_verbose "Verifying MySQL credentials for ${user}@${host:-localhost}"

    local exit_code
    if [ -n "$password" ]; then
        if [ ${#runner[@]} -gt 0 ]; then
            "${runner[@]}" env MYSQL_PWD="$password" "${cmd[@]}" >/dev/null 2>&1
        else
            MYSQL_PWD="$password" "${cmd[@]}" >/dev/null 2>&1
        fi
    else
        if [ ${#runner[@]} -gt 0 ]; then
            "${runner[@]}" "${cmd[@]}" >/dev/null 2>&1
        else
            "${cmd[@]}" >/dev/null 2>&1
        fi
    fi
    exit_code=$?

    if [ $exit_code -eq 0 ]; then
        log_success "Verified MySQL connectivity for ${user}@${host:-localhost}"
        return 0
    fi

    log_warning "Unable to verify MySQL connectivity for ${user}@${host:-localhost} (exit code $exit_code)"
    return 1
}
function secure_mysql {
    print_banner "MySQL/MariaDB Hardening"

    if [ "$ANSIBLE" == "true" ]; then
        log_warning "mysql_secure_installation cannot run non-interactively in this context."
        return 0
    fi

    local current_root_pass
    local new_root_pass

    current_root_pass=$(get_silent_input_string "Enter current MySQL root password (leave blank if none): ")
    echo

    new_root_pass=$(get_silent_input_string "Enter desired MySQL root password: ")
    echo

    if [ -z "$new_root_pass" ]; then
        log_warning "No new MySQL root password provided. Aborting MySQL hardening."
        return 1
    fi

    local escaped_new_pass
    escaped_new_pass=$(_escape_sql_string "$new_root_pass")

    local connection_password=""
    local candidate_passwords=()

    if [ -n "$current_root_pass" ]; then
        candidate_passwords+=("$current_root_pass")
    fi
    candidate_passwords+=("")

    for candidate in "${candidate_passwords[@]}"; do
        if _mysql_connection_ok "$candidate"; then
            connection_password="$candidate"
            break
        fi
    done

    if [ -z "$connection_password" ] && ! _mysql_connection_ok ""; then
        log_error "Unable to authenticate to MySQL as root. Root may be configured for auth_socket access."
        log_error "Update root credentials manually and rerun this function if needed."
        return 1
    fi

    local effective_root_pass="$connection_password"
    local set_password_success="false"

    log_info "Attempting to update root password using ALTER USER."
    local alter_output
    if alter_output=$(_mysql_exec "$connection_password" -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${escaped_new_pass}';" 2>&1); then
        log_success "Root password updated via ALTER USER."
        effective_root_pass="$new_root_pass"
        set_password_success="true"
    else
        log_warning "ALTER USER failed: $alter_output"
        log_info "Attempting to switch root to mysql_native_password."
        if alter_output=$(_mysql_exec "$connection_password" -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${escaped_new_pass}';" 2>&1); then
            log_success "Root password updated using mysql_native_password authenticator."
            effective_root_pass="$new_root_pass"
            set_password_success="true"
        else
            log_warning "mysql_native_password alteration failed: $alter_output"
            log_info "Attempting legacy SET PASSWORD syntax."
            if alter_output=$(_mysql_exec "$connection_password" -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('${escaped_new_pass}');" 2>&1); then
                log_success "Root password updated using legacy SET PASSWORD syntax."
                effective_root_pass="$new_root_pass"
                set_password_success="true"
            else
                log_warning "SET PASSWORD failed: $alter_output"
            fi
        fi
    fi

    if [ "$set_password_success" != "true" ]; then
        log_warning "Root password was not updated. MySQL may be using auth_socket or stricter password validation policies."
        log_warning "Continuing with additional hardening steps using the existing authentication method."
    fi

    local post_password="$effective_root_pass"
    if ! _mysql_connection_ok "$post_password"; then
        log_warning "Unable to authenticate with the effective credentials; retrying with socket/no-password authentication."
        if _mysql_connection_ok ""; then
            post_password=""
        else
            log_error "Unable to connect to MySQL for clean-up queries."
            return 1
        fi
    fi

    local plugin_output
    if plugin_output=$(_mysql_exec "$post_password" -Nse "SELECT plugin FROM mysql.user WHERE user='root' AND host='localhost';" 2>&1); then
        if [[ "$plugin_output" == "auth_socket" ]]; then
            log_warning "Root user is configured with auth_socket. Password changes may not take effect until the plugin is changed manually."
        fi
    fi
    _run_mysql_query "$post_password" "Removing anonymous MySQL users" "DELETE FROM mysql.user WHERE User = '';"
    _run_mysql_query "$post_password" "Restricting remote root access" "DELETE FROM mysql.user WHERE User = 'root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    _run_mysql_query "$post_password" "Dropping test database" "DROP DATABASE IF EXISTS test;"
    _run_mysql_query "$post_password" "Cleaning privileges for test databases" "DELETE FROM mysql.db WHERE Db = 'test' OR Db LIKE 'test\\_%';"
    _run_mysql_query "$post_password" "Flushing privilege tables" "FLUSH PRIVILEGES;"

    log_info "MySQL hardening routine completed."
}

function _prompt_web_directories {
    local input_dirs
    read -r -p "Enter web root directories to scan (space-separated) [/var/www /srv/www /usr/share/nginx/html]: " input_dirs
    if [ -z "$input_dirs" ]; then
        echo "/var/www /srv/www /usr/share/nginx/html"
    else
        echo "$input_dirs"
    fi
}
function rotate_db_passwords {
    print_banner "Database Credential Rotation"

    if [ "$ANSIBLE" == "true" ]; then
        log_warning "Database rotation prompts are not supported in non-interactive Ansible mode."
        return 0
    fi

    local database_name
    local database_user
    local database_host
    local new_password
    local root_password

    database_name=$(get_input_string "Enter the database name (leave blank to skip privilege refresh): ")
    database_user=$(get_input_string "Enter the database user to rotate: ")
    if [ -z "$database_user" ]; then
        log_error "Database user is required to rotate credentials."
        return 1
    fi

    database_host=$(get_input_string "Enter the database host (leave blank to keep current CMS host values) [localhost]: ")
    if [ -z "$database_host" ]; then
        database_host="localhost"
    fi

    local cms_host_update="$database_host"
    if [ "$ANSIBLE" != "true" ] && [[ "$database_host" != "localhost" && "$database_host" != "127.0.0.1" && "$database_host" != "::1" ]]; then
        log_warning "Non-local database host $database_host specified. Ensure the CMS can reach this host before updating configuration files."
        local confirm_host
        confirm_host=$(get_input_string "Propagate ${database_host} to CMS configuration files? (y/N): ")
        if [[ ! "$confirm_host" =~ ^[Yy]$ ]]; then
            log_info "CMS configuration host entries will be left unchanged."
            cms_host_update=""
        fi
    fi

    new_password=$(get_silent_input_string "Enter the new password for $database_user@$database_host: ")
    echo
    if [ -z "$new_password" ]; then
        log_error "New password cannot be empty."
        return 1
    fi

    root_password=$(get_silent_input_string "Enter MySQL root password (leave blank to use socket/no-password auth): ")
    echo

    local connection_password="$root_password"
    if ! _mysql_connection_ok "$connection_password"; then
        if _mysql_connection_ok ""; then
            log_warning "Falling back to socket/no-password authentication for root."
            connection_password=""
        else
            log_error "Unable to authenticate to MySQL as root."
            return 1
        fi
    fi

    local escaped_user
    local escaped_host
    local escaped_pass
    escaped_user=$(_escape_sql_string "$database_user")
    escaped_host=$(_escape_sql_string "$database_host")
    escaped_pass=$(_escape_sql_string "$new_password")

    local alter_output
    if alter_output=$(_mysql_exec "$connection_password" -e "ALTER USER '${escaped_user}'@'${escaped_host}' IDENTIFIED BY '${escaped_pass}';" 2>&1); then
        log_success "Updated credentials for ${database_user}@${database_host}."
    else
        log_warning "ALTER USER failed: $alter_output"
        log_info "Attempting legacy SET PASSWORD syntax."
        if alter_output=$(_mysql_exec "$connection_password" -e "SET PASSWORD FOR '${escaped_user}'@'${escaped_host}' = PASSWORD('${escaped_pass}');" 2>&1); then
            log_success "Updated credentials using legacy syntax for ${database_user}@${database_host}."
        else
            log_error "Unable to update password for ${database_user}@${database_host}: $alter_output"
            return 1
        fi
    fi

    if [ -n "$database_name" ]; then
        local escaped_db
        escaped_db=$(_escape_mysql_identifier "$database_name")
        _run_mysql_query "$connection_password" "Reasserting privileges for ${database_user}@${database_host} on ${database_name}" "GRANT ALL PRIVILEGES ON \`$escaped_db\`.* TO '${escaped_user}'@'${escaped_host}';"
    fi

    _run_mysql_query "$connection_password" "Flushing privilege tables" "FLUSH PRIVILEGES;"

    local dir_input
    dir_input=$(_prompt_web_directories)
    read -r -a search_dirs <<< "$dir_input"

    if _verify_mysql_application_login "$database_user" "$database_host" "$new_password" "$database_name"; then
        update_cms_configs "$database_name" "$database_user" "$cms_host_update" "$new_password" "${search_dirs[@]}"
    else
        log_error "Skipping CMS configuration updates to avoid breaking connectivity. Verify credentials for ${database_user}@${database_host} and rerun the helper if needed."
    fi
}
function _cms_helper_check {
    if ! command -v python3 >/dev/null 2>&1; then
        log_error "python3 is required to update CMS configuration files."
        return 1
    fi
    if [ ! -f "$CMS_CONFIG_HELPER" ]; then
        log_error "CMS configuration helper not found at $CMS_CONFIG_HELPER"
        return 1
    fi
    return 0
}

function _run_cms_helper {
    local mode="$1"
    local file_path="$2"
    shift 2
    local args=("python3" "$CMS_CONFIG_HELPER" "$mode" "$file_path")
    while [ $# -gt 0 ]; do
        args+=("$1")
        shift
    done
    "${args[@]}"
}
function update_wordpress_config {
    local file_path="$1"
    local db_name="$2"
    local db_user="$3"
    local db_host="$4"
    local db_pass="$5"

    [ -f "$file_path" ] || return 1
    _cms_helper_check || return 1

    local helper_args=()
    [ -n "$db_name" ] && helper_args+=("--db-name" "$db_name")
    [ -n "$db_user" ] && helper_args+=("--db-user" "$db_user")
    [ -n "$db_host" ] && helper_args+=("--db-host" "$db_host")
    [ -n "$db_pass" ] && helper_args+=("--db-pass" "$db_pass")

    local output
    output=$(_run_cms_helper "wordpress" "$file_path" "${helper_args[@]}" 2>&1)
    local status=$?
    if [ $status -eq 0 ]; then
        log_success "Updated $file_path"
        return 0
    elif [ $status -eq 10 ]; then
        log_info "No credential entries found in $file_path"
        return 1
    else
        log_error "Failed to update $file_path: $output"
        return 1
    fi
}

function update_prestashop_config {
    local file_path="$1"
    local db_name="$2"
    local db_user="$3"
    local db_host="$4"
    local db_pass="$5"

    [ -f "$file_path" ] || return 1
    _cms_helper_check || return 1

    local helper_args=()
    [ -n "$db_name" ] && helper_args+=("--db-name" "$db_name")
    [ -n "$db_user" ] && helper_args+=("--db-user" "$db_user")
    [ -n "$db_host" ] && helper_args+=("--db-host" "$db_host")
    [ -n "$db_pass" ] && helper_args+=("--db-pass" "$db_pass")

    local output
    output=$(_run_cms_helper "prestashop" "$file_path" "${helper_args[@]}" 2>&1)
    local status=$?
    if [ $status -eq 0 ]; then
        log_success "Updated $file_path"
        return 0
    elif [ $status -eq 10 ]; then
        log_info "No credential entries found in $file_path"
        return 1
    else
        log_error "Failed to update $file_path: $output"
        return 1
    fi
}

function update_joomla_config {
    local file_path="$1"
    local db_name="$2"
    local db_user="$3"
    local db_host="$4"
    local db_pass="$5"

    [ -f "$file_path" ] || return 1
    _cms_helper_check || return 1

    local helper_args=()
    [ -n "$db_name" ] && helper_args+=("--db-name" "$db_name")
    [ -n "$db_user" ] && helper_args+=("--db-user" "$db_user")
    [ -n "$db_host" ] && helper_args+=("--db-host" "$db_host")
    [ -n "$db_pass" ] && helper_args+=("--db-pass" "$db_pass")

    local output
    output=$(_run_cms_helper "joomla" "$file_path" "${helper_args[@]}" 2>&1)
    local status=$?
    if [ $status -eq 0 ]; then
        log_success "Updated $file_path"
        return 0
    elif [ $status -eq 10 ]; then
        log_info "No credential entries found in $file_path"
        return 1
    else
        log_error "Failed to update $file_path: $output"
        return 1
    fi
}

function update_env_file {
    local file_path="$1"
    local db_name="$2"
    local db_user="$3"
    local db_host="$4"
    local db_pass="$5"

    [ -f "$file_path" ] || return 1
    _cms_helper_check || return 1

    local helper_args=()
    [ -n "$db_name" ] && helper_args+=("--db-name" "$db_name")
    [ -n "$db_user" ] && helper_args+=("--db-user" "$db_user")
    [ -n "$db_host" ] && helper_args+=("--db-host" "$db_host")
    [ -n "$db_pass" ] && helper_args+=("--db-pass" "$db_pass")

    local output
    output=$(_run_cms_helper "env" "$file_path" "${helper_args[@]}" 2>&1)
    local status=$?
    if [ $status -eq 0 ]; then
        log_success "Updated $file_path"
        return 0
    elif [ $status -eq 10 ]; then
        log_info "No credential entries found in $file_path"
        return 1
    else
        log_error "Failed to update $file_path: $output"
        return 1
    fi
}
function update_cms_configs {
    local db_name="$1"
    local db_user="$2"
    local db_host="$3"
    local db_pass="$4"
    shift 4
    local search_dirs=("$@")
    if [ ${#search_dirs[@]} -eq 0 ]; then
        search_dirs=("/var/www" "/srv/www" "/usr/share/nginx/html")
    fi

    local updated_count=0
    local scanned_dirs=0

    for dir in "${search_dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            log_verbose "Skipping non-existent directory $dir"
            continue
        fi
        log_info "Scanning $dir for CMS configuration files."
        scanned_dirs=$((scanned_dirs + 1))

        while IFS= read -r -d '' wp_config; do
            log_verbose "Discovered WordPress configuration at $wp_config"
            if update_wordpress_config "$wp_config" "$db_name" "$db_user" "$db_host" "$db_pass"; then
                updated_count=$((updated_count + 1))
            fi
        done < <(find "$dir" -type f -name "wp-config.php" -print0 2>/dev/null)

        while IFS= read -r -d '' presta_config; do
            log_verbose "Discovered PrestaShop configuration at $presta_config"
            if update_prestashop_config "$presta_config" "$db_name" "$db_user" "$db_host" "$db_pass"; then
                updated_count=$((updated_count + 1))
            fi
        done < <(find "$dir" -type f \( -path "*/app/config/parameters.php" -o -path "*/config/settings.inc.php" \) -print0 2>/dev/null)

        while IFS= read -r -d '' env_file; do
            log_verbose "Discovered environment file at $env_file"
            if update_env_file "$env_file" "$db_name" "$db_user" "$db_host" "$db_pass"; then
                updated_count=$((updated_count + 1))
            fi
        done < <(find "$dir" -type f -name ".env" -print0 2>/dev/null)

        while IFS= read -r -d '' joomla_config; do
            log_verbose "Discovered Joomla configuration at $joomla_config"
            if update_joomla_config "$joomla_config" "$db_name" "$db_user" "$db_host" "$db_pass"; then
                updated_count=$((updated_count + 1))
            fi
        done < <(find "$dir" -type f -name "configuration.php" -print0 2>/dev/null)

        while IFS= read -r -d '' drupal_settings; do
            log_warning "Drupal configuration detected at $drupal_settings. Review manually to ensure database credentials are updated."
        done < <(find "$dir" -type f -path "*/sites/default/settings.php" -print0 2>/dev/null)
    done

    if [ $scanned_dirs -eq 0 ]; then
        log_warning "No valid directories were provided for CMS configuration scanning."
    fi

    if [ $updated_count -gt 0 ]; then
        log_success "Completed configuration updates for $updated_count file(s)."
    else
        log_warning "No CMS configurations were updated. Review logs to ensure credentials are synchronized."
    fi
}

function my_secure_sql_installation {
    secure_mysql
}
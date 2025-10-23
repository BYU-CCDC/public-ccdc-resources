#!/usr/bin/env bash

function secure_php_ini {
    print_banner "Securing php.ini Files"

    local php_ini_block='[PHP]
engine = On
short_open_tag = Off
precision = 14
output_buffering = 4096
zlib.output_compression = Off
implicit_flush = Off
unserialize_callback_func =
serialize_precision = -1
disable_functions = proc_open, popen, disk_free_space, diskfreespace, set_time_limit, leak, tmpfile, exec, system, shell_exec, passthru, show_source, phpinfo, pcntl_exec
disable_classes =
zend.enable_gc = On
expose_php = Off
max_execution_time = 30
max_input_time = 60
memory_limit = 128M
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
display_errors = Off
display_startup_errors = Off
log_errors = On
log_errors_max_len = 1024
ignore_repeated_errors = Off
ignore_repeated_source = Off
variables_order = "GPCS"
request_order = "GP"
register_argc_argv = Off
auto_globals_jit = On
post_max_size = 8M
auto_prepend_file =
auto_append_file =
default_mimetype = "text/html"
default_charset = "UTF-8"
doc_root =
user_dir =
enable_dl = Off
file_uploads = Off
upload_max_filesize = 2M
max_file_uploads = 20
allow_url_fopen = Off
allow_url_include = Off
default_socket_timeout = 60

[CLI Server]
cli_server.color = On

[Pdo_mysql]
pdo_mysql.default_socket=

[mail function]
mail.add_x_header = Off

[ODBC]
odbc.allow_persistent = On
odbc.check_persistent = On
odbc.max_persistent = -1
odbc.max_links = -1
odbc.defaultlrl = 4096
odbc.defaultbinmode = 1

[Interbase]
ibase.allow_persistent = 1
ibase.max_persistent = -1
ibase.max_links = -1
ibase.timestampformat = "%Y-%m-%d %H:%M:%S"
ibase.dateformat = "%Y-%m-%d"
ibase.timeformat = "%H:%M:%S"

[MySQLi]
mysqli.max_persistent = -1
mysqli.allow_persistent = On
mysqli.max_links = -1
mysqli.default_port = 3306
mysqli.default_socket =
mysqli.default_host =
mysqli.default_user =
mysqli.default_pw =
mysqli.reconnect = Off

[mysqlnd]
mysqlnd.collect_statistics = On
mysqlnd.collect_memory_statistics = Off

[PostgreSQL]
pgsql.allow_persistent = On
pgsql.auto_reset_persistent = Off
pgsql.max_persistent = -1
pgsql.max_links = -1
pgsql.ignore_notice = 0
pgsql.log_notice = 0

[bcmath]
bcmath.scale = 0

[Session]
session.save_handler = files
session.use_strict_mode = 1
session.use_cookies = 1
session.use_only_cookies = 1
session.name = PHPSESSID
session.auto_start = 0
session.cookie_lifetime = 14400
session.cookie_path = /
session.cookie_domain =
session.cookie_httponly = 1
session.cookie_samesite = Strict
session.serialize_handler = php
session.gc_probability = 1
session.gc_divisor = 1000
session.gc_maxlifetime = 1440
session.referer_check =
session.cache_limiter = nocache
session.cache_expire = 60
session.use_trans_sid = 0
session.sid_length = 128
session.trans_sid_tags = "a=href,area=href,frame=src,form="
session.sid_bits_per_character = 6

[Assertion]
zend.assertions = -1

[Tidy]
tidy.clean_output = Off

[ldap]
ldap.max_links = -1
'

    for ini in $(find / -type f -name "php.ini" 2>/dev/null); do
        echo "[+] Securing $ini..."
        mkdir -p /opt/ironhide_backups/php_ini
        cp "$ini" "/opt/ironhide_backups/php_ini/$(basename $ini).bak"

        # Write secure base
        echo "$php_ini_block" > "$ini"

        # Add conditional for legacy PHP (magic_quotes_gpc)
        if php --ri magic_quotes_gpc &>/dev/null; then
            echo "magic_quotes_gpc = On" >> "$ini"
        else
            echo "; magic_quotes_gpc deprecated or not supported" >> "$ini"
        fi

        # Confirm write
        log_info "Updated $ini with hardened PHP configuration."
    done
}

# Fallback option / failsafe
#function secure_php_ini {
#    print_banner "Securing php.ini Files"
#    for ini in $(find / -name "php.ini" 2>/dev/null); do
#        echo "[+] Writing php.ini options to $ini..."
#        echo "disable_functions = shell_exec, exec, passthru, proc_open, popen, system, phpinfo" >> "$ini"
#        echo "max_execution_time = 3" >> "$ini"
#        echo "register_globals = off" >> "$ini"
#        echo "magic_quotes_gpc = on" >> "$ini"
#        echo "allow_url_fopen = off" >> "$ini"
#        echo "allow_url_include = off" >> "$ini"
#        echo "display_errors = off" >> "$ini"
#        echo "short_open_tag = off" >> "$ini"
#        echo "session.cookie_httponly = 1" >> "$ini"
#        echo "session.use_only_cookies = 1" >> "$ini"
#        echo "session.cookie_secure = 1" >> "$ini"
#    done
#}

function disable_phpmyadmin {
    print_banner "Disabling phpMyAdmin"

    # List of common phpMyAdmin directories
    local phpmyadmin_dirs=( "/etc/phpmyadmin" "/usr/share/phpmyadmin" "/var/www/phpmyadmin" "/var/www/html/phpmyadmin" "/usr/local/phpmyadmin" )
    for loc in "${phpmyadmin_dirs[@]}"; do
        if [ -d "$loc" ]; then
            sudo mv "$loc" "${loc}_disabled"
            log_info "Renamed directory $loc to ${loc}_disabled"
        fi
    done

    # List of common phpMyAdmin configuration files
    local phpmyadmin_configs=( "/etc/httpd/conf.d/phpMyAdmin.conf" "/etc/apache2/conf-enabled/phpmyadmin.conf" )
    for file in "${phpmyadmin_configs[@]}"; do
        if [ -f "$file" ]; then
            sudo mv "$file" "${file}.disabled"
            log_info "Renamed configuration file $file to ${file}.disabled"
        fi
    done
}

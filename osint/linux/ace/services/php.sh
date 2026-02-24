# Secure php.ini files

for ini in $(find / -name "php.ini" 2>/dev/null); do
	echo "[+] Writing php.ini options to $ini..."
	echo "disable_functions = shell_exec, exec, passthru, proc_open, popen, system, phpinfo" >> $ini
	echo "max_execution_time = 3" >> $ini
	echo "register_globals = off" >> $ini
	echo "magic_quotes_gpc = on" >> $ini
	echo "allow_url_fopen = off" >> $ini
	echo "allow_url_include = off" >> $ini
	echo "display_errors = off" >> $ini
	echo "short_open_tag = off" >> $ini
	echo "session.cookie_httponly = 1" >> $ini
	echo "session.use_only_cookies = 1" >> $ini
	echo "session.cookie_secure = 1" >> $ini
done

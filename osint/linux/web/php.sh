#!/bin/bash

HOSTNAME=$(hostname || cat /etc/hostname)
echo -e "HOST: $HOSTNAME"
echo "------------------"


sys=$(command -v service || command -v systemctl || command -v rc-service)



for file in $(find / -name 'php.ini' 2>/dev/null); do
	echo "disable_functions = 1e, exec, system, shell_exec, passthru, popen, curl_exec, curl_multi_exec, parse_file_file, show_source, proc_open, pcntl_exec/" >> $file
	echo "track_errors = off" >> $file
	echo "html_errors = off" >> $file
	echo "max_execution_time = 3" >> $file
	echo "display_errors = off" >> $file
	echo "short_open_tag = off" >> $file
	echo "session.cookie_httponly = 1" >> $file
	echo "session.use_only_cookies = 1" >> $file
	echo "session.cookie_secure = 1" >> $file
	echo "expose_php = off" >> $file
	echo "magic_quotes_gpc = off " >> $file
	echo "allow_url_fopen = off" >> $file
	echo "allow_url_include = off" >> $file
	echo "register_globals = off" >> $file
	echo "file_uploads = off" >> $file

	echo $file changed

done;



if [ -d /etc/nginx ]; then
	$sys nginx restart || $sys restart nginx
	echo nginx restarted
fi


if [ -d /etc/apache2 ]; then
	$sys apache2 restart || $sys restart apache2
	echo apache2 restarted
fi


if [ -d /etc/httpd ]; then
	$sys httpd restart || $sys restart httpd
	echo httpd restarted
fi

if [ -d /etc/lighttpd ]; then
	$sys lighttpd restart || $sys restart lighttpd
	echo lighttpd restarted
fi

file=$(find /etc -maxdepth 2 -type f -name 'php-fpm*' -print -quit)

if [ -d /etc/php/*/fpm ] || [ -n "$file" ]; then
        $sys *php* restart || $sys restart *php*
        echo php-fpm restarted
fi
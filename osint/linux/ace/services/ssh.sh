# Secure ssh
if service sshd status > /dev/null; then
	# We're using root over SSH, so we enable it
	sed -i '1s;^;PermitRootLogin yes\n;' /etc/ssh/sshd_config
	sed -i '1s;^;PubkeyAuthentication no\n;' /etc/ssh/sshd_config

	# Don't set UsePAM no for Fedora, RHEL, CentOS
	if ! cat /etc/os-release | grep -q "REDHAT_"; then
		sed -i '1s;^;UsePAM no\n;' /etc/ssh/sshd_config
	fi

	sed -i '1s;^;UseDNS no\n;' /etc/ssh/sshd_config
	sed -i '1s;^;PermitEmptyPasswords no\n;' /etc/ssh/sshd_config
	sed -i '1s;^;AddressFamily inet\n;' /etc/ssh/sshd_config
	sed -i '1s;^;Banner none\n;' /etc/ssh/sshd_config

	# Restart service if config is good
	sshd -t && systemctl restart sshd
fi

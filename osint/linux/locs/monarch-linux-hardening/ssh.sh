#!/bin/sh

HOSTNAME=$(hostname || cat /etc/hostname)
echo "HOST: $HOSTNAME"
echo "------------------"

sys=$(command -v service)
if [ $? -ne 0 ]; then
	sys=$(command -v systemctl)
	if [ $? -ne 0 ]; then
		sys="/etc/rc.d/sshd"
		cmd="none"
	else
		cmd="systemctl"
	fi
else
	cmd="service"
fi

cp -r /etc/ssh/sshd_config.d /etc/ssh/backup_sshd_config.d
rm -rf /etc/ssh/sshd_config.d

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
chattr +i /etc/ssh/sshd_config.bak

sed -i \
	-e 's/^[ ]*PubkeyAuthentication yes/PubkeyAuthentication no/' \
	-e 's/^[ ]*PermitEmptyPasswords yes/PermitEmptyPasswords no/' \
	-e 's/^[ ]*PasswordAuthentication no/PasswordAuthentication yes/' \
	-e 's/^[ ]*PermitRootLogin yes/PermitRootLogin no/' \
	/etc/ssh/sshd_config

cat <<EOF >>/etc/ssh/sshd_config

PubkeyAuthentication no
PermitEmptyPasswords no
PasswordAuthentication yes
PermitRootLogin no
UsePAM yes
Match Address 172.16.1.7
  PermitRootLogin yes
EOF

command_exists() {
	command -v "$1" >/dev/null 2>&1
}

if command_exists sshd && ! sshd -t; then
	echo "Syntax error in config"
	exit 1
fi

if command_exists ssh; then
	if ssh -o PreferredAuthentications=none -o NoHostAuthenticationForLocalhost=yes localhost 2>&1 | grep publickey; then
		echo "Warning: public key allowed for authentication"
	fi
fi

if [ "${cmd}" = "systemctl" ]; then
	$sys restart ssh 2>/dev/null
	if [ $? -eq 0 ]; then
		echo "Successfully restarted ssh"
	else
		$sys restart sshd 2>/dev/null
		if [ $? -eq 0 ]; then
			echo "Successfully restarted sshd"
		else
			echo "systemctl could not restart sshd/ssh"
		fi
	fi
elif [ "${cmd}" = "service" ]; then
	$sys ssh restart 2>/dev/null
	if [ $? -eq 0 ]; then
		echo "Successfully restarted ssh"
	else
		$sys sshd restart 2>/dev/null
		if [ $? -eq 0 ]; then
			echo "Successfully restarted ssh"
		else
			echo "service could not restart sshd/ssh"
		fi
	fi
else
	$sys restart 2>/dev/null
	if [ $? -eq 0 ]; then
		echo "/etc/rc.d/sshd successfully restarted ssh"
	else
		echo "/etc/rc.d/sshd could not restart ssh"
	fi
fi

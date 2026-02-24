#!/bin/sh

# I love chattr

nexec() {
	if command -v "$1"; then
		chmod 0400 $(command -v "$1")
	fi
}

chattr -R +i /etc/pam.d
find /lib /usr/lib /usr/lib64 -name "pam_*.so" -exec chattr +i {} \;
chattr +i /etc/ssh/sshd_config
chattr +i /etc/profile
chattr +i /etc/sudoers
chattr -R +i /etc/sudoers.d
chattr +i /etc/doas.conf

nexec pkexec
nexec sudoedit
nexec visudo

cat <<EOF >>/etc/sysctl.conf

kernel.unprivileged_bpf_disabled=1
kernel.modules_disabled=1
kernel.kexec_load_disabled=1
EOF

sysctl -p

chattr +i /etc/sysctl.conf
chattr -R +i /etc/sysctl.d/

# thanks ucf :D
killall cron
killall crond
killall atd
killall anacron

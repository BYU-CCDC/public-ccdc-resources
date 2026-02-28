# sysctl configurations

file="/etc/sysctl.conf"
echo "net.ipv4.tcp_syncookies = 1" >> $file
echo "net.ipv4.tcp_synack_retries = 2" >> $file
echo "net.ipv4.tcp_challenge_ack_limit = 1000000" >> $file
echo "net.ipv4.tcp_rfc1337 = 1" >> $file
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> $file
echo "net.ipv4.conf.all.accept_redirects = 0" >> $file
echo "net.ipv4.icmp_echo_ignore_all = 1" >> $file
echo "kernel.core_uses_pid = 1" >> $file
echo "kernel.kptr_restrict = 2" >> $file
echo "kernel.perf_event_paranoid = 2" >> $file
echo "kernel.randomize_va_space = 2" >> $file
echo "kernel.sysrq = 0" >> $file
echo "kernel.yama.ptrace_scope = 2" >> $file
echo "fs.protected_hardlinks = 1" >> $file
echo "fs.protected_symlinks = 1" >> $file
echo "fs.suid_dumpable = 0" >> $file
echo "kernel.unprivileged_userns_clone = 0" >> $file
echo "fs.protected_fifos = 2" >> $file
echo "fs.protected_regular = 2" >> $file
echo "kernel.kptr_restrict = 2" >> $file

sysctl -p >/dev/null

# disable kernel module insertion? (risky)
#/sbin/sysctl -w kernel.modules_disabled=1

# check if kernel version if old/vulnerable
#echo -n "[.] Kernel version: "
#uname -r

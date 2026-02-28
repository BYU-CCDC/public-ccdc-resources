#!/usr/bin/env bash

HOSTNAME=$(hostname || cat /etc/hostname)
echo -e "HOST: $HOSTNAME"
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

if ! grep -q -Fx "Include /etc/ssh/sshd_config.d/*.conf" /etc/ssh/sshd_config; then
  echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
fi


cp -r /etc/ssh/sshd_config.d /etc/ssh/backup_sshd_config.d
rm -rf /etc/ssh/sshd_config.d
mkdir /etc/ssh/sshd_config.d

echo "PubkeyAuthentication no" > /etc/ssh/sshd_config.d/dominion_ssh.conf
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config.d/dominion_ssh.conf
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config.d/dominion_ssh.conf
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config.d/dominion_ssh.conf
echo "UsePAM yes" >> /etc/ssh/sshd_config.d/dominion_ssh.conf


if [ "$(tail -1 /etc/ssh/sshd_config.d/dominion_ssh.conf)" == "PermitRootLogin yes" ] && [ "$(head -1 /etc/ssh/sshd_config.d/dominion_ssh.conf)" == "PubkeyAuthentication no" ]; then
  echo "Successfully changed config files"
else
  echo "Did not properly change config files"
fi
if [ "${cmd}" == "systemctl" ]; then
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
elif [ "${cmd}" == "service" ]; then
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

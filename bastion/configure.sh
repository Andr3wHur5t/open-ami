#!/bin/sh
set -e

# force sudo
if [ $EUID != 0 ]; then
    sudo "$0" "$@"
    exit $?
fi

echo "-- Uninstalling unused packages"
# TODO Uninstall unused

echo "-- Configure emergency access user"
useradd emergency -mUc 'Emergency TCP Proxy User'
mkdir '/home/emergency/.ssh/'
mv /tmp/files/emergency_authorized_keys /home/emergency/.ssh/authorized_keys
chmod 644 /home/emergency/.ssh/authorized_keys
chown emergency:emergency /home/emergency/.ssh/authorized_keys /home/emergency/.ssh
chattr +i /home/emergency/.ssh/authorized_keys /home/emergency/.ssh

echo "-- Configuring Access User"
useradd prox -mUc 'TCP Proxy User'
mkdir '/home/prox/.ssh/'
# Block Usage of authorized keys for prox user; all authentication will come through CA certs
touch /home/prox/.ssh/authorizedKeys
chattr +i /home/emergency/.ssh/authorized_keys

echo "-- Block access to ec2-user keys"
echo "" > /home/ec2-user/.ssh/authorized_keys
chattr +i /home/ec2-user/.ssh/authorized_keys

echo "-- Putting logs in append only mode"
chattr -R +a /var/log/

echo "-- Making shadow immutable"
chattr +i /etc/passwd
chattr +i /etc/shadow

echo "-- Updating OpenSSH config"
mv /tmp/files/sshd_config /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
service sshd restart

echo "-- Cleanup"
rm -r /tmp/files

echo "-- AIDE database update"
# TODO: Set AIDE init script


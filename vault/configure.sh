#!/bin/sh
set -e

# force sudo
if [ $EUID != 0 ]; then
    sudo "$0" "$@"
    exit $?
fi

# Install Vault Bin
echo "-- Installing vault"
unzip /tmp/files/vault_0.8.3_linux_386.zip
mv ./vault /usr/bin

# Try to help with tampering
echo "-- Setting bin permissions"
chown root:root /usr/bin/vault
chmod 555 /usr/bin/vault
chattr +i /usr/bin/vault

echo "-- Installing Damon"
mv /tmp/files/vaultd /etc/init.d/vaultd
chown root:root /etc/init.d/vaultd
chmod 751 /etc/init.d/vaultd
chattr +i /etc/init.d/vaultd

mv /tmp/files/vault.conf /etc/init/vault.conf
chmod 644 /etc/init/vault.conf
chattr +i /etc/init/vault.conf

echo "-- Registering for boot."
chkconfig --add vaultd

echo "-- Allow vault traffic in IP tables"
iptables -A INPUT -p tcp --dport 8200 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 8200 -m state --state ESTABLISHED -j ACCEPT
service iptables save

echo "-- Disable SSH"



#!/bin/sh
set -e

# force sudo
if [ $EUID != 0 ]; then
    sudo "$0" "$@"
    exit $?
fi

echo "-- Applying bulk config"
cp /tmp/provision/etc/* /etc/
cp /tmp/provision/sysconfig/* /etc/sysconfig/

# Disable unused file system types (1.1.1.1 - 1.1.1.8)
echo "-- Disabling unused file systems"
mv /tmp/provision/CIS.conf /etc/modprobe.d/CIS.conf

# Update Partitions (1.1.2 - 1.1.17)
echo "-- Updating partition & permissions"
DISK_NAME=`mount | grep 'on / ' | cut --delimiter=' ' -f1`
mv /tmp/provision/etc/fstab /etc/fstab
mount -o remount /dev/shm

# CIS (1.4.1)
echo "-- Update bootloader permissions"
chown root:root /boot/grub/menu.lst
chmod og-rwx /boot/grub/menu.lst

# CIS (1.4.3)
echo "-- Disable interactive boot & force password login for single user mode"
mv /tmp/provision/sysconfig/init /etc/sysconfig/init

# CIS (1.5.1)
echo "-- Disable core dumps & hard limit on system settings"
# Loaded in alphabetical order
mv /tmp/provision/security_override.conf /etc/security/limits.d/zzz.conf
mv /tmp/provision/etc/sysctl.conf /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0

# CIS (1.7.1 - 1.7.1.3)
echo "-- Updating banners to reduce data leakage"
mv /tmp/provision/banners/* /etc/
chown root:root /etc/motd /etc/issue /etc/issue.net
chmod 644 /etc/motd /etc/issue /etc/issue.net

# CIS (2.2.1 - 2.2.1.2)
echo "-- Update NTP time sync configuration"
mv /tmp/provision/ntp/ntp.conf /etc/ntp.conf
mv /tmp/provision/ntp/ntpd /etc/sysconfig/ntpd
service ntpd force-reload

# CIS (2.2.2)
echo "-- Removing X window server"
rpm -e --nodeps $(rpm -qa | grep '^xorg-x11')

# CIS (2.2.3 - 2.2.14)
echo "-- Ensure unneeded services are disabled"
chkconfig rpcbind off

# CIS (3.1.2 - 3.2.7)
echo "-- Harden network interfaces"
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1

# CIS (3.3.1 - 3.3.3)
echo "-- Disable IPv6 Routing (Not Fully Supported By AWS)"
# IPv6 is not fully supported by AWS and imposes additional attack surface
#
# We are disabling so we don't need to worry about bypassing firewall rules which are normally created with IPv4
#
# Assume that all external IPv6 requests will be downgraded by edge servers.
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1

# CIS (4.1.1.1 - 4.1.18)
echo "-- Configure Autitd"
mv /tmp/provision/audit/* /etc/audit/
service auditd force-reload

# CIS (4.2.1.2)
echo "-- Remove rsyslog && aws-kinesis-agent for central logging"
rpm -e --nodeps rsyslog
mv /tmp/provision/aws-kinesis/*  /etc/aws-kinesis/
chkconfig aws-kinesis-agent on

# CIS (5.1.1 - 5.1.8)
echo "-- Lockdown cron"
chmod 600 /etc/crontab
chmod 600 /etc/cron.hourly
chmod 600 /etc/cron.daily
chmod 600 /etc/cron.weekly
chmod 600 /etc/cron.monthly
chmod 600 /etc/cron.d
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

# CIS (5.2.1 - 5.2.15)
echo "-- Lockdown sshd"
mv /tmp/provision/ssh/*  /etc/ssh/
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
service sshd restart

# CIS (5.3.1)
echo "-- Lockdown PAM"
mv /tmp/provision/pwquality.conf  /etc/security/pwquality.conf
mv /tmp/provision/pam.d/* /etc/pam.d/
rm /etc/pam.d/smartcard-auth /etc/pam.d/password-auth /etc/pam.d/system-auth
ln -s /etc/pam.d/smartcard-auth-local /etc/pam.d/smartcard-auth
ln -s /etc/pam.d/system-auth-local /etc/pam.d/system-auth
ln -s /etc/pam.d/password-auth-local /etc/pam.d/password-auth
chmod 600 /etc/pam.d/smartcard-auth-local /etc/pam.d/system-auth-local /etc/pam.d/password-auth-local /etc/pam.d/su
chown root:root /etc/pam.d/smartcard-auth-local /etc/pam.d/system-auth-local /etc/pam.d/password-auth-local

# CIS (5.4.1.4)
echo "-- Retire unused users"
useradd -D -f 30

# CIS (5.4.4)
echo "-- Set umask"
touch /etc/bashrc
echo "umask 027" >> /etc/bashrc
touch /etc/profile
echo "umask 027" >> /etc/profile
### Make default User non-root and non sudoer ###
### Disable IPv6 (Firewall Support) ###

### BELOW MUST HAPPEN LAST ###

# Add Sticky bit on world readable dirs (1.1.18)
echo "-- Set sticky bit on globally r/w dirs"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

# Add AIDE to cron for regular check (1.3.2)
echo "-- Install AIDE cron to check fs"
echo "0 5 * * * /usr/sbin/aide --check" | crontab -u root -

# Install and Configure AIDE (1.3.1)
echo "-- Init AIDE file integrity monitor"
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz



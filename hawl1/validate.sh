#!/bin/sh
set -e

# force sudo
if [ $EUID != 0 ]; then
    sudo "$0" "$@"
    exit $?
fi

validateEquals () {
  if [[ "$1" == $2 ]]; then
    return 0
  else
    echo "Got: '$1' Expected: '$2'"
    return 1
  fi
}

validateInstalled () {
  echo "-- Validate installation of $1"
  if [[ -z `rpm -q "$1" | grep 'not installed'` ]]; then
    return 0
  else
    echo "Expected '$1' to be installed!"
    return 1
  fi
}

validateUninstalled () {
  echo "-- Validate $1 uninstalled"
  if [[ ! -z `rpm -q "$1" | grep 'not installed'` ]]; then
    return 0
  else
    echo "Expected '$1' to be uninstalled!"
    return 1
  fi
}

validateSigniture () {
  data_sig="$(echo "$1" | md5sum | cut -d " " -f1)"
  echo "-- Validate '$data_sig' matches '$2'"
  if [[ "$1" == "$2" ]]; then
    echo "Hash of '$data_sig' did not match '$2' source:"
    echo "$1"
    return 1
  else
    return 0
  fi
}

validateDisabled () {
  echo "-- Validate disabled '$1'"
  validateEquals "`chkconfig --list $1 2> /dev/null`" ""
}

validateServiceOff () {
  echo "-- Validate off '$1'"
  validateEquals "`chkconfig --list $1 | grep on`" ""
}

validatePermissions () {
  echo "-- Validate permissions of $1 is $2"
  validateEquals "`stat "$1" --format "%u %g %a"`" "$2"
}

validateDisabledDeviceType () {
  echo "-- Validate device type removed $1"
  if [[ `modprobe -n -v $1` == 'install /bin/true' ]] &&\
    [[ -v `lsmod | grep $1` ]]; then
    return 1
  else
    return 0
  fi
}

# CIS (1.1.1.1 - 1.1.1.8)
validateDisabledDeviceType cramfs
validateDisabledDeviceType freevxfs
validateDisabledDeviceType jffs2
validateDisabledDeviceType hfs
validateDisabledDeviceType hfsplus
validateDisabledDeviceType squashfs
validateDisabledDeviceType udf
validateDisabledDeviceType vfat

# CIS (1.1.2 - 1.1.10)
echo "-- Validate /tmp partition"
# TODO: separate partition for /tmp
# TODO: lock down to `noexec, nosuid, nodev, `

# CIS (1.1.6)
echo "-- Validate /var partition"
# TODO: Separate partition for /var

# CIS (1.1.7 - 1.1.10)
echo "-- Validate /var/tmp partition"
# TODO: Separate partition for /var/tmp
# TODO: lockdown to `nodev, nosuid, noexec`

# CIS (1.1.11)
echo "-- Validate /var/log partition"
# TODO: Separate partition for /var/log

# CIS (1.1.12)
echo "-- Validate /var/log/audit partition"
# TODO: Separate partition for /var/log/audit

# CIS (1.1.13 - 1.1.14)
echo "-- Validate /home partition"
# TODO: Separate partition for /home
# TODO: lockdown to `nodev`

# CIS (1.1.15 - 1.1.17)
echo "-- Validate /dev/shm partition"
# TODO: /dev/shm lockdown to `nodev, nosuid, noexec`

# CIS (1.1.18)
echo "-- Validate global r/w dir sticky bit"
[[ -z `df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null` ]]

# CIS (1.1.19)
echo "-- NOTE: Auto mounting does not exist on amazon linux"

# CIS (1.2.2)
echo "-- Validate only approved repo GPG keys are added"
validateEquals `rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release}'`  'gpg-pubkey-21c0f39f-56d0e29a'

# CIS (1.2.3)
echo "-- Validate GPG package checking is enabled"
validateEquals `grep ^gpgcheck /etc/yum.conf` 'gpgcheck=1'

# CIS (1.3.1)
echo "-- Validate AIDE file integrity check is installed & enabled"
validateInstalled aide
validatePermissions /var/lib/aide/aide.db.gz "0 0 600"

# CIS (1.3.2)
echo "-- Validate AIDE is regularly executed"
validateEquals "`crontab -u root -l | grep aide`" '0 5 * * * /usr/sbin/aide --check'

# CIS (1.4.1)
echo "-- Validate bootloader permissions"
validatePermissions /boot/grub/menu.lst '0 0 600'

# CIS (1.4.2)
echo "-- Validate authentication required for single user mode"
validateEquals "`grep ^SINGLE /etc/sysconfig/init`" 'SINGLE=/sbin/sulogin'

# CIS (1.4.3)
echo "-- Validate interactive boot is disabled."
validateEquals "`grep "^PROMPT=" /etc/sysconfig/init`" 'PROMPT=no'

# CIS (1.5.1)
echo "-- Validate core is not dumpable"
validateEquals "`grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*`" "/etc/security/limits.d/zzz.conf:hard core 0"
validateEquals "`sysctl fs.suid_dumpable`" "fs.suid_dumpable = 0"

# CIS (1.5.3)
echo "-- Validate address space layout randomization"
validateEquals "`sysctl kernel.randomize_va_space`" "kernel.randomize_va_space = 2"

# CIS (1.5.4)
echo "-- Validate prelink is uninstalled"
validateUninstalled prelink

# CIS (1.7.1 - 1.7.1.3)
echo "-- Validate banners dont leak data"
validatePermissions /etc/motd '0 0 644'
validatePermissions /etc/issue '0 0 644'
validatePermissions /etc/issue.net '0 0 644'

# CIS (2.1.1 - 2.1.5)
echo "-- Validate debug services are not online."
validateEquals "`chkconfig --list | grep chargen-dgram`" ""
validateEquals "`chkconfig --list | grep chargen-stream`" ""

validateEquals "`chkconfig --list | grep daytime-dgram`" ""
validateEquals "`chkconfig --list | grep daytime-stream`" ""

validateEquals "`chkconfig --list | grep discard-dgram`" ""
validateEquals "`chkconfig --list | grep discard-stream`" ""

validateEquals "`chkconfig --list | grep echo-dgram`" ""
validateEquals "`chkconfig --list | grep echo-stream`" ""

validateEquals "`chkconfig --list | grep time-dgram`" ""
validateEquals "`chkconfig --list | grep time-stream`" ""

# CIS (2.1.6 - 2.1.10)
echo "-- Validate insecure remote services are disabled."
validateEquals "`chkconfig --list | grep rsh`" ""
validateEquals "`chkconfig --list | grep rlogin`" ""
validateEquals "`chkconfig --list | grep rexec`" ""
validateEquals "`chkconfig --list | grep talk`" ""
validateEquals "`chkconfig --list | grep tftp`" ""
validateEquals "`chkconfig --list | grep rsync`" ""

# CIS (2.1.11)
echo "-- Validate super Damon is offline."
validateEquals "`chkconfig --list | grep xinetd`" ""

# CIS (2.2.1 - 2.2.1.2)
echo "-- Validate time synchronization is installed and configured"
validateInstalled ntp
validateEquals "` grep "^restrict" /etc/ntp.conf`" "restrict -4 default nomodify notrap nopeer noquery"
validateEquals "` grep "^server 0" /etc/ntp.conf`" "server 0.amazon.pool.ntp.org iburst"

# CIS (2.2.2)
echo "-- Validate X window server is removed"
validateEquals "`rpm -qa xorg-x11*`" ""

# CIS (2.2.3 - 2.2.14)
echo "-- Validate unneeded tools are not installed"
validateDisabled avahi-daemon
validateDisabled cups
validateDisabled dhcpd
validateDisabled sldap
validateServiceOff nfs
validateServiceOff rpcbind
validateDisabled named
validateDisabled vsftpd
validateDisabled httpd
validateDisabled dovecot
validateDisabled smb
validateDisabled squid
validateDisabled snmpd

# CIS (2.2.15)
echo "-- Validate unneeded tools are not installed"
# TODO: make sure sendmail is not listening to loop back

# CIS (2.2.16 - 2.3.5)
echo "-- Validate old insecure software is not installed or configured"
validateDisabled ypserv
validateUninstalled ypbind
validateUninstalled rsh
validateUninstalled talk
validateUninstalled telnet
validateUninstalled openldap-clients

# CIS (3.1.1) (HOST ONLY)
echo "-- Validate networking is sane"
validateEquals "`sysctl net.ipv4.ip_forward`" "net.ipv4.ip_forward = 0"
validateEquals "`sysctl net.ipv4.conf.all.send_redirects`" "net.ipv4.conf.all.send_redirects = 0"
validateEquals "`sysctl net.ipv4.conf.default.send_redirects`" "net.ipv4.conf.default.send_redirects = 0"

# CIS (3.2.1)
echo "-- Validate source routed packets are disabled"
validateEquals "`sysctl net.ipv4.conf.all.accept_source_route`" "net.ipv4.conf.all.accept_source_route = 0"
validateEquals "`sysctl net.ipv4.conf.default.accept_source_route`" "net.ipv4.conf.default.accept_source_route = 0"

# CIS (3.2.2 - 3.2.3)
echo "-- Validate ICMP remote altering of route tables is disabled"
validateEquals "`sysctl net.ipv4.conf.all.accept_redirects`" "net.ipv4.conf.all.accept_redirects = 0"
validateEquals "`sysctl net.ipv4.conf.default.accept_redirects`" "net.ipv4.conf.default.accept_redirects = 0"
validateEquals "`sysctl net.ipv4.conf.all.secure_redirects`" "net.ipv4.conf.all.secure_redirects = 0"
validateEquals "`sysctl net.ipv4.conf.default.secure_redirects`" "net.ipv4.conf.default.secure_redirects = 0"

# CIS (3.2.4)
echo "-- Log suspicious packets"
validateEquals "`sysctl net.ipv4.conf.all.log_martians`" "net.ipv4.conf.all.log_martians = 1"
validateEquals "`sysctl net.ipv4.conf.default.log_martians`" "net.ipv4.conf.default.log_martians = 1"

# CIS (3.2.5 - 3.2.6)
echo "-- Validate ignore ICMP ping & bogus requests"
validateEquals "`sysctl net.ipv4.icmp_echo_ignore_broadcasts`" "net.ipv4.icmp_echo_ignore_broadcasts = 1"
validateEquals "`sysctl net.ipv4.icmp_ignore_bogus_error_responses`" "net.ipv4.icmp_ignore_bogus_error_responses = 1"


# CIS (3.2.7)
echo "-- Validate reverse path filtering is enabled"
validateEquals "`sysctl net.ipv4.conf.all.rp_filter`" "net.ipv4.conf.all.rp_filter = 1"
validateEquals "`sysctl net.ipv4.conf.default.rp_filter`" "net.ipv4.conf.default.rp_filter = 1"

# CIS (3.2.8)
echo "-- Validate TCP cookies are enabled to prevent SYN flood"
validateEquals "`sysctl net.ipv4.tcp_syncookies`" "net.ipv4.tcp_syncookies = 1"


# CIS (3.3.1 - 3.3.3)
echo "-- Validate IPv6 exposure is reduced"
validateEquals "`sysctl net.ipv6.conf.all.accept_ra`" "net.ipv6.conf.all.accept_ra = 0"
validateEquals "`sysctl net.ipv6.conf.default.accept_ra`" "net.ipv6.conf.default.accept_ra = 0"
validateEquals "`sysctl net.ipv6.conf.all.accept_redirects`" "net.ipv6.conf.all.accept_redirects = 0"
validateEquals "`sysctl net.ipv6.conf.default.accept_redirects`" "net.ipv6.conf.default.accept_redirects = 0"
validateEquals "`modprobe -c | grep ipv6 | grep "disable=1"`" "options ipv6 disable=1"

# CIS (3.4.1)
echo "-- Validate TCP ACL service is installed"
validateInstalled tcp_wrappers
validateInstalled tcp_wrappers-libs

# CIS (3.4.2 - 3.4.3)
echo "-- (Ignored) Validate configuration of host.allow and host.deny"
# Our system is dynamic and we do not wish to support whitelists or blacklists on a per instance level

# CIS (3.4.4 - 3.4.5)
echo "-- Validate permissions of host.allow and host.deny"
# Though we don't support white lists and blacklists verifying file permissions is important
validatePermissions /etc/hosts.allow "0 0 644"
validatePermissions /etc/hosts.deny "0 0 644"

# CIS (3.5.1  - 3.5.4)
echo "-- Validate uncommon network protocols disabled"
validateDisabledDeviceType dccp
validateDisabledDeviceType sctp
validateDisabledDeviceType rds
validateDisabledDeviceType tipc

# CIS (3.6.1)
echo "-- Validate iptables 'firewall' is installed"
validateInstalled iptables

# CIS (3.6.2)
echo "-- Validate iptables default deny policy"
validateEquals "`iptables -L | grep 'Chain INPUT'`" "Chain INPUT (policy DROP)"
validateEquals "`iptables -L | grep 'Chain FORWARD'`" "Chain FORWARD (policy DROP)"
validateEquals "`iptables -L | grep 'Chain OUTPUT'`" "Chain OUTPUT (policy DROP)"

# CIS (3.6.3)
echo "-- Validate iptables 127.0.0.1 is denied to force usage of loopback interface"
validateEquals "`iptables -L INPUT -v -n  | grep 127.0.0.0/8 | grep -v DROP`" ""
echo "-- Validate iptables loopback interface is allowed"
validateEquals "`iptables -L INPUT -v -n  | grep lo | grep -v ACCEPT`" ""
validateEquals "`iptables -L OUTPUT -v -n  | grep lo | grep -v ACCEPT`" ""

# CIS (4.1.2 - 4.1.18)
echo "-- Validate auditd is enabled and configured"
validateEquals "`chkconfig --list auditd`" "auditd         	0:off	1:off	2:on	3:on	4:on	5:on	6:off"

# Get sums via md5 provision/audit/*
validateEquals "`md5sum /etc/audit/autit.rules`" "4e9e5bc3d41a0b2b01204aef37eb2c1f  /etc/audit/autit.rules"
validateEquals "`md5sum /etc/audit/autitd.conf`" "d5c721d33018502d99367b9f7f887a96  /etc/audit/autitd.conf"

# CIS (4.2.1.1 - 4.2.1.3)
echo "-- Validate rsyslog is uninstalled (Using Kinisis Directly)"
validateUninstalled rsyslog
validateDisabled rsyslog
validateInstalled aws-kinesis-agent

# CIS (5.1.1 - 5.1.8)
echo "-- Validate cron is configured and locked down"
validateEquals "`chkconfig --list crond`" "crond          	0:off	1:off	2:on	3:on	4:on	5:on	6:off"
validatePermissions /etc/crontab "0 0 600"
validatePermissions /etc/cron.hourly "0 0 600"
validatePermissions /etc/cron.daily "0 0 600"
validatePermissions /etc/cron.weekly "0 0 600"
validatePermissions /etc/cron.monthly "0 0 600"
validatePermissions /etc/cron.d "0 0 600"
validatePermissions /etc/cron.d "0 0 600"
validateEquals "`stat /etc/cron.deny 2> /dev/null`" ""
validateEquals "`stat /etc/at.deny 2> /dev/null`" ""

# CIS (5.2.1 - 5.2.15)
echo "-- Validate SSH is config is hardened"
validateEquals "`grep "^Protocol" /etc/ssh/sshd_config`" "Protocol 2"
validateEquals "`grep "^LogLevel" /etc/ssh/sshd_config`" "LogLevel INFO"
validateEquals "`grep "^X11Forwarding" /etc/ssh/sshd_config`" "X11Forwarding no"
validateEquals "`grep "^MaxAuthTries" /etc/ssh/sshd_config`" "MaxAuthTries 4"
validateEquals "`grep "^IgnoreRhosts" /etc/ssh/sshd_config`" "IgnoreRhosts yes"
validateEquals "`grep "^HostbasedAuthentication" /etc/ssh/sshd_config`" "HostbasedAuthentication no"
validateEquals "`grep "^PermitRootLogin" /etc/ssh/sshd_config`" "PermitRootLogin no"
validateEquals "`grep "^PermitEmptyPasswords" /etc/ssh/sshd_config`" "PermitEmptyPasswords no"
validateEquals "`grep "^PermitUserEnvironment" /etc/ssh/sshd_config`" "PermitUserEnvironment no"
validateEquals "`grep "^ClientAliveInterval" /etc/ssh/sshd_config`" "ClientAliveInterval 300"
validateEquals "`grep "^ClientAliveCountMax" /etc/ssh/sshd_config`" "ClientAliveCountMax 0"
validateEquals "`grep "^LoginGraceTime" /etc/ssh/sshd_config`" "LoginGraceTime 60"
validateEquals "`grep "^Banner" /etc/ssh/sshd_config`" "Banner /etc/issue.net"

echo "-- Validate SSH crypto is strong"
validateEquals "`grep "^Ciphers" /etc/ssh/sshd_config`" \
  "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
validateEquals "`grep "^MACs" /etc/ssh/sshd_config`" \
  "MACs hmac-sha2-256,hmac-sha2-512,umac-128@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"
validateEquals "`grep "^KexAlgorithms" /etc/ssh/sshd_config`" \
  "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521"

echo "-- (TODO) Validate Allowed SSH users"
validatePermissions /etc/ssh/sshd_config "0 0 600"

# CIS (5.3.1)
echo "-- Validate PAM password strength configuration"
validateEquals "`grep pam_pwquality.so /etc/pam.d/password-auth`" \
  "password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type="
validateEquals "`grep pam_pwquality.so /etc/pam.d/system-auth`" \
  "password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type="
validateEquals "`grep "^minlen" /etc/security/pwquality.conf`" "minlen=18"
validateEquals "`grep "^dcredit" /etc/security/pwquality.conf`" "dcredit=-1"
validateEquals "`grep "^lcredit" /etc/security/pwquality.conf`" "lcredit=-1"
validateEquals "`grep "^ocredit" /etc/security/pwquality.conf`" "ocredit=-1"
validateEquals "`grep "^ucredit" /etc/security/pwquality.conf`" "ucredit=-1"

# CIS (5.3.2)
echo "-- Validate PAM fail count module is enabled."
# Manually review file for compliance then update hash
validateEquals "`md5sum /etc/pam.d/password-auth`" "fb952cd95b600acf337d958c917d833a  /etc/pam.d/password-auth"
validateEquals "`md5sum /etc/pam.d/system-auth`" "799ef8690c30e2c109595c6c2d187234  /etc/pam.d/system-auth"

# CIS (5.3.3)
echo "-- Validate password reuse policy is in place and strong crypto"
policy_pam_password="`egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth`"
policy_pam_system="`egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth`"
validateEquals "`echo "$policy_pam_password"| grep -v "remember=5"`" ""
validateEquals "`echo "$policy_pam_system"| grep -v "remember=5"`" ""
validateEquals "`echo "$policy_pam_password"| grep -v "sha512"`" ""
validateEquals "`echo "$policy_pam_system"| grep -v "sha512"`" ""

# CIS (5.4.1.1 - 5.4.1.3)
echo "-- Validte shadow password config is reasonable"
# Check age of existing passwords; if there are any we would probably delete
validateEquals "`egrep "^PASS_MAX_DAYS" /etc/login.defs`" "PASS_MAX_DAYS 90"
validateEquals "`egrep "^PASS_MIN_DAYS" /etc/login.defs`" "PASS_MIN_DAYS 7"
validateEquals "`egrep "^PASS_WARN_AGE" /etc/login.defs`" "PASS_WARN_AGE 7"
validateEquals "`egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1`" ""

# CIS (5.4.1.4)
echo "-- Validate inactive users auto expire"
validateEquals "`sudo useradd -D | grep INACTIVE`" "INACTIVE=30"

# CIS (5.4.2)
echo "-- Validate system users are not login users"
validateEquals "`egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && \
  $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false") {print}'`" ""

#CIS (5.4.3 - 5.4.4)
echo "-- Validate user defaults are resonabale"
validateEquals "`grep "^root:" /etc/passwd | cut -f4 -d:`" "0"
validateEquals "`grep "^umask" /etc/bashrc`" "umask 027"
validateEquals "`grep "^umask" /etc/profile`" "umask 027"

# CIS (5.5)
echo "-- Validate sudo is locked down"
validateEquals "`grep pam_wheel.so /etc/pam.d/su | egrep "^auth"`" "auth		required	pam_wheel.so use_uid"

# CIS (6.1.2 - 6.1.9)
echo "-- Validate /etc/* permissions"
validatePermissions /etc/passwd "0 0 644"
validatePermissions /etc/shadow "0 0 0"
validatePermissions /etc/group "0 0 644"
validatePermissions /etc/gshadow "0 0 0"
validatePermissions /etc/passwd- "0 0 600"
validatePermissions /etc/shadow- "0 0 600"
validatePermissions /etc/group- "0 0 600"
validatePermissions /etc/gshadow- "0 0 600"

echo "-- Validate global filesystem ownership permissions"
# CIS (6.1.10) Ensure no world writable dirs
validateEquals "`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002`" ""
validateEquals "`find $(mount | grep "ext4" | cut -d" " -f1) -xdev -type f -perm -0002`" ""

# CIS (6.1.11) Ensure No unowned files
validateEquals "`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser`" ""
validateEquals "`find $(mount | grep "ext4" | cut -d" " -f1) -xdev -nouser`" ""

# CIS (6.1.12) Ensure every file has a group
validateEquals "`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup`" ""
validateEquals "`find $(mount | grep "ext4" | cut -d" " -f1) -xdev -nogroup`" ""

# CIS (6.1.13) Ensure SUID (administrative role bypass) is correct (Manual Validation)
validateSigniture "`sudo df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -type f -perm -4000`" \
  "d3a35645f03d67e654246768754844f7"
validateSigniture "`find $(mount | grep "ext4" | cut -d" " -f1) -xdev -type f -perm -4000`" \
  "68b329da9893e34099c7d8ad5cb9c940"


# CIS (6.1.14) Ensure SGID (administrative role bypass) is correct (Manual Validation)
validateSigniture "`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000`" \
  "68b329da9893e34099c7d8ad5cb9c940"
validateSigniture "`find $(mount | grep "ext4" | cut -d" " -f1) -xdev -type f -perm -2000`" \
  "68b329da9893e34099c7d8ad5cb9c940"

# CIS (6.2.1 - 6.2.5)
echo "-- Validate current user config is reasonable"
validateEquals "`cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'`" ""
validateEquals "`grep '^+:' /etc/passwd`" ""
validateEquals "`grep '^+:' /etc/shadow`" ""
validateEquals "`grep '^+:' /etc/group`" ""
validateEquals "`cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'`" "root"
validateEquals "`cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'`" "root"

# CIS (6.2.6)
echo "-- Validate path integrity"
for filename in /tmp/validation-scripts/*; do
  echo "-- Validate no output from $filename"
  chmod a+x "$filename"
  validateEquals "`$filename`" ""
done
rm -r /tmp/validation-scripts

echo "-- Validate AIDE database matches FS"
aide --check

echo "-- Validate audit report with clean state"
service auditd rotate
aureport


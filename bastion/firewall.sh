#!/bin/sh
# Update Firewall to block common attacks

# force sudo
if [ $EUID != 0 ]; then
    sudo "$0" "$@"
    exit $?
fi

### Set vars ###
IPT=/sbin/iptables
SYSCTL=/sbin/sysctl

# Internet Interface
EXT_IF="eth0"

### Block RFC 1918 private address space range ###
SPOOFDIP="127.0.0.0/8 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8 169.254.0.0/16 0.0.0.0/8 240.0.0.0/4 255.255.255.255/32 168.254.0.0/16 224.0.0.0/4 240.0.0.0/5 248.0.0.0/5 192.0.2.0/24"

### Turn on SYN flooding protection ###
$SYSCTL -w net/ipv4/tcp_syncookies=1

# WARNING: This does not allow internal IP addresses; if you explicitly need to add it reduce scope of CIDR
### Block the RFC 1918 private address space ranges ###
for rfc in $SPOOFDIP
do
	$IPT -A INPUT -i ${EXT_IF} -s ${rfc} -j LOG --log-prefix " SPOOF DROP "
	$IPT -A INPUT -i ${EXT_IF} -s ${rfc} -j DROP
done

### Drop bad stuff ###
$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN,PSH SYN,FIN,PSH -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN,RST SYN,FIN,RST -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN,RST,PSH SYN,FIN,RST,PSH -j DROP
# FIN-Only
$IPT -A INPUT -p tcp --tcp-flags FIN FIN -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL SYN -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# FIN
$IPT  -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP

# NULL packets (TCP Keep Alive will be effected)
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# XMAS
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# Fragments
$IPT -A INPUT -f -j DROP

# sync
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

### Log ###
$IPT -A INPUT -m state --state INVALID -j LOG --log-prefix " INVAID DROP "
$IPT -A INPUT -m state --state INVALID -j DROP

$IPT -A INPUT -i ${EXT_IF} -j LOG --log-prefix " INPUT DROP "
$IPT -A OUTPUT -o ${EXT_IF} -j LOG --log-prefix " OUTPUT DROP "

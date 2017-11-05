#!/bin/bash
set -e

echo "-- Flush Tables"
sudo iptables -F

echo "-- Establish Deny All Polocy"
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP

echo "-- Allow loopback traffic via interface only"
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP

echo "-- Allow outbound traffic and established connections"
sudo iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

echo "-- Allow inbound SSH traffic"
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

echo "-- Saving IP Tables For Boot --"
sudo service iptables save


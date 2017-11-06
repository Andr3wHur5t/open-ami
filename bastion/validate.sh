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

validateSetting () {
  validateEquals "`grep "^$2" $1`" "$2 $3"
}

echo "-- Validate sshd_config"
validateSetting /etc/ssh/sshd_config AllowTcpForwarding yes
validateSetting /etc/ssh/sshd_config PermitTunnel no
validateSetting /etc/ssh/sshd_config X11Forwarding no
validateSetting /etc/ssh/sshd_config AllowStreamLocalForwarding no
validateSetting /etc/ssh/sshd_config GatewayPorts no
validateSetting /etc/ssh/sshd_config PermitTTY no
validateSetting /etc/ssh/sshd_config AllowUsers "prox, emergency"
validateSetting /etc/ssh/sshd_config SyslogFacility AUTHPRIV
validateSetting /etc/ssh/sshd_config LogLevel INFO


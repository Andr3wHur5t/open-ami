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

exit 0

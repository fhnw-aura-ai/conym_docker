#!/bin/bash

if [ -z "$1" -o "$1" == "--help" -o "$1" == "-h" ]
then
	echo "usage: $0 <servicename>" >&2
	echo "" >&2
	echo "(alwayys run as root" >&2
	exit 100
fi

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo "installing systemd service"
SERVICENAME=$1
sudo cat >/etc/systemd/system/$SERVICENAME.service <<EOF
[Unit]
Description=$SERVICENAME
Requires=docker.service
After=docker.service

[Service]
Restart=always
User=root
Group=docker
WorkingDirectory=$(readlink -f $(dirname "$0")/../docker)
ExecStart=$(readlink -f $(dirname "$0"))/run.sh up
ExecStop=$(readlink -f $(dirname "$0"))/run.sh down

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable $SERVICENAME.service
sudo systemctl start  $SERVICENAME.service

echo "Getting conym system state"
sudo systemctl status $SERVICENAME.service

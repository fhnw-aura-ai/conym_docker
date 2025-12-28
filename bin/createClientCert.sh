#!/bin/bash

if [ -z "$1" ] 
then
	echo "usage: $0 <filename/cn> [<caFile without key/crt>]" >&2
	exit 100
fi

BASEDIR=$(readlink -f $(dirname "$0")/../docker)
if [ -z "$2" ]
then
	CA_FILE=${BASEDIR}/data/conymCA
else
	CA_FILE=$2
fi

if [ ! -f $CA_FILE.crt -o ! -f $CA_FILE.key ]
then
	echo "CA File $CA_FILE.(crt|key) missing" >&2
	exit 2
fi

CLIENT_FILE=$1
CLIENT_NAME=$(basename "$CLIENT_FILE")

openssl req -x509 -days 730 -sha256 -config <(cat /etc/ssl/openssl.cnf) -subj "/C=CH/ST=Aargau/O=FHNW/CN=${CLIENT_NAME}" -newkey rsa:2048 -nodes -keyout $CLIENT_FILE.key -out $CLIENT_FILE.crt -outform PEM -CAkey $CA_FILE.key -CA $CA_FILE.crt
	

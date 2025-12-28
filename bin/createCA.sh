#!/bin/bash

# create CA if not available
BASEDIR=$(readlink -f $(dirname "$0")/../docker)
if [ -z "$1" ]
then
        CA_FILE=${BASEDIR}/data/conymCA
else
        CA_FILE=$1
fi

if [ ! -f $CA_FILE.crt -o ! -f $CA_FILE.key ]
then
        echo "CA is missing... creating file $CA_FILE.key and $CA_FILE.crt"
    	openssl req -x509 -days 1800 -sha256 -reqexts EXT -reqexts v3_ca -config <(cat /etc/ssl/openssl.cnf; printf "\n[ EXT ]\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\nbasicConstraints=critical,CA:true\nkeyUsage=keyCertSign,cRLSign") -subj "/C=CH/ST=Aargau/O=FHNW/CN=CoNym CA " -newkey rsa:4096 -nodes -keyout $CA_FILE.key -out $CA_FILE.crt -outform PEM
        if [ -z $CA_FILE.key ]
        then
                echo "ERROR: key is empty deleting files..."
                rm $CA_FILE.{key,crt}
                exit 100
        fi
else
        echo "SKIPPED CA Creation... file already exists ($CA_FILE)"
fi

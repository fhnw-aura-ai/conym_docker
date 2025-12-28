#!/bin/sh
# Directory to store certificates
CERT_DIR="/etc/letsencrypt/live/${WEBHOST_NAME}"
USE_SELF_SIGNED="${USE_SELF_SIGNED:-false}"
if [ "$USE_SELF_SIGNED" = "true" ]; then
	# Check if self-signing is enabled
    echo "##INFO: Using self-signed certificate for testing purposes"
	if [ ! -d "$CERT_DIR" ]; then
	   echo "##INFO: Generating new self-signed certificate as it does not exist"
       mkdir -p "${CERT_DIR}"  > /dev/null 2>&1
	   #openssl req -x509 -newkey ed25519 -keyout "${CERT_DIR}/privkey.pem" -out "${CERT_DIR}/fullchain.pem" -days 1825 -nodes -subj "/CN=${WEBHOST_NAME}"
	   openssl req -x509 -newkey rsa:4096 -keyout "${CERT_DIR}/privkey.pem" -out "${CERT_DIR}/fullchain.pem" -sha256 -days 1825 -nodes -subj "/C=CH/ST=Aargau/O=FHNW/CN=${WEBHOST_NAME}"
	   echo "##WARN: You may need to restart for ssl to be avaiable, as first start may not have seen the self signed cert"
	fi
else
    echo "##INFO: Using Let's Encrypt certificates for ssl"
	# Check if Let's Encrypt certificates already exist
    if [ ! -d "$CERT_DIR" ]; then
        echo "##INFO: Getting new Let's Encrypt certificates"
        certbot certonly --non-interactive --agree-tos -m webmaster@${WEBHOST_NAME} --webroot -w /var/www/certbot/ -v -d ${WEBHOST_NAME}
		echo "##WARN: You may need to restart for ssl to be avaiable, as first start may not have seen the self signed cert"
	else
        echo "##INFO: Refreshing Let's Encrypt certificates (if required)"
        certbot renew
    fi
fi

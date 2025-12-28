#!/bin/sh

# Check prerequisites (certbot and WEBHOST environment variable)
if [ "${WEBHOST_NAME}" == "" ]
then
	echo "##SEVERE: Server name is not set"
	exit
fi
if [ "${WEBHOST_PORT_SSL}" == "" ]
then
	echo "##SEVERE: Server SSL port is not set"
	exit
fi

if [ ! -e /etc/letsencrypt/live/${WEBHOST_NAME}/privkey.pem ]
then
	echo "##WARNING: letsencrypt certificates not found under /etc/letsencrypt/live/${WEBHOST_NAME}/"
fi

# create default nginx config
mkdir /var/www/certbot 2>/dev/null || /bin/true
mkdir /etc/nginx/conf.d 2>/dev/null || /bin/true

if [ ! -e /etc/nginx/conf.d/${WEBHOST_NAME}.conf -o -z "$(cat /etc/nginx/conf.d/${WEBHOST_NAME}.conf)" -o /etc/nginx/conf.d/${WEBHOST_NAME}.conf.t -nt /etc/nginx/conf.d/${WEBHOST_NAME}.conf ]
then
	# creating config file
	echo "##INFO: First run of webhost detected... creating /etc/nginx/conf.d/${WEBHOST_NAME}.conf"
	cat << EOF >/etc/nginx/conf.d/${WEBHOST_NAME}.conf
	server {
 	    listen 80;
	    listen [::]:80;

	    server_name ${WEBHOST_NAME};
	    server_tokens off;

	    location /.well-known/acme-challenge/ {
	        root /var/www/certbot;
	    }

	    location / {
	        return 301 https://${WEBHOST_NAME}\$request_uri;
	    }
	}
EOF
	touch /etc/nginx/conf.d/${WEBHOST_NAME}.conf.t
fi
	

if [ ! -e /etc/nginx/conf.d/${WEBHOST_NAME}_ssl.conf -o -z "$(cat /etc/nginx/conf.d/${WEBHOST_NAME}_ssl.conf)" ]
then
	# Note: This requires double start (cert-bot gens: privkey.pem) but cert-bot depends on webserver for lets encrypt - so on first run privkey.pem not avaiable
	#		In the second run webserver can create this conf
	if [  -e /etc/letsencrypt/live/${WEBHOST_NAME}/privkey.pem ]
	then
		# creating config file
		echo "##INFO: First run of webhost detected... creating /etc/nginx/conf.d/${WEBHOST_NAME}_ssl.conf"
		
		
		# Decide if Register should be blocked
		case "$JANSSEN_DYNAMIC_CLIENTS_ENABLED" in
		  false|internal|private)
			REGISTER_BLOCK_CONFIG="location /jans-auth/restv1/register { deny all; }"
			;;
		  *)
			REGISTER_BLOCK_CONFIG=""
			;;
		esac
		
		cat << EOF >/etc/nginx/conf.d/${WEBHOST_NAME}_ssl.conf
		server {
			ssl_protocols TLSv1.2 TLSv1.3;
		
		    listen 443 default_server ssl;
		    listen [::]:443 ssl;

		    server_name ${WEBHOST_NAME};

		    ssl_certificate /etc/letsencrypt/live/${WEBHOST_NAME}/fullchain.pem;
		    ssl_certificate_key /etc/letsencrypt/live/${WEBHOST_NAME}/privkey.pem;
			
			ssl_verify_client ${WEBHOST_CONYM_CERT:-optional_no_ca};
			
		    location /.well-known/openid-configuration {
    			proxy_pass https://janssen/.well-known/openid-configuration;
				sub_filter "https://${WEBHOST_NAME}/" "https://${WEBHOST_NAME}:${WEBHOST_PORT_SSL}/";
				sub_filter "https://janssen/" "https://${WEBHOST_NAME}:${WEBHOST_PORT_SSL}/";
				sub_filter_types *;
			    sub_filter_once off;
		    }
			
		    location /jans-auth/ {
				# Set the header to forward the certificate
				proxy_set_header ssl-client-cert \$ssl_client_escaped_cert;
				# If this is != SUCCESS backend needs to check that it is Self-Signed before using X-SSL-Client-Cert
				proxy_set_header ssl_client_verify \$ssl_client_verify;
				
			    proxy_pass https://janssen/jans-auth/;
			    proxy_redirect "https://${WEBHOST_NAME}/jans-auth/" "https://${WEBHOST_NAME}:${WEBHOST_PORT_SSL}/jans-auth/";
			    proxy_redirect "https://janssen/jans-auth/" "https://${WEBHOST_NAME}:${WEBHOST_PORT_SSL}/jans-auth/";
				sub_filter "https://${WEBHOST_NAME}/" "https://${WEBHOST_NAME}:${WEBHOST_PORT_SSL}/";
				sub_filter "https://janssen/" "https://${WEBHOST_NAME}:${WEBHOST_PORT_SSL}/";
				sub_filter_types *;
			    sub_filter_once off;
				
				$REGISTER_BLOCK_CONFIG
		    }
			
		    location /proacc/ {
    			    proxy_pass http://proacc/proacc/;
		    }
			
			location /sector {
    			    proxy_pass http://proacc/proacc/sector;
		    }	
			
			location / {
    			    proxy_pass http://proacc/proacc/${PROACC_TRANSPARENCY_ENDPOINT}/;
		    }
		}
		
		server {
			ssl_protocols TLSv1.2 TLSv1.3;
		
		    listen 444 default_server ssl;
		    listen [::]:444 ssl;

		    server_name ${WEBHOST_NAME};

		    ssl_certificate /etc/letsencrypt/live/${WEBHOST_NAME}/fullchain.pem;
		    ssl_certificate_key /etc/letsencrypt/live/${WEBHOST_NAME}/privkey.pem;
			
			# For now on local as their is a ca cert error and i want to see if thats the problem
			ssl_verify_client ${WEBHOST_COCOA_CERT:-on};
			ssl_client_certificate /etc/nginx/client_ca.crt;
			
		    location /cocoa/ {
					# if (\$ssl_client_verify != "SUCCESS") { return 403; }
					proxy_set_header ssl-client-subject-dn \$ssl_client_s_dn;
					proxy_set_header ssl-client-verify \$ssl_client_verify;
    			    proxy_pass http://cocoa:8080/cocoa/;
		    }
		}
EOF
		touch /etc/nginx/conf.d/${WEBHOST_NAME}_ssl.conf.t
	else
		echo "##WARN: SSL config etc/nginx/conf.d/${WEBHOST_NAME}_ssl.conf was not created as /etc/letsencrypt/live/${WEBHOST_NAME}/privkey.pem was missing"
		echo "##INFO: Server may need to be restarted for SSL to be avaiable"
	fi
fi

# start NGINX webserver
/docker-entrypoint.sh "$@"

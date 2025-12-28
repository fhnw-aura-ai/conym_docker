FROM certbot/certbot:latest

# creates a certificate 
####################################################################

COPY src/certbot-startup.sh /startup.sh

RUN chmod 755 /startup.sh

STOPSIGNAL SIGQUIT

ENTRYPOINT ["/startup.sh"]

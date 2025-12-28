FROM nginx:1.25.4-alpine-slim

# Frontend webserver
####################################################################
# Creates initial config in config directory
# Creates/renews LetsEncrypt certs if required on container startup
# Forwards the following hooks:
#   - [cocoa]:80 -> https://<WEBHOST>/cocoa
#   - [gluu]:80  -> https://<WEBHOST>/sso

EXPOSE 80/tcp 443/tcp 444/tcp

COPY src/startup.sh /startup.sh

RUN chmod 755 /startup.sh

STOPSIGNAL SIGQUIT

ENTRYPOINT ["/startup.sh"]

CMD ["nginx", "-g", "daemon off;"]

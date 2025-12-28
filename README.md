# Conym Docker

This Repository contains the docker-compose setup for the Authentication Proxy Conym of the Aura.ai Project.
The Authentication Proxy is part of the Aura.ai Project and is one of the parts developed by the FHNW team.

The folder bin contains scripts to start and stop conym (see Setup). The docker folder contains the different components of Conym including corresponding docker configurations.
Conym consist of the following Components:

- [Janssen](https://docs.jans.io/stable/): An OAuth 2.0 Server extended with Conym specific logic
- JanssenConfigurer: A Java application that automatically configures the Janssen OAuth 2.0 Server for use in Conym
- Cocoa: A Rest service that accepts and manages Behavioural Authentication data for use in Conym (Janssen)
- [Postfix](https://www.postfix.org/): A configured Postfix smtp Server that forwards psudonym e-mail addresses to the registered original address.
- Proacc: Access Proxy which transparently routes request and exchanges token
- Webserver: Nginx proxy and cert-bot that serve as entry point to Conym and secure the connection

This Repository is only to manage the docker containers, the customized code running in the containers is held in different Repositories.
Currently Docker-Compose is used. But Janssen suggests using a Kubernetes deployment for productive usages.

## Preparations
If code was changed the artifacts has to be copied over if the updated version should be used.
- Janssen (Scripts): Copy the scripts and script config files to /docker/janssen/extension/
- Janssen (JanssenBase Library): Copy the jar to /docker/janssen/template/custom/auth/libs/
- JanssenConfigurer: Copy the jar to: docker/janssenConfigurer/app/
- Cocoa: Copy the war to /docker/cocoa/builds/
- Proacc: Copy the jar to /docker/proacc/app/

### Configurations
The overall configurations is contained in the docker/.env.default and docker/.env.override files.
The default contains values that should be independent of where the system runs as well as default values.
The .env.override allows to override the values and specifies environment specific properties. 
(override is not committed and must be manually create)

The following properties can be set:
- WEBHOST_PORT: The port the webserver listens to (default 80)
- WEBHOST_PORT_SSL: The port the webserver listens to (default 443)
- WEBHOST_COCOA_PORT_SSL: The port cocoa listens to (default 444)
- WEBHOST_COCOA_CERT: Defines if a client cert is necessary to access cocoa. Options are: On (CA signed cert needed - default), optional_no_ca (for test purposes allow self signed)
- NGINX_CONF_FOLDER: Where the Nginx config is located (default nginx/conf)
- COCOA_DB_FOLDER: Where the coca database should be stored (default cocoa-db)
- MARIADB_ROOT_PASSWORD: What password should be used for the cocoa db root user
- MARIADB_COCOA_PASSWORD: What password should be used for the cocoa db user
- JANSSEN_VERSION: Which Janssen version should be used (default 1.9.0-1)
- JANSSEN_DB_FOLDER: Where the janssen database should be stored (default janssen/db)
- JANSSEN_ADMIN_PASSWORD: What password should be used for the janssen db admin user
- JANSSEN_MYSQL_PASSWORD: What password should be used for the janssen db user
- JANSSEN_CREATED_FOLDER: Where to store client configs generated during startup (default janssen/created)
- JANSSEN_CERT_FOLDER: Where to store janssen certificate (default janssen/certs) ????????
- JANSSEN_ANALYTHIC_FOLDER: Where to store analythic logs (janssen/analytics)
- JANSSEN_DYNAMIC_CLIENTS_ENABLED: Should dynamic client creation be publicly available. Valid options are internal (only for other containers - default) or public (for everyone)
- POSTFIX_LOG_FOLDER: Where should postfix logs be stored (default postfix/logs)
- PROACC_TRANSPARENCY_ENDPOINT: Defines the proacc endpoint where transparent requests are routed to (default default_route)
- DELEGATE_MODE: Allows to select host specific config file by appending this value (default "")
- DOCKER_PREFIX: Which prefix to use in docker to avoid name confilcts (defautl local_conym)
- WEBHOST_NAME: The external host name conym is reachable under

In addition to the overall configuration, some component have specific configurations:
- /docker/janssen/extension/ contains scripts and their configuration files
- /docker/proacc/ contains proacc specific config, like routes and filters
- /docker/janssenConfigurer contains the config that defines which scripts to deploy
- /docker/postfix/config/run.config contains code that configures postfix

## Running Conym
The /bin/run.sh script allows to manage conym.
It is intended to be run form /docker as working directory, thus ../bin/run.sh <command> should be used.
The following commands are supported
- up: starts Conym (the first time a lengthy setup executes)
- down: stops Conym (the first time the result of the setup is persisted)
- clean: stops Conym and deletes all state (after this up will execute the setup again)




#!/bin/bash
SERVICENAME=$(basename $(readlink -f $(pwd)/..))
BASEDIR=$(readlink -f $(dirname "$0")/../docker)
INSTALLED_JANNSEN_NAME=installed-janssen
JANSSEN_SERVICE_NAME=janssen

. ${BASEDIR}/.env.default
[ -f ${BASEDIR}/.env.override ] && . ${BASEDIR}/.env.override

safe_rm_under_data() {
  local subpath="$1"
  [ -z "$subpath" ] && return

  local base="${BASEDIR}/data"
  local target="${base}/${subpath}"

  local realbase realtarget
  realbase=$(readlink -f "$base") || return
  realtarget=$(readlink -f "$target") || return

  case "$realtarget" in
    "$realbase"/*) rm -rf "$realtarget" ;;
    *) return ;;
  esac
}

echo "Starting..."
echo "  BASEDIR      : ${BASEDIR}"
echo "  WEBHOST_NAME : ${WEBHOST_NAME}"
echo "  DOCKER_PREFIX: ${DOCKER_PREFIX}"

## make sure that data directory exists
if [ ! -d ${BASEDIR}/data ]
then
	mkdir -p ${BASEDIR}/data &> /dev/null
fi

# Check for docker version
if [ $(docker version|grep Version|head -n 1|sed 's/.*: *//;s/\..*//') -lt 26 ]
then 
	echo "ERROR: Installed docker version is too low (below mnayor version 26)" >&2
	exit 10
fi


# execute docker action
if [ "$1" = "up" ]; 
then
	(
		cd $BASEDIR
		if [ -f .env.override ]
		then
			OPTIONS="$OPTIONS --env-file .env.override"
		fi
		
		mkdir -p ${BASEDIR}/data/${NGINX_CONF_FOLDER} &> /dev/null;
		mkdir -p ${BASEDIR}/data/${JANSSEN_NOTIFY_FOLDER} &> /dev/null;
		mkdir -p ${BASEDIR}/data/${JANSSEN_CREATED_FOLDER} &> /dev/null;
		mkdir -p ${BASEDIR}/data/${JANSSEN_ANALYTHIC_FOLDER} &> /dev/null;
		mkdir -p ${BASEDIR}/data/${POSTFIX_LOG_FOLDER} &> /dev/null;
		
		## create empty files
		for i in ${BASEDIR}/data/${NGINX_CONF_FOLDER}/${WEBHOST_NAME}.conf ${BASEDIR}/data/${NGINX_CONF_FOLDER}/${WEBHOST_NAME}_ssl.conf
		do
			if [ ! -e "${i}" ]
			then
				touch ${i}
			fi
		done

		chmod 777 ${BASEDIR}/data/${JANSSEN_NOTIFY_FOLDER} &> /dev/null;
		chmod 733 ${BASEDIR}/data/${JANSSEN_CREATED_FOLDER} &> /dev/null;
		chmod 777 ${BASEDIR}/data/${JANSSEN_ANALYTHIC_FOLDER} &> /dev/null;
		chmod 777 ${BASEDIR}/data/${POSTFIX_LOG_FOLDER} &> /dev/null;
	
		JANSSEN_IMAGE=${DOCKER_PREFIX}-${INSTALLED_JANNSEN_NAME}:${JANSSEN_VERSION}
		if docker image inspect $JANSSEN_IMAGE &> /dev/null; then
			echo "after install janssen image found - it will be used"
		else
			echo "no after install janssen image found - original image with empty database and fresh certs will be executed"
			safe_rm_under_data "${JANSSEN_DB_FOLDER}"
			safe_rm_under_data "${JANSSEN_CERT_FOLDER}"
			JANSSEN_IMAGE="ghcr.io/janssenproject/jans/monolith:${JANSSEN_VERSION}"
		fi
		export JANSSEN_IMAGE
		cp -r ${BASEDIR}/janssen/template/custom ${BASEDIR}/janssen/

		docker compose --env-file .env.default $OPTIONS -p "${DOCKER_PREFIX}" build --no-cache
		docker compose --env-file .env.default $OPTIONS -p "${DOCKER_PREFIX}" up -d
		docker compose --env-file .env.default $OPTIONS -p "${DOCKER_PREFIX}" logs -f
	)
elif [ "$1" = "down" ]; 
then
  	(
		cd $BASEDIR
		JANSSEN_IMAGE=${DOCKER_PREFIX}-${INSTALLED_JANNSEN_NAME}:${JANSSEN_VERSION}
		JANSSEN_CONTAINER="${DOCKER_PREFIX}-${JANSSEN_SERVICE_NAME}-1"
		CLEANUP_NEEDED=false
		if ! docker image inspect $JANSSEN_IMAGE &> /dev/null; then
			if docker exec "${JANSSEN_CONTAINER}" sh -c '[ -e /janssen/deployed ]'; then
				echo "installation of janssen was sucessfull - an after install janssen image will be created (this can take a while)"
				docker exec "${JANSSEN_CONTAINER}" sh -c "rm -rf /opt/jans/jans-setup" &> /dev/null;
				docker stop ${JANSSEN_CONTAINER} &> /dev/null;
				docker commit ${JANSSEN_CONTAINER} $JANSSEN_IMAGE
				CLEANUP_NEEDED=true
			fi
		fi
        docker compose -p "${DOCKER_PREFIX}" down
		if $CLEANUP_NEEDED; then
			docker image rm "ghcr.io/janssenproject/jans/monolith:${JANSSEN_VERSION}";
		fi
  	)
elif [ "$1" = "clean" ]; 
then
  	(
		cd $BASEDIR
        docker compose -p "${DOCKER_PREFIX}" down
		# This removes all volumes assosiated with DOCKER_PREFIX and all that are assosiated with none
		docker volume rm $(docker volume ls --filter "label=com.docker.compose.project=${DOCKER_PREFIX}" -q)
		docker volume rm $(docker volume ls -qf "dangling=true")
		# Note: This will not remove shared images like mysql, janssen, etc.. (but it will remove the built ones)
		docker image rm $(docker image ls --filter "label=com.docker.compose.project=${DOCKER_PREFIX}" -q)		

		JANSSEN_IMAGE=${DOCKER_PREFIX}-${INSTALLED_JANNSEN_NAME}:${JANSSEN_VERSION}
		# this image is not assosiated with the ${DOCKER_PREFIX} project as its built by this script
		if docker image inspect ${JANSSEN_IMAGE} &> /dev/null; then
			echo "Their is an janssen after install image for version ${JANSSEN_VERSION}. Should it be kept (recomended) ? (y/n)"
			read -r response
			if [[ "$response" =~ ^[Nn]$ ]]; then
				echo "Janssen after install image is removed"
				docker image rm ${JANSSEN_IMAGE}
			else
				echo "Janssen after install image will be kept. (Note: it can still be manually removed over 'docker image rm' or 'docker system prune')"
			fi
		fi
		#  clean state even dbs and jans certs (maybe a command without removing the dbs just rebuilding everything?)
		safe_rm_under_data "${JANSSEN_DB_FOLDER}"
		safe_rm_under_data "${JANSSEN_CERT_FOLDER}"
		safe_rm_under_data "${COCOA_DB_FOLDER}"
		
		# ensure if the conf changed we rebuild it
		safe_rm_under_data "${NGINX_CONF_FOLDER}/${WEBHOST_NAME}.conf"
		safe_rm_under_data "${NGINX_CONF_FOLDER}/${WEBHOST_NAME}_ssl.conf"

		# ensure if janssen changes we rebuild
		rm -rf ${BASEDIR}/janssen/custom/*
		
		safe_rm_under_data "${JANSSEN_NOTIFY_FOLDER}"
		safe_rm_under_data "${JANSSEN_CREATED_FOLDER}"
		
  	)
else
	echo "ERROR: unknown command \"$1\" (known are \"up\" and \"down\" and \"clean\")" >&2
fi

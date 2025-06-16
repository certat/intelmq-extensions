#!/bin/bash

DOCKER_PROJECT_NAME=$1
TOX_ROOT=$2
TMP_DIR=$3

docker compose -f contrib/docker-compose-common-services.yaml -p $DOCKER_PROJECT_NAME up -d
sleep 3 # wait for initialization
$TOX_ROOT/contrib/initdb.sh
sed 's/events/tests/g' /tmp/initdb.sql > $TMP_DIR/initdb.sql
sed 's/events/tests/g' $TOX_ROOT/contrib/constituency.sql > $TMP_DIR/constituency.sql
sed 's/boilerplates/boilerplates_tests/g' $TOX_ROOT/contrib/boilerplates.sql > $TMP_DIR/boilerplates.sql
docker compose -p $DOCKER_PROJECT_NAME cp $TMP_DIR/initdb.sql postgres:/tmp/initdb.sql
docker compose -p $DOCKER_PROJECT_NAME cp $TMP_DIR/constituency.sql postgres:/tmp/constituency.sql
docker compose -p $DOCKER_PROJECT_NAME cp $TMP_DIR/boilerplates.sql postgres:/tmp/boilerplates.sql
docker compose -p $DOCKER_PROJECT_NAME exec postgres psql -w -v ON_ERROR_STOP=on -d postgresql://intelmq@localhost/intelmq -f /tmp/initdb.sql
docker compose -p $DOCKER_PROJECT_NAME exec postgres psql -w -v ON_ERROR_STOP=on -d postgresql://intelmq@localhost/intelmq -f /tmp/constituency.sql
docker compose -p $DOCKER_PROJECT_NAME exec postgres psql -w -v ON_ERROR_STOP=on -d postgresql://intelmq@localhost/intelmq -f /tmp/boilerplates.sql
rm /tmp/initdb.sql
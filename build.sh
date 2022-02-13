#!/bin/bash
existing_container_id=sudo docker ps -a -q --filter="name=sso-system_server_1"
if [ ${#existing_container_id} == 0 ]
then
    echo ''
else
  sudo docker stop $existing_container_id
  sudo docker rm $existing_container_id
fi
sudo docker-compose up -d --build --remove-orphans --force-recreate
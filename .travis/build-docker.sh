#!/usr/bin/env bash

set -e

docker login -u="$DOCKER_USERNAME" -p="$DOCKER_PASSWORD"
export TAG=`if [ "$TRAVIS_BRANCH" == "master" ]; then echo "latest"; else echo $TRAVIS_BRANCH | tr / - ; fi`
docker build -t anroots/certstream-sniffer:$TAG .

docker push anroots/certstream-sniffer:$TAG
docker rmi anroots/certstream-sniffer:$TAG

docker logout

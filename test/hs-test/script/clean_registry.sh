#!/bin/bash

blue () { printf "\e[0;34m$1\e[0m\n" >&2 ; }

REGISTRY_URL="http://localhost:5001"

REPOS=$(curl -s $REGISTRY_URL/v2/_catalog | jq -r '.repositories[]')

if [ -z "$REPOS" ]; then
    blue "Registry is empty."
    exit 0
fi

blue "Repositories: $REPOS"

for REPO in $REPOS; do
    TAGS=$(curl -s $REGISTRY_URL/v2/$REPO/tags/list | jq -r '.tags[]')

    if [ "$TAGS" == "null" ]; then
        blue "No tags found for $REPO"
        continue
    fi

    for TAG in $TAGS; do
        blue "$REPO:$TAG"
        DIGEST=$(curl -v -s -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
            $REGISTRY_URL/v2/$REPO/manifests/$TAG 2>&1 | grep "< Docker-Content-Digest:" | awk '{print $3}' | tr -d '\r')

        if [ -n "$DIGEST" ]; then
            blue "Deleting digest: $DIGEST"
            curl -k -X DELETE -s "$REGISTRY_URL/v2/$REPO/manifests/$DIGEST"
        else
            blue "Could not find digest for $REPO:$TAG"
        fi
    done
done

blue "Deleting repositories"
docker exec local-registry rm -rf /var/lib/registry/docker/registry/v2/repositories/*
docker exec local-registry /bin/registry garbage-collect /etc/docker/registry/config.yml
docker restart local-registry

blue "Done. You may need to use 'make test ... FORCE_BUILD=true'"
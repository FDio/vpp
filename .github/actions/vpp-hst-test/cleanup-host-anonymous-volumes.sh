#!/usr/bin/env bash

set -euo pipefail

host_docker_socket=/var/run/docker-host.sock

if [[ ! -S "$host_docker_socket" ]]; then
    echo "Host Docker socket $host_docker_socket not found; skipping host volume cleanup."
    exit 0
fi

volume_list=$(docker --host "unix://$host_docker_socket" volume ls --quiet --filter dangling=true --filter driver=local)
mapfile -t candidates <<< "$volume_list"
anonymous_volumes=()

for volume in "${candidates[@]}"; do
    if [[ "$volume" =~ ^[0-9a-f]{64}$ ]]; then
        anonymous_volumes+=("$volume")
    fi
done

if ((${#anonymous_volumes[@]} == 0)); then
    echo "No dangling anonymous host Docker volumes found."
    exit 0
fi

echo "Removing ${#anonymous_volumes[@]} dangling anonymous host Docker volume(s)."
docker --host "unix://$host_docker_socket" volume rm "${anonymous_volumes[@]}"

#!/bin/bash

set -eu

MAX_RETRIES=5
INITIAL_DELAY=15

if [ "$#" -eq 0 ]; then
  echo "Usage: $0 [apt-get install options] package..." >&2
  exit 2
fi

for attempt in $(seq 1 "$MAX_RETRIES"); do
  if apt-get update && \
    apt-get -o Acquire::Retries=3 install -y "$@"; then
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    exit 0
  fi

  if [ "$attempt" -eq "$MAX_RETRIES" ]; then
    echo "APT transaction failed after $attempt attempts" >&2
    exit 1
  fi

  delay=$((INITIAL_DELAY * 2 ** (attempt - 1)))
  echo "APT transaction failed; retrying in ${delay}s" >&2
  rm -rf /var/lib/apt/lists/*
  sleep "$delay"
done

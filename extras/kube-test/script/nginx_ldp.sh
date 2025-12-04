#!/usr/bin/env bash

# shellcheck disable=SC2068
$1 -v && LD_PRELOAD=$LDP $@ > /proc/1/fd/1 2>&1

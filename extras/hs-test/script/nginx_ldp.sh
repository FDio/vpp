#!/usr/bin/env bash

$1 -v && LD_PRELOAD=$LDP $@ 2>&1 > /proc/1/fd/1

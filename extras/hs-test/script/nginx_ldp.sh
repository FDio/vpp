#!/usr/bin/env bash

LD_PRELOAD=$LDP $@ 2>&1 > /proc/1/fd/1

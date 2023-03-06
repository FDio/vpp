#!/usr/bin/env bash

LD_PRELOAD=$LDP nginx $@ 2>&1 > /proc/1/fd/1

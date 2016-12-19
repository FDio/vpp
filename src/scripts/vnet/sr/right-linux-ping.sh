#!/bin/bash

ifconfig eth1 inet6 add db04::1/64
route -A inet6 add db02::1/128 gw db04::2

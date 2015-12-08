#!/bin/bash

ifconfig srlocal inet6 add db04::1/64
route -6 add db02::0/64 gw db04::99

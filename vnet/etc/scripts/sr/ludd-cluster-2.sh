#!/bin/bash
ifconfig eth2 inet6 add db02::1/64
route -A inet6 add db04::1/128 gw db02::2

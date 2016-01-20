#!/bin/bash

echo vpp process
ps aux | grep vpp

echo Free memory
free -m

echo List vpp packages
dpkg -l \*vpp\*


echo List /proc/meminfo
cat /proc/meminfo



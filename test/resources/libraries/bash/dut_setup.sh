#!/bin/bash

echo vpe process
ps aux | grep vpe

echo Free memory
free -m

echo List vpp packages
dpkg -l \*vpp\*


echo List /proc/meminfo
cat /proc/meminfo



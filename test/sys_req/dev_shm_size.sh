#!/bin/sh

# this script verifies that /dev/shm is big enough for test purposes
# 512MB seems to be enough with room to spare at the time of writing this test
# (motivation for this check is the default docker /dev/shm size of 64M, which
# was occasionally overrun when running the tests)
req_min_size_megabytes=512

cur_size=`df -BM --output=size /dev/shm | awk ' NR==2 { print $1 } ' | cut -f 1 -d 'M'`

if test "$V" = "2"
then
	echo -n "Checking /dev/shm size..."
fi

if test "$cur_size" -lt "$req_min_size_megabytes"
then
	echo "/dev/shm size ${cur_size}M is too small, attempting to enlarge to ${req_min_size_megabytes}M."
	sudo mount -o remount /dev/shm -o size=512M
	cur_size=`df -BM --output=size /dev/shm | awk ' NR==2 { print $1 } ' | cut -f 1 -d 'M'`
	if test "$cur_size" -lt "$req_min_size_megabytes"
	then
		echo "Couldn't enlarge /dev/shm. Please enlarge it manually so that it's at least ${req_min_size_megabytes}M big."
		exit 1
	fi
	echo "/dev/shm successfully enlarged."
elif test "$V" = "2"
then
	echo "OK (current size: ${cur_size}M, required size: ${req_min_size_megabytes}M)"
fi

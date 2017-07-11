#!/bin/bash

rv=0

atexit() {
	group_id=`ps -p $$ -o pgid=`
	my_id=$$
	ids=`pgrep -g $group_id -d ' ' | sed "s/\b$my_id\b//g"`
	echo "Killing possible remaining process IDs: $ids"
	for id in $ids
	do
		if ps -p $id > /dev/null
		then
			kill -9 $id
		fi
	done
	exit $rv
}

trap "atexit" SIGINT SIGTERM

$*
rv=$?
atexit
exit $rv

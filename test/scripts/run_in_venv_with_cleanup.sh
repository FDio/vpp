#!/usr/bin/env bash

rv=0

# Minimalist version of cleanup, used for signal handling.
# Sends a SIGKILL to the entire process group, including ourselves.
# Needs just two external commands, making it more
# robust in case of resource issues.
panic() {
	echo "$0(pid $$): Caught a signal, emergency clean-up"
	# use "pgid:1=" output format to get unpadded process group ID
	group_id=`ps -p $$ -o pgid:1=`
	echo "$0(pid $$): sending kill to process group ID:${group_id}"
	kill -9 -- -${group_id}
	# not reached
}

# Happy camper leisurely clean up - send the signal only to other
# processes in the process group, and also check
# that the processes exists before sending the signal.
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
	exit ${rv}
}

trap "panic;" SIGINT SIGTERM

FORCE_FOREGROUND=$1
shift

source $1
shift

if [[ "${FORCE_FOREGROUND}" == "1" ]]
then
	$*
else
	$* &
	pid=$!
	wait ${pid}
fi

rv=$?
atexit
exit ${rv}

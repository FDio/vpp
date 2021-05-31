#!/bin/bash

cmd=$1
force_foreground=$2
shift
shift

if [[ "$force_foreground" == "1" ]]
then
	setsid $cmd $force_foreground $*
else
	setsid $cmd $force_foreground $* &
	pid=$!
	trap "echo setsid_wrapper.sh: got signal, killing child pid ${pid}; kill ${pid}; sleep .1;" SIGINT SIGTERM
	wait ${pid}
	exit $?
fi

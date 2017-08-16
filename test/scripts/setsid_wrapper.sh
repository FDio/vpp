#!/bin/bash

if [[ "$1" == "1" ]]
then
	setsid scripts/run_in_venv_with_cleanup.sh $*
else
	setsid scripts/run_in_venv_with_cleanup.sh $* &
	pid=$!
	trap "echo setsid_wrapper.sh: got signal, killing child pid ${pid}; kill ${pid}; sleep .1;" SIGINT SIGTERM
	wait ${pid}
	exit $?
fi

#!/bin/bash

function usage() {
 echo "$0" 1>&2
 echo "" 1>&2
 echo "Usage: $0 [-p <pre-exec-cmd>] [-m <email>] -- <make test options|verify>" 1>&2
 echo "" 1>&2
 echo "Parameters:" 1>&2
 echo "    -p <pre-exec-cmd> - run a command before each test loop (e.g. 'git pull')" 1>&2
 echo "    -m <email>        - if set, email is sent to this address on failure" 1>&2
 echo "" 1>&2
 echo "Examples:" 1>&2
 echo "    $0 -m <somebody@cisco.com> -- test-debug TEST=l2bd" 1>&2
 echo "    $0 -m <somebody@cisco.com> -- verify" 1>&2
 exit 1;
}

PRE_EXEC_CMD=""
EMAIL=""

while getopts "p:m:h" o; do
	case "${o}" in
	p)
		PRE_EXEC_CMD=${OPTARG}
		;;
	m)
		regex="^[a-z0-9!#\$%&'*+/=?^_\`{|}~-]+(\.[a-z0-9!#$%&'*+/=?^_\`{|}~-]+)*@([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?\$"
		m=${OPTARG}
		if [[ ! $m =~ $regex ]]
		then
			echo "Invalid -m parameter value: \`$m'" >&2
			usage
		fi
		EMAIL="$m"
		;;
	h)
		usage
		;;
	?)
		usage
		;;
esac
	done
shift $((OPTIND-1))

if ! echo $* | grep test >/dev/null
then
	if ! echo $* | grep verify >/dev/null
	then
		echo "Error: command line doesn't look right - should contain \`test' or \`verify' token..." >&2
		usage
	fi
fi

function finish {
	NOW=`date +%s`
	RUNTIME=$((NOW - START))
	AVG=$(echo "scale=2; $RUNTIME/$COUNT" | bc)
	OUT="*********************************************************************"
	OUT="$OUT\n* tail -n 30 $TMP:"
	OUT="$OUT\n*********************************************************************"
	OUT="$OUT\n`tail -n 30 $TMP`"
	OUT="$OUT\n*********************************************************************"
	OUT="$OUT\n* Total runtime: ${RUNTIME}s"
	OUT="$OUT\n* Iterations:    ${COUNT}"
	OUT="$OUT\n* Average time:  ${AVG}s"
	OUT="$OUT\n* Log file:      ${TMP}"
	OUT="$OUT\n*********************************************************************"
	echo -e "$OUT"
	if [[ "$EMAIL" != "" && "$REASON" != "" ]]
	then
		SUBJECT="test loop finished ($REASON)"
		echo -e "$OUT" | mail -s "$SUBJECT" $EMAIL
	fi
}

trap "echo Caught signal, exiting...; REASON=\"received signal\"; finish; exit -1" SIGINT SIGTERM

TMP=`mktemp`
START=`date +%s`
COUNT=0

if ! test -f "$TMP"
then
	echo "Couldn't create temporary file!"
	exit -1
fi

echo "Temporary file is $TMP"
CMD="make $*"
echo "Command line is \`$CMD'"

REASON=""
while true
do
	COUNT=$((COUNT+1))
	BEFORE=`date +%s`
	if [[ "$PRE_EXEC_CMD" != "" ]]
	then
		echo "Executing \`$PRE_EXEC_CMD' before test.."
		if ! ($PRE_EXEC_CMD 2>&1 | tee $TMP)
		then
			echo "\`$PRE_EXEC_CMD' failed!" >&2
			REASON="$PRE_EXEC_CMD failed"
			break
		fi
	fi
	echo -n "Running test iteration #$COUNT..."
	if ! ($CMD >$TMP 2>&1)
	then
		AFTER=`date +%s`
		RUNTIME=$((AFTER-BEFORE))
		echo "FAILED! (after ${RUNTIME}s)"
		REASON="test failed"
		break
	fi
	AFTER=`date +%s`
	RUNTIME=$((AFTER-BEFORE))
	echo "PASSED (after ${RUNTIME}s)"
done

finish
exit 1

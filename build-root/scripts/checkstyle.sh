#!/bin/bash

VPP_DIR=`dirname $0`/../../
EXIT_CODE=0
ST="-st"

# If the user provides --fix, then actually fix things
# Note: this is meant for use outside of the CI Jobs, by users cleaning things up

if [ $# -gt 0 ] && [ ${1} == '--fix' ]; then
    ST=""
fi

# Check to make sure we have indent.  Exit if we don't with an error message, but
# don't *fail*.
command -v indent > /dev/null
if [ $? != 0 ]; then
    echo "Cound not find required commend \"indent\".  Checkstyle aborted"
    exit ${EXIT_CODE}
fi

cd ${VPP_DIR}
for i in `git diff --name-only HEAD^1`;do
    if [ ${i} != "build-root/scripts/checkstyle.sh" ]; then
    	grep -q "fd.io coding-style-patch-verification: ON" ${i}
        if [ $? == 0 ]; then
            echo "checkstyle ${i}"
            indent ${ST} ${i} > /dev/null
            if [ $? !=0 ]; then
                EXIT_CODE = 1
            fi
        else
        	echo "Not checkstyle ${i}"
        fi
    else 
        echo "Not checkstyle ${i}"
    fi
done
if [ ${EXIT_CODE} == 0 ]; then
    echo "*******************************************************************"
    echo "* VPP CHECKSTYLE SUCCESSFULLY COMPLETED"
    echo "*******************************************************************"
else
    echo "*******************************************************************"
    echo "* VPP CHECKSTYLE FAILED"
    echo "* CONSULT FAILURE LOG ABOVE"
    echo "* NOTE: RUNNING 'build-root/scripts/checkstyle.sh --fix' *MAY* FIX YOUR ISSUE"
    echo "*******************************************************************"
exit ${EXIT_CODE}
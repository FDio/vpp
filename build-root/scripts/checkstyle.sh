#!/bin/bash

VPP_DIR=`dirname $0`/../../
EXIT_CODE=0

#Check to make sure we have indent.  Exit if we don't with an error message, but
#don't *fail*.
command -v indent
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
            indent -st ${i} > /dev/null
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
exit ${EXIT_CODE}
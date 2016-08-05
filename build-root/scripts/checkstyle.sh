#!/bin/bash

VPP_DIR=`dirname $0`/../../
EXIT_CODE=0
FIX="0"
CHECKSTYLED_FILES=""
UNCHECKSTYLED_FILES=""

# If the user provides --fix, then actually fix things
# Note: this is meant for use outside of the CI Jobs, by users cleaning things up

if [ $# -gt 0 ] && [ ${1} == '--fix' ]; then
    FIX="1"
fi

# Check to make sure we have indent.  Exit if we don't with an error message, but
# don't *fail*.
command -v indent > /dev/null
if [ $? != 0 ]; then
    echo "Cound not find required commend \"indent\".  Checkstyle aborted"
    exit ${EXIT_CODE}
fi

cd ${VPP_DIR}
for i in `git ls-tree -r master --name-only`;do
    if [ -f ${i} ] && [ ${i} != "build-root/scripts/checkstyle.sh" ]; then
        grep -q "fd.io coding-style-patch-verification: ON" ${i}
        if [ $? == 0 ]; then
            CHECKSTYLED_FILES="${CHECKSTYLED_FILES} ${i}"
            if [ ${FIX} == 0 ]; then
                indent ${i} -o ${i}.out
                diff -q ${i} ${i}.out
                rm ${i}.out
            else
                indent ${i}
            fi
            if [ $? != 0 ]; then
                EXIT_CODE=1
                echo "Checkstyle failed for ${i}.  Run \"indent ${i}\" to fix."
            fi
        else
            UNCHECKSTYLED_FILES="${UNCHECKSTYLED_FILES} ${i}"
        fi
    else
        UNCHECKSTYLED_FILES="${UNCHECKSTYLED_FILES} ${i}"
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
fi
exit ${EXIT_CODE}

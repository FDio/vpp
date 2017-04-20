#!/bin/bash

VPP_DIR=`dirname $0`/../../
EXIT_CODE=0
FIX="0"
FULL="0"
CHECKSTYLED_FILES=""
UNCHECKSTYLED_FILES=""

# If the user provides --fix, then actually fix things
# Note: this is meant for use outside of the CI Jobs, by users cleaning things up

while true; do
	case ${1} in
		--fix)
			FIX="1"
			;;
		--full)
			FULL="1"
			;;
	esac
	shift || break
done

if [ "${FULL}" == "1" ]; then
	FILELIST=$(git ls-tree -r HEAD --name-only)
else
	FILELIST=$((git diff HEAD~1.. --name-only; git ls-files -m ) | sort -u)
fi

# Check to make sure we have indent.  Exit if we don't with an error message, but
# don't *fail*.
command -v indent > /dev/null
if [ $? != 0 ]; then
    echo "Cound not find required commend \"indent\".  Checkstyle aborted"
    exit ${EXIT_CODE}
fi
indent --version

cd ${VPP_DIR}
git status
for i in ${FILELIST}; do
    if [ -f ${i} ] && [ ${i} != "build-root/scripts/checkstyle.sh" ] && [ ${i} != "extras/emacs/fix-coding-style.el" ]; then
        grep -q "fd.io coding-style-patch-verification: ON" ${i}
        if [ $? == 0 ]; then
            CHECKSTYLED_FILES="${CHECKSTYLED_FILES} ${i}"
            if [ ${FIX} == 0 ]; then
                indent ${i} -o ${i}.out1 > /dev/null 2>&1
                indent ${i}.out1 -o ${i}.out2 > /dev/null 2>&1
		# Remove trailing whitespace
		sed -i -e 's/[[:space:]]*$//' ${i}.out2
                diff -q ${i} ${i}.out2
            else
                indent ${i}
                indent ${i}
		# Remove trailing whitespace
		sed -i -e 's/[[:space:]]*$//' ${i}
            fi
            if [ $? != 0 ]; then
                EXIT_CODE=1
                echo
                echo "Checkstyle failed for ${i}."
                echo "Run indent (twice!) as shown to fix the problem:"
                echo "indent ${VPP_DIR}${i}"
                echo "indent ${VPP_DIR}${i}"
            fi
            if [ -f ${i}.out1 ]; then
                rm ${i}.out1
            fi
            if [ -f ${i}.out2 ]; then
                rm ${i}.out2
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
    echo "* NOTE: Running 'build-root/scripts/checkstyle.sh --fix' *MAY* fix the issue"
    echo "*******************************************************************"
fi
exit ${EXIT_CODE}

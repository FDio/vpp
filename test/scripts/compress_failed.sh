#!/usr/bin/env bash

if [ ! -d "${FAILED_DIR}" ]; then
    echo "FAILED_DIR (${FAILED_DIR}) is not a directory."
elif [ -z "$(ls -A "${FAILED_DIR}")" ]; then
    echo "No failed test artifacts found in ${FAILED_DIR}."
else
    if [ "${COMPRESS_FAILED_TEST_LOGS}" == "yes" ]
    then
	echo -n "Compressing files in temporary directories from failed test runs... "
	cd "${FAILED_DIR}"
	for d in *
	do
	    if [ -d "${d}" ]; then
	        cd "${d}"
	        find . ! -path . -print0 | xargs -0 -n1 gzip
	        cd "${FAILED_DIR}"
	    fi
	done
	echo "done."
        if [ -n "${WORKSPACE}" ]
        then
            echo "Copying failed test logs into build log archive directory (${WORKSPACE}/archives)... "
            for failed_test in $(ls "${FAILED_DIR}")
            do
                if [ -d "${FAILED_DIR}/${failed_test}" ]; then
                    mkdir -p "${WORKSPACE}/archives/${failed_test}"
                    cp -a "${FAILED_DIR}/${failed_test}"/* "${WORKSPACE}/archives/${failed_test}"
                elif [ -f "${FAILED_DIR}/${failed_test}" ]; then
                    mkdir -p "${WORKSPACE}/archives"
                    cp -a "${FAILED_DIR}/${failed_test}" "${WORKSPACE}/archives/"
                fi
            done
	    echo "done."
        fi

    else
	echo "Not compressing files in temporary directories from failed test runs."
    fi
fi

# This script gets run only if there was a 'make test' failure,
# so return failure error status so that the build results are
# recorded correctly.
exit 1

#!/bin/bash

if [ "$(ls -A ${VPP_TEST_FAILED_DIR})" ]
then
    if [ "${COMPRESS_FAILED_TEST_LOGS}" == "yes" ]
    then
	echo -n "Compressing files in temporary directories from failed test runs... "
	cd ${VPP_TEST_FAILED_DIR}
	for d in *
	do
	    cd ${d}
	    find . ! -path . -print0 | xargs -0 -n1 gzip
	    cd ${VPP_TEST_FAILED_DIR}
	done
	echo "done."
        if [ -n "$WORKSPACE" ]
        then
            echo "Copying failed test logs into build log archive directory ($WORKSPACE/archives)... "
            for failed_test in $(ls $VPP_TEST_FAILED_DIR)
            do
                mkdir -p $WORKSPACE/archives/$failed_test
                cp -a $VPP_TEST_FAILED_DIR/$failed_test/* $WORKSPACE/archives/$failed_test
            done
	    echo "done."
        fi
        
    else
	echo "Not compressing files in temporary directories from failed test runs."
    fi
else
    echo "No symlinks to failed tests' temporary directories found in ${VPP_TEST_FAILED_DIR}."
fi

# This script gets run only if there was a 'make test' failure,
# so return failure error status so that the build results are
# recorded correctly.
exit 1

#!/bin/bash

if [ "$(ls -A ${VPP_TEST_FAILED_DIR})" ]
then
	if [ "${COMPRESS_FAILED_TEST_LOGS}" == "yes" ]
	then
		echo -n "Compressing files in temporary directories from failed test runs..."
		cd ${VPP_TEST_FAILED_DIR}
		for d in *
		do
			cd ${d}
			find . ! -path . -print0 | xargs -0 -n1 gzip
			cd ${VPP_TEST_FAILED_DIR}
		done
		echo "done."
	else
		echo "Not compressing files in temporary directories from failed test runs."
	fi
else
	echo "No symlinks to failed tests' temporary directories found in ${VPP_TEST_FAILED_DIR}."
fi

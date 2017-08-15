#!/bin/bash

if [ "$(ls -A ${VPP_TEST_FAILED_DIR})" ]
then
	if [ "${COMPRESS_FAILED_TEST_LOGS}" == "yes" ]
	then
		echo "Compressing temporary directories from failed test runs:"
		cd ${VPP_TEST_FAILED_DIR}
		for i in *
		do
			echo "Compressing ${i}..."
			tar -c -h -z -f ${i}.tar.gz  ${i}
			echo "Removing ${i}..."
			rm $i
		done
	else
		echo "Not compressing temporary directories from failed test runs."
	fi
else
	echo "No symlinks to failed tests' temporary directories found in ${VPP_TEST_FAILED_DIR}."
fi

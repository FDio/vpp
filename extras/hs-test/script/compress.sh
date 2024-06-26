#!/usr/bin/env bash

# if failed-summary.log is not empty, exit status = 1
if [ -s "${HS_ROOT}/summary/failed-summary.log" ]
then
    if [ -n "${WORKSPACE}" ]
    then
        echo -n "Copying docker logs..."
        dirs=$(jq -r '.[0] | .SpecReports[] | select(.State == "failed") | .LeafNodeText' ${HS_ROOT}/summary/report.json)
        for dirName in $dirs; do
            logDir=/tmp/hs-test/$dirName
            if [ -d "$logDir" ]; then
                mkdir -p ${WORKSPACE}/archives/summary
                cp -r $logDir ${WORKSPACE}/archives/summary/
            fi
        done
        echo "Done."

        echo -n "Copying failed test logs into build log archive directory (${WORKSPACE}/archives)... "
        mkdir -p ${WORKSPACE}/archives/summary
        cp -a ${HS_ROOT}/summary/* ${WORKSPACE}/archives/summary
        echo "Done."

        echo -n "Compressing files in ${WORKSPACE}/archives from test runs... "
        cd ${WORKSPACE}/archives
        find . -type f \( -name "*.json" -o -name "*.log" \) -exec gzip {} \;
        echo "Done."

    else
        echo "Not compressing files in temporary directories from test runs."
    fi
    echo "*************************** SUMMARY ***************************"
    cat "${HS_ROOT}/summary/failed-summary.log"
    exit 1
fi

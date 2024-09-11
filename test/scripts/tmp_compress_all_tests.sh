#!/usr/bin/env bash

echo -n "Compressing files in temporary directories from failed test runs... "
cd /tmp || exit 1

for d in $(ls -d /tmp/vpp-unittest* | xargs -n 1 basename)
do
    cd "$d" || continue
    find . -path . -print0 | xargs -0 -n1 gzip
    cd /tmp || exit 1
done

echo "done."

if [ -n "$WORKSPACE" ]
then
    echo "Copying all test logs into build log archive directory ($WORKSPACE/archives)... "
    for single_test in $(ls -d /tmp/vpp-unittest* | xargs -n 1 basename)
    do
        mkdir -p $WORKSPACE/archives/$single_test
        cp -a /tmp/$single_test/* $WORKSPACE/archives/$single_test
    done
    echo "done."
else
    echo "No WORKSPACE path!!!"
fi

exit 1

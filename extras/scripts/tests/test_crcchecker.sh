#!/bin/sh
set -eux

TMPDIR=$(mktemp -d /tmp/vpp-crccheck-test-XXXXX)

CURR_ROOT=$(git rev-parse --show-toplevel)
CURR_DIR=$(pwd)

verify_check_patchset_fails() {
	if (extras/scripts/crcchecker.py --check-patchset); then
		echo "ERROR - check succeeded, it should have failed!"
		exit 1;
	fi
}

# make a copy of the current repo that we can play with
cd ${TMPDIR}
mkdir misc-files
git clone ${CURR_ROOT} vpp-uut
cd vpp-uut

echo "TEST 1: Check the current patchset..."
extras/scripts/crcchecker.py --check-patchset

echo "TEST 2: Dumping the current manifest..."
extras/scripts/crcchecker.py --dump-manifest >${TMPDIR}/misc-files/manifest.txt

echo "TEST 3: Checking the 20.01 version of acl.api...."
extras/scripts/crcchecker.py --git-revision v20.01 src/plugins/acl/acl.api

echo "TEST 4: Add a new field into a message in acl.api, and check patchset - must fail..."
sed -i -e 's#vpe_pid;#vpe_pid; u32 sneaky_new_field;#' src/plugins/acl/acl.api
verify_check_patchset_fails

echo "TEST 5: Rename the changed acl.api file and not add it to git... must fail (due to deletion of the APIs)..."
mv src/plugins/acl/acl.api src/plugins/acl/acl_new.api
verify_check_patchset_fails

echo "TEST 6: Add the renamed file to git commit... must fail (due to addition of the fields)..."
git add src/plugins/acl/acl_new.api
git commit -m "added acl_new.api"
verify_check_patchset_fails

echo "TEST 7: Verify we can delete deprecated message"
git commit -a -m "reset"
cat >crccheck.api <<EOL
option version="1.0.0";
autoreply define crccheck
{
  option deprecated="v20.11";
  bool foo;
};
EOL
git add crccheck.api
git commit -m "deprecated api";
# delete API
cat >crccheck.api <<EOL
option version="1.0.0";
autoreply define crccheck_2
{
  bool foo;
};
EOL
git add crccheck.api
git commit -m "deprecated api";
extras/scripts/crcchecker.py --check-patchset

exit 0;
echo "TEST: All tests got the expected result, cleaning up."

# done with all the tests - clean up
cd ${CURR_DIR}

# beware of empty variables, careful with deletion
rm -rf ${TMPDIR}/vpp-uut
rm -rf ${TMPDIR}/misc-files
rmdir ${TMPDIR}


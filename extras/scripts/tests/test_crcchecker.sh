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

finish() {
	if [ -e "$TMPDIR" ]; then
		echo "Temporary directory is: $TMPDIR"
	fi
}
trap finish EXIT


# make a copy of the current repo that we can play with
cd ${TMPDIR}
mkdir misc-files
git clone ${CURR_ROOT} vpp-uut
cd vpp-uut

# maybe grab the CRC checker
# git fetch "https://gerrit.fd.io/r/vpp" refs/changes/81/26881/14 && git cherry-pick FETCH_HEAD || echo "Already there"


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
  option deprecated;
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

echo "TEST 7.1: Verify we can delete deprecated message (old/confused style)"
cat >crccheck_dep.api <<EOL
option version="1.0.0";
autoreply define crccheck
{
  option status="deprecated";
  bool foo;
};
EOL
git add crccheck_dep.api
git commit -m "deprecated api";
# delete API
cat >crccheck_dep.api <<EOL
option version="1.0.0";
autoreply define crccheck_2
{
  bool foo;
};
EOL
git add crccheck_dep.api
git commit -m "deprecated api";
extras/scripts/crcchecker.py --check-patchset

echo "TEST 8: Verify that we can not rename a non-deprecated message"
sed -i -e 's/crccheck_2/crccheck_3/g' crccheck.api
git add crccheck.api
git commit -m "renamed api";
verify_check_patchset_fails
# fix it.
sed -i -e 's/crccheck_3/crccheck_2/g' crccheck.api
git commit -a --amend -m "empty commit after we renamed api back" --allow-empty

echo "TEST 9: Verify that the check fails if the changes are not committed"
cat >>crccheck.api <<EOL
autoreply define crc_new_check_in_progress
{
  option status="in_progress";
  bool foobar;
};
EOL
verify_check_patchset_fails

echo "TEST10: Verify that the in-progress message can be added"
git add crccheck.api
git commit -m "added a new in-progress api";
extras/scripts/crcchecker.py --check-patchset

echo "TEST11: Verify we can rename an in-progress API"
sed -i -e 's/crc_new_check_in_progress/crc_new_check_in_progress_2/g' crccheck.api
git add crccheck.api
git commit -m "renamed in-progress api";
extras/scripts/crcchecker.py --check-patchset

echo "TEST11.1: Switch to new designation of in-progress API"
sed -i -e 's/status="in_progress"/in_progress/g' crccheck.api
git add crccheck.api
git commit -m "new designation of in-progress api";
extras/scripts/crcchecker.py --check-patchset


echo "TEST12: Verify we can add a field to an in-progress API"
sed -i -e 's/foobar;/foobar; bool new_baz;/g' crccheck.api
git add crccheck.api
git commit -m "new field added in in-progress api";
extras/scripts/crcchecker.py --check-patchset

echo "TEST13: Verify we fail the check if the file can not be compiled"
cat >crccheck2.api <<EOL
option version="0.0.1";
autoreply define spot_the_error
{
  option status="in_progress"
  bool something_important;
};
EOL
git add crccheck2.api
git commit -m "a new message with a syntax error";
verify_check_patchset_fails

# get rid of the "erroneous" commit in the previous test
git reset --hard HEAD~1

echo "TEST14: Verify we handle new .api file"
cat >crccheck3.api <<EOL
autoreply define foo
{
  bool bar;
};
EOL
git add crccheck3.api
git commit -m "a new message in new file";
extras/scripts/crcchecker.py --check-patchset

echo "TEST: All tests got the expected result, cleaning up."

# done with all the tests - clean up
cd ${CURR_DIR}

# beware of empty variables, careful with deletion
rm -rf ${TMPDIR}/vpp-uut
rm -rf ${TMPDIR}/misc-files
rmdir ${TMPDIR}

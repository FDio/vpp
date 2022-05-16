#/bin/env bash

KNOWN_FEATURES=$(cat MAINTAINERS | sed -ne 's/^I:[[:space:]]*//p')
FEATURES=$(git show -s --format=%s --no-color \
    | sed -ne 's/^\([a-z0-9_ -]*\):.*$/\1/p')
KNOWN_TYPES="feature fix refactor improvement style docs test make"
TYPE=$(git show -s --format=%b --no-color | sed -ne 's/^Type:[[:space:]]*//p')
FIXES_COMMIT=$(git show -s --format=%b --no-color | sed -ne 's/^Fixes:[[:space:]]*//p')
ERR="=============================== ERROR ==============================="

# Chech that subject line contains at least one feature id
if [ $(echo ${FEATURES} | wc -w) -eq 0 ]; then
  echo $ERR
  echo "git commit 'Subject:' line must contain at least one known feature id."
  echo "feature id(s) must be listed before ':' and space delimited "
  echo "if more then one is listed."
  echo "Please refer to the MAINTAINERS file (I: lines) for known feature ids."
  echo $ERR
  exit 1
fi

# Check that feature ids in subject line are known
for i in ${FEATURES}; do
  is_known=false
  for j in ${KNOWN_FEATURES}; do
    [ "${i}" = "${j}" ] && is_known=true
  done
  if [ ${is_known} = "false" ] ; then
    echo $ERR
    echo "Unknown feature '${i}' in commit 'Subject:' line."
    echo "Feature must exist in MAINTAINERS file. If this commit introduces "
    echo "a new feature, then this commit must add an entry to the "
    echo "MAINTAINERS file."
    echo $ERR
    exit 1
  fi
done

# Check that Message body contains valid Type: entry
is_known=false
for i in ${KNOWN_TYPES}; do
  [ "${i}" = "${TYPE}" ] && is_known=true
done
if [ ${is_known} = "false" ] ; then
  echo $ERR
  echo "Unknown commit type '${TYPE}' in commit message body."
  echo "Commit message must contain known 'Type:' entry."
  echo "Known types are: ${KNOWN_TYPES}"
  echo $ERR
  exit 1
fi

# check that for type = "fix" there is also a valid "Fixes: XXXX" header
# and the commit it references is valid
if [ "${TYPE}" = "fix" ]; then
	if [ "x${FIXES_COMMIT}" = "x" ]; then
		echo $ERR
		echo "Type 'fix' must have a 'Fixes: XXXXX' in the commit message,"
		echo "where XXXXX must be the git commit ID which introduced the bug."
		echo "The goal is to communicate:"
		echo "    'if you have commit XXXXX, you must have this fix.'"
		echo $ERR
		exit 1
	fi
	if [ ! $(git show "${FIXES_COMMIT}" >/dev/null 2>&1) ]; then
		echo $ERR
		echo "Could not find '${FIXES_COMMIT}' in git history."
		echo "The 'Fixes:' header must specify the git commit ID which"
		echo "has introduced the bug which required this bugfix."
		echo "The goal is to communicate:"
		echo "    'if you have commit XXXXX, you must have this fix.'"
		echo $ERR
		exit 1
	fi
fi

echo "*******************************************************************"
echo "* VPP Commit Message Checkstyle Successfully Completed"
echo "*******************************************************************"

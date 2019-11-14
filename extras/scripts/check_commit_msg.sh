#/bin/env bash

KNOWN_FEATURES=$(cat MAINTAINERS | sed -ne 's/^I:[[:space:]]*//p')
FEATURES=$(git show -s --format=%s --no-color | sed -e 's/\([a-z0-9 -]*\):.*/\1/')
KNOWN_TYPES="feature fix refactor style docs test make"
TYPE=$(git show -s --format=%b --no-color | sed -ne 's/^Type:[[:space:]]*//p')
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
echo "*******************************************************************"
echo "* VPP Commit Message Checkstyle Successfully Completed"
echo "*******************************************************************"

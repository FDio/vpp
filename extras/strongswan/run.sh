print_help() {
  echo "vpp/strongswan tests"
}

count=0
test_num=`ls -l test_* | wc -l`

for test_case in test_*
do
  let "count=$count + 1"

  base_name=`basename -a "$test_case"`
  printf "%2d/%d : %-48s" $count $test_num "$base_name"
  logger "test start $base_name"

  bash $test_case  &> /dev/null
  rc=$?

  if [ $rc -ne 0 ] ; then
    printf "failed!\n"
  else
    printf "passed.\n"
  fi
done

exit 0

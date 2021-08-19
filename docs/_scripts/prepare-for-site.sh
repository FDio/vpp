#!/bin/bash

if [ ! -d "docs" ]; then
  echo "This script is meant to be run from the root directory"
  exit 1;
fi

for f in $(find ./docs -type l)
do
  target=$(readlink $f)
  rm $f
  cp $(dirname $f)/$target $(dirname $f)/$(basename $target)
  echo "Replaced symlink $f"
done

echo "Cleaning doc build directory"
make docs-clean


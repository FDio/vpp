#!/bin/sh
CMD='git clean -dfX */'

if git pull | grep -v 'Already up-to-date.'
then
  echo "Executing $CMD"
  $CMD
fi

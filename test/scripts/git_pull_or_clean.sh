#!/bin/sh

# TODO: Add a header with copyright and license.

CMD='git clean -dfX */'

if git pull | grep -v 'Already up-to-date.'
then
  echo "Executing $CMD"
  $CMD
fi

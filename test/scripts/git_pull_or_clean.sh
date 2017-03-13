#!/bin/sh

git pull | grep -q -v 'Already up-to-date.' || git clean -dfX */

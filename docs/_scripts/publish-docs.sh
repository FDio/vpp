#!/bin/bash -ex

# publish-docs.sh
#
# This sccript is used to publish the VPP User documents to
# the FD.io Site.
#
# Arguments:
#
# $1: The main site repo user name
# $2: The release branch name for example 1908, 1904 etc.

# Some basic checks
if [ ! -d "docs" ]; then
  echo "This script is meant to be run from the root directory."
  exit 1;
fi

if [ "$#" -ne 2 ]; then
    echo "Please specify the site username and branch."
    exit 1;
fi

# Get the workspace root
WS_ROOT=$PWD

# Get the VPP branch and username
SITE_USERNAME=$1
VPP_BRANCH=$2

#Build the docs
make docs-clean
make docs-venv
make docs

# Clone the site repo
rm -fr site
rm -fr sphinx_env
git clone ssh://git@github.com/$SITE_USERNAME/site
cd site
git submodule update --init --recursive
git remote add upstream ssh://git@github.com/FDio/site
git remote -v
git fetch upstream
git merge -m "Publish the Docs" upstream/master

# Get the version
VERSION=`source $WS_ROOT/src/scripts/version`
VERSION=${VERSION/"~"/"-"}

# Copy the files to the appropriate directory
SRC_DIR=../docs/_build/html/.
if [ "$VPP_BRANCH" == "master" ]
then
    TARGET_DIR=./static/docs/vpp/master
    rm -fr $TARGET_DIR
else
    TARGET_DIR=./static/docs/vpp/v$VPP_BRANCH
    rm -fr $TARGET_DIR
    mkdir -p $TARGET_DIR
    VERSION=v$VPP_BRANCH
    rm ./static/docs/vpp/latest
    ln -s $VERSION ./static/docs/vpp/latest
fi

# Create a branch for the commit
git checkout -b $VERSION
git branch

# Copy the docs
cp -r $SRC_DIR $TARGET_DIR

# Create the feature list
pushd ..
source ./docs/venv/bin/activate
find . -name FEATURE.yaml | ./src/scripts/fts.py --markdown > site/content/vppProject/vppfeatures/features.md
deactivate
popd

# Push the new docs
git add "*"
git commit -s -m "Publish docs from VPP $VERSION"
git push origin "$VERSION"

exit 0

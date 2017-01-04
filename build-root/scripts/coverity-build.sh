#!/bin/bash

set -ex

token=${COVERITY_TOKEN}
email=dbarach@cisco.com
project="fd.io VPP"
project_encoded="fd.io+VPP"
url=https://scan.coverity.com

export COV_HOST=$(hostname -f)
export COV_USER=vpp

# Location of various directories

# run script from .../build-root

build_dir=`pwd`
covdir="${build_dir}/cov-int"
COVTOOLS="${COVTOOLS-/scratch/cov-analysis-latest}"

# Before we run the build, check that we can submit one
check=$(curl -s --form project="${project}" \
	--form token="${token}" "${url}/api/upload_permitted")
if [ "${check}" = "Access denied" ]; then
	echo "Bad token or project name."
	exit 1
fi
if [ "${check}" != '{"upload_permitted":true}' ]; then
	echo "Upload not permitted; stop now..."
        exit 1
fi

version=$(git describe)

# Run the build
cd ..
"${COVTOOLS}/bin/cov-build" --dir "${covdir}" make bootstrap build-coverity
cd ${build_dir}

# Tar the build artifacts that scan wants
tar -czf fd.io-vpp.tgz "$(basename ${covdir})"
# rm -rf "${covdir}"

# Submit the build
echo curl --form token="${token}" \
	--form email="${email}" \
	--form file=@fd.io-vpp.tgz \
	--form version="${version}" \
	--form description="master:${version}"  \
	"${url}/builds?project=${project_encoded}"

# All done!

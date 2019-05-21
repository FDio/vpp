This is a work-in-progress to automatically test the installability of the VPP
from the various repositories, to be run as part of the release process.

You will need to tweak and run run-docker-test script.
If it prints "ALL TESTS PASSED", this means VPP properly installs
according to your constraints in the tested environments.

You can supply the arguments to it via environment variables:

Select the PackageCloud repository:

PACKAGECLOUD_REPO=fdio/release  - select the repository

Select the method of install/check:

VPP_CHECK_VERSION=19.04-release - install default versions
of packages, check that the version in the running VPP is
this one.

OR:


VPP_EXACT_VERSION=19.01.2-release - install the specified
versions of packages, check that the version of the
running VPP matches.

VPP_PACKAGE_LIST=packagelists/default - the prefix for package
lists per-environment (ubuntu16, ubuntu18, centos)
to be installed.




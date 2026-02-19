.. _supported:

.. toctree::

Supported Archs and OS
**********************

The following architectures and operating systems are supported in VPP:

Architectures
-------------

* The FD.io VPP platform supports:

   * x86/64
   * ARM-AArch64

Operating Systems and Packaging
-------------------------------

FD.io VPP supports package installation on the following
recent LTS releases:

* Distributions:

   * Debian
   * Ubuntu

Release Branch Support Policy
-----------------------------

FD.io/VPP release branches are named 'stable/<release number>'.
For example, 'stable/2510', is the release branch for VPP Release 25.10.

VPP project support for release branch code, includes CI support, code review/merge,
and vpp debian packages uploaded to
`packagecloud.io/fdio/<release number> <https://packagecloud.io/fdio/2510>`__.
The current VPP project policy includes the master (next release) branch, and the
previous two stable branches.

During the release management process for new release, support continues for the
previous two stable branches plus the new stable branch (i.e. 4 branches supported total)
created in RC1 of the release management process.  Once a new release is announced, support
for the oldest stable branch ends.  Post-release CI maintenance will remove this branch
from the docker executor images in which the CI jobs are executed.

Hardware Driver Support Policy
------------------------------

VPP hardware drivers are not covered by per-patch CI jobs. CSIT performance tests exercise
VPP hardware drivers in the process of benchmarking VPP. The list of hardware devices (NICs, etc)
for each testbed is documented in the
`CSIT Testbed Specifications <https://csit.fd.io/cdocs/infrastructure/fdio_dc_testbed_specifications/#server-types>`__.
If you encounter hardware driver issues for hardware that is not installed in any CSIT testbed,
please contact the hardware manufacturer for support in addition to inquiring on the
`vpp development email list <mailto:vpp-dev@lists.fd.io>`__ for general information from the
community.

.. _reportingbugs:

.. toctree::

Data to include in bug reports
==============================

Image version and operating environment
---------------------------------------

Please make sure to include the vpp image version and command-line arguments.

.. code-block:: console

    $ sudo bash
    # vppctl show version verbose cmdline
    Version:                  v18.07-rc0~509-gb9124828
    Compiled by:              vppuser
    Compile host:             vppbuild
    Compile date:             Fri Jul 13 09:05:37 EDT 2018
    Compile location:         /scratch/vpp-showversion
    Compiler:                 GCC 7.3.0
    Current PID:              5211
    Command line arguments:
      /scratch/vpp-showversion/build-root/install-vpp_debug-native/vpp/bin/vpp
      unix
      interactive

With respect to the operating environment: if misbehavior involving a
specific VM / container / bare-metal environment is involved, please
describe the environment in detail:

* Linux Distro (e.g. Ubuntu 18.04.2 LTS, CentOS-7, etc.)
* NIC type(s) (ixgbe, i40e, enic, etc. etc.), vhost-user, tuntap
* NUMA configuration if applicable

Please note the CPU architecture (x86_86, aarch64), and hardware platform.

When practicable, please report issues against released software, or
unmodified master/latest software.

"Show" command output
---------------------

Every situation is different. If the issue involves a sequence of
debug CLI command, please enable CLI command logging, and send the
sequence involved. Note that the debug CLI is a developer's tool -
**no warranty express or implied** - and that we may choose not to fix
debug CLI bugs.

Please include "show error" [error counter] output. It's often helpful
to "clear error", send a bit of traffic, then "show error"
particularly when running vpp on noisy networks.

Please include ip4 / ip6 / mpls FIB contents ("show ip fib", "show ip6
fib", "show mpls fib", "show mpls tunnel").

Please include "show hardware", "show interface", and "show interface
address" output

Here is a consolidated set of commands that are generally useful
before/after sending traffic.  Before sending traffic:

.. code-block:: console

    vppctl clear hardware
    vppctl clear interface
    vppctl clear error
    vppctl clear run

Send some traffic and then issue the following commands.

.. code-block:: console

    vppctl show version verbose
    vppctl show hardware
    vppctl show interface address
    vppctl show interface
    vppctl show run
    vppctl show error

Here are some protocol specific show commands that may also make
sense.  Only include those features which have been configured.

.. code-block:: console

     vppctl show l2fib
     vppctl show bridge-domain

     vppctl show ip fib
     vppctl show ip neighbors

     vppctl show ip6 fib
     vppctl show ip6 neighbors

     vppctl show mpls fib
     vppctl show mpls tunnel

Network Topology
----------------

Please include a crisp description of the network topology, including
L2 / IP / MPLS / segment-routing addressing details. If you expect
folks to reproduce and debug issues, this is a must.

At or above a certain level of topological complexity, it becomes
problematic to reproduce the original setup.

Packet Tracer Output
--------------------

If you capture packet tracer output which seems relevant, please include it.

.. code-block:: console

    vppctl trace add dpdk-input 100  # or similar

send-traffic

.. code-block:: console

    vppctl show trace

Capturing post-mortem data
==========================

It should go without saying, but anyhow: **please put post-mortem data
in obvious, accessible places.** Time wasted trying to acquire
accounts, credentials, and IP addresses simply delays problem
resolution.

Please remember to add post-mortem data location information to GitHub
issues.

Syslog Output
-------------

The vpp signal handler typically writes a certain amount of data in
/var/log/syslog before exiting. Make sure to check for evidence, e.g
via "grep /usr/bin/vpp /var/log/syslog" or similar.

Binary API Trace
----------------

If the issue involves a sequence of control-plane API messages - even
a very long sequence - please enable control-plane API
tracing. Control-plane API post-mortem traces end up in
/tmp/api_post_mortem.<pid>.

Please remember to put post-mortem binary api traces in accessible
places.

These API traces are especially helpful in cases where the vpp engine
is throwing traffic on the floor, e.g. for want of a default route or
similar.

Make sure to leave the default stanza "... api-trace { on } ... " in
the vpp startup configuration file /etc/vpp/startup.conf, or to
include it in the command line arguments passed by orchestration
software.

Core Files
----------

Production systems, as well as long-running pre-production soak-test
systems, **must** arrange to collect core images. There are various
ways to configure core image capture, including e.g. the Ubuntu
"corekeeper" package. In a pinch, the following very basic sequence
will capture usable vpp core files in /tmp/dumps.

.. code-block:: console

    # mkdir -p /tmp/dumps
    # sysctl -w debug.exception-trace=1
    # sysctl -w kernel.core_pattern="/tmp/dumps/%e-%t"
    # ulimit -c unlimited
    # echo 2 > /proc/sys/fs/suid_dumpable

If you start VPP from systemd, you also need to edit
/lib/systemd/system/vpp.service and uncomment the "LimitCORE=infinity"
line before restarting VPP.

Vpp core files often appear enormous, but they are invariably
sparse. Gzip compresses them to manageable sizes. A multi-GByte
corefile often compresses to 10-20 Mbytes.

When decompressing a vpp core file, we suggest using "dd" as shown to
create a sparse, uncompressed core file:

.. code-block:: console

   $ zcat vpp_core.gz | dd conv=sparse of=vpp_core

Please remember to put compressed core files in accessible places.

Make sure to leave the default stanza "... unix { ... full-coredump
... } ... " in the vpp startup configuration file
/etc/vpp/startup.conf, or to include it in the command line arguments
passed by orchestration software.

Core files from Private Images
==============================

Core files from private images require special handling. If it's
necessary to go that route, copy the **exact** Debian packages (or
RPMs) which correspond to the core file to the same public place as
the core file. A no-excuses-allowed, hard-and-fast requirement.

In particular:

.. code-block:: console

  libvppinfra_<version>_<arch>.deb # vppinfra library
  libvppinfra-dev_<version>_<arch>.deb # vppinfra library development pkg
  vpp_<version>_<arch>.deb         # the vpp executable
  vpp-dbg_<version>_<arch>.deb     # debug symbols
  vpp-dev_<version>_<arch>.deb     # vpp development pkg
  vpp-lib_<version>_<arch>.deb     # shared libraries
  vpp-plugin-core_<version>_<arch>.deb # core plugins
  vpp-plugin-dpdk_<version>_<arch>.deb # dpdk plugin

For reference, please include git commit-ID, branch, and git repo
information [for repos other than gerrit.fd.io] in the GitHub issue.

Note that git commit-ids are crypto sums of the head [latest]
**merged** patch. They say **nothing whatsoever** about local
workspace modifications, branching, or the git repo in question.

Even given a byte-for-byte identical source tree, it's easy to build
dramatically different binary artifacts. All it takes is a different
toolchain version.


On-the-fly Core File Compression
--------------------------------

Depending on operational requirements, it's possible to compress
corefiles as they are generated. Please note that it takes several
seconds' worth of wall-clock time to compress a vpp core file on the
fly, during which all packet processing activities are suspended.

To create compressed core files on the fly, create the following
script, e.g. in /usr/local/bin/compressed_corefiles, owned by root,
executable:

.. code-block:: console

  #!/bin/sh
  exec /bin/gzip -f - >"/tmp/dumps/core-$1.$2.gz"

Adjust the kernel core file pattern as shown:

.. code-block:: console

  sysctl -w kernel.core_pattern="|/usr/local/bin/compressed_corefiles %e %t"

Core File Summary
-----------------

Bottom line: please follow core file handling instructions to the
letter. It's not complicated. Simply copy the exact Debian packages or
RPMs which correspond to core files to accessible locations.

If we go through the setup process only to discover that the image and
core files don't match, it will simply delay resolution of the issue;
to say nothing of irritating the person who just wasted their time.

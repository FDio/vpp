.. _building:

.. toctree::

Building VPP
=====================

To get started developing with VPP, you need to get the required VPP sources and then build the packages.
For more detailed information on the build system please refer to :ref:`buildsystem`.

.. _makesureinstalled:

VPP for Ubuntu: Environment Setup
-------------------------------------------

If you are not downloading VPP on Ubuntu with WSL (Windows Subsystem for Linux), please disregard this section
and jump to 'Get the VPP Sources'.

Before starting on VPP for Ubuntu, make sure WSL2 and Ubuntu are installed.

To install WSL2 and Ubuntu, run Windows PowerShell as an administrator and enter this in the terminal:

.. code-block:: console

    $ wsl --install

Next, go to the 'resolv.conf' file in Ubuntu's '/etc' folder.
It should have been automatically generated when Ubuntu was installed; if it doesn't exist, create it.
Please use 'sudo' to avoid "File resolv.conf is unwritable" errors.

.. code-block:: console

    $ cd /etc
    $ sudo nano resolv.conf

In the file, add the following content in place of the current 'nameserver X.X.X.X' line:

.. code-block:: console

    nameserver 8.8.8.8

This replaces the DNS nameserver on your machine with the Google DNS service,
resolving any DNS Internet connection issues.

Note: by default, the 'resolv.conf' file regenerates every time you restart Ubuntu, so your changes won't be saved.
To keep your changes, run the following command to make 'resolv.conf' immutable:

.. code-block:: console

    $ sudo chattr +i /etc/resolv.conf


Now copy the following lines from 'resolv.conf':

.. code-block:: console

    [network]
    generateResolvConf = false

Then, go to the 'wsl.conf' file in '/etc' and paste the lines there.
Please use 'sudo' here as well to avoid "File wsl.conf is unwritable" errors.

.. code-block:: console

    $ sudo nano wsl.conf

In order to test your DNS server connection, please ping 8.8.8.8 on the terminal:

.. code-block:: console

    $ ping 8.8.8.8
    PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
    64 bytes from 8.8.8.8: icmp_seq=1 ttl=116 time=9.58 ms
    64 bytes from 8.8.8.8: icmp_seq=2 ttl=116 time=45.8 ms
    64 bytes from 8.8.8.8: icmp_seq=3 ttl=116 time=9.62 ms
    64 bytes from 8.8.8.8: icmp_seq=4 ttl=116 time=11.4 ms
    64 bytes from 8.8.8.8: icmp_seq=5 ttl=116 time=12.2 ms
    64 bytes from 8.8.8.8: icmp_seq=6 ttl=116 time=8.69 ms
    64 bytes from 8.8.8.8: icmp_seq=7 ttl=116 time=52.4 ms
    64 bytes from 8.8.8.8: icmp_seq=8 ttl=116 time=11.0 ms
    ...

While still in /etc, run the following commands:

.. code-block:: console

    $ sudo apt-get update
    $ sudo apt-get dist-upgrade
    $ sudo apt-get install --reinstall ca-certificates
    $ sudo update-ca-certificates


Finally, head back to your home directory and jump to 'Get the VPP Sources'.

.. _setupproxies:

Set up Proxies
--------------------------

Depending on the environment you are operating in, proxies may need to be set.
Run these proxy commands to specify the *proxy-server-name* and corresponding *port-number*:

.. code-block:: console

    $ export http_proxy=http://<proxy-server-name>.com:<port-number>
    $ export https_proxy=https://<proxy-server-name>.com:<port-number>


Get the VPP Sources
-----------------------------------

To get the VPP sources that are used to create the build, run the following commands:

.. code-block:: console

    $ git clone https://gerrit.fd.io/r/vpp
    $ cd vpp

As VPP version is derived from git description (which is based on git tags),
if the github generated tarballs are used, the version information
will be missing from the version file (.../src/scripts/.version)
which is required by the version script when building
in a non-git based workspace or the build will fail.
In that case, put the desired version string into
.../src/scripts/.version to satisfy the requirements of the version script.

Alternatively, the ``make dist`` command in a cloned git workspace
will generate an xz compressed tarball of the source
including the .../src/scripts/.version file containing the git hash
using the standard nomenclature for VPP images.

Extract the tarball using the -J option to decompress it using xz. For example,
``tar xvJf ./build-root/vpp-23.10-rc0~184-g48cd559fb.tar.xz``

Build VPP Dependencies
--------------------------------------

Before building a VPP image, make sure there are no FD.io VPP or DPDK packages
installed, by entering the following commands:

.. code-block:: console

    $ dpkg -l | grep vpp
    $ dpkg -l | grep DPDK

There should be no output, or no packages shown after the above commands are run.

Please make sure **make** is installed before running the next command.
If it is not installed, run the following command first:

.. code-block:: console

    $ sudo apt install make

Run the following **make** command to install the dependencies for FD.io VPP.

If the download hangs at any point, then you may need to
:ref:`set up proxies <setupproxies>` for the download to work.

.. code-block:: console

    $ make install-dep
    Hit:1 http://us.archive.ubuntu.com/ubuntu xenial InRelease
    Get:2 http://us.archive.ubuntu.com/ubuntu xenial-updates InRelease [109 kB]
    Get:3 http://security.ubuntu.com/ubuntu xenial-security InRelease [107 kB]
    Get:4 http://us.archive.ubuntu.com/ubuntu xenial-backports InRelease [107 kB]
    Get:5 http://us.archive.ubuntu.com/ubuntu xenial-updates/main amd64 Packages [803 kB]
    Get:6 http://us.archive.ubuntu.com/ubuntu xenial-updates/main i386 Packages [732 kB]
    ...
    ...
    Update-alternatives: using /usr/lib/jvm/java-8-openjdk-amd64/bin/jmap to provide /usr/bin/jmap (jmap) in auto mode
    Setting up default-jdk-headless (2:1.8-56ubuntu2) ...
    Processing triggers for libc-bin (2.23-0ubuntu3) ...
    Processing triggers for systemd (229-4ubuntu6) ...
    Processing triggers for ureadahead (0.100.0-19) ...
    Processing triggers for ca-certificates (20160104ubuntu1) ...
    Updating certificates in /etc/ssl/certs...
    0 added, 0 removed; done.
    Running hooks in /etc/ca-certificates/update.d...

    done.
    done.

Build VPP (Debug)
----------------------------

This build version contains debug symbols which are useful for modifying VPP. The
**make** command below builds a debug version of VPP. The binaries, when building the
debug images, can be found in /build-root/vpp_debug-native.

The Debug build version contains debug symbols, which are useful for troubleshooting
or modifying VPP. The **make** command below, builds a debug version of VPP. The
binaries used for building the debug image can be found in */build-root/vpp_debug-native*.

.. code-block:: console

    $ make build
    make[1]: Entering directory '/home/vagrant/vpp-master/build-root'
    @@@@ Arch for platform 'vpp' is native @@@@
    @@@@ Finding source for dpdk @@@@
    @@@@ Makefile fragment found in /home/vagrant/vpp-master/build-data/packages/dpdk.mk @@@@
    @@@@ Source found in /home/vagrant/vpp-master/dpdk @@@@
    @@@@ Arch for platform 'vpp' is native @@@@
    @@@@ Finding source for vpp @@@@
    @@@@ Makefile fragment found in /home/vagrant/vpp-master/build-data/packages/vpp.mk @@@@
    @@@@ Source found in /home/vagrant/vpp-master/src @@@@
    ...
    ...
    make[5]: Leaving directory '/home/vagrant/vpp-master/build-root/build-vpp_debug-native/vpp/vpp-api/java'
    make[4]: Leaving directory '/home/vagrant/vpp-master/build-root/build-vpp_debug-native/vpp/vpp-api/java'
    make[3]: Leaving directory '/home/vagrant/vpp-master/build-root/build-vpp_debug-native/vpp'
    make[2]: Leaving directory '/home/vagrant/vpp-master/build-root/build-vpp_debug-native/vpp'
    @@@@ Installing vpp: nothing to do @@@@
    make[1]: Leaving directory '/home/vagrant/vpp-master/build-root'

Build VPP (Release Version)
-----------------------------------------

This section describes how to build the regular release version of FD.io VPP. The
release build is optimized and does not create any debug symbols.
The binaries used in building the release images are found in */build-root/vpp-native*.

Use the following **make** command below to build the release version of FD.io VPP.

.. code-block:: console

    $ make build-release

Installing External Dependencies
-------------------------------------------
At this point, there are still some VPP external dependencies left to install. They could be installed
using 'make-build', but this only installs them locally in the VPP tree, not in the operating system.
In order to fix this and save time, run the following command:

.. code-block:: console

    $ make install-ext-deps

-------------------------------------------
Building Necessary Packages
-------------------------------------------

The package that needs to be built depends on the type system VPP will be running on:

* The :ref:`Debian package <debianpackages>` is built if VPP is going to run on Ubuntu
* The :ref:`RPM package <rpmpackages>` is built if VPP is going to run on Centos or Redhat

.. _debianpackages:

Building Debian Packages
^^^^^^^^^^^^^^^^^^^^^^^^^

To build the debian packages, use the following command:

.. code-block:: console

    $ make pkg-deb

.. _rpmpackages:

Building RPM Packages
^^^^^^^^^^^^^^^^^^^^^^^

To build the rpm packages, use one of the following commands below, depending on the system:

.. code-block:: console

    $ make pkg-rpm

Once the packages are built they can be found in the build-root directory.

.. code-block:: console

    $ ls build-root/*.deb

    If the packages are built correctly, then this should be the corresponding output:

    vpp_18.07-rc0~456-gb361076_amd64.deb             vpp-dbg_18.07-rc0~456-gb361076_amd64.deb
    vpp-dev_18.07-rc0~456-gb361076_amd64.deb         vpp-api-lua_18.07-rc0~456-gb361076_amd64.deb
    vpp-lib_18.07-rc0~456-gb361076_amd64.deb         vpp-api-python_18.07-rc0~456-gb361076_amd64.deb
    vpp-plugins_18.07-rc0~456-gb361076_amd64.deb

Finally, the created packages can be installed using the following commands. Install
the package that corresponds to OS that VPP will be running on:

For Ubuntu:

.. code-block:: console

   $ sudo dpkg -i build-root/*.deb

For Centos or Redhat:

.. code-block:: console

   $ sudo rpm -ivh build-root/*.rpm

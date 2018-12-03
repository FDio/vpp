.. _building:

.. toctree::

Building VPP
============

To get started developing with VPP, you need to get the required VPP sources and then build the packages. 
For more detailed information on the build system please refer to :ref:`buildsystem`.

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

Build VPP Dependencies
--------------------------------------

Before building a VPP image, make sure there are no FD.io VPP or DPDK packages
installed, by entering the following commands:

.. code-block:: console

    $ dpkg -l | grep vpp 
    $ dpkg -l | grep DPDK

There should be no output, or no packages shown after the above commands are run.

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


Building Necessary Packages
--------------------------------------------

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
    
    $ ls *.deb

    If the packages are built correctly, then this should be the corresponding output:

    vpp_18.07-rc0~456-gb361076_amd64.deb             vpp-dbg_18.07-rc0~456-gb361076_amd64.deb
    vpp-dev_18.07-rc0~456-gb361076_amd64.deb         vpp-api-lua_18.07-rc0~456-gb361076_amd64.deb
    vpp-lib_18.07-rc0~456-gb361076_amd64.deb         vpp-api-python_18.07-rc0~456-gb361076_amd64.deb
    vpp-plugins_18.07-rc0~456-gb361076_amd64.deb

Finally, the created packages can be installed using the following commands. Install
the package that correspnds to OS that VPP will be running on:

For Ubuntu:

.. code-block:: console

   $ sudo bash
   # dpkg -i *.deb

For Centos or Redhat:

.. code-block:: console

   $ sudo bash
   # rpm -ivh *.rpm

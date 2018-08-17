.. _centos:

.. toctree::

Setup the fd.io Repository - Centos 7
=====================================

Update the OS
-------------

Before starting the repository setup, it is a good idea to first update and upgrade
the OS; run the following command to update the OS:

.. code-block:: console

    $ sudo yum update


Point to the Repository
-----------------------

For CentOS based systems, there are two respositories to pull VPP binaries from:

* CentOS NFV SIG Repository
* Nexus Repository


CentOS NFV SIG Repository
^^^^^^^^^^^^^^^^^^^^^^^^^

VPP is not in the official CentOS 7 distro; however, CentOS has Special
Interest Groups (SIG), which are smaller groups within the CentOS community that
focus on a small set of issues. The CentOS NFV (Network Function Virtualization)
SIG was created to provide a CentOS-based stack that will serve as a platform

To install released packages from the CentOS NFV SIG Repository on an updated
Centos 7 system, first, install the CentOS NFV SIG FIDO repo file by running the
following command:

.. code-block:: console

    $ sudo yum install centos-release-fdio

then **'Install VPP RPMs'**, as described below.

This will install the latest VPP version from the repository. To install an
older version, once the CentOS NFV SIG FDIO repo file has been installed, list
the stored versions:

.. code-block:: console

    $ sudo yum --showduplicates list vpp* | expand
    Loaded plugins: fastestmirror
    Loading mirror speeds from cached hostfile
     * base: repos-va.psychz.net
     * epel: download-ib01.fedoraproject.org
     * extras: mirror.siena.edu
     * updates: repo1.ash.innoscale.net
    Available Packages
    vpp.x86_64                                17.10-1                    centos-fdio
    vpp.x86_64                                18.01.1-1                  centos-fdio
    vpp.x86_64                                18.01.2-1                  centos-fdio
    vpp.x86_64                                18.04-1                    centos-fdio
    vpp-api-java.x86_64                       17.10-1                    centos-fdio
    vpp-api-java.x86_64                       18.01.1-1                  centos-fdio
    vpp-api-java.x86_64                       18.01.2-1                  centos-fdio
    vpp-api-java.x86_64                       18.04-1                    centos-fdio
    vpp-api-lua.x86_64                        17.10-1                    centos-fdio
    vpp-api-lua.x86_64                        18.01.1-1                  centos-fdio
    vpp-api-lua.x86_64                        18.01.2-1                  centos-fdio
    vpp-api-lua.x86_64                        18.04-1                    centos-fdio
    vpp-api-python.x86_64                     17.10-1                    centos-fdio
    vpp-api-python.x86_64                     18.01.1-1                  centos-fdio
    vpp-api-python.x86_64                     18.01.2-1                  centos-fdio
    vpp-api-python.x86_64                     18.04-1                    centos-fdio
    vpp-devel.x86_64                          17.10-1                    centos-fdio
    vpp-devel.x86_64                          18.01.1-1                  centos-fdio
    vpp-devel.x86_64                          18.01.2-1                  centos-fdio
    vpp-devel.x86_64                          18.04-1                    centos-fdio
    vpp-lib.x86_64                            17.10-1                    centos-fdio
    vpp-lib.x86_64                            18.01.1-1                  centos-fdio
    vpp-lib.x86_64                            18.01.2-1                  centos-fdio
    vpp-lib.x86_64                            18.04-1                    centos-fdio
    vpp-plugins.x86_64                        17.10-1                    centos-fdio
    vpp-plugins.x86_64                        18.01.1-1                  centos-fdio
    vpp-plugins.x86_64                        18.01.2-1                  centos-fdio
    vpp-plugins.x86_64                        18.04-1                    centos-fdio
    vpp-selinux-policy.x86_64                 18.04-1                    centos-fdio

Then install a particular version:

.. code-block:: console

    $ sudo yum install vpp-17.10-1.x86_64


Nexus Repository
^^^^^^^^^^^^^^^^

Build artifacts are also posted to a FD.io Nexus Repository. This includes
official point releases, as well as nightly builds. To use any of these build
artifacts, create a file *'/etc/yum.repos.d/fdio-release.repo'* with the
content that points to the version needed. Below are some common examples of
the content needed:


VPP Latest Release
""""""""""""""""""

To allow *'yum'* access to the official VPP releases, create the file
*'/etc/yum.repos.d/fdio-release.repo'* with the following content.

.. code-block:: console

   $ cat /etc/yum.repos.d/fdio-release.repo
   [fdio-release]
   name=fd.io release branch latest merge
   baseurl=https://nexus.fd.io/content/repositories/fd.io.centos7/
   enabled=1
   gpgcheck=0

The *'yum install vpp'* command will install the most recent release. To
install older releases, run the following command to get the list of releases
provided.

.. code-block:: console

   $ sudo yum --showduplicates list vpp* | expand

Then choose the release to install. See **'CentOS NFV SIG Repository'** for
sample *'yum --showduplicates list'* output and an example of installing a
particular version of the RPMs.

VPP Stable Branch
"""""""""""""""""""

To allow *yum* access to the build artifacts for a VPP stable branch, create
the file *'/etc/yum.repos.d/fdio-release.repo'* with the following content.

.. code-block:: console

   $ cat /etc/yum.repos.d/fdio-release.repo
   [fdio-stable-1804]
   name=fd.io stable/1804 branch latest merge
   baseurl=https://nexus.fd.io/content/repositories/fd.io.stable.1804.centos7/
   enabled=1
   gpgcheck=0

For other stable branches, replace the *'1804'* from the above content with the
desired release. Examples: 1606, 1609, 1701, 1704, 1707, 1710, 1804, 1807

The *'yum install vpp'* command will install the most recent build on the
branch, not the latest offical release. Run the following command to get the
list of images produce by the branch:

.. code-block:: console

   $ sudo yum --showduplicates list vpp* | expand

Then choose the image to install. See **'CentOS NFV SIG Repository'** for
sample *'yum --showduplicates list'* output and an example of installing a
particular version of the RPMs.


VPP Master Branch
"""""""""""""""""""

To allow *yum* access to the nightly builds from the VPP master branch, create
the file *'/etc/yum.repos.d/fdio-release.repo'* with the following content.

.. code-block:: console

   $ cat /etc/yum.repos.d/fdio-release.repo
   [fdio-master]
   name=fd.io master branch latest merge
   baseurl=https://nexus.fd.io/content/repositories/fd.io.master.centos7/
   enabled=1
   gpgcheck=0

The *'yum install vpp'* command will install the most recent build on the
branch. Run the following command to get the list of images produce by the
branch.

.. code-block:: console

   $ sudo yum --showduplicates list vpp* | expand

Then choose the image to install. See **'CentOS NFV SIG Repository'** for
sample *'yum --showduplicates list'* output and an example of installing a
particular version of the RPMs.


Install VPP RPMs
================

To install the VPP packet engine, run the following command:

.. code-block:: console

   $ sudo yum install vpp

The *vpp* RPM depends on the *vpp-lib* and *vpp-selinux-policy*
RPMs, so they will be installed as well.

.. note::

    The *vpp-selinux-policy* will not enable SELinux on the system. It
    will install a Custom VPP SELinux policy that will be used if SELinux is
    enabled at any time.

There are additional packages that are optional. These packages can be
combined with the command above and installed all at once, or installed as
needed: 

.. code-block:: console

   $ sudo yum install vpp-plugins vpp-devel vpp-api-python vpp-api-lua vpp-api-java

Starting VPP
============

Once VPP is installed on the system, to run VPP as a systemd service on CentOS,
run the following command:

.. code-block:: console

   $ sudo systemctl start vpp

Then to enable VPP to start on system reboot, run the following command:

.. code-block:: console

   $ sudo systemctl enable vpp

Outside of running VPP as a systemd service, VPP can be started manually or
made to run within GDB for debugging. See :ref:`running` for more details and
ways to tailor VPP to a specific system.


Uninstall the VPP RPMs
======================

To uninstall a VPP RPM, run the following command:

.. code-block:: console

   $ sudo yum autoremove vpp*

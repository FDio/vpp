.. _centos:

.. toctree::

Setup the FD.io Repository - Centos 7
=====================================

Update the OS
-------------

Before starting the repository setup, it is a good idea to first update and upgrade
the OS; run the following commands to update the OS and get some packages.

.. code-block:: console

    $ sudo yum update
    $ sudo yum install pygpgme yum-utils


Package Cloud Repository
^^^^^^^^^^^^^^^^^^^^^^^^

Build artifacts are also posted to a packagecloud.io Repository. This includes
official point releases. To use any of these build artifacts, create a file
*'/etc/yum.repos.d/fdio-release.repo'* with the content that points to the
version needed. Below are some common examples of the content needed:


VPP Latest Release
""""""""""""""""""

To allow *'yum'* access to the official VPP releases, create the file
*'/etc/yum.repos.d/fdio-release.repo'* with the following content.

.. code-block:: console

   $ cat /etc/yum.repos.d/fdio-release.repo
   [fdio_release]
   name=fdio_release
   baseurl=https://packagecloud.io/fdio/release/el/7/$basearch
   repo_gpgcheck=1
   gpgcheck=0
   enabled=1
   gpgkey=https://packagecloud.io/fdio/release/gpgkey
   sslverify=1
   sslcacert=/etc/pki/tls/certs/ca-bundle.crt
   metadata_expire=300

   [fdio_release-source]
   name=fdio_release-source
   baseurl=https://packagecloud.io/fdio/release/el/7/SRPMS
   repo_gpgcheck=1
   gpgcheck=0
   enabled=1
   gpgkey=https://packagecloud.io/fdio/release/gpgkey
   sslverify=1
   sslcacert=/etc/pki/tls/certs/ca-bundle.crt
   metadata_expire=300

Update your local yum cache.

.. code-block:: console

   $ sudo yum clean all
   $ sudo yum -q makecache -y --disablerepo='*' --enablerepo='fdio_release'

The *'yum install vpp'* command will install the most recent release. To
install older releases, run the following command to get the list of releases
provided.

.. code-block:: console

   $ sudo yum --showduplicates list vpp* | expand

VPP Stable Branch
"""""""""""""""""""

To allow *yum* access to the build artifacts for a VPP stable branch, create
the file *'/etc/yum.repos.d/fdio-release.repo'* with the following content.

.. code-block:: console

   $ cat /etc/yum.repos.d/fdio-release.repo
   [fdio_1810]
   name=fdio_1810
   baseurl=https://packagecloud.io/fdio/1810/el/7/$basearch
   repo_gpgcheck=1
   gpgcheck=0
   enabled=1
   gpgkey=https://packagecloud.io/fdio/1810/gpgkey
   sslverify=1
   sslcacert=/etc/pki/tls/certs/ca-bundle.crt
   metadata_expire=300

   [fdio_1810-source]
   name=fdio_1810-source
   baseurl=https://packagecloud.io/fdio/1810/el/7/SRPMS
   repo_gpgcheck=1
   gpgcheck=0
   enabled=1
   gpgkey=https://packagecloud.io/fdio/1810/gpgkey
   sslverify=1
   sslcacert=/etc/pki/tls/certs/ca-bundle.crt
   metadata_expire=300

For other stable branches, replace the *'1810'* from the above content with the
desired release. Examples: 1606, 1609, 1701, 1704, 1707, 1710, 1804, 1807

Update your local yum cache.

.. code-block:: console

   $ sudo yum clean all
   $ sudo yum -q makecache -y --disablerepo='*' --enablerepo='fdio_1810'

The *'yum install vpp'* command will install the most recent build on the
branch, not the latest offical release. Run the following command to get the
list of images produce by the branch:

.. code-block:: console

   $ sudo yum --showduplicates list vpp* | expand


VPP Master Branch
"""""""""""""""""""

To allow *yum* access to the nightly builds from the VPP master branch, create
the file *'/etc/yum.repos.d/fdio-release.repo'* with the following content.

.. code-block:: console

   $ cat /etc/yum.repos.d/fdio-release.repo
   [fdio_master]
   name=fdio_master
   baseurl=https://packagecloud.io/fdio/master/el/7/$basearch
   repo_gpgcheck=1
   gpgcheck=0
   enabled=1
   gpgkey=https://packagecloud.io/fdio/master/gpgkey
   sslverify=1
   sslcacert=/etc/pki/tls/certs/ca-bundle.crt
   metadata_expire=300

   [fdio_master-source]
   name=fdio_master-source
   baseurl=https://packagecloud.io/fdio/master/el/7/SRPMS
   repo_gpgcheck=1
   gpgcheck=0
   enabled=1
   gpgkey=https://packagecloud.io/fdio/master/gpgkey
   sslverify=1
   sslcacert=/etc/pki/tls/certs/ca-bundle.crt
   metadata_expire=300

Update your local yum cache.

.. code-block:: console

   $ sudo yum clean all
   $ sudo yum -q makecache -y --disablerepo='*' --enablerepo='fdio_master'

The *'yum install vpp'* command will install the most recent build on the
branch. Run the following command to get the list of images produce by the
branch.

.. code-block:: console

   $ sudo yum clean all
   $ sudo yum --showduplicates list vpp* | expand

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

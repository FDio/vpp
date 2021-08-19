.. _config_getting_started:

=======================================
Getting started with the configuration
=======================================

After a successful installation, VPP installs a startup config file named
*startup.conf* in the */etc/vpp/* directory. This file can be tailored to
make VPP run as desired, but contains default values for typical installations.

Below are more details about this file and some of the the parameters and values
it contains.

Command-line Arguments
----------------------

Before we describe details of the startup configuration file (startup.conf) it
should be mentioned that VPP can be started without a startup configuration
file.

Parameters are grouped by a section name. When providing more than one
parameter to a section, all parameters for that section must be wrapped in
curly braces. For example, to start VPP with configuration data via the
command line with the section name *'unix'*:

.. code-block:: console

    $ sudo /usr/bin/vpp unix { interactive cli-listen 127.0.0.1:5002 }

The command line can be presented as a single string or as several; anything
given on the command line is concatenated with spaces into a single string
before parsing. VPP applications must be able to locate their own executable
images. The simplest way to ensure this will work is to invoke a VPP
application by giving its absolute path. For example:
*'/usr/bin/vpp <options>'*  At startup, VPP applications parse through their
own ELF-sections [primarily] to make lists of init, configuration, and exit
handlers.

When developing with VPP, in gdb it's often sufficient to start an application
like this:

.. code-block:: console

    (gdb) run unix interactive


Configuration File (startup.conf)
-----------------------------------------

The more typical way to specify the startup configuration to VPP is with the
startup configuration file (startup.conf).

The path of the file is provided to the VPP application on the command line.
This is typically at /etc/vpp/startup.conf. If VPP is installed as a package
a default startup.conf file is provided at this location.

The format of the configuration file is a simple text file with the same content
as the command line.

**A very simple startup.conf file:**

.. code-block:: console

    $ cat /etc/vpp/startup.conf
    unix {
      nodaemon
      log /var/log/vpp/vpp.log
      full-coredump
      cli-listen localhost:5002
    }

    api-trace {
      on
    }

    dpdk {
      dev 0000:03:00.0
    }

VPP is instructed to load this file with the -c option. For example:

.. code-block:: console

    $ sudo /usr/bin/vpp -c /etc/vpp/startup.conf
.. _configutil:

#########################
VPP Configuration Utility
#########################

This guide provides instructions on how to install and use the vpp configuration
utility.

The FD.io VPP Configuration Utility, or vpp-config, allows the user to configure
FD.io VPP in a simple and safe manner. The utility takes input from the user and
creates the configuration files in a dry run directory. The user should then examine
these files for correctness. If the configuration files look correct, the user
can then apply the configuration. Once the configuration is applied the user
should then check the system configuration with the utility and see if it was
applied correctly.

This utility also includes a utility that can be used to install or uninstall FD.io VPP
packages. This should be used to insure the latest tested release is installed.

.. toctree::

   installing
   usingvppconfig
   commandfour
   commandone
   commandtwo
   commandthree
   configapplied


.. _config-command-four:

**************************
List/Install/Uninstall VPP
**************************

With command option "4" the user can list, install, or uninstall the FD.io VPP
packages. If there are packages already installed, then the packages will be listed
and the user will be asked if the packages should be uninstalled. If no packages are
installed, then the user will be asked if the FD.io packages should be installed. The
packages installed will be the latest released packages.

Uninstalling the packages:

.. code-block:: console

    What would you like to do?
    
    1) Show basic system information
    2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
    3) Full configuration (WARNING: This will change the system configuration)
    4) List/Install/Uninstall VPP.
    q) Quit
    
    Command: 4
    
    These packages are installed on node localhost
    Name                      Version
    vpp                       18.04-release
    vpp-api-java              18.04-release
    vpp-api-lua               18.04-release
    vpp-api-python            18.04-release
    vpp-dbg                   18.04-release
    vpp-dev                   18.04-release
    vpp-dpdk-dev              17.01.1-release
    vpp-dpdk-dkms             17.01.1-release
    vpp-lib                   18.04-release
    vpp-nsh-plugin            18.04
    vpp-nsh-plugin-dbg        18.04
    vpp-nsh-plugin-dev        18.04
    vpp-plugins               18.04-release
    
    Do you want to uninstall these packages [y/N]? y
    INFO:root: Local Command: service vpp stop
    INFO:root:Uninstall Ubuntu
    INFO:root: Local Command: dpkg -l | grep vpp
    ....
    What would you like to do?
    
    1) Show basic system information
    2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
    3) Full configuration (WARNING: This will change the system configuration)
    4) List/Install/Uninstall VPP.
    q) Quit
    
    Command:

Installing the packages:

.. code-block:: console

    1) Show basic system information
    2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
    3) Full configuration (WARNING: This will change the system configuration)
    4) List/Install/Uninstall VPP.
    q) Quit
    
    Command: 4
    
    There are no VPP packages on node localhost.
    Do you want to install VPP [Y/n]? Y
    INFO:root:  Ubuntu
    INFO:root:Install Ubuntu
    INFO:root: Local Command: ls /etc/apt/sources.list.d/99fd.io.list.orig
    INFO:root:  /etc/apt/sources.list.d/99fd.io.list.orig
    ....

    What would you like to do?
    
    1) Show basic system information
    2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
    3) Full configuration (WARNING: This will change the system configuration)
    4) List/Install/Uninstall VPP.
    q) Quit
    
    Command: 4

    These packages are installed on node localhost
    Name                      Version
    vpp                       18.04-release
    vpp-api-java              18.04-release
    vpp-api-lua               18.04-release
    vpp-api-python            18.04-release
    vpp-dbg                   18.04-release
    vpp-dev                   18.04-release
    vpp-dpdk-dev              17.01.1-release
    vpp-dpdk-dkms             17.01.1-release
    vpp-lib                   18.04-release
    vpp-nsh-plugin            18.04
    vpp-nsh-plugin-dbg        18.04
    vpp-nsh-plugin-dev        18.04
    vpp-plugins               18.04-release
    
    Do you want to uninstall these packages [y/N]? N

    What would you like to do?
    
    1) Show basic system information
    2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
    3) Full configuration (WARNING: This will change the system configuration)
    4) List/Install/Uninstall VPP.
    q) Quit
    
    Command:

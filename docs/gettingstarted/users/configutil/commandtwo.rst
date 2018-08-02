.. _config-command-two:

*******
Dry Run
*******

With command option '2' (the config utility *dry run* option) the important
configuration files are created so that the user can examine them, and then
if they look reasonable apply them with command option 3. 

The files for **Ubuntu** can be found in the root directory */usr/local/vpp/vpp-config/dryrun*
and for **Centos** in directory */usr/vpp/vpp-config/dryrun*.

The important configuration files are **/etc/vpp/startup.conf**, **/etc/sysctl.d/80-vpp.conf**,
and **/etc/default/grub** 

Startup.conf
============

FD.io VPP startup parameters are configured in the file **/etc/vpp/startup.conf**.
The utility creates this file under the *vpp-config* root directory in the file *vpp/startup.conf*.
The values in this file come from the questions asked about the devices, cores, rx queues,
and tcp parameters.

80-vpp.conf
============

The huge page configuration comes by setting values in the file **/etc/sysctl.d/80-vpp.conf**.
The utility creates the file under the root directory in the file *sysctl.d/80-vpp.conf*. When asked the
question about huge pages the correct values are put in the dryrun file.

grub
====

CPUs can be isolated for use by VPP or other processes such as VMs using the grub
configuration file. This file is **/etc/default/grub**. This file must be modified with
care. It is possible to make your system unusable if this file is modified incorrectly.
The dry run file is located under the *vpp-config* root directory and then default.

***********************
Executing the Dry Run
***********************

The following is an example of how to execute a dry run. Defaults should be picked first,
and then the values increased accordingly.

.. code-block:: console

    1) Show basic system information
    2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
    3) Full configuration (WARNING: This will change the system configuration)
    4) List/Install/Uninstall VPP.
    q) Quit
    
    Command: 2
    
    These devices have kernel interfaces, but appear to be safe to use with VPP.
    
    PCI ID          Kernel Interface(s)       Description
    ------------------------------------------------------------------------------------------
    0000:8f:00.0    enp143s0                  VIC Ethernet NIC
    0000:84:00.0    enp132s0f0,enp132s0f0d1   Ethernet Controller XL710 for 40GbE QSFP+
    0000:84:00.1    enp132s0f1,enp132s0f1d1   Ethernet Controller XL710 for 40GbE QSFP+
    0000:08:00.1    enp8s0f1                  I350 Gigabit Network Connection
    0000:02:00.0    enp2s0f0                  82599ES 10-Gigabit SFI/SFP+ Network Connection
    0000:02:00.1    enp2s0f1                  82599ES 10-Gigabit SFI/SFP+ Network Connection
    0000:86:00.0    enp134s0f0                82599ES 10-Gigabit SFI/SFP+ Network Connection
    0000:86:00.1    enp134s0f1                82599ES 10-Gigabit SFI/SFP+ Network Connection
    
    Would you like to use any of these device(s) for VPP [y/N]? y
    Would you like to use device 0000:8f:00.0 for VPP [y/N]?
    Would you like to use device 0000:84:00.0 for VPP [y/N]?
    Would you like to use device 0000:84:00.1 for VPP [y/N]?
    Would you like to use device 0000:08:00.1 for VPP [y/N]?
    Would you like to use device 0000:02:00.0 for VPP [y/N]?
    Would you like to use device 0000:02:00.1 for VPP [y/N]?
    Would you like to use device 0000:86:00.0 for VPP [y/N]? y
    Would you like to use device 0000:86:00.1 for VPP [y/N]? y
    
    These device(s) will be used by VPP.
    
    PCI ID          Description
    ----------------------------------------------------------------
    0000:86:00.0    82599ES 10-Gigabit SFI/SFP+ Network Connection
    0000:86:00.1    82599ES 10-Gigabit SFI/SFP+ Network Connection
    0000:90:00.0    VIC Ethernet NIC
    
    Would you like to remove any of these device(s) [y/N]? y
    Would you like to remove 0000:86:00.0 [y/N]?
    Would you like to remove 0000:86:00.1 [y/N]?
    Would you like to remove 0000:90:00.0 [y/N]? y
    
    These device(s) will be used by VPP, please rerun this option if this is incorrect.
    
    PCI ID          Description
    ----------------------------------------------------------------
    0000:86:00.0    82599ES 10-Gigabit SFI/SFP+ Network Connection
    0000:86:00.1    82599ES 10-Gigabit SFI/SFP+ Network Connection
    
    Your system has 32 core(s) and 2 Numa Nodes.
    To begin, we suggest not reserving any cores for VPP or other processes.
    Then to improve performance start reserving cores and adding queues as needed.
    
    How many core(s) shall we reserve for VPP [0-4][0]? 2
    How many core(s) do you want to reserve for processes other than VPP? [0-15][0]?
    Should we reserve 1 core for the VPP Main thread? [y/N]? y
    How many RX queues per port shall we use for VPP [1-4][1]? 2
    
    How many active-open / tcp client sessions are expected [0-10000000][0]?
    How many passive-open / tcp server sessions are expected [0-10000000][0]?
    
    There currently 896 2048 kB huge pages free.
    Do you want to reconfigure the number of huge pages [y/N]? y
    
    There currently a total of 1024 huge pages.
    How many huge pages do you want [1024 - 15644][1024]? 8192
    
    What would you like to do?
    
    1) Show basic system information
    2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
    3) Full configuration (WARNING: This will change the system configuration)
    4) List/Install/Uninstall VPP.
    q) Quit
    
    Command:

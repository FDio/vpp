.. _config-applied:

*************************
The Configuration Applied
*************************

After the configuration is applied the system parameters should be examined.

.. code-block:: console

    What would you like to do?
    
    1) Show basic system information
    2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
    3) Full configuration (WARNING: This will change the system configuration)
    4) List/Install/Uninstall VPP.
    q) Quit
    
    Command: 1
    
    ==============================
    NODE: DUT1
    
    CPU:
              Model name:    Intel(R) Xeon(R) CPU E5-2667 v3 @ 3.20GHz
                  CPU(s):    32
      Thread(s) per core:    2
      Core(s) per socket:    8
               Socket(s):    2
       NUMA node0 CPU(s):    0-7,16-23
       NUMA node1 CPU(s):    8-15,24-31
             CPU max MHz:    3600.0000
             CPU min MHz:    1200.0000
                     SMT:    Enabled
    
    VPP Threads: (Name: Cpu Number)
      vpp_main  : 8
      vpp_wk_1  : 10
      vpp_wk_0  : 9
      vpp_stats : 0
    
    Grub Command Line:
      Current: BOOT_IMAGE=/vmlinuz-4.4.0-128-generic root=UUID=9930aeee-b1d3-4cf5-b0de-d95dbb7dec5e ro
      Configured: GRUB_CMDLINE_LINUX_DEFAULT="isolcpus=1,8,9-10 nohz_full=1,8,9-10 rcu_nocbs=1,8,9-10"
    
    Huge Pages:
      Total System Memory           : 65863384 kB
      Total Free Memory             : 31169292 kB
      Actual Huge Page Total        : 8196
      Configured Huge Page Total    : 8196
      Huge Pages Free               : 7942
      Huge Page Size                : 2048 kB
    
    Devices:
    Total Number of Buffers: 25600
    
    Devices with link up (can not be used with VPP):
    0000:08:00.0    enp8s0f0                  I350 Gigabit Network Connection
    
    Devices bound to kernel drivers:
    0000:90:00.0    enp144s0                  VIC Ethernet NIC
    0000:8f:00.0    enp143s0                  VIC Ethernet NIC
    0000:84:00.0    enp132s0f0,enp132s0f0d1   Ethernet Controller XL710 for 40GbE QSFP+
    0000:84:00.1    enp132s0f1,enp132s0f1d1   Ethernet Controller XL710 for 40GbE QSFP+
    0000:08:00.1    enp8s0f1                  I350 Gigabit Network Connection
    0000:02:00.0    enp2s0f0                  82599ES 10-Gigabit SFI/SFP+ Network Connection
    0000:02:00.1    enp2s0f1                  82599ES 10-Gigabit SFI/SFP+ Network Connection
    
    Devices bound to DPDK drivers:
    0000:86:00.0                              82599ES 10-Gigabit SFI/SFP+ Network Connection
    0000:86:00.1                              82599ES 10-Gigabit SFI/SFP+ Network Connection
    
    Devices in use by VPP:
    Name                           Socket RXQs RXDescs TXQs TXDescs
    TenGigabitEthernet86/0/0            1    2    1024    3    1024
    TenGigabitEthernet86/0/1            1    2    1024    3    1024
    
    VPP Service Status:
      active (running)

.. toctree::

   sysinfo



Summary:

The purpose of the VPP configuration utility is to allow the user to configure
VPP in a simple and safe manner. The utility takes input from the user and
then modifies the key configuration files. The user can then examine these files
to be sure they are correct and then actually apply the configuration. The user
can also install a released and stable version of VPP. This is currently
released with release 17.10.

Use:

The installation and executing of the VPP configuration utility is simple. First
install the python pip module. Using pip install, then pip install vpp-config.
Then simply type �vpp-config� and answer the questions. If you are not sure what
to answer choose the default. For yes or no questions the capital letter
designates the default. For example, for a question that shows [Y/n] Y is the
default. For numbers the default is within the brackets for example for a
question that shows [1024]. 1024 is the default. 

The flow of the utility is to inspect the system, if VPP is not install it,
create dry run configurations, inspect the files created during the dry run,
apply the configuration and then inspect the system again and then repeat.  

Caveats:

- Supports Ubuntu, centos7, RedHat is coming shortly.

For Developers:

Modifying the code is reasonable simple. The process would be edit and debug the
code from the root directory. In order to do this, we need a script that will copy
or data files to the proper place. This is where they end up with pip install. For
Ubuntu, this is /usr/local/vpp/vpp-config. I have provided a script that will copy
the relevant files correctly. I have also provided a script that will clean the
environment so you can start from scratch. These are the steps to run the utility
in this environment. The scripts are meant to be run from the root directory.

  ./scripts/clean.sh
  ./scripts/cp-data.sh
  ./vpp-config

When the utility is installed with pip the wrapper scripts/vpp-config is written to
/usr/local/bin. However, the starting point when debugging this script locally is
vpp-config. Run the utility by executing vpp-config.

The start point in the code is in vpp_config.py. However, most of the work is
done in
the files in ./vpplib

Uploading to PyPi:

To upload this utility to PpPi simple do the following. Currently, I have my own account
when we want everyone to contribute we will need to change that.

  sudo �H bash
  cd vpp_config
  python setup.py sdist bdist_wheel
  twine upload dist/*

Example Run:

# pip install vpp-config
# vpp-config

Welcome to the VPP system configuration utility

These are the files we will modify:
    /etc/vpp/startup.conf
    /etc/sysctl.d/80-vpp.conf
    /etc/default/grub

Before we change them, we'll create working copies in /usr/local/vpp/vpp-config/dryrun
Please inspect them carefully before applying the actual configuration (option 3)!

What would you like to do?

1) Show basic system information
2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
       and user input in /usr/local/vpp/vpp-config/configs/auto-config.yaml
3) Full configuration (WARNING: This will change the system configuration)
4) Install/Uninstall VPP.
5) Dry Run from /usr/local/vpp/vpp-config/auto-config.yaml (will not ask questions).
6) Install QEMU patch (Needed when running openstack).
9 or q) Quit

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

Grub Command Line:
  Current: BOOT_IMAGE=/boot/vmlinuz-4.4.0-96-generic root=UUID=d760b82f-f37b-47e2-9815-db8d479a3557 ro
  Configured: GRUB_CMDLINE_LINUX_DEFAULT=""

Huge Pages:
  Total System Memory           : 65863484 kB
  Total Free Memory             : 41325924 kB
  Actual Huge Page Total        : 8192
  Configured Huge Page Total    : 1024
  Huge Pages Free               : 8192
  Huge Page Size                : 2048 kB

Devices:

Status:
  Not Installed

==============================

What would you like to do?

1) Show basic system information
2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
       and user input in /usr/local/vpp/vpp-config/configs/auto-config.yaml
3) Full configuration (WARNING: This will change the system configuration)
4) Install/Uninstall VPP.
5) Dry Run from /usr/local/vpp/vpp-config/auto-config.yaml (will not ask questions).
6) Install QEMU patch (Needed when running openstack).
9 or q) Quit

Command: 4

There are no VPP packages on node localhost.
Do you want to install VPP [Y/n]? 
INFO:root: Local Command: ls /etc/apt/sources.list.d/99fd.io.list.orig
INFO:root:  /etc/apt/sources.list.d/99fd.io.list.orig
��..

What would you like to do?

1) Show basic system information
2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
       and user input in /usr/local/vpp/vpp-config/configs/auto-config.yaml
3) Full configuration (WARNING: This will change the system configuration)
4) Install/Uninstall VPP.
5) Dry Run from /usr/local/vpp/vpp-config/auto-config.yaml (will not ask questions).
6) Install QEMU patch (Needed when running openstack).
9 or q) Quit

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
  vpp_main  : 0   
  vpp_stats : 0   

Grub Command Line:
  Current: BOOT_IMAGE=/boot/vmlinuz-4.4.0-96-generic root=UUID=d760b82f-f37b-47e2-9815-db8d479a3557 ro
  Configured: GRUB_CMDLINE_LINUX_DEFAULT=""

Huge Pages:
  Total System Memory           : 65863484 kB
  Total Free Memory             : 55877364 kB
  Actual Huge Page Total        : 1024
  Configured Huge Page Total    : 1024
  Huge Pages Free               : 1024
  Huge Page Size                : 2048 kB

Devices:
Name                           Socket RXQs RXDescs TXQs TXDescs

Status:
  active (running)

==============================

What would you like to do?

1) Show basic system information
2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
       and user input in /usr/local/vpp/vpp-config/configs/auto-config.yaml
3) Full configuration (WARNING: This will change the system configuration)
4) Install/Uninstall VPP.
5) Dry Run from /usr/local/vpp/vpp-config/auto-config.yaml (will not ask questions).
6) Install QEMU patch (Needed when running openstack).
9 or q) Quit

Command: 2

These device(s) are currently NOT being used by VPP or the OS.

PCI ID          Description                                       
----------------------------------------------------------------
0000:02:00.0    82599ES 10-Gigabit SFI/SFP+ Network Connection    
0000:02:00.1    82599ES 10-Gigabit SFI/SFP+ Network Connection    

Would you like to give any of these devices back to the OS [y/N]? y
Would you like to use device 0000:02:00.0 for the OS [y/N]? y
Would you like to use device 0000:02:00.1 for the OS [y/N]? y

These devices have kernel interfaces, but appear to be safe to use with VPP.

PCI ID          Kernel Interface(s)       Description                                       
------------------------------------------------------------------------------------------
0000:90:00.0    enp144s0                  VIC Ethernet NIC                                  
0000:8f:00.0    enp143s0                  VIC Ethernet NIC                                  
0000:84:00.0    enp132s0f0,enp132s0f0d1   Ethernet Controller XL710 for 40GbE QSFP+         
0000:84:00.1    enp132s0f1,enp132s0f1d1   Ethernet Controller XL710 for 40GbE QSFP+         
0000:08:00.1    enp8s0f1                  I350 Gigabit Network Connection                   
0000:02:00.0    enp2s0f0                  82599ES 10-Gigabit SFI/SFP+ Network Connection    
0000:02:00.1    enp2s0f1                  82599ES 10-Gigabit SFI/SFP+ Network Connection    
0000:86:00.0    enp134s0f0                82599ES 10-Gigabit SFI/SFP+ Network Connection    
0000:86:00.1    enp134s0f1                82599ES 10-Gigabit SFI/SFP+ Network Connection    

Would you like to use any of these device(s) for VPP [y/N]? y
Would you like to use device 0000:90:00.0 for VPP [y/N]? 
Would you like to use device 0000:8f:00.0 for VPP [y/N]? 
Would you like to use device 0000:84:00.0 for VPP [y/N]? 
Would you like to use device 0000:84:00.1 for VPP [y/N]? 
Would you like to use device 0000:08:00.1 for VPP [y/N]? 
Would you like to use device 0000:02:00.0 for VPP [y/N]? y
Would you like to use device 0000:02:00.1 for VPP [y/N]? y
Would you like to use device 0000:86:00.0 for VPP [y/N]? y
Would you like to use device 0000:86:00.1 for VPP [y/N]? y

These device(s) will be used by VPP.

PCI ID          Description                                       
----------------------------------------------------------------
0000:86:00.0    82599ES 10-Gigabit SFI/SFP+ Network Connection    
0000:86:00.1    82599ES 10-Gigabit SFI/SFP+ Network Connection    
0000:02:00.0    82599ES 10-Gigabit SFI/SFP+ Network Connection    
0000:02:00.1    82599ES 10-Gigabit SFI/SFP+ Network Connection    

Would you like to remove any of these device(s) [y/N]? 

These device(s) will be used by VPP, please rerun this option if this is incorrect.

PCI ID          Description                                       
----------------------------------------------------------------
0000:86:00.0    82599ES 10-Gigabit SFI/SFP+ Network Connection    
0000:86:00.1    82599ES 10-Gigabit SFI/SFP+ Network Connection    
0000:02:00.0    82599ES 10-Gigabit SFI/SFP+ Network Connection    
0000:02:00.1    82599ES 10-Gigabit SFI/SFP+ Network Connection    

Your system has 32 core(s) and 2 Numa Nodes.
To begin, we suggest not reserving any cores for VPP or other processes.
Then to improve performance try reserving cores as needed. 

How many core(s) do you want to reserve for processes other than VPP? [0-16][0]? 4
How many core(s) shall we reserve for VPP workers[0-4][0]? 2
Should we reserve 1 core for the VPP Main thread? [Y/n]? 

There currently 1024 2048 kB huge pages free.
Do you want to reconfigure the number of huge pages [y/N]? y

There currently a total of 1024 huge pages.
How many huge pages do you want [1024 - 22511][1024]? 8192

What would you like to do?

1) Show basic system information
2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
       and user input in /usr/local/vpp/vpp-config/configs/auto-config.yaml
3) Full configuration (WARNING: This will change the system configuration)
4) Install/Uninstall VPP.
5) Dry Run from /usr/local/vpp/vpp-config/auto-config.yaml (will not ask questions).
6) Install QEMU patch (Needed when running openstack).
9 or q) Quit

Command: 3

We are now going to configure your system(s).

Are you sure you want to do this [Y/n]? 
These are the changes we will apply to
the huge page file (/etc/sysctl.d/80-vpp.conf).

1,2d0
< # Number of 2MB hugepages desired
< vm.nr_hugepages=1024
4,7c2,3
< # Must be greater than or equal to (2 * vm.nr_hugepages).
< vm.max_map_count=3096
< 
< # All groups allowed to access hugepages
---
> vm.nr_hugepages=8192
> vm.max_map_count=17408
8a5
> kernel.shmmax=17179869184
10,15d6
< # Shared Memory Max must be greator or equal to the total size of hugepages.
< # For 2MB pages, TotalHugepageSize = vm.nr_hugepages * 2 * 1024 * 1024
< # If the existing kernel.shmmax setting  (cat /sys/proc/kernel/shmmax)
< # is greater than the calculated TotalHugepageSize then set this parameter
< # to current shmmax value.
< kernel.shmmax=2147483648


Are you sure you want to apply these changes [Y/n]? 
These are the changes we will apply to
the VPP startup file (/etc/vpp/startup.conf).

3c3
<   nodaemon
---
>   interactive
5a6
>   cli-listen /run/vpp/cli.sock
17c18,25
< 	## In the VPP there is one main thread and optionally the user can create worker(s)
---
> 
>   main-core 8
>   corelist-workers 9-10,5-6
> 
>   scheduler-policy fifo
>   scheduler-priority 50
> 
>         ## In the VPP there is one main thread and optionally the user can create worker(s)
52,53c60,76
< # dpdk {
< 	## Change default settings for all intefaces
---
> dpdk {
> 
>   dev 0000:86:00.0 { 
>     num-rx-queues 2
>   }
>   dev 0000:86:00.1 { 
>     num-rx-queues 2
>   }
>   dev 0000:02:00.0 { 
>     num-rx-queues 2
>   }
>   dev 0000:02:00.1 { 
>     num-rx-queues 2
>   }
>   num-mbufs 71680
> 
>         ## Change default settings for all intefaces
82a106,115
> 	## Specify bonded interface and its slaves via PCI addresses
> 	## 
>         ## Bonded interface in XOR load balance mode (mode 2) with L3 and L4 headers 
> 	# vdev eth_bond0,mode=2,slave=0000:02:00.0,slave=0000:03:00.0,xmit_policy=l34
> 	# vdev eth_bond1,mode=2,slave=0000:02:00.1,slave=0000:03:00.1,xmit_policy=l34
> 	##
> 	## Bonded interface in Active-Back up mode (mode 1)
> 	# vdev eth_bond0,mode=1,slave=0000:02:00.0,slave=0000:03:00.0
> 	# vdev eth_bond1,mode=1,slave=0000:02:00.1,slave=0000:03:00.1
> 
99c132
< # }
---
> }
108a142
> 


Are you sure you want to apply these changes [Y/n]? 

The configured grub cmdline looks like this:
GRUB_CMDLINE_LINUX_DEFAULT="intel_pstate=disable isolcpus=1-4,8,9-10,5-6 nohz_full=1-4,8,9-10,5-6 rcu_nocbs=1-4,8,9-10,5-6"

The current boot cmdline looks like this:
BOOT_IMAGE=/boot/vmlinuz-4.4.0-96-generic root=UUID=d760b82f-f37b-47e2-9815-db8d479a3557 ro

Do you want to keep the current boot cmdline [Y/n]? 

What would you like to do?

1) Show basic system information
2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
       and user input in /usr/local/vpp/vpp-config/configs/auto-config.yaml
3) Full configuration (WARNING: This will change the system configuration)
4) Install/Uninstall VPP.
5) Dry Run from /usr/local/vpp/vpp-config/auto-config.yaml (will not ask questions).
6) Install QEMU patch (Needed when running openstack).
9 or q) Quit

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

Grub Command Line:
  Current: BOOT_IMAGE=/boot/vmlinuz-4.4.0-96-generic root=UUID=d760b82f-f37b-47e2-9815-db8d479a3557 ro
  Configured: GRUB_CMDLINE_LINUX_DEFAULT="intel_pstate=disable isolcpus=1-4,8,9-10,5-6 nohz_full=1-4,8,9-10,5-6 rcu_nocbs=1-4,8,9-10,5-6"

Huge Pages:
  Total System Memory           : 65863484 kB
  Total Free Memory             : 41163916 kB
  Actual Huge Page Total        : 8192
  Configured Huge Page Total    : 8192
  Huge Pages Free               : 3108
  Huge Page Size                : 2048 kB

Devices:
Total Number of Buffers: 71680

Status:
  active (running)
  Sep 27 12:49:59 tf-ucs-3 vpp[13671]: EAL: No free hugepages reported in hugepages-1048576kB

==============================

What would you like to do?

1) Show basic system information
2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
       and user input in /usr/local/vpp/vpp-config/configs/auto-config.yaml
3) Full configuration (WARNING: This will change the system configuration)
4) Install/Uninstall VPP.
5) Dry Run from /usr/local/vpp/vpp-config/auto-config.yaml (will not ask questions).
6) Install QEMU patch (Needed when running openstack).
9 or q) Quit

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
  vpp_stats : 0   
  vpp_wk_2  : 9   
  vpp_wk_3  : 10  
  vpp_wk_0  : 5   
  vpp_wk_1  : 6   
  vpp_main  : 8   

Grub Command Line:
  Current: BOOT_IMAGE=/boot/vmlinuz-4.4.0-96-generic root=UUID=d760b82f-f37b-47e2-9815-db8d479a3557 ro
  Configured: GRUB_CMDLINE_LINUX_DEFAULT="intel_pstate=disable isolcpus=1-4,8,9-10,5-6 nohz_full=1-4,8,9-10,5-6 rcu_nocbs=1-4,8,9-10,5-6"

Huge Pages:
  Total System Memory           : 65863484 kB
  Total Free Memory             : 41170684 kB
  Actual Huge Page Total        : 8192
  Configured Huge Page Total    : 8192
  Huge Pages Free               : 7936
  Huge Page Size                : 2048 kB

Devices:
Total Number of Buffers: 71680
Name                           Socket RXQs RXDescs TXQs TXDescs
TenGigabitEthernet2/0/0             0    2    1024    5    1024
TenGigabitEthernet2/0/1             0    2    1024    5    1024
TenGigabitEthernet86/0/0            1    2    1024    5    1024
TenGigabitEthernet86/0/1            1    2    1024    5    1024

Status:
  active (running)

==============================

What would you like to do?

1) Show basic system information
2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
       and user input in /usr/local/vpp/vpp-config/configs/auto-config.yaml
3) Full configuration (WARNING: This will change the system configuration)
4) Install/Uninstall VPP.
5) Dry Run from /usr/local/vpp/vpp-config/auto-config.yaml (will not ask questions).
6) Install QEMU patch (Needed when running openstack).
9 or q) Quit

Command: q
# 

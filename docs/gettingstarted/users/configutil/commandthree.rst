.. _config-command-three:

************************
Apply the Configuration
************************

After the configuration files have been examined and verified as correct, then the
configuration can be applied by using command option '3'. After the configuration
is applied, use option "1" to check the system configuration. Notice the default is
NOT to change the grub file. If the option to change the grub command line is selected,
then a reboot of the system will be required.

.. code-block:: console

   What would you like to do?

   1) Show basic system information
   2) Dry Run (Will save the configuration files in /usr/local/vpp/vpp-config/dryrun for inspection)
   3) Full configuration (WARNING: This will change the system configuration)
   4) List/Install/Uninstall VPP.
   q) Quit

   Command: 3

   We are now going to configure your system(s).

   Are you sure you want to do this [Y/n]? y
   These are the changes we will apply to
   the huge page file (/etc/sysctl.d/80-vpp.conf).

   1,2d0
   < vm.nr_hugepages=1024
   4,7c2,3
   < vm.max_map_count=3096
   ---
   > vm.nr_hugepages=8192
   > vm.max_map_count=17408
   8a5
   > kernel.shmmax=17179869184
   10,15d6
   < kernel.shmmax=2147483648

   Are you sure you want to apply these changes [Y/n]? 
   These are the changes we will apply to
   the VPP startup file (/etc/vpp/startup.conf).

   ---
   > 
   >   main-core 8
   >   corelist-workers 9-10
   > 
   >   scheduler-policy fifo
   >   scheduler-priority 50
   > 
   67,68c56,66
   < # dpdk {
   ---
   > dpdk {
   > 
   >   dev 0000:86:00.0 { 
   >     num-rx-queues 2
   >   }
   >   dev 0000:86:00.1 { 
   >     num-rx-queues 2
   >   }
   >   num-mbufs 25600
   > 
   124c122
   < # }
   ---
   > }

   Are you sure you want to apply these changes [Y/n]? 

   The configured grub cmdline looks like this:
   GRUB_CMDLINE_LINUX_DEFAULT="isolcpus=8,9-10 nohz_full=8,9-10 rcu_nocbs=8,9-10"

   The current boot cmdline looks like this:
   BOOT_IMAGE=/boot/vmlinuz-4.4.0-97-generic root=UUID=d760b82f-f37b-47e2-9815-db8d479a3557 ro

   Do you want to keep the current boot cmdline [Y/n]? 

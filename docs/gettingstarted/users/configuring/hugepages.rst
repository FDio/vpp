.. _hugepages:

Huge Pages
----------

VPP requires *hugepages* to run during VPP operation, to manage large pages of memory.
During VPP installation, VPP will overwrite the existing hugepage settings.
By default, VPP sets the number of hugepages on a system to 1024 2M hugepages.
This is the number of hugepages on the system, not just used by VPP. 

When VPP is installed, the following configuration file is copied to the system. The
hugepage settings are applied in the VPP installation and on system reboots. To set
the hugepage settings, perform the following commands:

.. code-block:: console

    $ cat /etc/sysctl.d/80-vpp.conf
    # Number of 2MB hugepages desired
    vm.nr_hugepages=1024
    
    # Must be greater than or equal to (2 * vm.nr_hugepages).
    vm.max_map_count=3096
    
    # All groups allowed to access hugepages
    vm.hugetlb_shm_group=0
    
    # Shared Memory Max must be greator or equal to the total size of hugepages.
    # For 2MB pages, TotalHugepageSize = vm.nr_hugepages * 2 * 1024 * 1024
    # If the existing kernel.shmmax setting  (cat /sys/proc/kernel/shmmax)
    # is greater than the calculated TotalHugepageSize then set this parameter
    # to current shmmax value.
    kernel.shmmax=2147483648

Depending on how the system is being used, this configuration file can be updated to adjust
the number of hugepages reserved on a system. Below are some examples of
possible settings.
 
For a small VM with minimal workload:

.. code-block:: console

    vm.nr_hugepages=512
    vm.max_map_count=2048
    kernel.shmmax=1073741824

For a large system running multiple VMs, each needing its own set of hugepages:

.. code-block:: console

    vm.nr_hugepages=32768
    vm.max_map_count=66560
    kernel.shmmax=68719476736


.. note::

    If VPP is being run in a Virtual Machine (VM), the VM must have hugepage
    backing. When VPP is installed, it will attempt to overwrite existing the
    hugepage setting. If the VM does not have hugepage backing, the install will fail,
    but the failure may go unnoticed. When the VM is rebooted, on system startup,
    *'vm.nr_hugepages'* will be reapplied, and will fail, and the VM will abort kernel
    boot, locking up the VM. To avoid this scenario, ensure the VM has enough
    hugepage backing.

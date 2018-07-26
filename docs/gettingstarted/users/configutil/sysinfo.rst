.. _sysinfo:

CPU
---

The CPU section of the system information is a summary of the CPU characteristics of the system.
It is important to understand the CPU topology and frequency in order to understand what the VPP
performance characteristics would be. 

Threads
-------

It usually is not needed, but VPP can be configured to run on isolated CPUs. In the example shown
VPP is configured with 2 workers. The main thread is also configured to run on a seperate CPU. The
stats thread will always run on CPU 0. This utilty will put the worker threads on CPUs that are
associated with the ports that are configured.

Grub Command Line
-----------------

In general the Grub command line does not need to be changed. If the system is running many processes
it may be neccessary to isolate CPUs for VPP or other processes.

Huge Pages
----------

As default when VPP is configured the number of huge pages that will be configured will be 1024.
This may not be enough. This section will show the total system memory and how many are configured.


Devices
-------

In the devices section we have the "Total Number of Buffers". This utility allocates the correct
number of buffers. The number of buffers are calculated from the number of rx queues.

VPP will not use links that are up. Those devices are shown with this utility.

The devices bound to the kernel are not being used by VPP, but can be.

The devices that are being used by VPP are shown with the interface name be used with VPP. The
socket being used by the VPP port is also shown. Notice in this example the worker thread are
on the correct CPU. The number of RX, TX Descriptors and TX queues are calculated from the number
of RX queues.


VPP Service Status
------------------

The VPP service status, will be installed, not installed, running or not.

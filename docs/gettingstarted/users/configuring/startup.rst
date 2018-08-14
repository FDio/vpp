.. _startup:


.. toctree::


=======================================
VPP Configuration File - 'startup.conf'
=======================================


After a successful installation, VPP installs a startup config file named
*startup.conf* in the */etc/vpp/* directory. This file can be tailored to
make VPP run as desired, but contains default values for typical installations.

Below are more details about this file and the parameters and values it contains.

Introduction
------------

The VPP network stack comes with several configuration options that can be
provided either on the command line when VPP is started, or in a configuration
file. Specific applications built on the stack have been known to require a dozen
arguments, depending on requirements.

Command-line Arguments
----------------------

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

Configuration File
------------------

It is also possible to supply the configuration parameters in a startup
configuration. The path of the file is provided to the VPP application on its
command line. The format of the configuration file is a simple text file with
the same content as the command line, but with the benefit of being able to use
newlines to make the content easier to read. For example:

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

VPP is then instructed to load this file with the -c option. For example:

.. code-block:: console

    $ sudo /usr/bin/vpp -c /etc/vpp/startup.conf

When the VPP service is started, VPP is started with this option via another
installed file, vpp.service (Ubuntu: /lib/systemd/system/vpp.service and
CentOS: /usr/lib/systemd/system/vpp.service). See *'ExecStart'* below:

.. code-block:: console

    $ cat /lib/systemd/system/vpp.service
    [Unit]
    Description=vector packet processing engine
    After=network.target
    
    [Service]
    Type=simple
    ExecStartPre=-/bin/rm -f /dev/shm/db /dev/shm/global_vm /dev/shm/vpe-api
    ExecStartPre=-/sbin/modprobe uio_pci_generic
    ExecStart=/usr/bin/vpp -c /etc/vpp/startup.conf
    ExecStopPost=/bin/rm -f /dev/shm/db /dev/shm/global_vm /dev/shm/vpe-api
    Restart=always
    
    [Install]
    WantedBy=multi-user.target


Configuration Parameters
------------------------

Below is the list of section names and their associated parameters. This is not
an exhaustive list of parameters available. The command-line argument parsers
can be found in the source code by searching for instances of the
**VLIB_CONFIG_FUNCTION** and **VLIB_EARLY_CONFIG_FUNCTION** macro.

For example, the invocation *'VLIB_CONFIG_FUNCTION (foo_config, "foo")'* will
cause the function *'foo_config'* to receive all parameters given in a
parameter block named "foo": "foo { arg1 arg2 arg3 ... }". 


List of Basic Parameters:
-------------------------

| unix_ 
| dpdk_ 
| cpu_  

List of Advanced Parameters:
----------------------------

| acl-plugin_ 
| api-queue_
| api-segment_
| api-trace_
| buffers_
| cj_
| dns_
| heapsize_
| ip_
| ip6_
| l2learn_
| l2tp_
| logging_
| mactime_
| map_
| mc_
| nat_
| oam_
| plugins_
| plugin_path_
| punt_
| session_
| socketsvr_
| stats_
| statseg_
| tapcli_
| tcp_
| tls_
| tuntap_
| vhost-user_
| vlib_

.. _unix:

"unix" Parameters
_________________

Configure VPP startup and behavior type attributes, as well and any OS based
attributes.

 * **interactive**
     Attach CLI to stdin/out and provide a debugging command line interface.
     Implies nodaemon.
     
     **Example:** interactive
     
 * **nodaemon**
     Do not fork / background the vpp process. Typical when invoking VPP
     applications from a process monitor. Set by default in the default
     *'startup.conf'* file.
     
     **Example:** nodaemon
     
 * **log <filename>**
     Logs the startup configuration and all subsequent CLI commands in filename.
     Very useful in situations where folks don't remember or can't be bothered
     to include CLI commands in bug reports. The default *'startup.conf'* file
     is to write to *'/var/log/vpp/vpp.log'*.
     
     In VPP 18.04, the default log file location was moved from '/tmp/vpp.log'
     to '/var/log/vpp/vpp.log' . The VPP code is indifferent to the file location.
     However, if SELinux is enabled, then the new location is required for the file
     to be properly labeled. Check your local *'startup.conf'* file for the log file
     location on your system.
     
     **Example:** log /var/log/vpp/vpp-debug.log
     
 * **exec|startup-config <filename>**
     Read startup operational configuration from filename. The contents of the file
     will be performed as though entered at the CLI. The two keywords are aliases
     for the same function; if both are specified, only the last will have an effect.
     The file contains CLI commands, for example:

     | $ cat /usr/share/vpp/scripts/interface-up.txt
     | set interface state TenGigabitEthernet1/0/0 up
     | set interface state TenGigabitEthernet1/0/1 up
     
     **Example:** startup-config /usr/share/vpp/scripts/interface-up.txt
     
 * **gid number|name>**
     Sets the effective group ID to the input group ID or group name of the calling
     process.
     
     **Example:** gid vpp
     
 * **full-coredump**
     Ask the Linux kernel to dump all memory-mapped address regions, instead of
     just text+data+bss.
     
     **Example:** full-coredump
     
 * **coredump-size unlimited|<n>G|<n>M|<n>K|<n>**
     Set the maximum size of the coredump file. The input value can be set in
     GB, MB, KB or bytes, or set to *'unlimited'*.
     
     **Example:** coredump-size unlimited
     
 * **cli-listen <ipaddress:port>|<socket-path>**
     Bind the CLI to listen at address localhost on TCP port 5002. This will
     accept an ipaddress:port pair or a filesystem path; in the latter case a
     local Unix socket is opened instead. The default *'startup.conf'* file
     is to open the socket *'/run/vpp/cli.sock'*.
     
     **Example:** cli-listen localhost:5002
     **Example:** cli-listen /run/vpp/cli.sock
     
 * **cli-line-mode**
     Disable character-by-character I/O on stdin. Useful when combined with,
     for example, emacs M-x gud-gdb.
     
     **Example:** cli-line-mode
     
 * **cli-prompt <string>**
     Configure the CLI prompt to be string.
     
     **Example:** cli-prompt vpp-2
     
 * **cli-history-limit <n>**
     Limit commmand history to <n> lines. A value of 0 disables command history.
     Default value: 50
     
     **Example:** cli-history-limit 100
     
 * **cli-no-banner**
     Disable the login banner on stdin and Telnet connections.
     
     **Example:** cli-no-banner
     
 * **cli-no-pager**
     Disable the output pager.
     
     **Example:** cli-no-pager
     
 * **cli-pager-buffer-limit <n>**
     Limit pager buffer to <n> lines of output. A value of 0 disables the
     pager. Default value: 100000
     
     **Example:** cli-pager-buffer-limit 5000
     
 * **runtime-dir <dir>**
     Set the runtime directory, which is the default location for certain
     files, like socket files. Default is based on User ID used to start VPP.
     Typically it is *'root'*, which defaults to *'/run/vpp/'*. Otherwise,
     defaults to *'/run/user/<uid>/vpp/'*.
     
     **Example:** runtime-dir /tmp/vpp
     
 * **poll-sleep-usec <n>**
     Add a fixed-sleep between main loop poll. Default is 0, which is not to
     sleep.
     
     **Example:** poll-sleep-usec 100
     
 * **pidfile <filename>**
     Writes the pid of the main thread in the given filename.
     
     **Example:** pidfile /run/vpp/vpp1.pid

.. _dpdk:

"dpdk" Parameters
_________________

Command line DPDK configuration controls a number of parameters, including
device whitelisting, the number of CPUs available for launching
dpdk-eal-controlled threads, the number of I/O buffers, and the process
affinity mask. In addition, the DPDK configuration function attempts to support
all of the DPDK EAL configuration parameters.

All of the DPDK EAL options should be available.
See ../src/plugins/dpdk/device/dpdk_priv.h, look at the set of
"foreach_eal_XXX" macros.

Popular options include:
 * **dev <pci-dev>**
     White-list [as in, attempt to drive] a specific PCI device. PCI-dev is a
     string of the form "DDDD:BB:SS.F" where:
     
        | DDDD = Domain
        | BB = Bus Number
        | SS = Slot number
        | F = Function
     
     This is the same format used in the linux sysfs tree (i.e.
     /sys/bus/pci/devices) for PCI device directory names.
     
     **Example:** dev 0000:02:00.0
     
 * **dev <pci-dev> { .. }**
     When whitelisting specific interfaces by specifying PCI address,
     additional custom parameters can also be specified. Valid options include:

      * **num-rx-queues <n>**
          Number of receive queues. Also enables RSS. Default value is 1.
      * **num-tx-queues <n>**
          Number of transmit queues. Default is equal to number of worker
          threads or 1 if no workers treads.
      * **num-rx-desc <n>**
          Number of descriptors in receive ring. Increasing or reducing number
          can impact performance. Default is 1024.
      * **num-rt-desc <n>**
          Number of descriptors in transmit ring. Increasing or reducing number
          can impact performance. Default is 1024.
      * **workers**
          TBD
      * **vlan-strip-offload on|off**:
          VLAN strip offload mode for interface. VLAN stripping is off by default
          for all NICs except VICs, using ENIC driver, which has VLAN stripping on
          by default.
      * **hqos**
          Enable the Hierarchical Quaity-of-Service (HQoS) scheduler, default is
          disabled. This enables HQoS on specific output interface.
      * **hqos { .. }**
          HQoS can also have its own set of custom parameters. Setting a custom
          parameter also enables HQoS.

          * **hqos-thread <n>**
              HQoS thread used by this interface. To setup a pool of threads that
              are shared by all HQoS interfaces, set via the*'cpu'* section using
              either *'corelist-hqos-threads'* or *'coremask-hqos-threads'*.

      * **rss**
          TBD
     
     **Example:**
     
                 | dev 0000:02:00.1 {
                 |    num-rx-queues 2 
                 |    num-tx-queues 2
                 | }

 * **vdev <eal-command>**
     Provide a DPDK EAL command to specify bonded Ethernet interfaces, operating
     modes and PCI addresses of slave links. Only XOR balanced (mode 2) mode is
     supported.
     
     **Example:**

                 | vdev eth_bond0,mode=2,slave=0000:0f:00.0,slave=0000:11:00.0,xmit_policy=l34
                 | vdev eth_bond1,mode=2,slave=0000:10:00.0,slave=0000:12:00.0,xmit_policy=l34

 * **num-mbufs <n>**
     Increase number of buffers allocated. May be needed in scenarios with
     large number of interfaces and worker threads, or a lot of physical
     interfaces with multiple RSS queues. Value is per CPU socket. Default is
     16384.
     
     **Example:** num-mbufs 128000

 * **no-pci**
     When VPP is started, if an interface is not owned by the linux kernel
     (interface is administratively down), VPP will attempt to manage the
     interface. *'no-pci'* indicates that VPP should not walk the PCI table
     looking for interfaces.
     
     **Example:** no-pci

 * **no-hugetlb**
     Don't use huge TLB pages. Potentially useful for running simulator images.
     
     **Example:** no-hugetlb

 * **kni <n>**
     Number of KNI interfaces. Refer to the DPDK documentation.
     
     **Example:** kni 2

 * **uio-driver uio_pci_generic|igb_uio|vfio-pci|auto**
     Change UIO driver used by VPP. Default is *'auto'*.
     
     **Example:** uio-driver igb_uio

 * **socket-mem <n>**
     Change hugepages allocation per-socket, needed only if there is need for
     larger number of mbufs. Default is 64 hugepages on each detected CPU
     socket.
     
     **Example:** socket-mem 2048,2048

**Other options include:**

 * **enable-tcp-udp-checksum**
     Enables UDP/TCP RX checksum offload.
     
     **Example:** enable-tcp-udp-checksum

 * **no-multi-seg**
     Disable mutli-segment buffers, improves performance but disables Jumbo MTU
     support.
     
     **Example:** no-multi-seg

 * **no-tx-checksum-offload**
     Disables UDP/TCP TX checksum offload. Typically needed for use faster
     vector PMDs (together with no-multi-seg).
     
     **Example:** no-tx-checksum-offload

 * **decimal-interface-names**
     Format DPDK device names with decimal, as opposed to hexadecimal. 
     
     **Example:** decimal-interface-names

 * **log-level  emergency|alert|critical|error|warning|notice|info|debug**
     Set the log level for DPDK logs. Default is *'notice'*.
     
     **Example:** log-level error

 * **dev default { .. }**
     Change default settings for all intefaces. This sections supports the
     same set of custom parameters described in *'dev <pci-dev> { .. }*'.
     
     **Example:**

                 | dev default {
                 |    num-rx-queues 3
                 |    num-tx-queues 3
                 | }

.. _cpu:

"cpu" Parameters
________________

Command-line CPU configuration controls the creation of named thread types, and
the cpu affinity thereof. In the VPP there is one main thread and optionally
the user can create worker(s). The main thread and worker thread(s) can be
pinned to CPU core(s) automatically or manually.

**Automatic Pinning:**

 * **workers <n>**
     Create <n> worker threads.
     
     **Example:** workers 4

 * **io <n>**
     Create <n> i/o threads.
     
     **Example:** io 2
 
 * **main-thread-io**
     Handle i/o devices from thread 0, hand off traffic to worker threads.
     Requires "workers <n>".
     
     **Example:** main-thread-io
 
 * **skip-cores <n>**
     Sets number of CPU core(s) to be skipped (1 ... N-1). Skipped CPU core(s)
     are not used for pinning main thread and working thread(s). The main thread
     is automatically pinned to the first available CPU core and worker(s) are
     pinned to next free CPU core(s) after core assigned to main threadLeave
     the low nn bits of the process affinity mask clear.
     
     **Example:** skip-cores 4

**Manual Pinning:**

 * **main-core <n>**
     Assign main thread to a specific core.
     
     **Example:** main-core 1
     
 * **coremask-workers <hex-mask>**
     Place worker threads according to the bitmap hex-mask.
     
     **Example:** coremask-workers 0x0000000000C0000C
     
 * **corelist-workers <list>**
     Same as coremask-workers but accepts a list of cores instead of a bitmap.
     
     **Example:** corelist-workers 2-3,18-19
     
 * **coremask-io <hex-mask>**
     Place I/O threads according to the bitmap hex-mask.
     
     **Example:** coremask-io 0x0000000003000030
     
 * **corelist-io <list>**
     Same as coremask-io but accepts a list of cores instead of a bitmap.
     
     **Example:** corelist-io 4-5,20-21
     
 * **coremask-hqos-threads <hex-mask>**
     Place HQoS threads according to the bitmap hex-mask. A HQoS thread can
     run multiple HQoS objects each associated with different output interfaces.
     
     **Example:** coremask-hqos-threads 0x000000000C0000C0

 * **corelist-hqos-threads <list>**
     Same as coremask-hqos-threads but accepts a list of cores instead of a
     bitmap.
     
     **Example:** corelist-hqos-threads 6-7,22-23

**Other:**

 * **use-pthreads**
     TBD
     
     **Example:** use-pthreads

 * **thread-prefix <prefix>**
     Set a prefix to be prepended to each thread name. The thread name already
     contains an underscore. If not provided, the default is *'vpp'*.
     Currently, prefix used on threads: *'vpp_main'*, *'vpp_stats'*
     
     **Example:** thread-prefix vpp1

 * **scheduler-policy rr|fifo|batch|idle|other**
     TBD
     
     **Example:** scheduler-policy fifo

 * **scheduler-priority <n>**
     Set the scheduler priority. Only valid if the *'scheduler-policy'* is set
     to *'fifo'* or *'rr'*. The valid ranges for the scheduler priority depends
     on the *'scheduler-policy'* and the current kernel version running. The
     range is typically 1 to 99, but see the linux man pages for *'sched'* for
     more details. If this value is not set, the current linux kernel default
     is left in place.
     
     **Example:** scheduler-priority 50

 * **<thread-name> <count>**
     Set the number of threads for a given thread (by name). Some threads, like
     *'stats'*, have a fixed number of threads and cannot be changed. List of
     possible threads include (but not limited too): hqos-threads, workers
     
     **Example:** hqos-threads 2

.. note::

    The "main" thread always occupies the lowest core-id specified in the
    DPDK [process-level] coremask.

Here's a full-bore manual placement example:

.. code-block:: console

   /usr/bin/vpp  unix interactive tuntap disable cpu { main-thread-io coremask-workers 18 coremask-stats 4 } dpdk { coremask 1e }
   
   # taskset -a -p <vpe-pid>
   pid 16251's current affinity mask: 2        # main thread
   pid 16288's current affinity mask: ffffff   # DPDK interrupt thread (not bound to a core)
   pid 16289's current affinity mask: 4        # stats thread
   pid 16290's current affinity mask: 8        # worker thread 0
   pid 16291's current affinity mask: 10       # worker thread 1


.. _acl-plugin:

"acl-plugin" Parameters
_______________________

These parameters change the configuration of the ACL (access control list) plugin,
such as how the ACL bi-hash tables are initialized.

They should only be set by those that are familiar with the interworkings of VPP
and the ACL Plugin.

The first three parameters, *connection hash buckets*, *connection hash memory*,
and *connection count max*, set the **connection table per-interface parameters**
for modifying how the two bounded-index extensible hash tables for
IPv6 (40\*8 bit key and 8\*8 bit value pairs) and IPv4
(16\*8 bit key and 8\*8 bit value pairs) **ACL plugin FA interface sessions**
are initialized.

 * **connection hash buckets <n>**
     Sets the number of hash buckets (rounded up to a power of 2) in each
     of the two bi-hash tables. Defaults to 64\*1024 (65536) hash buckets.
     
     **Example:** connection hash buckets 65536
     
 * **connection hash memory <n>**
     Sets the allocated memory size (in bytes) for each of the two bi-hash tables.
     Defaults to 1073741824 bytes.
     
     **Example:** connection hash memory 1073741824
     
 * **connection count max <n>**
     Sets the maximum number of pool elements when allocating each per-worker
     pool of sessions for both bi-hash tables. Defaults to 500000 elements in each pool.
     
     **Example:** connection count max 500000
     
 * **main heap size <n>G|<n>M|<n>K|<n>**
     Sets the size of the main memory heap that holds all the ACL module related
     allocations (other than hash.) Default size is 0, but during
     ACL heap initialization is equal to
     *per_worker_size_with_slack * tm->n_vlib_mains + bihash_size + main_slack*.
     Note that these variables are partially based on the
     **connection table per-interface parameters** mentioned above.
     
     **Example:** main heap size 3G

The next three parameters, *hash lookup heap size*, *hash lookup hash buckets*,
and *hash lookup hash memory*, modify the initialization of the bi-hash lookup
table used by the ACL plugin. This table is initialized when attempting to apply
an ACL to the existing vector of ACLs looked up during packet processing
(but it is found that the table does not exist / has not been initialized yet.)
     
 * **hash lookup heap size  <n>G|<n>M|<n>K|<n>**
     Sets the size of the memory heap that holds all the miscellaneous allocations
     related to hash-based lookups. Default size is 67108864 bytes.
     
     **Example:** hash lookup heap size 70M
     
 * **hash lookup hash buckets <n>**
     Sets the number of hash buckets (rounded up to a power of 2) in the bi-hash
     lookup table. Defaults to 65536 hash buckets.
     
     **Example:** hash lookup hash buckets 65536
     
 * **hash lookup hash memory <n>**
     Sets the allocated memory size (in bytes) for the bi-hash lookup table.
     Defaults to 67108864 bytes.
     
     **Example:** hash lookup hash memory 67108864
     
 * **use tuple merge <n>**
     Sets a boolean value indicating whether or not to use TupleMerge
     for hash ACL's. Defaults to 1 (true), meaning the default implementation
     of hashing ACL's **does use** TupleMerge.
     
     **Example:** use tuple merge 1
     
 * **tuple merge split threshold <n>**
     Sets the maximum amount of rules (ACE's) that can collide in a bi-hash
     lookup table before the table is split into two new tables. Splitting ensures
     less rule collisions by hashing colliding rules based on their common tuple
     (usually their maximum common tuple.) Splitting occurs when the
     *length of the colliding rules vector* is greater than this threshold amount.
     Defaults to a maximum of 39 rule collisions per table.
     
     **Example:** tuple merge split threshold 30
     
 * **reclassify sessions <n>**
     Sets a boolean value indicating whether or not to take the epoch of the session
     into account when dealing with re-applying ACL's or changing already applied ACL's.
     Defaults to 0 (false), meaning the default implementation **does NOT** take the
     epoch of the session into account.
     
     **Example:** reclassify sessions 1

.. _api-queue:

"api-queue" Parameters
______________________

The following parameters should only be set by those that are familiar with the
interworkings of VPP.

 * **length  <n>**
     Sets the api queue length. Minimum valid queue length is 1024, which is
     also the default.
     
     **Example:** length 2048

.. _api-segment:

"api-segment" Parameters
________________________

These values control various aspects of the binary API interface to VPP.

 * **prefix <path>**
     Sets the prefix prepended to the name used for shared memory (SHM)
     segments. The default is empty, meaning shared memory segments are created
     directly in the SHM directory *'/dev/shm'*. It is worth noting that on
     many systems *'/dev/shm'* is a symbolic link to somewhere else in the file
     system; Ubuntu links it to *'/run/shm'*.
     
     **Example:** prefix /run/shm

 * **uid <number|name>**
     Sets the user ID or name that should be used to set the ownership of the
     shared memory segments. Defaults to the same user that VPP is started
     with, probably root.

     **Example:** uid root

 * **gid <number|name>**
     Sets the group ID or name that should be used to set the ownership of the
     shared memory segments. Defaults to the same group that VPP is started
     with, probably root.
     
     **Example:** gid vpp

The following parameters should only be set by those that are familiar with the
interworkings of VPP.

 * **baseva <x>**
     Set the base address for SVM global region. If not set, on AArch64, the
     code will try to determine the base address. All other default to
     0x30000000.
     
     **Example:** baseva 0x20000000

 * **global-size <n>G|<n>M|<n>**
     Set the global memory size, memory shared across all router instances,
     packet buffers, etc. If not set, defaults to 64M. The input value can be
     set in GB, MB or bytes.
     
     **Example:** global-size 2G

 * **global-pvt-heap-size <n>M|size <n>**
     Set the size of the global VM private mheap. If not set, defaults to 128k.
     The input value can be set in MB or bytes.
     
     **Example:** global-pvt-heap-size size 262144

 * **api-pvt-heap-size <n>M|size <n>**
     Set the size of the api private mheap. If not set, defaults to 128k.
     The input value can be set in MB or bytes.
     
     **Example:** api-pvt-heap-size 1M

 * **api-size <n>M|<n>G|<n>**
     Set the size of the API region. If not set, defaults to 16M. The input
     value can be set in GB, MB or bytes.
     
     **Example:** api-size 64M

.. _api-trace:

"api-trace" Parameters
______________________

The ability to trace, dump, and replay control-plane API traces makes all the
difference in the world when trying to understand what the control-plane has
tried to ask the forwarding-plane to do.

 * **on|enable**
     Enable API trace capture from the beginning of time, and arrange for a
     post-mortem dump of the API trace if the application terminates abnormally.
     By default, the (circular) trace buffer will be configured to capture
     256K traces. The default *'startup.conf'* file has trace enabled by default,
     and unless there is a very strong reason, it should remain enabled.
     
     **Example:** on

 * **nitems <n>**
     Configure the circular trace buffer to contain the last <n> entries. By
     default, the trace buffer captures the last 256K API messages received.
     
     **Example:** nitems 524288

 * **save-api-table <filename>**
     Dumps the API message table to /tmp/<filename>.
     
     **Example:** save-api-table apiTrace-07-04.txt

Typically, one simply enables the API message trace scheme:

     api-trace { on }

.. _buffers:

"buffers" Parameters
____________________

Command line Buffer configuration controls buffer management.

 * **memory-size-in-mb <n>**
     Configure the memory size used for buffers. If not set, VPP defaults
     to 32MB.
     
     **Example:** memory-size-in-mb 64


.. _cj:

"cj" Parameters
_______________

The circular journal (CJ) thread-safe circular log buffer scheme is
occasionally useful when chasing bugs. Calls to it should not be checked in.
See .../vlib/vlib/unix/cj.c. The circular journal is disables by default.
When enabled, the number of records must be provided, there is no default
value.

 * **records <n>**
     Configure the number of circular journal records in the circular buffer.
     The number of records should be a power of 2.
     
     **Example:** records 131072

 * **on**
     Turns on logging at the earliest possible moment.
     
     **Example:** on

.. _dns:

"dns" Parameters
________________

 * **max-cache-size <n>**
     Set the maximum number of active elements allowed in the pool of
     dns cache entries. When resolving an expired entry or adding a new
     static entry and the max number of active entries is reached,
     a random, non-static entry is deleted. Defaults to 65535 entries.
     
     **Example:** max-cache-size 65535
     
 * **max-ttl <n>**
     Currently not implemented. Defaults to 86400 seconds (24 hours.)
     
     **Example:** max-ttl 86400

.. _heapsize:

"heapsize" Parameters
_____________________

Heapsize configuration controls the size of the main heap. The heap size is
configured very early in the boot sequence, before loading plug-ins or doing
much of anything else.

 * **heapsize <n>M|<n>G**
     Specifies the size of the heap in MB or GB. The default is 1GB. Setting the
     main heap size to 4GB or more requires recompilation of the entire system
     with CLIB_VEC64 > 0. See .../clib/clib/vec_bootstrap.h.
     
     **Example:** heapsize 2G

.. _ip:

"ip" Parameters
_______________

IPv4 heap configuration. he heap size is configured very early in the boot
sequence, before loading plug-ins or doing much of anything else.

 * **heap-size <n>G|<n>M|<n>K|<n>**
     Set the IPv4 mtrie heap size, which is the amount of memory dedicated to
     the destination IP lookup table. The input value can be set in GB, MB, KB
     or bytes. The default value is 32MB.
     
     **Example:** heap-size 64M

.. _ip6:

"ip6" Parameters
________________

IPv6 heap configuration. he heap size is configured very early in the boot
sequence, before loading plug-ins or doing much of anything else.


 * **heap-size <n>G|<n>M|<n>K|<n>**
     Set the IPv6 forwarding table heap size. The input value can be set in GB,
     MB, KB or bytes. The default value is 32MB.
     
     **Example:** heap-size 64M
     
 * **hash-buckets <n>**
     Set the number of IPv6 forwarding table hash buckets. The default value is
     64K (65536).
     
     **Example:** hash-buckets 131072

.. _l2learn:

"l2learn" Parameters
____________________

Configure Layer 2 MAC Address learning parameters.

 * **limit <n>**
     Configures the number of L2 (MAC) addresses in the L2 FIB at any one time,
     which limits the size of the L2 FIB to <n> concurrent entries.  Defaults to
     4M entries (4194304).
     
     **Example:** limit 8388608

.. _l2tp:

"l2tp" Parameters
_________________

IPv6 Layer 2 Tunnelling Protocol Version 3 (IPv6-L2TPv3) configuration controls
the method used to locate a specific IPv6-L2TPv3 tunnel. The following settings
are mutually exclusive:

 * **lookup-v6-src**
     Lookup tunnel by IPv6 source address.
     
     **Example:** lookup-v6-src
     
 * **lookup-v6-dst**
     Lookup tunnel by IPv6 destination address.
     
     **Example:** lookup-v6-dst
     
 * **lookup-session-id**
     Lookup tunnel by L2TPv3 session identifier.
     
     **Example:** lookup-session-id

.. _logging:

"logging" Parameters
____________________

 * **size <n>**
     TBD
     
     **Example:** TBD
     
 * **unthrottle-time <n>**
     TBD
     
     **Example:** TBD
     
 * **default-log-level emerg|alertcrit|err|warn|notice|info|debug|disabled**
     TBD
     
     **Example:** TBD
     
 * **default-syslog-log-level emerg|alertcrit|err|warn|notice|info|debug|disabled**
     TBD
     
     **Example:** TBD

.. _mactime:

"mactime" Parameters
____________________

 * **lookup-table-buckets <n>**
     Sets the number of hash buckets in the mactime bi-hash lookup table.
     Defaults to 128 buckets.
     
     **Example:** lookup-table-buckets 128
     
 * **lookup-table-memory <n>G|<n>M|<n>K|<n>**
     Sets the allocated memory size (in bytes) for the mactime bi-hash lookup table.
     The input value can be set in GB, MB, KB or bytes. The default value is 262144
     (256 << 10) bytes or roughly 256KB.
     
     **Example:** lookup-table-memory 300K
     
 * **timezone_offset <n>**
     Sets the timezone offset from UTC. Defaults to an offset of -5 hours
     from UTC (US EST / EDT.)
     
     **Example:** timezone_offset -5

.. _map:

"map" Parameters
________________

 * **customer edge**
     Sets a boolean true to indicate that the MAP node is a Customer Edge (CE)
     router. The boolean defaults to false, meaning the MAP node is not treated
     as a CE router.
     
     **Example:** customer edge

.. _mc:

"mc" Parameters
_______________

MC Test Process.

 * **interface <name>**
     TBD
     
     **Example:** TBD
     
 * **n-bytes <n>**
     TBD
     
     **Example:** TBD
     
 * **max-n-bytes <n>**
     TBD
     
     **Example:** TBD
     
 * **min-n-bytes <n>**
     TBD
     
     **Example:** TBD
     
 * **seed <n>**
     TBD
     
     **Example:** TBD
     
 * **window <n>**
     TBD
     
     **Example:** TBD
     
 * **verbose**
     TBD
     
     **Example:** verbose
     
 * **no-validate**
     TBD
     
     **Example:** no-validate
     
 * **min-delay <n.n>**
     TBD
     
     **Example:** TBD
     
 * **max-delay <n.n>**
     TBD
     
     **Example:** TBD
     
 * **no-delay**
     TBD
     
     **Example:** no-delay
     
 * **n-packets <n.n>**
     TBD
     
     **Example:** TBD

.. _nat:


"nat" Parameters
________________

These parameters change the configuration of the NAT (Network address translation)
plugin, such as how the NAT & NAT64 bi-hash tables are initialized, if the NAT is
endpoint dependent, or if the NAT is deterministic.

For each NAT per thread data, the following 4 parameters change how certain
bi-hash tables are initialized.

 * **translation hash buckets <n>**
     Sets the number of hash buckets in each of the two in/out NAT bi-hash lookup
     tables. Defaults to 1024 buckets.

     If the NAT is indicated to be endpoint dependent, which can be set with the
     :ref:`endpoint-dependent parameter <endpointLabel>`, then this parameter sets
     the number of hash buckets in each of the two endpoint dependent sessions
     NAT bi-hash lookup tables.
     
     **Example:** translation hash buckets 1024
     
 * **translation hash memory <n>**
     Sets the allocated memory size (in bytes) for each of the two in/out NAT
     bi-hash tables. Defaults to 134217728 (128 << 20) bytes, which is roughly 128 MB.

     If the NAT is indicated to be endpoint dependent, which can be set with the
     :ref:`endpoint-dependent parameter <endpointLabel>`, then this parameter sets the
     allocated memory size for each of the two endpoint dependent sessions NAT bi-hash
     lookup tables.
     
     **Example:** translation hash memory 134217728
     
 * **user hash buckets <n>**
     Sets the number of hash buckets in the user bi-hash lookup table
     (src address lookup for a user.) Defaults to 128 buckets.
     
     **Example:** user hash buckets 128
     
 * **user hash memory <n>**
     Sets the allocated memory size (in bytes) for the user bi-hash lookup table
     (src address lookup for a user.) Defaults to 67108864 (64 << 20) bytes,
     which is roughly 64 MB.
     
     **Example:** user hash memory 67108864
     
 * **max translations per user <n>**
     Sets the maximum amount of dynamic and/or static NAT sessions each user can have.
     Defaults to 100. When this limit is reached, the least recently used translation
     is recycled.
     
     **Example:** max translations per user 50
     
 * **outside VRF id <n>**
     TBD
     
     **Example:** TBD
     
 * **outside ip6 VRF id <n>**
     TBD
     
     **Example:** TBD
     
 * **inside VRF id <n>**
     TBD
     
     **Example:** TBD
     
 * **inside VRF id <n>**
     TBD
     
     **Example:** TBD
     
 * **static mapping only**
     TBD
     
     **Example:** static mapping only
     
 * **connection tracking**
     TBD
     
     **Example:** connection tracking
     
 * **deterministic**
     Sets a boolean value to 1 indicating that the NAT is deterministic. Defaults to 0,
     meaning the NAT is not deterministic.
     
     **Example:** deterministic
     
 * **nat64 bib hash buckets <n>**
     Sets the number of hash buckets in each of the two in/out NAT64 BIB bi-hash
     tables. Defaults to 1024 buckets.
     
     **Example:** nat64 bib hash buckets 1024
     
 * **nat64 bib hash memory <n>**
     Sets the allocated memory size (in bytes) for each of the two in/out NAT64
     BIB bi-hash tables. Defaults to 134217728 (128 << 20) bytes,
     which is roughly 128 MB.
     
     **Example:** nat64 bib hash memory 134217728
     
 * **nat64 st hash buckets <n>**
     Sets the number of hash buckets in each of the two in/out NAT64 session table
     bi-hash tables. Defaults to 2048 buckets.
     
     **Example:** nat64 st hash buckets 2048
     
 * **nat64 st hash memory <n>**
     Sets the allocated memory size (in bytes) for each of the two in/out NAT64 session
     table bi-hash tables. Defaults to 268435456 (256 << 20) bytes, which is roughly
     256 MB.
     
     **Example:** nat64 st hash memory 268435456
     
 * **out2in dpo**
     TBD
     
     **Example:** out2in dpo
     
 * **dslite ce**
     TBD
     
     **Example:** dslite ce
     
.. _endpointLabel:

 * **endpoint-dependent**
     Sets a boolean value to 1, indicating that the NAT is endpoint dependent.
     Defaults to 0, meaning the NAT is not endpoint dependent.
     
     **Example:** endpoint-dependent

.. _oam:

"oam" Parameters
________________

OAM configuration controls the (ip4-icmp) interval, and number of misses
allowed before reporting an oam target down to any registered listener.

 * **interval <n.n>**
     Interval, floating-point seconds, between sending OAM IPv4 ICMP messages.
     Default is 2.04 seconds.
     
     **Example:** interval 3.5
     
 * **misses-allowed <n>**
     Number of misses before declaring an OAM target down. Default is 3 misses.
     
     **Example:** misses-allowed 5

.. _plugins:

"plugins" Parameters
____________________

A plugin can be disabled by default. It may still be in an experimental phase
or only be needed in special circumstances. If this is the case, the plugin can
be explicitely enabled in *'startup.conf'*. Also, a plugin that is enabled by
default can be explicitely disabled in *'startup.conf'*.

Another useful use of this section is to disable all the plugins, then enable
only the plugins that are desired.

 * **path <path>**
     Adjust the plugin path depending on where the VPP plugins are installed.
     
     **Example:** path /home/bms/vpp/build-root/install-vpp-native/vpp/lib64/vpp_plugins
     
 * **name-filter <filter-name>**
     TBD
     
     **Example:** TBD
     
 * **vat-path <path>**
     TBD
     
     **Example:** TBD
     
 * **vat-name-filter <filter-name>**
     TBD
     
     **Example:** TBD
     
 * **plugin <plugin.so> { .. }**
     Configure parameters for a given plugin. Valid parameters are as follows: 

      * **enable**
          Enable the given plugin.
      * **disable**
          Disable the given plugin.
      * **skip-version-check**
          In the plugin registration, if *'.version_required'* is set, the
          plugin will not be loaded if there is version mismatch between
          plugin and VPP. This can be bypassed by setting "skip-version-check"
          for specific plugin.
     
     **Example:** plugin ila_plugin.so { enable skip-version-check }
     
 * **plugin default { .. }**
     Set the default behavior for all plugins. Valid parameters are as follows:
     
       * **disable**
          Disable all plugins.
     
     **Example:**
               | plugin default { disable }
               | plugin dpdk_plugin.so { enable }
               | plugin acl_plugin.so { enable }

.. _plugin_path:

"plugin_path" Parameters
________________________

Alternate syntax to choose plugin path. Plugin_path configuration controls the
set of directories searched for vlib plugins. Supply a colon-separated list of
(absolute) directory names: plugin_path dir1:dir2:...:dirN

    **Example:** plugin_path /home/bms/vpp/build-root/install-vpp-native/vpp/lib64/vpp_plugins

.. _punt:

"punt" Parameters
_________________

Configuration parameters for the local TCP/IP stack punt infrastructure.

 * **socket <path>**
     The filesystem pathname of a bound UNIX domain socket to be used with punt.
     
     **Example:** TBD

.. _session:

"session" Parameters
____________________

 * **event-queue-length <n>**
     TBD
     
     **Example:** TBD
     
 * **preallocated-sessions <n>**
     TBD
     
     **Example:** TBD
     
 * **v4-session-table-buckets <n>**
     TBD
     
     **Example:** TBD
     
 * **v4-halfopen-table-buckets <n>**
     TBD
     
     **Example:** TBD
     
 * **v6-session-table-buckets <n>**
     TBD
     
     **Example:** TBD
     
 * **v6-halfopen-table-buckets <n>**
     TBD
     
     **Example:** TBD
     
 * **v4-session-table-memory <n>G|<n>M|<n>K|<n>**
     TBD
     The input value can be set in GB, MB, KB or bytes.
     
     **Example:** TBD
     
 * **v4-halfopen-table-memory <n>G|<n>M|<n>K|<n>**
     TBD
     The input value can be set in GB, MB, KB or bytes.
     
     **Example:** TBD
     
 * **v6-session-table-memory <n>G|<n>M|<n>K|<n>**
     TBD
     The input value can be set in GB, MB, KB or bytes.
     
     **Example:** TBD
     
 * **v6-halfopen-table-memory <n>G|<n>M|<n>K|<n>**
     TBD
     The input value can be set in GB, MB, KB or bytes.
     
     **Example:** TBD
     
 * **local-endpoints-table-memory <n>G|<n>M|<n>K|<n>**
     TBD
     The input value can be set in GB, MB, KB or bytes.
     
     **Example:** TBD
     
 * **local-endpoints-table-buckets <n>**
     TBD
     
     **Example:** TBD
     
 * **evt_qs_memfd_seg**
     TBD
     
     **Example:** evt_qs_memfd_seg

.. _socketsvr:

"socketsvr" Parameters
______________________

Create a socket server for API server (.../vlibmemory/socksvr_vlib.c.).
If not set, API server doesn't run.

 * **socket-name <filename>**
     Configure API socket filename.
     
     **Example:** socket-name /run/vpp/vpp-api.sock
     
 * **default**
     Use the default API socket (/run/vpp-api.sock).
     
     **Example:** default

.. _stats:

"stats" Parameters
__________________

Create a socket server for *'stats'* poller. If not set, 'stats'* poller
doesn't run.

 * **socket-name <filename>**
     Configure *'stats'* socket filename.
     
     **Example:** socket-name /run/vpp/stats.sock
     
 * **default**
     Use the default *'stats'* socket (/run/vpp/stats.sock).
     
     **Example:** default

.. _statseg:

"statseg" Parameters
____________________

 * **size <n>G|<n>M|<n>K|<n>**
     Sets the size of the memory mapped stats segment object *stat_segment*.
     The input value can be set in GB, MB, KB or bytes. Defaults to 33554432
     (32 << 20) bytes or roughly 32 MB.
     
     **Example:** size 32M
     
.. _tapcli:     

"tapcli" Parameters
___________________

Configuration parameters for TAPCLI (dynamic tap interface hookup.)

 * **mtu <n>**
     Sets interface MTU (maximum transmission unit) size in bytes. This size
     is also related to the number of MTU buffers. Defaults to 1500 bytes.
     
     **Example:** mtu 1500
     
 * **disable**
     Disables TAPCLI. Default is that TAPCLI is enabled.
     
     **Example:** disable

.. _tcp:

"tcp" Parameters
________________

Configuration parameters for TCP host stack utilities. The following
preallocation parameters are related to the initialization of fixed-size,
preallocation pools.

 * **preallocated-connections <n>**
     Sets the number of preallocated TCP connections. Defaults to 0.
     The preallocated connections per thread is related to this value,
     equal to (preallocated_connections / (num_threads - 1)).
     
     **Example:** preallocated-connections 5
     
 * **preallocated-half-open-connections <n>**
     Sets the number of preallocated TCP half-open connections. Defaults to 0.
     
     **Example:** preallocated-half-open-connections 5
     
 * **buffer-fail-fraction <n.n>**
     Sets the TCP buffer fail fraction (a float) used for fault-injection
     when debugging TCP buffer allocation. Its use is found in *tcp_debug.h*.
     Defaults to 0.0.
     
     **Example:** buffer-fail-fraction 0.0

.. _tls:

"tls" Parameters
________________

Configures TLS parameters, such as enabling the use of test certificates.
These parameters affect the tlsmbedtls and tlsopenssl plugins.

 * **use-test-cert-in-ca**
     Sets a boolean value to 1 to indicate during the initialization of a
     TLS CA chain to attempt to parse and add test certificates to the chain.
     Defaults to 0, meaning test certificates are not used.
     
     **Example:** use-test-cert-in-ca
     
 * **ca-cert-path <filename>**
     Sets the filename path of the location of TLS CA certificates, used when
     initializing and loading TLS CA certificates during the initialization
     of a TLS CA chain. If not set, the default filename path is
     */etc/ssl/certs/ca-certificates.crt*.
     
     **Example:** ca-cert-path /etc/ssl/certs/ca-certificates.crt

.. _tuntap:

"tuntap" Parameters
___________________

The "tuntap" driver configures a point-to-point interface between the vpp
engine and the local Linux kernel stack. This allows e.g. users to ssh to the
host | VM | container via vpp "revenue" interfaces. It's marginally useful, and
is currently disabled by default. To [dynamically] create TAP interfaces - the
preferred scheme - see the "tap_connect" binary API. The Linux network stack
"vnet" interface needs to manually configure, and VLAN and other settings if
desired.

 * **enable|disable**
     Enable or disable the tun/tap driver. 
     
     **Example:** enable
     
 * **ethernet|ether**
     Create a tap device (ethernet MAC) instead of a tun device (point-to-point
     tunnel). The two keywords are aliases for the same function.
     
     **Example:** ethernet
     
 * **have-normal-interface|have-normal**
     Treat the host Linux stack as a routing peer instead of programming VPP
     interface L3 addresses onto the tun/tap devices. The two keywords are
     aliases for the same function.
     
     **Example:** have-normal-interface
     
 * **name <name>**
     Assign name to the tun/tap device.
     
     **Example:** name vpp1

Here's a typical multiple parameter invocation:

     | tuntap { ethernet have-normal-interface name vpp1 }

.. _vhost-user:

"vhost-user" Parameters
_______________________

Vhost-user configuration parameters control the vhost-user driver.

 * **coalesce-frames <n>**
     Subject to deadline-timer expiration - see next item - attempt to transmit
     at least <n> packet frames. Default is 32 frames.
     
     **Example:** coalesce-frames 64
     
 * **coalesce-time <seconds>**
     Hold packets no longer than (floating-point) seconds before transmitting
     them. Default is 0.001 seconds
     
     **Example:** coalesce-time 0.002
     
 * **dont-dump-memory**
     vhost-user shared-memory segments can add up to a large amount of memory, so
     it's handy to avoid adding them to corefiles when using a significant number
     of such interfaces.
     
     **Example:** dont-dump-memory

.. _vlib:

"vlib" Parameters
_________________

These parameters configure VLIB, such as allowing you to choose whether to
enable memory traceback or a post-mortem elog dump.

 * **memory-trace**
     Enables memory trace (mheap traceback.) Defaults to 0, meaning memory
     trace is disabled.
     
     **Example:** memory-trace
     
 * **elog-events <n>**
     Sets the number of elements/events (the size) of the event ring
     (a circular buffer of events.) This number rounds to a power of 2.
     Defaults to 131072 (128 << 10) elements.
     
     **Example:** elog-events 4096
     
 * **elog-post-mortem-dump**
     Enables the attempt of a post-mortem elog dump to
     */tmp/elog_post_mortem.<PID_OF_CALLING_PROCESS>* if os_panic or
     os_exit is called.
     
     **Example:** elog-post-mortem-dump
 

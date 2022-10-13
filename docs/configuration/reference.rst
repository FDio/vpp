.. _configuration_reference:

Configuration Reference
=======================

Below is the list of some section names and their associated parameters.
This is not an exhaustive list, but should give you an idea of how VPP can be configured.

For all of the configuration parameters search the source code for instances of
**VLIB_CONFIG_FUNCTION** and **VLIB_EARLY_CONFIG_FUNCTION**.

For example, the invocation *'VLIB_CONFIG_FUNCTION (foo_config, "foo")'* will
cause the function *'foo_config'* to receive all parameters given in a
parameter block named "foo": "foo { arg1 arg2 arg3 ... }".

The unix section
----------------

Configures VPP startup and behavior type attributes, as well and any OS based
attributes.

.. code-block:: console

  unix {
    nodaemon
    log /var/log/vpp/vpp.log
    full-coredump
    cli-listen /run/vpp/cli.sock
    gid vpp
  }

nodaemon
^^^^^^^^

Do not fork / background the vpp process. Typical when invoking VPP
applications from a process monitor. Set by default in the default
*'startup.conf'* file.

.. code-block:: console

   nodaemon

nosyslog
^^^^^^^^

Disable syslog and log errors to stderr instead. Typical when invoking
VPP applications from a process monitor like runit or daemontools that
pipe service's output to a dedicated log service, which will typically
attach a timestamp and rotate the logs as necessary.

.. code-block:: console

   nosyslog

interactive
^^^^^^^^^^^

Attach CLI to stdin/out and provide a debugging command line interface.

.. code-block:: console

   interactive

log <filename>
^^^^^^^^^^^^^^

Logs the startup configuration and all subsequent CLI commands in filename.
Very useful in situations where folks don't remember or can't be bothered
to include CLI commands in bug reports. The default *'startup.conf'* file
is to write to *'/var/log/vpp/vpp.log'*.

In VPP 18.04, the default log file location was moved from '/tmp/vpp.log'
to '/var/log/vpp/vpp.log' . The VPP code is indifferent to the file location.
However, if SELinux is enabled, then the new location is required for the file
to be properly labeled. Check your local *'startup.conf'* file for the log file
location on your system.

.. code-block:: console

   log /var/log/vpp/vpp-debug.log

exec | startup-config <filename>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Read startup operational configuration from filename. The contents of the file
will be performed as though entered at the CLI. The two keywords are aliases
for the same function; if both are specified, only the last will have an effect.

A file of CLI commands might look like:

.. code-block:: console

   $ cat /usr/share/vpp/scripts/interface-up.txt
   set interface state TenGigabitEthernet1/0/0 up
   set interface state TenGigabitEthernet1/0/1 up

Parameter Example:

.. code-block:: console

     startup-config /usr/share/vpp/scripts/interface-up.txt

gid <number | name>
^^^^^^^^^^^^^^^^^^^

Sets the effective group ID to the input group ID or group name of the calling
process.

.. code-block:: console

   gid vpp

full-coredump
^^^^^^^^^^^^^

Ask the Linux kernel to dump all memory-mapped address regions, instead of
just text+data+bss.

.. code-block:: console

   full-coredump

coredump-size unlimited | <n>G | <n>M | <n>K | <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

     Set the maximum size of the coredump file. The input value can be set in
     GB, MB, KB or bytes, or set to *'unlimited'*.

.. code-block:: console

   coredump-size unlimited

cli-listen <ipaddress:port> | <socket-path>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

     Bind the CLI to listen at address localhost on TCP port 5002. This will
     accept an ipaddress:port pair or a filesystem path; in the latter case a
     local Unix socket is opened instead. The default *'startup.conf'* file
     is to open the socket *'/run/vpp/cli.sock'*.

.. code-block:: console

     cli-listen localhost:5002
     cli-listen /run/vpp/cli.sock

cli-line-mode
^^^^^^^^^^^^^

     Disable character-by-character I/O on stdin. Useful when combined with,
     for example, emacs M-x gud-gdb.

.. code-block:: console

   cli-line-mode

cli-prompt <string>
^^^^^^^^^^^^^^^^^^^

     Configure the CLI prompt to be string.

.. code-block:: console

     cli-prompt vpp-2

cli-history-limit <n>
^^^^^^^^^^^^^^^^^^^^^

     Limit command history to <n> lines. A value of 0 disables command history.
     Default value: 50

.. code-block:: console

     cli-history-limit 100

cli-no-banner
^^^^^^^^^^^^^

     Disable the login banner on stdin and Telnet connections.

.. code-block:: console

     cli-no-banner

cli-no-pager
^^^^^^^^^^^^

     Disable the output pager.

.. code-block:: console

     cli-no-pager

cli-pager-buffer-limit <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^

     Limit pager buffer to <n> lines of output. A value of 0 disables the
     pager. Default value: 100000

.. code-block:: console

     cli-pager-buffer-limit 5000

runtime-dir <dir>
^^^^^^^^^^^^^^^^^

     Set the runtime directory, which is the default location for certain
     files, like socket files. Default is based on User ID used to start VPP.
     Typically it is *'root'*, which defaults to *'/run/vpp/'*. Otherwise,
     defaults to *'/run/user/<uid>/vpp/'*.

.. code-block:: console

     runtime-dir /tmp/vpp

poll-sleep-usec <n>
^^^^^^^^^^^^^^^^^^^

     Add a fixed-sleep between main loop poll. Default is 0, which is not to
     sleep.

.. code-block:: console

     poll-sleep-usec 100

pidfile <filename>
^^^^^^^^^^^^^^^^^^

     Writes the pid of the main thread in the given filename.

.. code-block:: console

     pidfile /run/vpp/vpp1.pid


The api-trace Section
---------------------

The ability to trace, dump, and replay control-plane API traces makes all the
difference in the world when trying to understand what the control-plane has
tried to ask the forwarding-plane to do.

Typically, one simply enables the API message trace scheme:

.. code-block:: console

   api-trace {
     api-trace on
   }

on | enable
^^^^^^^^^^^

     Enable API trace capture from the beginning of time, and arrange for a
     post-mortem dump of the API trace if the application terminates abnormally.
     By default, the (circular) trace buffer will be configured to capture
     256K traces. The default *'startup.conf'* file has trace enabled by default,
     and unless there is a very strong reason, it should remain enabled.

.. code-block:: console

    on

nitems <n>
^^^^^^^^^^

     Configure the circular trace buffer to contain the last <n> entries. By
     default, the trace buffer captures the last 256K API messages received.

.. code-block:: console

    nitems 524288

save-api-table <filename>
^^^^^^^^^^^^^^^^^^^^^^^^^

     Dumps the API message table to /tmp/<filename>.

.. code-block:: console

    save-api-table apiTrace-07-04.txt


The api-segment Section
-----------------------

These values control various aspects of the binary API interface to VPP.

The default looks like the following:

.. code-block:: console

   api-segment {
     gid vpp
   }


prefix <path>
^^^^^^^^^^^^^

     Sets the prefix prepended to the name used for shared memory (SHM)
     segments. The default is empty, meaning shared memory segments are created
     directly in the SHM directory *'/dev/shm'*. It is worth noting that on
     many systems *'/dev/shm'* is a symbolic link to somewhere else in the file
     system; Ubuntu links it to *'/run/shm'*.

.. code-block:: console

    prefix /run/shm

uid <number | name>
^^^^^^^^^^^^^^^^^^^

     Sets the user ID or name that should be used to set the ownership of the
     shared memory segments. Defaults to the same user that VPP is started
     with, probably root.

.. code-block:: console

    uid root

gid <number | name>
^^^^^^^^^^^^^^^^^^^

     Sets the group ID or name that should be used to set the ownership of the
     shared memory segments. Defaults to the same group that VPP is started
     with, probably root.

.. code-block:: console

    gid vpp

**The following parameters should only be set by those that are familiar with the
interworkings of VPP.**

baseva <x>
^^^^^^^^^^

     Set the base address for SVM global region. If not set, on AArch64, the
     code will try to determine the base address. All other default to
     0x30000000.

.. code-block:: console

    baseva 0x20000000

global-size <n>G | <n>M | <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

     Set the global memory size, memory shared across all router instances,
     packet buffers, etc. If not set, defaults to 64M. The input value can be
     set in GB, MB or bytes.

.. code-block:: console

    global-size 2G

global-pvt-heap-size <n>M | size <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

     Set the size of the global VM private mheap. If not set, defaults to 128k.
     The input value can be set in MB or bytes.

.. code-block:: console

    global-pvt-heap-size size 262144

api-pvt-heap-size <n>M | size <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

     Set the size of the api private mheap. If not set, defaults to 128k.
     The input value can be set in MB or bytes.

.. code-block:: console

    api-pvt-heap-size 1M

api-size <n>M | <n>G | <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^

     Set the size of the API region. If not set, defaults to 16M. The input
     value can be set in GB, MB or bytes.

.. code-block:: console

    api-size 64M

The socksvr Section
-------------------

Enables a Unix domain socket which processes binary API messages. See
.../vlibmemory/socket_api.c.  If this parameter is not set, vpp
won't process binary API messages over sockets.

.. code-block:: console

   socksvr {
      # Explicitly name a socket file
      socket-name /run/vpp/api.sock
      or
      # Use defaults as described below
      default
   }

The "default" keyword instructs vpp to use /run/vpp/api.sock when
running as root, otherwise to use /run/user/<uid>/api.sock.

The cpu Section
---------------

In the VPP there is one main thread and optionally the user can create worker(s)
The main thread and worker thread(s) can be pinned to CPU core(s) manually or automatically

.. code-block:: console

   cpu {
      main-core 1
      corelist-workers 2-3,18-19
   }


Manual pinning of thread(s) to CPU core(s)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

main-core
^^^^^^^^^

Set logical CPU core where main thread runs, if main core is not set VPP will use
core 1 if available

.. code-block:: console

   main-core 1

corelist-workers
^^^^^^^^^^^^^^^^

Set logical CPU core(s) where worker threads are running

.. code-block:: console

   corelist-workers 2-3,18-19

Automatic pinning of thread(s) to CPU core(s)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

skip-cores number
^^^^^^^^^^^^^^^^^

Sets number of CPU core(s) to be skipped (1 ... N-1), Skipped CPU core(s) are
not used for pinning main thread and working thread(s).

The main thread is automatically pinned to the first available CPU core and worker(s)
are pinned to next free CPU core(s) after core assigned to main thread

.. code-block:: console

   skip-cores 4

workers number
^^^^^^^^^^^^^^

Specify a number of workers to be created Workers are pinned to N consecutive
CPU cores while skipping "skip-cores" CPU core(s) and main thread's CPU core

.. code-block:: console

   workers 2

scheduler-policy other | batch | idle | fifo | rr
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set scheduling policy and priority of main and worker threads

Scheduling policy options are: other (SCHED_OTHER), batch (SCHED_BATCH)
idle (SCHED_IDLE), fifo (SCHED_FIFO), rr (SCHED_RR)

.. code-block:: console

   scheduler-policy fifo

scheduler-priority number
^^^^^^^^^^^^^^^^^^^^^^^^^

Scheduling priority is used only for "real-time policies (fifo and rr),
and has to be in the range of priorities supported for a particular policy

.. code-block:: console

   scheduler-priority 50

The buffers Section
-------------------

.. code-block:: console

   buffers {
      buffers-per-numa 128000
      default data-size 2048
      page-size default-hugepage
   }

buffers-per-numa number
^^^^^^^^^^^^^^^^^^^^^^^

Increase number of buffers allocated, needed only in scenarios with
large number of interfaces and worker threads. Value is per numa node.
Default is 16384 (8192 if running unprivileged)

.. code-block:: console

   buffers-per-numa 128000

default data-size number
^^^^^^^^^^^^^^^^^^^^^^^^

Size of buffer data area, default is 2048

.. code-block:: console

   default data-size 2048

page-size number
^^^^^^^^^^^^^^^^

Set the page size for buffer allocation

.. code-block:: console

   page-size 4K
   page-size 2M
   page-size 1G
   page-size default
   page-size default-hugepage


The dpdk Section
----------------

.. code-block:: console

   dpdk {
      dev default {
         num-rx-desc 512
         num-tx-desc 512
      }

      dev 0000:02:00.1 {
         num-rx-queues 2
         name eth0
      }
   }

dev <pci-dev> | default { .. }
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

White-list [as in, attempt to drive] a specific PCI device. PCI-dev is a
string of the form "DDDD:BB:SS.F" where:

* DDDD = Domain
* BB = Bus Number
* SS = Slot number
* F = Function

If the keyword **default** is used the values will apply to all the devices.

This is the same format used in the linux sysfs tree (i.e./sys/bus/pci/devices)
for PCI device directory names.

.. code-block:: console

   dpdk {
      dev default {
         num-rx-desc 512
         num-tx-desc 512
      }

dev <pci-dev> { .. }
^^^^^^^^^^^^^^^^^^^^

Whitelist specific interface by specifying PCI address. When whitelisting specific
interfaces by specifying PCI address, additional custom parameters can also be
specified. Valid options include:

.. code-block:: console

   dev 0000:02:00.0
   dev 0000:03:00.0

blacklist <pci-dev>
^^^^^^^^^^^^^^^^^^^

Blacklist specific device type by specifying PCI vendor:device Whitelist entries
take precedence

.. code-block:: console

   blacklist 8086:10fb

name interface-name
^^^^^^^^^^^^^^^^^^^

Set interface name

.. code-block:: console

   dev 0000:02:00.1 {
      name eth0
   }

num-rx-queues <n>
^^^^^^^^^^^^^^^^^

Number of receive queues. Also enables RSS. Default value is 1.

.. code-block:: console

   dev 0000:02:00.1 {
      num-rx-queues <n>
   }

num-tx-queues <n>
^^^^^^^^^^^^^^^^^

Number of transmit queues. Default is equal to number of worker threads
or 1 if no workers treads.

.. code-block:: console

   dev 000:02:00.1 {
      num-tx-queues <n>
   }

num-rx-desc <n>
^^^^^^^^^^^^^^^

Number of descriptors in receive ring. Increasing or reducing number
can impact performance. Default is 1024.

.. code-block:: console

   dev 000:02:00.1 {
      num-rx-desc <n>
   }

vlan-strip-offload on | off
^^^^^^^^^^^^^^^^^^^^^^^^^^^

VLAN strip offload mode for interface. VLAN stripping is off by default
for all NICs except VICs, using ENIC driver, which has VLAN stripping on
by default.

.. code-block:: console

   dev 000:02:00.1 {
      vlan-strip-offload on|off
   }

uio-driver driver-name
^^^^^^^^^^^^^^^^^^^^^^

Change UIO driver used by VPP, Options are: igb_uio, vfio-pci, uio_pci_generic
or auto (default)


.. code-block:: console

   uio-driver vfio-pci

uio-bind-force
^^^^^^^^^^^^^^^^^^^^^^

Force VPP to rebind the interface(s) to the selected UIO driver, even if the
interface is up in Linux.
By default, VPP will refuse to bind an interface if it is up in Linux,
in case it is in active use.

.. code-block:: console

   uio-bind-force

no-multi-seg
^^^^^^^^^^^^

Disable multi-segment buffers, improves performance but disables Jumbo MTU support

.. code-block:: console

   no-multi-seg

socket-mem <n>
^^^^^^^^^^^^^^

Change hugepages allocation per-socket, needed only if there is need for
larger number of mbufs. Default is 256M on each detected CPU socket

.. code-block:: console

   socket-mem 2048,2048

no-tx-checksum-offload
^^^^^^^^^^^^^^^^^^^^^^

Disables UDP / TCP TX checksum offload. Typically needed for use faster
vector PMDs (together with no-multi-seg)

.. code-block:: console

   no-tx-checksum-offload

enable-tcp-udp-checksum
^^^^^^^^^^^^^^^^^^^^^^^

Enable UDP / TCP TX checksum offload This is the reversed option of
'no-tx-checksum-offload'

.. code-block:: console

   enable-tcp-udp-checksum

The plugins Section
-------------------

Configure VPP plugins.

.. code-block:: console

   plugins {
      path /ws/vpp/build-root/install-vpp-native/vpp/lib/vpp_plugins
      plugin dpdk_plugin.so enable
   }

path pathname
^^^^^^^^^^^^^

Adjust the plugin path depending on where the VPP plugins are.

.. code-block:: console

   path /ws/vpp/build-root/install-vpp-native/vpp/lib/vpp_plugins

plugin plugin-name | default enable | disable
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Disable all plugins by default and then selectively enable specific plugins

.. code-block:: console

   plugin default disable
   plugin dpdk_plugin.so enable
   plugin acl_plugin.so enable

Enable all plugins by default and then selectively disable specific plugins

.. code-block:: console

   plugin dpdk_plugin.so disable
   plugin acl_plugin.so disable

Th statseg Section
^^^^^^^^^^^^^^^^^^

.. code-block:: console

   statseg {
      per-node-counters on
    }

socket-name <filename>
^^^^^^^^^^^^^^^^^^^^^^

Name of the stats segment socket defaults to /run/vpp/stats.sock.

.. code-block:: console

   socket-name /run/vpp/stats.sock

size <nnn>[KMG]
^^^^^^^^^^^^^^^

The size of the stats segment, defaults to 32mb

.. code-block:: console

   size 1024M

per-node-counters on | off
^^^^^^^^^^^^^^^^^^^^^^^^^^

Defaults to none

.. code-block:: console

   per-node-counters on

update-interval <f64-seconds>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the segment scrape / update interval

.. code-block:: console

   update-interval 300


Some Advanced Parameters:
-------------------------


acl-plugin Section
------------------

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

connection hash buckets <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the number of hash buckets (rounded up to a power of 2) in each
of the two bi-hash tables. Defaults to 64\*1024 (65536) hash buckets.

.. code-block:: console

   connection hash buckets 65536

connection hash memory <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the allocated memory size (in bytes) for each of the two bi-hash tables.
Defaults to 1073741824 bytes.

.. code-block:: console

   connection hash memory 1073741824

connection count max <n>
^^^^^^^^^^^^^^^^^^^^^^^^

Sets the maximum number of pool elements when allocating each per-worker
pool of sessions for both bi-hash tables. Defaults to 500000 elements in each pool.

.. code-block:: console

   connection count max 500000

main heap size <n>G | <n>M | <n>K | <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the size of the main memory heap that holds all the ACL module related
allocations (other than hash.) Default size is 0, but during
ACL heap initialization is equal to
*per_worker_size_with_slack * tm->n_vlib_mains + bihash_size + main_slack*.
Note that these variables are partially based on the
**connection table per-interface parameters** mentioned above.

.. code-block:: console

   main heap size 3G

The next three parameters, *hash lookup heap size*, *hash lookup hash buckets*,
and *hash lookup hash memory*, modify the initialization of the bi-hash lookup
table used by the ACL plugin. This table is initialized when attempting to apply
an ACL to the existing vector of ACLs looked up during packet processing
(but it is found that the table does not exist / has not been initialized yet.)

hash lookup heap size  <n>G | <n>M | <n> K | <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the size of the memory heap that holds all the miscellaneous allocations
related to hash-based lookups. Default size is 67108864 bytes.

.. code-block:: console

   hash lookup heap size 70M

hash lookup hash buckets <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the number of hash buckets (rounded up to a power of 2) in the bi-hash
lookup table. Defaults to 65536 hash buckets.

.. code-block:: console

   hash lookup hash buckets 65536

hash lookup hash memory <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the allocated memory size (in bytes) for the bi-hash lookup table.
Defaults to 67108864 bytes.

.. code-block:: console

   hash lookup hash memory 67108864

use tuple merge <n>
^^^^^^^^^^^^^^^^^^^

Sets a boolean value indicating whether or not to use TupleMerge
for hash ACL's. Defaults to 1 (true), meaning the default implementation
of hashing ACL's does use TupleMerge.

.. code-block:: console

   use tuple merge 1

tuple merge split threshold <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the maximum amount of rules (ACE's) that can collide in a bi-hash
lookup table before the table is split into two new tables. Splitting ensures
less rule collisions by hashing colliding rules based on their common tuple
(usually their maximum common tuple.) Splitting occurs when the
*length of the colliding rules vector* is greater than this threshold amount.
Defaults to a maximum of 39 rule collisions per table.

.. code-block:: console

   tuple merge split threshold 30

reclassify sessions <n>
^^^^^^^^^^^^^^^^^^^^^^^

Sets a boolean value indicating whether or not to take the epoch of the session
into account when dealing with re-applying ACL's or changing already applied ACL's.
Defaults to 0 (false), meaning the default implementation does NOT take the
epoch of the session into account.

.. code-block:: console

   reclassify sessions 1

.. _api-queue:

api-queue Section
-----------------

length  <n>
^^^^^^^^^^^

Sets the api queue length. Minimum valid queue length is 1024, which is
also the default.

.. code-block:: console

   length 2048

.. _cj:

cj Section
----------

The circular journal (CJ) thread-safe circular log buffer scheme is
occasionally useful when chasing bugs. Calls to it should not be checked in.
See .../vlib/vlib/unix/cj.c. The circular journal is disables by default.
When enabled, the number of records must be provided, there is no default
value.

records <n>
^^^^^^^^^^^

Configure the number of circular journal records in the circular buffer.
The number of records should be a power of 2.

.. code-block:: console

   records 131072

on
^^

Turns on logging at the earliest possible moment.

.. code-block:: console

   on

dns Section
-----------

max-cache-size <n>
^^^^^^^^^^^^^^^^^^

Set the maximum number of active elements allowed in the pool of
dns cache entries. When resolving an expired entry or adding a new
static entry and the max number of active entries is reached,
a random, non-static entry is deleted. Defaults to 65535 entries.

.. code-block:: console

   max-cache-size 65535


ethernet Section
-----------------

default-mtu <n>
^^^^^^^^^^^^^^^

Specifies the default MTU size for Ethernet interfaces.  Must be in
the range of 64-9000.  The default is 9000.

.. code-block:: console

   default-mtu 1500

heapsize Section
-----------------

Heapsize configuration controls the size of the main heap. The heap size is
configured very early in the boot sequence, before loading plug-ins or doing
much of anything else.

heapsize <n>M | <n>G
^^^^^^^^^^^^^^^^^^^^

Specifies the size of the heap in MB or GB. The default is 1GB.

.. code-block:: console

   heapsize 2G

ip Section
----------

IPv4 heap configuration. he heap size is configured very early in the boot
sequence, before loading plug-ins or doing much of anything else.

heap-size <n>G | <n>M | <n>K | <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the IPv4 mtrie heap size, which is the amount of memory dedicated to
the destination IP lookup table. The input value can be set in GB, MB, KB
or bytes. The default value is 32MB.

.. code-block:: console

   heap-size 64M

ip6 Section
-----------

IPv6 heap configuration. he heap size is configured very early in the boot
sequence, before loading plug-ins or doing much of anything else.


heap-size <n>G | <n>M | <n>K | <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the IPv6 forwarding table heap size. The input value can be set in GB,
MB, KB or bytes. The default value is 32MB.

.. code-block:: console

   heap-size 64M

hash-buckets <n>
^^^^^^^^^^^^^^^^

Set the number of IPv6 forwarding table hash buckets. The default value is
64K (65536).

.. code-block:: console

   hash-buckets 131072

l2learn Section
---------------

Configure Layer 2 MAC Address learning parameters.

limit <n>
^^^^^^^^^

Configures the number of L2 (MAC) addresses in the L2 FIB at any one time,
which limits the size of the L2 FIB to <n> concurrent entries.  Defaults to
4M entries (4194304).

.. code-block:: console

   limit 8388608

l2tp Section
------------

IPv6 Layer 2 Tunnelling Protocol Version 3 (IPv6-L2TPv3) configuration controls
the method used to locate a specific IPv6-L2TPv3 tunnel. The following settings
are mutually exclusive:

lookup-v6-src
^^^^^^^^^^^^^

Lookup tunnel by IPv6 source address.

.. code-block:: console

   lookup-v6-src

lookup-v6-dst
^^^^^^^^^^^^^

Lookup tunnel by IPv6 destination address.

.. code-block:: console

   lookup-v6-dst

lookup-session-id
^^^^^^^^^^^^^^^^^

Lookup tunnel by L2TPv3 session identifier.

.. code-block:: console

   lookup-session-id

logging Section
---------------

size <n>
^^^^^^^^

Number of entries in the global logging buffer. Defaults to 512.

.. code-block:: console

   size 512

nthrottle-time <n>
^^^^^^^^^^^^^^^^^^

Set the global value for the time to wait (in seconds) before resuming
logging of a log subclass that exceeded the per-subclass message-per-second
threshold.  Defaults to 3.

.. code-block:: console

   unthrottle-time 3

default-log-level emerg|alert | crit | err | warn | notice | info | debug | disabled
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the default logging level of the system log.  Defaults to notice.

.. code-block:: console

   default-log-level notice

default-syslog-log-level emerg|alert | crit | err | warn | notice | info | debug | disabled
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the default logging level of the syslog target.  Defaults to warning.

.. code-block:: console

   default-syslog-log-level warning

mactime Section
---------------

lookup-table-buckets <n>
^^^^^^^^^^^^^^^^^^^^^^^^

Sets the number of hash buckets in the mactime bi-hash lookup table.
Defaults to 128 buckets.

.. code-block:: console

   lookup-table-buckets 128

lookup-table-memory <n>G | <n>M | <n>K | <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the allocated memory size (in bytes) for the mactime bi-hash lookup table.
The input value can be set in GB, MB, KB or bytes. The default value is 262144
(256 << 10) bytes or roughly 256KB.

.. code-block:: console

   lookup-table-memory 300K

timezone_offset <n>
^^^^^^^^^^^^^^^^^^^

Sets the timezone offset from UTC. Defaults to an offset of -5 hours
from UTC (US EST / EDT.)

.. code-block:: console

   timezone_offset -5

"map" Parameters
----------------

customer edge
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets a boolean true to indicate that the MAP node is a Customer Edge (CE)
router. The boolean defaults to false, meaning the MAP node is not treated
as a CE router.

.. code-block:: console

   customer edge

nat Section
-----------

These parameters change the configuration of the NAT (Network address translation)
plugin, such as how the NAT & NAT64 bi-hash tables are initialized, if the NAT is
endpoint dependent, or if the NAT is deterministic.

For each NAT per thread data, the following 4 parameters change how certain
bi-hash tables are initialized.

translation hash buckets <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the number of hash buckets in each of the two in/out NAT bi-hash lookup
tables. Defaults to 1024 buckets.

If the NAT is indicated to be endpoint dependent, which can be set with the
:ref:`endpoint-dependent parameter <endpointLabel>`, then this parameter sets
the number of hash buckets in each of the two endpoint dependent sessions
NAT bi-hash lookup tables.

.. code-block:: console

   translation hash buckets 1024

translation hash memory <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the allocated memory size (in bytes) for each of the two in/out NAT
bi-hash tables. Defaults to 134217728 (128 << 20) bytes, which is roughly 128 MB.

If the NAT is indicated to be endpoint dependent, which can be set with the
:ref:`endpoint-dependent parameter <endpointLabel>`, then this parameter sets the
allocated memory size for each of the two endpoint dependent sessions NAT bi-hash
lookup tables.

.. code-block:: console

   translation hash memory 134217728

user hash buckets <n>
^^^^^^^^^^^^^^^^^^^^^

Sets the number of hash buckets in the user bi-hash lookup table
(src address lookup for a user.) Defaults to 128 buckets.

.. code-block:: console

   user hash buckets 128

user hash memory <n>
^^^^^^^^^^^^^^^^^^^^

Sets the allocated memory size (in bytes) for the user bi-hash lookup table
(src address lookup for a user.) Defaults to 67108864 (64 << 20) bytes,
which is roughly 64 MB.

.. code-block:: console

   user hash memory 67108864

max translations per user <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the maximum amount of dynamic and/or static NAT sessions each user can have.
Defaults to 100. When this limit is reached, the least recently used translation
is recycled.

.. code-block:: console

   max translations per user 50

deterministic
^^^^^^^^^^^^^

Sets a boolean value to 1 indicating that the NAT is deterministic. Defaults to 0,
meaning the NAT is not deterministic.

.. code-block:: console

   deterministic

nat64 bib hash buckets <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the number of hash buckets in each of the two in/out NAT64 BIB bi-hash
tables. Defaults to 1024 buckets.

.. code-block:: console

   nat64 bib hash buckets 1024

nat64 bib hash memory <n>
^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the allocated memory size (in bytes) for each of the two in/out NAT64
BIB bi-hash tables. Defaults to 134217728 (128 << 20) bytes,
which is roughly 128 MB.

.. code-block:: console

   nat64 bib hash memory 134217728

nat64 st hash buckets <n>
^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the number of hash buckets in each of the two in/out NAT64 session table
bi-hash tables. Defaults to 2048 buckets.

.. code-block:: console

   nat64 st hash buckets 2048

nat64 st hash memory <n>
^^^^^^^^^^^^^^^^^^^^^^^^

Sets the allocated memory size (in bytes) for each of the two in/out NAT64 session
table bi-hash tables. Defaults to 268435456 (256 << 20) bytes, which is roughly
256 MB.

.. code-block:: console

   nat64 st hash memory 268435456

.. _endpointLabel:

endpoint-dependent
^^^^^^^^^^^^^^^^^^

Sets a boolean value to 1, indicating that the NAT is endpoint dependent.
Defaults to 0, meaning the NAT is not endpoint dependent.

.. code-block:: console

   endpoint-dependent

oam Section
-----------

OAM configuration controls the (ip4-icmp) interval, and number of misses
allowed before reporting an oam target down to any registered listener.

interval <n.n>
^^^^^^^^^^^^^^

Interval, floating-point seconds, between sending OAM IPv4 ICMP messages.
Default is 2.04 seconds.

.. code-block:: console

   interval 3.5

physmem Section
---------------

Configuration parameters used to specify base address and maximum size of
the memory allocated for the pmalloc module in VPP. pmalloc is a NUMA-aware,
growable physical memory allocator. pmalloc allocates memory for the DPDK
memory pool.

base-addr <address>
^^^^^^^^^^^^^^^^^^^

Specify the base address for pmalloc memory space.

.. code-block:: console

    base-addr 0xfffe00000000

max-size <n>G | <n>M | <n>K | <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Set the memory size for pmalloc memory space. The default is 16G.

.. code-block:: console

    max-size 4G

tapcli Section
--------------

Configuration parameters for TAPCLI (dynamic tap interface hookup.)

mtu <n>
^^^^^^^

Sets interface MTU (maximum transmission unit) size in bytes. This size
is also related to the number of MTU buffers. Defaults to 1500 bytes.

.. code-block:: console

   mtu 1500

disable
^^^^^^^

Disables TAPCLI. Default is that TAPCLI is enabled.

.. code-block:: console

   disable


tcp Section
-----------

Configuration parameters for TCP host stack utilities. The following
preallocation parameters are related to the initialization of fixed-size,
preallocation pools.

preallocated-connections <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the number of preallocated TCP connections. Defaults to 0.
The preallocated connections per thread is related to this value,
equal to (preallocated_connections / (num_threads - 1)).

.. code-block:: console

   preallocated-connections 5

preallocated-half-open-connections <n>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the number of preallocated TCP half-open connections. Defaults to 0.

.. code-block:: console

   preallocated-half-open-connections 5

buffer-fail-fraction <n.n>
^^^^^^^^^^^^^^^^^^^^^^^^^^

Sets the TCP buffer fail fraction (a float) used for fault-injection
when debugging TCP buffer allocation. Its use is found in *tcp_debug.h*.
Defaults to 0.0.

.. code-block:: console

   buffer-fail-fraction 0.0


tls Section
-----------

Configures TLS parameters, such as enabling the use of test certificates.
These parameters affect the tlsmbedtls and tlsopenssl plugins.

use-test-cert-in-ca
^^^^^^^^^^^^^^^^^^^

Sets a boolean value to 1 to indicate during the initialization of a
TLS CA chain to attempt to parse and add test certificates to the chain.
Defaults to 0, meaning test certificates are not used.

.. code-block:: console

   use-test-cert-in-ca

ca-cert-path <filename>
^^^^^^^^^^^^^^^^^^^^^^^

Sets the filename path of the location of TLS CA certificates, used when
initializing and loading TLS CA certificates during the initialization
of a TLS CA chain. If not set, the default filename path is
*/etc/ssl/certs/ca-certificates.crt*.

.. code-block:: console

   ca-cert-path /etc/ssl/certs/ca-certificates.crt


tuntap Section
--------------

The "tuntap" driver configures a point-to-point interface between the vpp
engine and the local Linux kernel stack. This allows e.g. users to ssh to the
host | VM | container via vpp "revenue" interfaces. It's marginally useful, and
is currently disabled by default. To [dynamically] create TAP interfaces - the
preferred scheme - see the "tap_connect" binary API. The Linux network stack
"vnet" interface needs to manually configure, and VLAN and other settings if
desired.


enable|disable
^^^^^^^^^^^^^^

Enable or disable the tun/tap driver.

.. code-block:: console

   enable

ethernet|ether
^^^^^^^^^^^^^^

Create a tap device (ethernet MAC) instead of a tun device (point-to-point
tunnel). The two keywords are aliases for the same function.

.. code-block:: console

   ethernet

have-normal-interface|have-normal
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Treat the host Linux stack as a routing peer instead of programming VPP
interface L3 addresses onto the tun/tap devices. The two keywords are
aliases for the same function.

.. code-block:: console

   have-normal-interface

name <name>
^^^^^^^^^^^

Assign name to the tun/tap device.

.. code-block:: console

   name vpp1


vhost-user Section
------------------

Vhost-user configuration parameters control the vhost-user driver.

coalesce-frames <n>
^^^^^^^^^^^^^^^^^^^

Subject to deadline-timer expiration - see next item - attempt to transmit
at least <n> packet frames. Default is 32 frames.

.. code-block:: console

   coalesce-frames 64

coalesce-time <seconds>
^^^^^^^^^^^^^^^^^^^^^^^

Hold packets no longer than (floating-point) seconds before transmitting
them. Default is 0.001 seconds

.. code-block:: console

   coalesce-time 0.002

dont-dump-memory
^^^^^^^^^^^^^^^^

vhost-user shared-memory segments can add up to a large amount of memory, so
it's handy to avoid adding them to corefiles when using a significant number
of such interfaces.

.. code-block:: console

   dont-dump-memory


vlib Section
------------

These parameters configure VLIB, such as allowing you to choose whether to
enable memory traceback or a post-mortem elog dump.

memory-trace
^^^^^^^^^^^^

Enables memory trace (mheap traceback.) Defaults to 0, meaning memory
trace is disabled.

.. code-block:: console

   memory-trace

elog-events <n>
^^^^^^^^^^^^^^^

Sets the number of elements/events (the size) of the event ring
(a circular buffer of events.) This number rounds to a power of 2.
Defaults to 131072 (128 << 10) elements.

.. code-block:: console

   elog-events 4096

elog-post-mortem-dump
^^^^^^^^^^^^^^^^^^^^^

Enables the attempt of a post-mortem elog dump to
*/tmp/elog_post_mortem.<PID_OF_CALLING_PROCESS>* if os_panic or
os_exit is called.

.. code-block:: console

   elog-post-mortem-dump

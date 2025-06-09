.. _Sflow_agent:

.. toctree::

sFlow Monitoring Agent
======================

Overview
________

This plugin implements the random packet-sampling, interface
telemetry streaming and packet drop monitoring necessary to support sFlow
export on Linux. The overhead is minimal, allowing detailed real-time
traffic analysis even under high load conditions. The samples, counters and
drops are sent to Linux Netlink channels PSAMPLE, USERSOCK and DROPMON where
tools such as host-sflow at https://sflow.net will receive them and export
standard sFlow. If the VPP linux-cp plugin is running then interfaces will
be mapped to their equivalent Linux tap ports.

Example Configuration
_____________________

::

    sflow sampling-rate 10000
    sflow polling-interval 20
    sflow header-bytes 128
    sflow direction both
    sflow drop-monitoring enable
    sflow enable GigabitEthernet0/8/0
    sflow enable GigabitEthernet0/9/0
    sflow enable GigabitEthernet0/a/0

Detailed notes
______________

Each VPP worker handling packets on an sFlow-enabled interface will enqueue
1:N random-sampled packet headers to a FIFO that is serviced by a process
in the main thread. These FIFOs are of limited depth. If a FIFO overflows the
worker will drop samples efficiently, which limits the overhead on both workers
and main thread even under high load conditions.

Similarly, all packets traversing the error-drop arc are enqueued on another
limited-depth FIFO that is also serviced in the main thread.

The main thread writes the sampled packet headers to netlink-PSAMPLE,
and the dropped packet headers to netlink-DROPMON. It also writes interface
status and counters to netlink-USERSOCK according to the configured
polling-interval. If a tool such as the host-sflow daemon at https://sflow.net
is running locally (with its vpp module enabled) then it will receive them and
export standard sFlow.

If the VPP linux-cp plugin is running, the mapping from vpp interface to
Linux interface is included in the netlink-USERSOCK feed, allowing the
host-sflow daemon to export with either numbering model.

For efficiency, the workers take advantage of the fact that sampling all
packets at 1:N is the same as sampling 1:N from each interface. The
same principle allows for sampling on "rx", "tx" or "both" directions
without incurring additional overhead.

If the configured sampling-rate is too aggressive for the current traffic
level the agent will drop samples, but information about this "clipping" is
also communicated to the sFlow collector.

External Dependencies
_____________________

This plugin only works on Linux platforms.
The Linux kernel "psample" module must be loaded with modprobe or insmod.
The open source host-sflow daemon is at https://sflow.net.
The sFlow v5 spec is published at https://sflow.org.
